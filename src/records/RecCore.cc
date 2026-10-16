/** @file

  Record core definitions

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include <algorithm>
#include <deque>
#include <utility>
#include <iostream>

#include "records/RecDefs.h"
#include "swoc/swoc_file.h"

#include "ts/apidefs.h"
#include "tscore/ink_platform.h"
#include "tscore/ink_memory.h"
#include "tscore/ink_string.h"
#include "tscore/Filenames.h"

#include "records/RecordsConfig.h"
#include "P_RecFile.h"
#include "P_RecCore.h"
#include "P_RecUtils.h"
#include "tscore/Layout.h"
#include "tsutil/ts_errata.h"
#include "tsutil/Metrics.h"
#include "tsutil/Regex.h"

using ts::Metrics;

namespace
{
// Cap on the backtracking steps one record name may cost during a regex lookup.
//
// The pattern comes from the admin_lookup_records RPC and is run against every record name, so a
// pattern that backtracks without limit monopolizes the single-threaded RPC server. This cap ends
// that particular shape: measured on a default build, which registers 576 config records, the
// shapes in the test suite drop from seconds to milliseconds per lookup, and a concurrent trivial
// lookup stops being blocked behind them. Those figures are one host's readings, and the metric
// count on any instance is a runtime quantity; only the order of magnitude transfers.
//
// What this cap does NOT do is bound the work a lookup can cost. It counts steps, and the cost of
// a step is set by the pattern, so a caller can stay inside the cap and still be expensive, and
// can be expensive while every name reaches an ordinary verdict. Nothing below reports that case,
// because the counting is keyed on the codes PCRE2 returns when a resource runs out. Bounding the
// work itself needs a different mechanism and is tracked separately; do not read this constant, or
// the reporting under it, as a general bound.
//
// For the shape it does cover: attacker cost grows linearly with the cap, while the longest name a
// legitimate pattern can still resolve grows only as its square root, since proving no match costs
// about L^2/2 steps for a backtracking run of length L. 50,000 resolves runs up to ~310
// characters, 4.7x the 66 character longest name a default build registers.
//
// So the cap is sized from each name, L^2 for a name of L characters, held between
// REGEX_MATCH_LIMIT_FLOOR and REGEX_MATCH_LIMIT. A single flat cap gives every short name the
// budget only the longest names need, and the short names are most of a store. The ceiling still
// applies from 224 characters up, so a long name resolves exactly what it did under the flat cap,
// and the floor keeps 1,024 steps for a name too short for L^2 to leave an ordinary pattern room.
//
// What the cap bounds is one start position, not one name. The limit is counted per pcre2_match()
// call and is reset for each call, not carried across the start offsets tried within one (pcre2api,
// MATCH LIMIT), so an unanchored pattern gets the whole budget again at every position. Probed on
// 10.47 with this call site's compile flags: "zq" against a subject of 200 'z' characters, where
// PCRE2's start-code-unit optimisation cannot skip a single offset, still resolves at a limit of 1,
// exactly as it does at 25 characters; an accumulating counter would have needed one unit per
// position. A name can therefore cost up to about L times the cap in total. Sizing the cap from L
// is still what keeps the per-position budget proportionate, but this is not a per-name bound, and
// bounding the work a whole lookup may cost is tracked separately.
//
// Every step count below is the minimum match limit at which the pattern reaches a verdict on PCRE2
// 10.47 with this call site's compile flags, against a subject of L 'a' characters, which holds
// neither '~' nor '='. The counts move with the name's content: the two for the grouped pattern
// further down shift by a few percent against a real record name, while the rest are unchanged.
//
// What L^2 covers is the L^2/2 model above, which is two wildcards composing over a run of length
// L, so that shape keeps about 2x headroom: ".*.*[~=]" needs 2,079 steps against the 3,844 a 62
// character name is given, and 25,424 against the 49,729 of a 223 character one. A single ambiguous
// quantifier is linear in L and nowhere near either number.
//
// Adding ambiguity beyond that costs about L^2 + 5L under the JIT, which for a name over about 30
// characters is just over the cap: a third wildcard, or an optional separator between two, is
// enough. Under the JIT ".*.*.*[~=]" needs 4,095 steps against the 3,844 a 62 character name is
// given, and "^(.*)\.?(.*)\.?[~=]" needs 4,158. Both bounds are JIT and length specific: at 30
// characters ".*.*.*[~=]" needs 1,023 against the 1,024 floor and resolves, and on the interpreter
// the two shapes diverge -- "^(.*)\.?(.*)\.?[~=]" needs only 2,081 at 62 characters and resolves,
// while ".*.*.*[~=]" grows cubically instead, 43,681 at 62 characters and 585,277 at 150. So a
// pattern past two ambiguous parts may be reported as undecided on names a flat 50,000 resolved,
// depending on the shape, the length and whether the JIT compiled it. The
// trade is deliberate, since those are also the shapes whose cost grows fastest, and a cap wide
// enough to admit every composition of them is the flat cap this replaces -- but it is a real
// narrowing, and an operator who writes one sees it reported rather than silently dropped.
//
// The 1750 still used by esi reaches only ~59 by the same model and so cannot resolve what ships.
// It is not a precedent for a work budget in any case: per apache/trafficserver#13651 the PCRE2
// conversion turned what had been a PCRE1 recursion-depth limit into a match-work limit, a
// different quantity, and apache/trafficserver#13652 removed it from regex_remap for that reason,
// leaving esi as its only remaining user.
constexpr uint32_t REGEX_MATCH_LIMIT       = 50000;
constexpr uint32_t REGEX_MATCH_LIMIT_FLOOR = 1024;

// Step cap for one record name of @a name_length characters, as described above.
uint32_t
match_limit_for(size_t name_length)
{
  if (name_length >= REGEX_MATCH_LIMIT) {
    // Any name this long clamps to the ceiling whatever its square is, so returning it here keeps
    // the multiply below away from a length that could overflow it.
    return REGEX_MATCH_LIMIT;
  }
  return static_cast<uint32_t>(
    std::clamp<uint64_t>(static_cast<uint64_t>(name_length) * name_length, REGEX_MATCH_LIMIT_FLOOR, REGEX_MATCH_LIMIT));
}
} // namespace

// This is needed to manage the size of the librecords record. It can't be static, because it needs to be modified
// and used (read) from several binaries / modules.
int                                          max_records_entries = REC_DEFAULT_ELEMENTS_SIZE;
static bool                                  g_initialized       = false;
RecRecord                                   *g_records           = nullptr;
std::unordered_map<std::string, RecRecord *> g_records_ht;
ink_rwlock                                   g_records_rwlock;
int                                          g_num_records = 0;

//-------------------------------------------------------------------------
// register_record
//-------------------------------------------------------------------------
static RecRecord *
register_record(RecT rec_type, const char *name, RecDataT data_type, RecData data_default, RecPersistT persist_type,
                bool *updated_p = nullptr)
{
  RecRecord *r = nullptr;

  // Metrics are restored from persistence before they are registered. In this case, when the registration arrives, we
  // might find that they have changed. For example, a metric might change it's type due to a software upgrade. Records
  // must not flip between config and metrics, but changing within those classes is OK.
  if (auto it = g_records_ht.find(name); it != g_records_ht.end()) {
    r = it->second;
    if (REC_TYPE_IS_STAT(rec_type)) {
      ink_release_assert(REC_TYPE_IS_STAT(r->rec_type));
    }

    if (REC_TYPE_IS_CONFIG(rec_type)) {
      ink_release_assert(REC_TYPE_IS_CONFIG(r->rec_type));
    }

    if (data_type != r->data_type) {
      // Clear with the old type before resetting with the new type.
      RecDataZero(r->data_type, &(r->data));
      RecDataZero(r->data_type, &(r->data_default));

      // If the data type changed, reset the current value to the default.
      RecDataSet(data_type, &(r->data), &(data_default));
    }

    // NOTE: Do not set r->data as we want to keep the previous value because we almost certainly restored a persisted
    // value before the metric was registered.
    RecDataSet(data_type, &(r->data_default), &(data_default));

    r->data_type = data_type;
    r->rec_type  = rec_type;

    if (updated_p) {
      *updated_p = true;
    }
  } else {
    if ((r = RecAlloc(rec_type, name, data_type)) == nullptr) {
      return nullptr;
    }

    // Set the r->data to its default value as this is a new record
    RecDataSet(r->data_type, &(r->data), &(data_default));
    RecDataSet(r->data_type, &(r->data_default), &(data_default));
    g_records_ht.emplace(name, r);

    if (REC_TYPE_IS_STAT(r->rec_type)) {
      r->stat_meta.persist_type = persist_type;
    }

    if (updated_p) {
      *updated_p = false;
    }
  }

  // we're now registered
  r->registered = true;
  r->version    = 0;

  return r;
}

//-------------------------------------------------------------------------
// link_XXX
//-------------------------------------------------------------------------
static int
link_int(const char * /* name */, RecDataT /* data_type */, RecData data, void *cookie)
{
  RecInt *rec_int = static_cast<RecInt *>(cookie);
  ink_atomic_swap(rec_int, data.rec_int);
  return REC_ERR_OKAY;
}

static int
link_int32(const char * /* name */, RecDataT /* data_type */, RecData data, void *cookie)
{
  *(static_cast<int32_t *>(cookie)) = static_cast<int32_t>(data.rec_int);
  return REC_ERR_OKAY;
}

static int
link_uint32(const char * /* name */, RecDataT /* data_type */, RecData data, void *cookie)
{
  *(static_cast<uint32_t *>(cookie)) = static_cast<uint32_t>(data.rec_int);
  return REC_ERR_OKAY;
}

static int
link_float(const char * /* name */, RecDataT /* data_type */, RecData data, void *cookie)
{
  *(static_cast<RecFloat *>(cookie)) = data.rec_float;
  return REC_ERR_OKAY;
}

static int
link_counter(const char * /* name */, RecDataT /* data_type */, RecData data, void *cookie)
{
  RecCounter *rec_counter = static_cast<RecCounter *>(cookie);
  ink_atomic_swap(rec_counter, data.rec_counter);
  return REC_ERR_OKAY;
}

// This is a convenience wrapper, to allow us to treat the RecInt's as a
// 1-byte entity internally.
static int
link_byte(const char * /* name */, RecDataT /* data_type */, RecData data, void *cookie)
{
  RecByte *rec_byte = static_cast<RecByte *>(cookie);
  RecByte  byte     = static_cast<RecByte>(data.rec_int);

  ink_atomic_swap(rec_byte, byte);
  return REC_ERR_OKAY;
}

// mimic Config.cc::config_string_alloc_cb
// cookie e.g. is the DEFAULT_xxx_str value which this function keeps up to date with
// the latest default applied during a config update from records
static int
link_string_alloc(const char * /* name */, RecDataT /* data_type */, RecData data, void *cookie)
{
  RecString _ss        = data.rec_string;
  RecString _new_value = nullptr;

  if (_ss) {
    _new_value = ats_strdup(_ss);
  }

  // set new string for DEFAULT_xxx_str tp point to
  RecString _temp2                    = *(static_cast<RecString *>(cookie));
  *(static_cast<RecString *>(cookie)) = _new_value;
  // free previous string DEFAULT_xxx_str points to
  ats_free(_temp2);

  return REC_ERR_OKAY;
}

//-------------------------------------------------------------------------
// RecCoreInit
//-------------------------------------------------------------------------
int
RecCoreInit(Diags *_diags)
{
  if (g_initialized) {
    return REC_ERR_OKAY;
  }

  // set our diags
  RecSetDiags(_diags);

  // Initialize config file parsing data structures.
  RecConfigFileInit();

  g_num_records = 0;

  // initialize record array for our internal stats (this can be reallocated later)
  g_records = static_cast<RecRecord *>(ats_malloc(max_records_entries * sizeof(RecRecord)));

  // initialize record rwlock
  ink_rwlock_init(&g_records_rwlock);

  // read stats
  RecReadStatsFile();

  // read configs
  bool file_exists = true;

  ink_mutex_init(&g_rec_config_lock);

  g_rec_config_fpath = ats_stringdup(RecConfigReadConfigPath(nullptr, ts::filename::RECORDS));

  // Make sure there is no legacy file, if so we drop a BIG WARNING and fail.
  // This is to avoid issues with someone ignoring that we now use records.yaml
  swoc::file::path old_config{RecConfigReadConfigPath(nullptr, "records.config")};
  if (swoc::file::is_readable(old_config)) {
    RecLog(DL_Fatal,
           "**** Found a legacy config file (%s). Please remove it and migrate to the new YAML format before continuing. ****",
           old_config.c_str());
  }

  if (RecFileExists(g_rec_config_fpath) == REC_ERR_FAIL) {
    RecLog(DL_Warning, "Could not find '%s', system will run with defaults\n", ts::filename::RECORDS);
    file_exists = false;
  }

  if (file_exists) {
    auto err = RecReadYamlConfigFile();
    RecLog(DL_Note, "records parsing completed.");
    if (!err.empty()) {
      std::string text;
      RecLog(DL_Warning, "%s",
             swoc::bwprint(text, "We have found the following issues when reading the records node:\n {}", err).c_str());
    }
  } else {
    RecLog(DL_Note, "%s does not exist.", g_rec_config_fpath);
  }

  RecLog(DL_Note, "%s finished loading", std::string{g_rec_config_fpath}.c_str());
  g_initialized = true;

  return REC_ERR_OKAY;
}

//-------------------------------------------------------------------------
// RecLinkConfigXXX
//-------------------------------------------------------------------------
RecErrT
RecLinkConfigInt(const char *name, RecInt *rec_int)
{
  auto tmp{RecGetRecordInt(name)};
  if (!tmp) {
    return REC_ERR_FAIL;
  }
  *rec_int = tmp.value();
  return RecRegisterConfigUpdateCb(name, link_int, (void *)rec_int);
}

RecErrT
RecLinkConfigInt32(const char *name, int32_t *p_int32)
{
  return RecRegisterConfigUpdateCb(name, link_int32, (void *)p_int32);
}

RecErrT
RecLinkConfigUInt32(const char *name, uint32_t *p_uint32)
{
  return RecRegisterConfigUpdateCb(name, link_uint32, (void *)p_uint32);
}

RecErrT
RecLinkConfigFloat(const char *name, RecFloat *rec_float)
{
  auto tmp{RecGetRecordFloat(name)};
  if (!tmp) {
    return REC_ERR_FAIL;
  }
  *rec_float = tmp.value();
  return RecRegisterConfigUpdateCb(name, link_float, (void *)rec_float);
}

RecErrT
RecLinkConfigCounter(const char *name, RecCounter *rec_counter)
{
  auto tmp{RecGetRecordCounter(name)};
  if (!tmp) {
    return REC_ERR_FAIL;
  }
  *rec_counter = tmp.value();
  return RecRegisterConfigUpdateCb(name, link_counter, (void *)rec_counter);
}

RecErrT
RecLinkConfigString(const char *name, RecString *rec_string)
{
  {
    auto tmp{RecGetRecordStringAlloc(name)};
    if (!tmp) {
      return REC_ERR_FAIL;
    }
    *rec_string = ats_stringdup(tmp);
  }
  return RecRegisterConfigUpdateCb(name, link_string_alloc, (void *)rec_string);
}

RecErrT
RecLinkConfigByte(const char *name, RecByte *rec_byte)
{
  auto tmp{RecGetRecordInt(name)};
  if (!tmp) {
    return REC_ERR_FAIL;
  }
  *rec_byte = tmp.value();
  return RecRegisterConfigUpdateCb(name, link_byte, (void *)rec_byte);
}

//-------------------------------------------------------------------------
// RecRegisterConfigUpdateCb
//-------------------------------------------------------------------------
RecErrT
RecRegisterConfigUpdateCb(const char *name, RecConfigUpdateCb const &update_cb, void *cookie)
{
  RecErrT err = REC_ERR_FAIL;

  ink_rwlock_rdlock(&g_records_rwlock);

  if (auto it = g_records_ht.find(name); it != g_records_ht.end()) {
    RecRecord *r = it->second;

    rec_mutex_acquire(&(r->lock));
    if (REC_TYPE_IS_CONFIG(r->rec_type)) {
      /* -- upgrade to support a list of callback functions
         if (!(r->config_meta.update_cb)) {
         r->config_meta.update_cb = update_cb;
         r->config_meta.update_cookie = cookie;
         err = REC_ERR_OKAY;
         }
       */

      RecConfigUpdateCbList *new_callback = new RecConfigUpdateCbList(update_cb, cookie);
      ink_assert(new_callback);
      if (!r->config_meta.update_cb_list) {
        r->config_meta.update_cb_list = new_callback;
      } else {
        RecConfigUpdateCbList *cur_callback  = nullptr;
        RecConfigUpdateCbList *prev_callback = nullptr;
        for (cur_callback = r->config_meta.update_cb_list; cur_callback; cur_callback = cur_callback->next) {
          prev_callback = cur_callback;
        }
        ink_assert(prev_callback);
        ink_assert(!prev_callback->next);
        prev_callback->next = new_callback;
      }
      err = REC_ERR_OKAY;
    }

    rec_mutex_release(&(r->lock));
  }

  ink_rwlock_unlock(&g_records_rwlock);

  return err;
}

void
Enable_Config_Var(std::string_view const &name, RecContextCb record_cb, RecConfigUpdateCb const &config_cb, void *cookie)
{
  // Must use this indirection because the API requires a pure function, therefore no values can
  // be bound in the lambda. Instead this is needed to pass in the data for both the lambda and
  // the actual callback.
  using Context = std::tuple<decltype(record_cb), void *>;

  Context ctx(record_cb, cookie);
  // Register the call back - this handles external updates.
  RecRegisterConfigUpdateCb(
    name.data(),
    [config_cb, record_cb](const char *name, RecDataT dtype, RecData data, void *cookie) -> int {
      if (record_cb(name, dtype, data, cookie)) {
        config_cb(name, dtype, data, cookie); // Let the caller handle the runtime config update.
      }
      return REC_ERR_OKAY;
    },
    cookie);

  // Use the record to do the initial data load.
  // Look it up and call the updater @a cb on that data.
  RecLookupRecord(
    name.data(),
    [](RecRecord const *r, void *ctx) -> void {
      auto &&[cb, cookie] = *static_cast<Context *>(ctx);
      (*cb)(r->name, r->data_type, r->data, cookie);
    },
    &ctx);
}

//-------------------------------------------------------------------------
// RecGetRecordXXX
//-------------------------------------------------------------------------
std::optional<RecInt>
RecGetRecordInt(const char *name, bool lock)
{
  RecData               data;
  std::optional<RecInt> rec_int;

  if (RecGetRecord_Xmalloc(name, RECD_INT, &data, lock) == REC_ERR_OKAY) {
    rec_int = data.rec_int;
  }
  return rec_int;
}

std::optional<RecFloat>
RecGetRecordFloat(const char *name, bool lock)
{
  RecData                 data;
  std::optional<RecFloat> rec_float;

  if (RecGetRecord_Xmalloc(name, RECD_FLOAT, &data, lock) == REC_ERR_OKAY) {
    rec_float = data.rec_float;
  }
  return rec_float;
}

std::optional<std::string_view>
RecGetRecordString(const char *name, char *buf, int buf_len, bool lock)
{
  std::optional<std::string_view> ret;

  if (lock) {
    ink_rwlock_rdlock(&g_records_rwlock);
  }
  if (auto it = g_records_ht.find(name); it != g_records_ht.end()) {
    RecRecord *r = it->second;

    rec_mutex_acquire(&(r->lock));
    if (r->registered && r->data_type == RECD_STRING) {
      if (r->data.rec_string == nullptr) {
        buf[0] = '\0';
      } else {
        ink_strlcpy(buf, r->data.rec_string, buf_len);
      }
      ret = std::string_view{buf};
    }
    rec_mutex_release(&(r->lock));
  }
  if (lock) {
    ink_rwlock_unlock(&g_records_rwlock);
  }
  return ret;
}

std::optional<std::string>
RecGetRecordStringAlloc(const char *name, bool lock)
{
  // Must use this indirection because the API requires a pure function, therefore no values can
  // be bound in the lambda.
  using Context = std::optional<std::string>;
  Context ret{};

  RecLookupRecord(
    name,
    [](RecRecord const *r, void *ctx) -> void {
      auto &&str = *static_cast<Context *>(ctx);
      if (r->registered && r->data_type == RECD_STRING) {
        if (auto rec_str{r->data.rec_string}; rec_str) {
          auto len{strlen(rec_str)};
          if (len) {
            // Chop trailing spaces
            auto end{rec_str + len - 1};
            while (end >= rec_str && isspace(*end)) {
              end--;
            }
            len = static_cast<std::string::size_type>(end + 1 - rec_str);
          }
          str = len ? std::string{rec_str, len} : std::string{};
        }
      }
    },
    &ret, lock);
  return ret;
}

std::optional<RecCounter>
RecGetRecordCounter(const char *name, bool lock)
{
  RecData                   data;
  std::optional<RecCounter> rec_counter;

  if (RecGetRecord_Xmalloc(name, RECD_COUNTER, &data, lock) == REC_ERR_OKAY) {
    rec_counter = data.rec_counter;
  }
  return rec_counter;
}

//-------------------------------------------------------------------------
// RecGetRec Attributes
//-------------------------------------------------------------------------

RecErrT
RecLookupRecord(const char *name, void (*callback)(const RecRecord *, void *), void *data, bool lock)
{
  RecErrT             err     = REC_ERR_FAIL;
  ts::Metrics        &metrics = ts::Metrics::instance();
  ts::Metrics::IdType metric_id;

  // A metric's storage is stable after creation. Avoid find()/end() here because end() is the current insertion position and
  // can advance between those two calls while another thread registers a metric.
  if (auto *metric = metrics.lookup(name, &metric_id); metric != nullptr) {
    RecRecord r{};

    r.rec_type     = RECT_PLUGIN;
    r.data_type    = metrics.type(metric_id) == ts::Metrics::MetricType::COUNTER ? RECD_COUNTER : RECD_INT;
    r.name         = name;
    r.data.rec_int = metric->load();
    r.registered   = true;

    callback(&r, data);
    err = REC_ERR_OKAY;
  } else {
    if (lock) {
      ink_rwlock_rdlock(&g_records_rwlock);
    }

    if (auto it = g_records_ht.find(name); it != g_records_ht.end()) {
      RecRecord *r = it->second;

      rec_mutex_acquire(&(r->lock));
      callback(r, data);
      err = REC_ERR_OKAY;
      rec_mutex_release(&(r->lock));
    }

    if (lock) {
      ink_rwlock_unlock(&g_records_rwlock);
    }

    // Also check for StaticString metrics
    if (err == REC_ERR_FAIL) {
      auto &strings = ts::Metrics::StaticString::instance();

      if (auto m = strings.lookup(std::string{name}); m) {
        RecRecord r{};
        r.rec_type                = RECT_PLUGIN;
        r.data_type               = RECD_STRING;
        r.name                    = name;
        r.data.rec_string         = const_cast<char *>(m->data());
        r.data_default.rec_string = const_cast<char *>(m->data());

        callback(&r, data);
        err = REC_ERR_OKAY;
      }
    }
  }

  return err;
}

RecErrT
RecLookupMatchingRecords(unsigned rec_type, const char *match, void (*callback)(const RecRecord *, void *), void *data,
                         bool /* lock ATS_UNUSED */, unsigned *indeterminate_out)
{
  Regex regex;

  if (indeterminate_out) {
    *indeterminate_out = 0;
  }

  std::string compile_error;
  int         compile_offset = 0;

  // RE_NEVER_UTF refuses a pattern that opens with (*UTF). In UTF mode pcre2 validates each subject
  // as UTF-8 first, and a record name is a byte string that nothing guarantees is valid UTF-8: such
  // a name returns PCRE2_ERROR_UTF8_ERR*, which the classification below counts as undecided, so
  // one verb from the caller reports the whole lookup incomplete over names the pattern does not
  // even match. The verb is refused only here, where the pattern is untrusted; elsewhere (*UTF) is
  // a documented thing for an operator to write (doc/admin-guide/configuration/regex-best-practices).
  //
  // It is not a backtracking bound. Measured against PCRE2 10.47 a (*UTF) pattern JIT-compiles and
  // stays on the JIT, hitting the same limits as the same pattern without it. (*NO_JIT) is the verb
  // that moves a match to the interpreter, and pcre2 offers no way to refuse that one; it buys an
  // attacker about 5x the CPU per name within the same step cap, which is the step-cost residual
  // this cap does not close and the file comment below describes.
  if (!regex.compile(match, compile_error, compile_offset, RE_CASE_INSENSITIVE | RE_UNANCHORED | RE_NEVER_UTF)) {
    // The pattern itself is not echoed; the log should not carry unvalidated input. PCRE2's message
    // and offset are its own, so they are safe to report and are the only way an operator learns
    // which character was rejected.
    SiteThrottledWarning("record lookup pattern failed to compile at offset %d: %s", compile_offset, compile_error.c_str());
    return REC_ERR_FAIL;
  }

  RegexMatchContext match_context;
  RegexMatches      matches;

  // A bounded match has three outcomes, not two. PCRE2 reports a match, the single code that means
  // "this name definitively does not match", or one of several codes meaning it gave up without
  // deciding. Only the middle one is a verdict, so classify by exclusion: anything else negative is
  // counted and reported once per lookup rather than silently dropping records from the caller's
  // results.
  //
  // Enumerating the expected code instead would be wrong, because which resource runs out first is
  // a property of the pattern, not a constant. Ordinary catastrophic backtracking does exhaust the
  // step count and report PCRE2_ERROR_MATCHLIMIT, but a recursive pattern exhausts the JIT stack
  // first and reports PCRE2_ERROR_JIT_STACKLIMIT, or PCRE2_ERROR_RECURSELOOP where JIT is
  // unavailable; depth and heap limits have their own codes again. These call sites make the
  // recursive case easier to reach than it would otherwise be, because a private match context
  // carries no JIT stack and so runs on PCRE2's default 32KB block rather than the 1MB the
  // thread-global context assigns (see RegexMatchContext, src/tsutil/Regex.cc). Counting only
  // MATCHLIMIT let such a pattern drop every record while reporting nothing.
  unsigned indeterminate = 0;
  int      first_error   = 0;
  uint32_t first_cap     = 0;

  // Matches @a name under its own step cap. True if it matched, false if the name should be
  // skipped. Bumps the counters as a side effect, so every call site caps and classifies
  // identically. The cap is sized from the same view the match runs on.
  auto matched = [&](std::string_view name) -> bool {
    match_context.set_match_limit(match_limit_for(name.size()));
    int const rc = regex.exec(name, matches, 0, &match_context);
    if (rc >= 0) {
      return true;
    }
    if (rc != RE_ERROR_NOMATCH) {
      ++indeterminate;
      if (first_error == 0) {
        first_error = rc;
        first_cap   = match_context.match_limit();
      }
    }
    return false;
  };

  if ((rec_type & (RECT_PROCESS | RECT_NODE | RECT_PLUGIN))) {
    // First find the new metrics, this is a bit of a hack, because we still use the old
    // librecords callback with a "pseudo" record.
    ts::Metrics::instance().for_each([&](std::string_view name, ts::Metrics::MetricType type, int64_t val) {
      if (matched(name.data())) {
        RecRecord tmp{};

        tmp.rec_type = RECT_PROCESS;

        tmp.name         = name.data();
        tmp.data_type    = type == ts::Metrics::MetricType::COUNTER ? RECD_COUNTER : RECD_INT;
        tmp.data.rec_int = val;
        callback(&tmp, data);
      }
    });
    // Finally check string metrics
    ts::Metrics::StaticString::instance().for_each([&](const std::string &name, const std::string &value) {
      if (matched(name)) {
        RecRecord tmp{};

        tmp.rec_type = RECT_PROCESS;

        tmp.name      = name.data();
        tmp.data_type = RECD_STRING;
        // NOTE(cmcfarlen): unfortunate relic here that the callbacks expect a non-const rec_string
        // This should be temp until traffic_ctl uses ts::Metrics directly
        tmp.data.rec_string = const_cast<char *>(value.c_str());
        callback(&tmp, data);
      }
    });
  }

  if (rec_type & RECT_HIDDEN_METRIC) {
    // Opt-in only: hidden metrics are never reachable through RECT_ALL, see RecDefs.h.
    auto &hidden = ts::Metrics::hidden_instance();

    hidden.for_each([&](std::string_view name, ts::Metrics::MetricType type, int64_t val) {
      // Slot 0 of every Storage is the reserved bad_id placeholder, so it exists under the same
      // name in both stores. Skip it here, otherwise a query matching it returns two identically
      // named records that differ only in value.
      if (name == ts::Metrics::BAD_ID_NAME) {
        return;
      }

      if (matched(name.data())) {
        RecRecord tmp{};

        // Tag both bits so that a caller asking only for RECT_HIDDEN_METRIC passes the rec_type
        // check the lookup callback applies to every record it is handed. Note this combination
        // satisfies neither REC_TYPE_IS_STAT nor REC_TYPE_IS_CONFIG (both compare for equality),
        // so the YAML encoder emits no stat_meta block for hidden metrics. That is intentional:
        // the meta fields of this synthetic record were never populated.
        tmp.rec_type = static_cast<RecT>(RECT_PROCESS | RECT_HIDDEN_METRIC);

        tmp.name         = name.data();
        tmp.data_type    = type == ts::Metrics::MetricType::COUNTER ? RECD_COUNTER : RECD_INT;
        tmp.data.rec_int = val;
        callback(&tmp, data);
      }
    });
  }

  int num_records = g_num_records;
  for (int i = 0; i < num_records; i++) {
    RecRecord *r = &(g_records[i]);

    if ((r->rec_type & rec_type) == 0) {
      continue;
    }

    if (!matched(r->name)) {
      continue;
    }

    rec_mutex_acquire(&(r->lock));
    callback(r, data);
    rec_mutex_release(&(r->lock));
  }

  if (indeterminate > 0) {
    // Throttled because admin_lookup_records is NON_RESTRICTED_API: it takes no credentials and the
    // management socket carries no peer check, so an unprivileged local caller can otherwise drive
    // this line at will and bury the instances that matter.
    //
    // The caller supplied pattern is deliberately not echoed; the log should not carry unvalidated
    // input.
    //
    // The step cap is reported as configuration and the PCRE2 error separately, because they are
    // not the same claim: a recursive pattern exhausts the JIT stack well before the step count, so
    // saying these names were undecided "within" the cap would misdescribe that case. The error
    // string is what tells an operator which resource was actually binding.
    //
    // Each name runs under its own cap, so the one named is the cap of the first undecided name,
    // read back from the context right after that name's match, together with the ceiling every
    // cap is held under. It is read back rather than recomputed so that the number named here is
    // the one installed, and a context that took no cap cannot be reported as though it had. It is
    // a ceiling rather than necessarily the limit applied: the caller's pattern can lower it with an
    // inline (*LIMIT_MATCH=n), which only truncates that caller's own lookup further and is still
    // reported, but cannot raise it.
    //
    // match_limit_for never returns zero, so a zero here can only mean the match context could not
    // be allocated. Regex::exec then refuses every name with RE_ERROR_NULL instead of matching under
    // PCRE2's default, so no name was evaluated at all. Say that, rather than print the zero as
    // though it were a cap. No PCRE2 error is printed either: every name was refused before PCRE2
    // saw it, and PCRE2's own text for that code describes a null argument it never received.
    if (first_cap != 0) {
      SiteThrottledWarning("record lookup pattern left %u record name(s) undecided (step cap %u for the first of them, "
                           "scaled to name length up to %u, first error: %s); results are incomplete",
                           indeterminate, first_cap, REGEX_MATCH_LIMIT, Regex::get_error_string(first_error).c_str());
    } else {
      SiteThrottledWarning("record lookup pattern left %u record name(s) undecided (the match context could not be "
                           "allocated, so nothing was matched); results are incomplete",
                           indeterminate);
    }
  }

  if (indeterminate_out) {
    *indeterminate_out = indeterminate;
  }

  return REC_ERR_OKAY;
}

RecErrT
RecGetRecordType(const char *name, RecT *rec_type, bool lock)
{
  RecErrT err = REC_ERR_FAIL;

  if (lock) {
    ink_rwlock_rdlock(&g_records_rwlock);
  }

  if (auto it = g_records_ht.find(name); it != g_records_ht.end()) {
    RecRecord *r = it->second;

    rec_mutex_acquire(&(r->lock));
    *rec_type = r->rec_type;
    err       = REC_ERR_OKAY;
    rec_mutex_release(&(r->lock));
  }

  if (lock) {
    ink_rwlock_unlock(&g_records_rwlock);
  }

  return err;
}

RecErrT
RecGetRecordDataType(const char *name, RecDataT *data_type, bool lock)
{
  RecErrT err = REC_ERR_FAIL;

  if (lock) {
    ink_rwlock_rdlock(&g_records_rwlock);
  }

  if (auto it = g_records_ht.find(name); it != g_records_ht.end()) {
    RecRecord *r = it->second;

    rec_mutex_acquire(&(r->lock));
    if (!r->registered) {
      err = REC_ERR_FAIL;
    } else {
      *data_type = r->data_type;
      err        = REC_ERR_OKAY;
    }
    rec_mutex_release(&(r->lock));
  }

  if (lock) {
    ink_rwlock_unlock(&g_records_rwlock);
  }

  return err;
}

RecErrT
RecGetRecordPersistenceType(const char *name, RecPersistT *persist_type, bool lock)
{
  RecErrT err = REC_ERR_FAIL;

  if (lock) {
    ink_rwlock_rdlock(&g_records_rwlock);
  }

  *persist_type = RECP_NULL;

  if (auto it = g_records_ht.find(name); it != g_records_ht.end()) {
    RecRecord *r = it->second;

    rec_mutex_acquire(&(r->lock));
    if (REC_TYPE_IS_STAT(r->rec_type)) {
      *persist_type = r->stat_meta.persist_type;
      err           = REC_ERR_OKAY;
    }
    rec_mutex_release(&(r->lock));
  }

  if (lock) {
    ink_rwlock_unlock(&g_records_rwlock);
  }

  return err;
}

RecErrT
RecGetRecordSource(const char *name, RecSourceT *source, bool lock)
{
  RecErrT err = REC_ERR_FAIL;

  if (lock) {
    ink_rwlock_rdlock(&g_records_rwlock);
  }

  if (auto it = g_records_ht.find(name); it != g_records_ht.end()) {
    RecRecord *r = it->second;

    rec_mutex_acquire(&(r->lock));
    *source = r->config_meta.source;
    err     = REC_ERR_OKAY;
    rec_mutex_release(&(r->lock));
  }

  if (lock) {
    ink_rwlock_unlock(&g_records_rwlock);
  }

  return err;
}

//-------------------------------------------------------------------------
// RecRegisterStat
//-------------------------------------------------------------------------
RecRecord *
RecRegisterStat(RecT rec_type, const char *name, RecDataT data_type, RecData data_default, RecPersistT persist_type)
{
  RecRecord *r = nullptr;

  ink_rwlock_wrlock(&g_records_rwlock);
  if ((r = register_record(rec_type, name, data_type, data_default, persist_type)) != nullptr) {
    // If the persistence type we found in the records hash is not the same as the persistence
    // type we are registering, then that means that it changed between the previous software
    // version and the current version. If the metric changed to non-persistent, reset to the
    // new default value.
    if ((r->stat_meta.persist_type == RECP_NULL || r->stat_meta.persist_type == RECP_PERSISTENT) &&
        persist_type == RECP_NON_PERSISTENT) {
      RecDebug(DL_Debug, "resetting default value for formerly persisted stat '%s'", r->name);
      RecDataSet(r->data_type, &(r->data), &(data_default));
    }

    r->stat_meta.persist_type = persist_type;
  } else {
    ink_assert(!"Can't register record!");
    RecDebug(DL_Warning, "failed to register '%s' record", name);
  }
  ink_rwlock_unlock(&g_records_rwlock);

  return r;
}

//-------------------------------------------------------------------------
// RecRegisterConfig
//-------------------------------------------------------------------------
RecRecord *
RecRegisterConfig(RecT rec_type, const char *name, RecDataT data_type, RecData data_default, RecUpdateT update_type,
                  RecCheckT check_type, const char *check_expr, RecSourceT source, RecAccessT access_type)
{
  RecRecord *r;
  bool       updated_p;

  ink_rwlock_wrlock(&g_records_rwlock);
  if ((r = register_record(rec_type, name, data_type, data_default, RECP_NULL, &updated_p)) != nullptr) {
    // Note: do not modify 'record->config_meta.update_required'
    r->config_meta.update_type = update_type;
    r->config_meta.check_type  = check_type;

    ats_free(r->config_meta.check_expr);

    r->config_meta.check_expr     = ats_strdup(check_expr);
    r->config_meta.update_cb_list = nullptr;
    r->config_meta.access_type    = access_type;
    if (!updated_p) {
      r->config_meta.source = source;
    }
  }
  ink_rwlock_unlock(&g_records_rwlock);

  return r;
}

//-------------------------------------------------------------------------
// RecGetRecord_Xmalloc
//-------------------------------------------------------------------------
RecErrT
RecGetRecord_Xmalloc(const char *name, RecDataT data_type, RecData *data, bool lock)
{
  RecErrT err = REC_ERR_OKAY;

  if (lock) {
    ink_rwlock_rdlock(&g_records_rwlock);
  }

  if (auto it = g_records_ht.find(name); it != g_records_ht.end()) {
    RecRecord *r = it->second;

    rec_mutex_acquire(&(r->lock));
    if (!r->registered || (r->data_type != data_type)) {
      err = REC_ERR_FAIL;
    } else {
      // Clear the caller's record just in case it has trash in it.
      // Passing trashy records to RecDataSet will cause confusion.
      memset(data, 0, sizeof(RecData));
      RecDataSet(data_type, data, &(r->data));
    }
    rec_mutex_release(&(r->lock));
  } else {
    err = REC_ERR_FAIL;
  }

  if (lock) {
    ink_rwlock_unlock(&g_records_rwlock);
  }

  return err;
}

//-------------------------------------------------------------------------
// RecForceInsert
//-------------------------------------------------------------------------
RecRecord *
RecForceInsert(RecRecord *record)
{
  RecRecord *r = nullptr;
  bool       r_is_a_new_record;

  ink_rwlock_wrlock(&g_records_rwlock);

  if (auto it = g_records_ht.find(record->name); it != g_records_ht.end()) {
    r                 = it->second;
    r_is_a_new_record = false;
    rec_mutex_acquire(&(r->lock));
    r->rec_type  = record->rec_type;
    r->data_type = record->data_type;
  } else {
    r_is_a_new_record = true;
    if ((r = RecAlloc(record->rec_type, record->name, record->data_type)) == nullptr) {
      ink_rwlock_unlock(&g_records_rwlock);
      return nullptr;
    }
  }

  // set the record value
  RecDataSet(r->data_type, &(r->data), &(record->data));
  RecDataSet(r->data_type, &(r->data_default), &(record->data_default));

  r->registered = record->registered;
  r->rsb_id     = record->rsb_id;

  if (REC_TYPE_IS_STAT(r->rec_type)) {
    r->stat_meta.persist_type = record->stat_meta.persist_type;
    r->stat_meta.data_raw     = record->stat_meta.data_raw;
  } else if (REC_TYPE_IS_CONFIG(r->rec_type)) {
    r->config_meta.update_required = record->config_meta.update_required;
    r->config_meta.update_type     = record->config_meta.update_type;
    r->config_meta.check_type      = record->config_meta.check_type;
    ats_free(r->config_meta.check_expr);
    r->config_meta.check_expr  = ats_strdup(record->config_meta.check_expr);
    r->config_meta.access_type = record->config_meta.access_type;
    r->config_meta.source      = record->config_meta.source;
  }

  if (r_is_a_new_record) {
    g_records_ht.emplace(r->name, r);
  } else {
    rec_mutex_release(&(r->lock));
  }

  ink_rwlock_unlock(&g_records_rwlock);

  return r;
}

//-------------------------------------------------------------------------
// RecDumpRecordsHt
//-------------------------------------------------------------------------

static void
debug_record_callback(RecT /* rec_type */, void * /* edata */, int registered, const char *name, int data_type, RecData *datum)
{
  switch (data_type) {
  case RECD_INT:
    RecDebug(DL_Note, "  ([%d] '%s', '%" PRId64 "')", registered, name, datum->rec_int);
    break;
  case RECD_FLOAT:
    RecDebug(DL_Note, "  ([%d] '%s', '%f')", registered, name, datum->rec_float);
    break;
  case RECD_STRING:
    RecDebug(DL_Note, "  ([%d] '%s', '%s')", registered, name, datum->rec_string ? datum->rec_string : "NULL");
    break;
  case RECD_COUNTER:
    RecDebug(DL_Note, "  ([%d] '%s', '%" PRId64 "')", registered, name, datum->rec_counter);
    break;
  default:
    RecDebug(DL_Note, "  ([%d] '%s', <? ? ?>)", registered, name);
    break;
  }
}

void
RecDumpRecords(RecT rec_type, RecDumpEntryCb callback, void *edata)
{
  int i, num_records;

  num_records = g_num_records;
  for (i = 0; i < num_records; i++) {
    RecRecord *r = &(g_records[i]);
    if ((rec_type == RECT_NULL) || (rec_type & r->rec_type)) {
      rec_mutex_acquire(&(r->lock));
      callback(r->rec_type, edata, r->registered, r->name, r->data_type, &r->data);
      rec_mutex_release(&(r->lock));
    }
  }

  // Dump all new metrics as well (no "type" for them)
  RecData datum;

  ts::Metrics::instance().for_each([&](std::string_view name, Metrics::MetricType type, int64_t val) {
    datum.rec_int = val;
    callback(RECT_PLUGIN, edata, true, name.data(),
             type == Metrics::MetricType::COUNTER ? TS_RECORDDATATYPE_COUNTER : TS_RECORDDATATYPE_INT, &datum);
  });

  ts::Metrics::StaticString::instance().for_each([&](const std::string &name, const std::string &value) {
    datum.rec_string = const_cast<char *>(value.c_str());

    callback(RECT_PLUGIN, edata, true, name.data(), TS_RECORDDATATYPE_STRING, &datum);
  });
}

void
RecDumpRecordsHt(RecT rec_type)
{
  RecDebug(DL_Note, "Dumping Records:");
  RecDumpRecords(rec_type, debug_record_callback, nullptr);
}

//-------------------------------------------------------------------------
// RecConfigReadConfigDir
//-------------------------------------------------------------------------
std::string
RecConfigReadConfigDir()
{
  if (const char *env = getenv("PROXY_CONFIG_CONFIG_DIR")) {
    return Layout::get()->relative(env);
  } else {
    return Layout::get()->sysconfdir;
  }
}

//-------------------------------------------------------------------------
// RecConfigReadRuntimeDir
//-------------------------------------------------------------------------
std::string
RecConfigReadRuntimeDir()
{
  char buf[PATH_NAME_MAX];

  buf[0] = '\0';
  RecGetRecordString("proxy.config.local_state_dir", buf, PATH_NAME_MAX);
  if (strlen(buf) > 0) {
    return Layout::get()->relative(buf);
  } else {
    return Layout::get()->runtimedir;
  }
}

//-------------------------------------------------------------------------
// RecConfigReadLogDir
//-------------------------------------------------------------------------
std::string
RecConfigReadLogDir()
{
  char buf[PATH_NAME_MAX];

  buf[0] = '\0';
  RecGetRecordString("proxy.config.log.logfile_dir", buf, PATH_NAME_MAX);
  if (strlen(buf) > 0) {
    return Layout::get()->relative(buf);
  } else {
    return Layout::get()->logdir;
  }
}

//-------------------------------------------------------------------------
// RecConfigReadBinDir
//-------------------------------------------------------------------------
std::string
RecConfigReadBinDir()
{
  char buf[PATH_NAME_MAX];

  buf[0] = '\0';
  RecGetRecordString("proxy.config.bin_path", buf, PATH_NAME_MAX);
  if (strlen(buf) > 0) {
    return Layout::get()->relative(buf);
  } else {
    return Layout::get()->bindir;
  }
}

//-------------------------------------------------------------------------
// RecConfigReadPluginDir
//-------------------------------------------------------------------------
std::string
RecConfigReadPluginDir()
{
  char buf[PATH_NAME_MAX];

  buf[0] = '\0';
  RecGetRecordString("proxy.config.plugin.plugin_dir", buf, PATH_NAME_MAX);
  if (strlen(buf) > 0) {
    return Layout::get()->relative(buf);
  } else {
    return Layout::get()->libexecdir;
  }
}

//-------------------------------------------------------------------------
// RecConfigReadConfigPath
//-------------------------------------------------------------------------
std::string
RecConfigReadConfigPath(const char *file_variable, const char *default_value)
{
  std::string sysconfdir(RecConfigReadConfigDir());

  // If the file name is in a configuration variable, look it up first ...
  if (file_variable) {
    char buf[PATH_NAME_MAX];

    buf[0] = '\0';
    RecGetRecordString(file_variable, buf, PATH_NAME_MAX);
    if (strlen(buf) > 0) {
      return Layout::get()->relative_to(sysconfdir, buf);
    }
  }

  // Otherwise take the default ...
  if (default_value) {
    return Layout::get()->relative_to(sysconfdir, default_value);
  }

  return {};
}

//-------------------------------------------------------------------------
// RecConfigReadPersistentStatsPath
//-------------------------------------------------------------------------
std::string
RecConfigReadPersistentStatsPath()
{
  std::string rundir(RecConfigReadRuntimeDir());
  return Layout::relative_to(rundir, ts::filename::RECORDS_STATS);
}

//-------------------------------------------------------------------------
// RecConfigWarnIfUnregistered
//-------------------------------------------------------------------------
/// Generate a warning if the record is a configuration name/value but is not registered.
void
RecConfigWarnIfUnregistered(ConfigContext ctx)
{
  RecDumpRecords(
    RECT_CONFIG,
    [](RecT, void *edata, int registered_p, const char *name, int, RecData *) -> void {
      if (!registered_p) {
        std::string err;
        swoc::bwprint(err, "Unrecognized configuration value '{}'", name);
        Warning("%s", err.c_str());
        auto *ctx_ptr = static_cast<ConfigContext *>(edata);
        ctx_ptr->log(err);
      }
    },
    &ctx);
}

//-------------------------------------------------------------------------
// i_am_the_record_owner, only used for librecords_p.a
//-------------------------------------------------------------------------
bool
i_am_the_record_owner(RecT rec_type)
{
  switch (rec_type) {
  case RECT_CONFIG:
  case RECT_PROCESS:
  case RECT_NODE:
  case RECT_LOCAL:
  case RECT_PLUGIN:
    return true;
  default:
    ink_assert(!"Unexpected RecT type");
    return false;
  }

  return false;
}
