/** @file

  [RFC 7541] HPACK: Header Compression for HTTP/2

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

#include "HPACK.h"
#include "HuffmanCodec.h"

// [RFC 7541] 4.1. Calculating Table Size
// The size of an entry is the sum of its name's length in octets (as defined in Section 5.2),
// its value's length in octets, and 32.
const static unsigned ADDITIONAL_OCTETS = 32;

// TODO: masaori: refer statictable::max
static constexpr uint32_t TS_HPACK_STATIC_TABLE_ENTRY_NUM = 61;

struct StaticTable {
  StaticTable(const char *n, const char *v) : name(n), value(v), name_size(strlen(name)), value_size(strlen(value)) {}
  const char *name;
  const char *value;
  const int name_size;
  const int value_size;
};

static const StaticTable STATIC_TABLE[] = {{"", ""},
                                           {":authority", ""},
                                           {":method", "GET"},
                                           {":method", "POST"},
                                           {":path", "/"},
                                           {":path", "/index.html"},
                                           {":scheme", "http"},
                                           {":scheme", "https"},
                                           {":status", "200"},
                                           {":status", "204"},
                                           {":status", "206"},
                                           {":status", "304"},
                                           {":status", "400"},
                                           {":status", "404"},
                                           {":status", "500"},
                                           {"accept-charset", ""},
                                           {"accept-encoding", "gzip, deflate"},
                                           {"accept-language", ""},
                                           {"accept-ranges", ""},
                                           {"accept", ""},
                                           {"access-control-allow-origin", ""},
                                           {"age", ""},
                                           {"allow", ""},
                                           {"authorization", ""},
                                           {"cache-control", ""},
                                           {"content-disposition", ""},
                                           {"content-encoding", ""},
                                           {"content-language", ""},
                                           {"content-length", ""},
                                           {"content-location", ""},
                                           {"content-range", ""},
                                           {"content-type", ""},
                                           {"cookie", ""},
                                           {"date", ""},
                                           {"etag", ""},
                                           {"expect", ""},
                                           {"expires", ""},
                                           {"from", ""},
                                           {"host", ""},
                                           {"if-match", ""},
                                           {"if-modified-since", ""},
                                           {"if-none-match", ""},
                                           {"if-range", ""},
                                           {"if-unmodified-since", ""},
                                           {"last-modified", ""},
                                           {"link", ""},
                                           {"location", ""},
                                           {"max-forwards", ""},
                                           {"proxy-authenticate", ""},
                                           {"proxy-authorization", ""},
                                           {"range", ""},
                                           {"referer", ""},
                                           {"refresh", ""},
                                           {"retry-after", ""},
                                           {"server", ""},
                                           {"set-cookie", ""},
                                           {"strict-transport-security", ""},
                                           {"transfer-encoding", ""},
                                           {"user-agent", ""},
                                           {"vary", ""},
                                           {"via", ""},
                                           {"www-authenticate", ""}};

/**
  Threshold for total HdrHeap size which used by HPAK Dynamic Table.
  The HdrHeap is filled by MIMEHdrImpl and MIMEFieldBlockImpl like below.
  This threshold allow to allocate 3 HdrHeap at maximum.

                     +------------------+-----------------------------+
   HdrHeap 1 (2048): | MIMEHdrImpl(592) | MIMEFieldBlockImpl(528) x 2 |
                     +------------------+-----------------------------+--...--+
   HdrHeap 2 (4096): | MIMEFieldBlockImpl(528) x 7                            |
                     +------------------------------------------------+--...--+--...--+
   HdrHeap 3 (8192): | MIMEFieldBlockImpl(528) x 15                                   |
                     +------------------------------------------------+--...--+--...--+
*/
static constexpr uint32_t HPACK_HDR_HEAP_THRESHOLD = sizeof(MIMEHdrImpl) + sizeof(MIMEFieldBlockImpl) * (2 + 7 + 15);

/******************
 * Local functions
 ******************/
static inline bool
hpack_field_is_literal(HpackField ftype)
{
  return ftype == HpackField::INDEXED_LITERAL || ftype == HpackField::NOINDEX_LITERAL || ftype == HpackField::NEVERINDEX_LITERAL;
}

//
// The first byte of an HPACK field unambiguously tells us what
// kind of field it is. Field types are specified in the high 4 bits
// and all bits are defined, so there's no way to get an invalid field type.
//
static HpackField
hpack_parse_field_type(uint8_t ftype)
{
  if (ftype & 0x80) {
    return HpackField::INDEX;
  }

  if (ftype & 0x40) {
    return HpackField::INDEXED_LITERAL;
  }

  if (ftype & 0x20) {
    return HpackField::TABLESIZE_UPDATE;
  }

  if (ftype & 0x10) {
    return HpackField::NEVERINDEX_LITERAL;
  }

  ink_assert((ftype & 0xf0) == 0x0);
  return HpackField::NOINDEX_LITERAL;
}

//
// HPACK
//
HpackLookupResult
HPACK::lookup(const MIMEFieldWrapper &field) const
{
  int target_name_len = 0, target_value_len = 0;
  const char *target_name  = field.name_get(&target_name_len);
  const char *target_value = field.value_get(&target_value_len);
  return lookup(target_name, target_name_len, target_value, target_value_len);
}

/**
   Lookup indexing table (both of static & dynamic table) by name & value.

   NOTE: name & value should be smashed in lower case and stop using casecmp?
   For the HTTP/2 connection to the origin server, we need to figure out how to deal with well known string tokens.
 */
HpackLookupResult
HPACK::lookup(const char *name, int name_len, const char *value, int value_len) const
{
  // static table
  HpackLookupResult result = HPACK::StaticTable::lookup(name, name_len, value, value_len);

  // if match type is NAME, lookup dynamic table for exact match
  if (result.match_type == HpackMatch::EXACT) {
    return result;
  }

  // dynamic table
  if (HpackLookupResult dt_result = this->_dynamic_table.lookup(name, name_len, value, value_len);
      dt_result.match_type == HpackMatch::EXACT) {
    // Convert index from dynamic table space to indexing table space
    dt_result.index += TS_HPACK_STATIC_TABLE_ENTRY_NUM;

    return dt_result;
  }

  return result;
}

int
HPACK::get_header_field(uint32_t index, MIMEFieldWrapper &field) const
{
  // Index Address Space starts at 1, so index == 0 is invalid.
  if (!index) {
    return HPACK_ERROR_COMPRESSION_ERROR;
  }

  if (index < TS_HPACK_STATIC_TABLE_ENTRY_NUM) {
    // static table
    field.name_set(STATIC_TABLE[index].name, STATIC_TABLE[index].name_size);
    field.value_set(STATIC_TABLE[index].value, STATIC_TABLE[index].value_size);
  } else if (index < TS_HPACK_STATIC_TABLE_ENTRY_NUM + _dynamic_table.length()) {
    // dynamic table
    const MIMEField *m_field = _dynamic_table.get_header_field(index - TS_HPACK_STATIC_TABLE_ENTRY_NUM);

    int name_len, value_len;
    const char *name  = m_field->name_get(&name_len);
    const char *value = m_field->value_get(&value_len);

    field.name_set(name, name_len);
    field.value_set(value, value_len);
  } else {
    // [RFC 7541] 2.3.3. Index Address Space
    // Indices strictly greater than the sum of the lengths of both tables
    // MUST be treated as a decoding error.
    return HPACK_ERROR_COMPRESSION_ERROR;
  }

  return 0;
}

void
HPACK::add_header_field(const MIMEField *field)
{
  _dynamic_table.add_header_field(field);
}

uint32_t
HPACK::maximum_size() const
{
  return _dynamic_table.maximum_size();
}

uint32_t
HPACK::size() const
{
  return _dynamic_table.size();
}

bool
HPACK::update_maximum_size(uint32_t new_size)
{
  return _dynamic_table.update_maximum_size(new_size);
}

//
// Static Table
//

enum class HPACK::StaticTable::Index : uint32_t {
  NONE = 0,
  AUTHORITY,
  METHOD_GET,
  METHOD_POST,
  PATH_ROOT,
  PATH_INDEX,
  SCHEME_HTTP,
  SCHEME_HTTPS,
  STATUS_200,
  STATUS_204,
  STATUS_206,
  STATUS_304,
  STATUS_400,
  STATUS_404,
  STATUS_500,
  ACCEPT_CHARSET,
  ACCEPT_ENCODING,
  ACCEPT_LANGUAGE,
  ACCEPT_RANGES,
  ACCEPT,
  ACCESS_CONTROL_ALLOW_ORIGIN,
  AGE,
  ALLOW,
  AUTHORIZATION,
  CACHE_CONTROL,
  CONTENT_DISPOSITION,
  CONTENT_ENCODING,
  CONTENT_LANGUAGE,
  CONTENT_LENGTH,
  CONTENT_LOCATION,
  CONTENT_RANGE,
  CONTENT_TYPE,
  COOKIE,
  DATE,
  ETAG,
  EXPECT,
  EXPIRES,
  FROM,
  HOST,
  IF_MATCH,
  IF_MODIFIED_SINCE,
  IF_NONE_MATCH,
  IF_RANGE,
  IF_UNMODIFIED_SINCE,
  LAST_MODIFIED,
  LINK,
  LOCATION,
  MAX_FORWARDS,
  PROXY_AUTHENTICATE,
  PROXY_AUTHORIZATION,
  RANGE,
  REFERER,
  REFRESH,
  RETRY_AFTER,
  SERVER,
  SET_COOKIE,
  STRICT_TRANSPORT_SECURITY,
  TRANSFER_ENCODING,
  USER_AGENT,
  VARY,
  VIA,
  WWW_AUTHENTICATE,
  MAX,
};

HpackLookupResult
HPACK::StaticTable::lookup(const char *name, int name_len, const char *value, int value_len)
{
  Index index = _lookup_name(name, name_len);
  if (index == Index::NONE) {
    return {0, HpackIndex::NONE, HpackMatch::NONE};
  }

  HpackLookupResult result;

  switch (index) {
  case HPACK::StaticTable::Index::METHOD_GET:
    if (HPACK::StaticTable::Index r = _lookup_value(index, HPACK::StaticTable::Index::METHOD_POST, value, value_len);
        r != HPACK::StaticTable::Index::NONE) {
      return {static_cast<uint32_t>(r), HpackIndex::STATIC, HpackMatch::EXACT};
    }
    break;
  case HPACK::StaticTable::Index::PATH_ROOT:
    if (HPACK::StaticTable::Index r = _lookup_value(index, HPACK::StaticTable::Index::PATH_INDEX, value, value_len);
        r != HPACK::StaticTable::Index::NONE) {
      return {static_cast<uint32_t>(r), HpackIndex::STATIC, HpackMatch::EXACT};
    }
    break;
  case HPACK::StaticTable::Index::SCHEME_HTTP:
    if (HPACK::StaticTable::Index r = _lookup_value(index, HPACK::StaticTable::Index::SCHEME_HTTPS, value, value_len);
        r != HPACK::StaticTable::Index::NONE) {
      return {static_cast<uint32_t>(r), HpackIndex::STATIC, HpackMatch::EXACT};
    }
    break;
  case HPACK::StaticTable::Index::STATUS_200:
    if (HPACK::StaticTable::Index r = _lookup_value(index, HPACK::StaticTable::Index::STATUS_500, value, value_len);
        r != HPACK::StaticTable::Index::NONE) {
      return {static_cast<uint32_t>(r), HpackIndex::STATIC, HpackMatch::EXACT};
    }
    break;
  default:
    uint32_t i = static_cast<uint32_t>(index);
    if (STATIC_TABLE[i].value_size == value_len && memcmp(STATIC_TABLE[i].value, value, value_len) == 0) {
      return {i, HpackIndex::STATIC, HpackMatch::EXACT};
    }
  }

  return {static_cast<uint32_t>(index), HpackIndex::STATIC, HpackMatch::NAME};
}

/**
   This is based on logic of nghttp2 hapck header lookup.
   https://github.com/nghttp2/nghttp2
 */
HPACK::StaticTable::Index
HPACK::StaticTable::_lookup_name(const char *name, int name_len)
{
  switch (name_len) {
  case 3:
    switch (name[2]) {
    case 'a':
      if (memcmp("vi", name, 2) == 0) {
        return HPACK::StaticTable::Index::VIA;
      }
      break;
    case 'e':
      if (memcmp("ag", name, 2) == 0) {
        return HPACK::StaticTable::Index::AGE;
      }
      break;
    }
    break;
  case 4:
    switch (name[3]) {
    case 'e':
      if (memcmp("dat", name, 3) == 0) {
        return HPACK::StaticTable::Index::DATE;
      }
      break;
    case 'g':
      if (memcmp("eta", name, 3) == 0) {
        return HPACK::StaticTable::Index::ETAG;
      }
      break;
    case 'k':
      if (memcmp("lin", name, 3) == 0) {
        return HPACK::StaticTable::Index::LINK;
      }
      break;
    case 'm':
      if (memcmp("fro", name, 3) == 0) {
        return HPACK::StaticTable::Index::FROM;
      }
      break;
    case 't':
      if (memcmp("hos", name, 3) == 0) {
        return HPACK::StaticTable::Index::HOST;
      }
      break;
    case 'y':
      if (memcmp("var", name, 3) == 0) {
        return HPACK::StaticTable::Index::VARY;
      }
      break;
    }
    break;
  case 5:
    switch (name[4]) {
    case 'e':
      if (memcmp("rang", name, 4) == 0) {
        return HPACK::StaticTable::Index::RANGE;
      }
      break;
    case 'h':
      if (memcmp(":pat", name, 4) == 0) {
        return HPACK::StaticTable::Index::PATH_ROOT;
      }
      break;
    case 'w':
      if (memcmp("allo", name, 4) == 0) {
        return HPACK::StaticTable::Index::ALLOW;
      }
      break;
    }
    break;
  case 6:
    switch (name[5]) {
    case 'e':
      if (memcmp("cooki", name, 5) == 0) {
        return HPACK::StaticTable::Index::COOKIE;
      }
      break;
    case 'r':
      if (memcmp("serve", name, 5) == 0) {
        return HPACK::StaticTable::Index::SERVER;
      }
      break;
    case 't':
      if (memcmp("accep", name, 5) == 0) {
        return HPACK::StaticTable::Index::ACCEPT;
      }
      if (memcmp("expec", name, 5) == 0) {
        return HPACK::StaticTable::Index::EXPECT;
      }
      break;
    }
    break;
  case 7:
    switch (name[6]) {
    case 'd':
      if (memcmp(":metho", name, 6) == 0) {
        return HPACK::StaticTable::Index::METHOD_GET;
      }
      break;
    case 'e':
      if (memcmp(":schem", name, 6) == 0) {
        return HPACK::StaticTable::Index::SCHEME_HTTP;
      }
      break;
    case 'h':
      if (memcmp("refres", name, 6) == 0) {
        return HPACK::StaticTable::Index::REFRESH;
      }
      break;
    case 'r':
      if (memcmp("refere", name, 6) == 0) {
        return HPACK::StaticTable::Index::REFERER;
      }
      break;
    case 's':
      if (memcmp(":statu", name, 6) == 0) {
        // TODO: check value
        return HPACK::StaticTable::Index::STATUS_200;
      }
      if (memcmp("expire", name, 6) == 0) {
        return HPACK::StaticTable::Index::EXPIRES;
      }
      break;
    }
    break;
  case 8:
    switch (name[7]) {
    case 'e':
      if (memcmp("if-rang", name, 7) == 0) {
        return HPACK::StaticTable::Index::IF_RANGE;
      }
      break;
    case 'h':
      if (memcmp("if-matc", name, 7) == 0) {
        return HPACK::StaticTable::Index::IF_MATCH;
      }
      break;
    case 'n':
      if (memcmp("locatio", name, 7) == 0) {
        return HPACK::StaticTable::Index::LOCATION;
      }
      break;
    }
    break;
  case 10:
    switch (name[9]) {
    case 'e':
      if (memcmp("set-cooki", name, 9) == 0) {
        return HPACK::StaticTable::Index::SET_COOKIE;
      }
      break;
    case 't':
      if (memcmp("user-agen", name, 9) == 0) {
        return HPACK::StaticTable::Index::USER_AGENT;
      }
      break;
    case 'y':
      if (memcmp(":authorit", name, 9) == 0) {
        return HPACK::StaticTable::Index::AUTHORITY;
      }
      break;
    }
    break;
  case 11:
    switch (name[10]) {
    case 'r':
      if (memcmp("retry-afte", name, 10) == 0) {
        return HPACK::StaticTable::Index::RETRY_AFTER;
      }
      break;
    }
    break;
  case 12:
    switch (name[11]) {
    case 'e':
      if (memcmp("content-typ", name, 11) == 0) {
        return HPACK::StaticTable::Index::CONTENT_TYPE;
      }
      break;
    case 's':
      if (memcmp("max-forward", name, 11) == 0) {
        return HPACK::StaticTable::Index::MAX_FORWARDS;
      }
      break;
    }
    break;
  case 13:
    switch (name[12]) {
    case 'd':
      if (memcmp("last-modifie", name, 12) == 0) {
        return HPACK::StaticTable::Index::LAST_MODIFIED;
      }
      break;
    case 'e':
      if (memcmp("content-rang", name, 12) == 0) {
        return HPACK::StaticTable::Index::CONTENT_RANGE;
      }
      break;
    case 'h':
      if (memcmp("if-none-matc", name, 12) == 0) {
        return HPACK::StaticTable::Index::IF_NONE_MATCH;
      }
      break;
    case 'l':
      if (memcmp("cache-contro", name, 12) == 0) {
        return HPACK::StaticTable::Index::CACHE_CONTROL;
      }
      break;
    case 'n':
      if (memcmp("authorizatio", name, 12) == 0) {
        return HPACK::StaticTable::Index::AUTHORIZATION;
      }
      break;
    case 's':
      if (memcmp("accept-range", name, 12) == 0) {
        return HPACK::StaticTable::Index::ACCEPT_RANGES;
      }
      break;
    }
    break;
  case 14:
    switch (name[13]) {
    case 'h':
      if (memcmp("content-lengt", name, 13) == 0) {
        return HPACK::StaticTable::Index::CONTENT_LENGTH;
      }
      break;
    case 't':
      if (memcmp("accept-charse", name, 13) == 0) {
        return HPACK::StaticTable::Index::ACCEPT_CHARSET;
      }
      break;
    }
    break;
  case 15:
    switch (name[14]) {
    case 'e':
      if (memcmp("accept-languag", name, 14) == 0) {
        return HPACK::StaticTable::Index::ACCEPT_LANGUAGE;
      }
      break;
    case 'g':
      if (memcmp("accept-encodin", name, 14) == 0) {
        return HPACK::StaticTable::Index::ACCEPT_ENCODING;
      }
      break;
    }
    break;
  case 16:
    switch (name[15]) {
    case 'e':
      if (memcmp("content-languag", name, 15) == 0) {
        return HPACK::StaticTable::Index::CONTENT_LANGUAGE;
      }
      if (memcmp("www-authenticat", name, 15) == 0) {
        return HPACK::StaticTable::Index::WWW_AUTHENTICATE;
      }
      break;
    case 'g':
      if (memcmp("content-encodin", name, 15) == 0) {
        return HPACK::StaticTable::Index::CONTENT_ENCODING;
      }
      break;
    case 'n':
      if (memcmp("content-locatio", name, 15) == 0) {
        return HPACK::StaticTable::Index::CONTENT_LOCATION;
      }
      break;
    }
    break;
  case 17:
    switch (name[16]) {
    case 'e':
      if (memcmp("if-modified-sinc", name, 16) == 0) {
        return HPACK::StaticTable::Index::IF_MODIFIED_SINCE;
      }
      break;
    case 'g':
      if (memcmp("transfer-encodin", name, 16) == 0) {
        return HPACK::StaticTable::Index::TRANSFER_ENCODING;
      }
      break;
    }
    break;
  case 18:
    switch (name[17]) {
    case 'e':
      if (memcmp("proxy-authenticat", name, 17) == 0) {
        return HPACK::StaticTable::Index::PROXY_AUTHENTICATE;
      }
      break;
    }
    break;
  case 19:
    switch (name[18]) {
    case 'e':
      if (memcmp("if-unmodified-sinc", name, 18) == 0) {
        return HPACK::StaticTable::Index::IF_UNMODIFIED_SINCE;
      }
      break;
    case 'n':
      if (memcmp("content-dispositio", name, 18) == 0) {
        return HPACK::StaticTable::Index::CONTENT_DISPOSITION;
      }
      if (memcmp("proxy-authorizatio", name, 18) == 0) {
        return HPACK::StaticTable::Index::PROXY_AUTHORIZATION;
      }
      break;
    }
    break;
  case 25:
    switch (name[24]) {
    case 'y':
      if (memcmp("strict-transport-securit", name, 24) == 0) {
        return HPACK::StaticTable::Index::STRICT_TRANSPORT_SECURITY;
      }
      break;
    }
    break;
  case 27:
    switch (name[26]) {
    case 'n':
      if (memcmp("access-control-allow-origi", name, 26) == 0) {
        return HPACK::StaticTable::Index::ACCESS_CONTROL_ALLOW_ORIGIN;
      }
      break;
    }
    break;
  }

  return HPACK::StaticTable::Index::NONE;
}

/**
   Lookup given rage (from @begin to @end) of static table by value
 */
HPACK::StaticTable::Index
HPACK::StaticTable::_lookup_value(HPACK::StaticTable::Index begin, HPACK::StaticTable::Index end, const char *value, int value_len)
{
  for (uint32_t i = static_cast<uint32_t>(begin); i <= static_cast<uint32_t>(end); ++i) {
    if (STATIC_TABLE[i].value_size == value_len && strncasecmp(STATIC_TABLE[i].value, value, value_len) == 0) {
      return static_cast<HPACK::StaticTable::Index>(i);
    }
  }

  return HPACK::StaticTable::Index::NONE;
}

//
// HpackDynamicTable
//
HPACK::DynamicTable::DynamicTable(uint32_t size, Context c) : _maximum_size(size), _context(c)
{
  _mhdr = new MIMEHdr();
  _mhdr->create();

  // TODO: masaori: adjust reserve number
  this->_lookup_table.reserve(1000);
}

HPACK::DynamicTable::~DynamicTable()
{
  this->_headers.clear();

  this->_mhdr->fields_clear();
  this->_mhdr->destroy();
  delete this->_mhdr;

  if (this->_mhdr_old != nullptr) {
    this->_mhdr_old->fields_clear();
    this->_mhdr_old->destroy();
    delete this->_mhdr_old;
  }
}

const MIMEField *
HPACK::DynamicTable::get_header_field(uint32_t index) const
{
  return this->_headers.at(index);
}

void
HPACK::DynamicTable::add_header_field(const MIMEField *field)
{
  std::string_view name  = field->name_get();
  std::string_view value = field->value_get();
  uint32_t header_size   = ADDITIONAL_OCTETS + name.size() + value.size();

  if (header_size > _maximum_size) {
    // [RFC 7541] 4.4. Entry Eviction When Adding New Entries
    // It is not an error to attempt to add an entry that is larger than
    // the maximum size; an attempt to add an entry larger than the entire
    // table causes the table to be emptied of all existing entries.
    this->_headers.clear();
    this->_mhdr->fields_clear();
    this->_current_size = 0;
  } else {
    this->_current_size += header_size;
    this->_evict_overflowed_entries();

    // Copy @field to current HdrHeap
    MIMEField *new_field = this->_mhdr->field_create(name.data(), name.size());
    new_field->value_set(this->_mhdr->m_heap, this->_mhdr->m_mime, value.data(), value.size());
    this->_mhdr->field_attach(new_field);
    this->_headers.push_front(new_field);

    // TODO: figure out deal with wks
    if (this->_context == HPACK::Context::ENCODING) {
      uint32_t index = this->_abs_index++;

      // Get pointers of pushed header field
      std::string_view new_name  = new_field->name_get();
      std::string_view new_value = new_field->value_get();

      Debug("hpack_encode", "name=%.*s value=%.*s index=%" PRId32, static_cast<int>(new_name.size()), new_name.data(),
            static_cast<int>(new_value.size()), new_value.data(), index);

      this->_lookup_table.emplace(std::make_pair(new_name, std::make_pair(new_value, index)));
    }
  }
}

HpackLookupResult
HPACK::DynamicTable::lookup(const char *name, int name_len, const char *value, int value_len) const
{
  ink_assert(this->_context == HPACK::Context::ENCODING);

  auto range = this->_lookup_table.equal_range(std::string_view(name, name_len));
  if (range.first == this->_lookup_table.end()) {
    return {0, HpackIndex::NONE, HpackMatch::NONE};
  }

  uint32_t index = 0;
  for (auto it = range.first; it != range.second; ++it) {
    index = it->second.second;
    if (it->second.first.compare(std::string_view(value, value_len)) == 0) {
      Debug("hpack_encode", "name=%.*s value=%.*s %p", name_len, name, value_len, value, it->second.first.data());

      index = this->_index(index);
      return {index, HpackIndex::DYNAMIC, HpackMatch::EXACT};
    }
  }

  index = this->_index(index);
  return {index, HpackIndex::DYNAMIC, HpackMatch::NAME};
}

uint32_t
HPACK::DynamicTable::maximum_size() const
{
  return _maximum_size;
}

uint32_t
HPACK::DynamicTable::size() const
{
  return _current_size;
}

//
// [RFC 7541] 4.3. Entry Eviction when Header Table Size Changes
//
// Whenever the maximum size for the header table is reduced, entries
// are evicted from the end of the header table until the size of the
// header table is less than or equal to the maximum size.
//
bool
HPACK::DynamicTable::update_maximum_size(uint32_t new_size)
{
  this->_maximum_size = new_size;
  return this->_evict_overflowed_entries();
}

uint32_t
HPACK::DynamicTable::length() const
{
  return this->_headers.size();
}

bool
HPACK::DynamicTable::_evict_overflowed_entries()
{
  if (this->_current_size <= this->_maximum_size) {
    // Do nothing
    return true;
  }

  for (auto h = this->_headers.rbegin(); h != this->_headers.rend(); ++h) {
    std::string_view name  = (*h)->name_get();
    std::string_view value = (*h)->value_get();

    Debug("hpack_encode", "name=%.*s value=%.*s", static_cast<int>(name.size()), name.data(), static_cast<int>(value.size()),
          value.data());

    this->_current_size -= ADDITIONAL_OCTETS + name.size() + value.size();
    this->_mhdr->field_delete(*h, false);
    this->_headers.pop_back();

    if (this->_context == HPACK::Context::ENCODING) {
      auto range = this->_lookup_table.equal_range(name);
      for (auto it = range.first; it != range.second; ++it) {
        if (it->second.first.compare(value) == 0) {
          this->_lookup_table.erase(it);
          this->_offset++;
          break;
        }
      }
    }

    if (this->_current_size <= this->_maximum_size) {
      break;
    }
  }

  if (this->_headers.size() == 0) {
    return false;
  }

  this->_mime_hdr_gc();

  return true;
}

/**
   When HdrHeap size of current MIMEHdr exceeds the threshold, allocate new MIMEHdr and HdrHeap.
   The old MIMEHdr and HdrHeap will be freed, when all MIMEFiled are deleted by HPACK Entry Eviction.
 */
void
HPACK::DynamicTable::_mime_hdr_gc()
{
  if (this->_mhdr_old == nullptr) {
    if (this->_mhdr->m_heap->total_used_size() >= HPACK_HDR_HEAP_THRESHOLD) {
      this->_mhdr_old = this->_mhdr;
      this->_mhdr     = new MIMEHdr();
      this->_mhdr->create();
    }
  } else {
    if (this->_mhdr_old->fields_count() == 0) {
      this->_mhdr_old->destroy();
      this->_mhdr_old = nullptr;
    }
  }
}

/**
   Calculate dynamic table index from absolute @index & offset
 */
uint32_t
HPACK::DynamicTable::_index(uint32_t index) const
{
  ink_assert(this->_offset + this->length() >= index + 1);

  return this->_offset + this->length() - index - 1;
}

//
// Low level interfaces
//
int64_t
encode_indexed_header_field(uint8_t *buf_start, const uint8_t *buf_end, uint32_t index)
{
  if (buf_start >= buf_end) {
    return -1;
  }

  uint8_t *p = buf_start;

  // Index
  const int64_t len = xpack_encode_integer(p, buf_end, index, 7);
  if (len == -1) {
    return -1;
  }

  // Representation type
  if (p + 1 >= buf_end) {
    return -1;
  }

  *p |= 0x80;
  p += len;

  Debug("hpack_encode", "Encoded field: %d", index);
  return p - buf_start;
}

int64_t
encode_literal_header_field_with_indexed_name(uint8_t *buf_start, const uint8_t *buf_end, const MIMEFieldWrapper &header,
                                              uint32_t index, HPACK &indexing_table, HpackField type)
{
  uint8_t *p = buf_start;
  int64_t len;
  uint8_t prefix = 0, flag = 0;

  ink_assert(hpack_field_is_literal(type));

  switch (type) {
  case HpackField::INDEXED_LITERAL:
    indexing_table.add_header_field(header.field_get());
    prefix = 6;
    flag   = 0x40;
    break;
  case HpackField::NOINDEX_LITERAL:
    prefix = 4;
    flag   = 0x00;
    break;
  case HpackField::NEVERINDEX_LITERAL:
    prefix = 4;
    flag   = 0x10;
    break;
  default:
    return -1;
  }

  // Index
  *p  = 0;
  len = xpack_encode_integer(p, buf_end, index, prefix);
  if (len == -1) {
    return -1;
  }

  // Representation type
  if (p + 1 >= buf_end) {
    return -1;
  }
  *p |= flag;
  p += len;

  // Value String
  int value_len;
  const char *value = header.value_get(&value_len);
  len               = xpack_encode_string(p, buf_end, value, value_len);
  if (len == -1) {
    return -1;
  }
  p += len;

  Debug("hpack_encode", "Encoded field: %d: %.*s", index, value_len, value);
  return p - buf_start;
}

int64_t
encode_literal_header_field_with_new_name(uint8_t *buf_start, const uint8_t *buf_end, const MIMEFieldWrapper &header,
                                          HPACK &indexing_table, HpackField type)
{
  uint8_t *p = buf_start;
  int64_t len;
  uint8_t flag = 0;

  ink_assert(hpack_field_is_literal(type));

  switch (type) {
  case HpackField::INDEXED_LITERAL:
    indexing_table.add_header_field(header.field_get());
    flag = 0x40;
    break;
  case HpackField::NOINDEX_LITERAL:
    flag = 0x00;
    break;
  case HpackField::NEVERINDEX_LITERAL:
    flag = 0x10;
    break;
  default:
    return -1;
  }
  if (p + 1 >= buf_end) {
    return -1;
  }
  *(p++) = flag;

  // Convert field name to lower case to follow HTTP2 spec.
  // This conversion is needed because WKSs in MIMEFields is old fashioned
  Arena arena;
  int name_len;
  const char *name = header.name_get(&name_len);
  char *lower_name = arena.str_store(name, name_len);
  for (int i = 0; i < name_len; i++) {
    lower_name[i] = ParseRules::ink_tolower(lower_name[i]);
  }

  // Name String
  len = xpack_encode_string(p, buf_end, lower_name, name_len);
  if (len == -1) {
    return -1;
  }
  p += len;

  // Value String
  int value_len;
  const char *value = header.value_get(&value_len);
  len               = xpack_encode_string(p, buf_end, value, value_len);
  if (len == -1) {
    return -1;
  }

  p += len;

  Debug("hpack_encode", "Encoded field: %.*s: %.*s", name_len, name, value_len, value);
  return p - buf_start;
}

int64_t
encode_dynamic_table_size_update(uint8_t *buf_start, const uint8_t *buf_end, uint32_t size)
{
  buf_start[0]      = 0x20;
  const int64_t len = xpack_encode_integer(buf_start, buf_end, size, 5);
  if (len == -1) {
    return -1;
  }

  return len;
}

//
// [RFC 7541] 6.1. Indexed Header Field Representation
//
int64_t
decode_indexed_header_field(MIMEFieldWrapper &header, const uint8_t *buf_start, const uint8_t *buf_end, HPACK &indexing_table)
{
  uint64_t index = 0;
  int64_t len    = 0;

  len = xpack_decode_integer(index, buf_start, buf_end, 7);
  if (len == XPACK_ERROR_COMPRESSION_ERROR) {
    return HPACK_ERROR_COMPRESSION_ERROR;
  }

  if (indexing_table.get_header_field(index, header) == HPACK_ERROR_COMPRESSION_ERROR) {
    return HPACK_ERROR_COMPRESSION_ERROR;
  }

  if (is_debug_tag_set("hpack_decode")) {
    int decoded_name_len;
    const char *decoded_name = header.name_get(&decoded_name_len);
    int decoded_value_len;
    const char *decoded_value = header.value_get(&decoded_value_len);

    Arena arena;
    Debug("hpack_decode", "Decoded field: %s: %s", arena.str_store(decoded_name, decoded_name_len),
          arena.str_store(decoded_value, decoded_value_len));
  }

  return len;
}

//
// [RFC 7541] 6.2. Literal Header Field Representation
// Decode Literal Header Field Representation based on HpackFieldType
//
int64_t
decode_literal_header_field(MIMEFieldWrapper &header, const uint8_t *buf_start, const uint8_t *buf_end, HPACK &indexing_table)
{
  const uint8_t *p         = buf_start;
  bool isIncremental       = false;
  uint64_t index           = 0;
  int64_t len              = 0;
  HpackField ftype         = hpack_parse_field_type(*p);
  bool has_http2_violation = false;

  if (ftype == HpackField::INDEXED_LITERAL) {
    len           = xpack_decode_integer(index, p, buf_end, 6);
    isIncremental = true;
  } else if (ftype == HpackField::NEVERINDEX_LITERAL) {
    len = xpack_decode_integer(index, p, buf_end, 4);
  } else {
    ink_assert(ftype == HpackField::NOINDEX_LITERAL);
    len = xpack_decode_integer(index, p, buf_end, 4);
  }

  if (len == XPACK_ERROR_COMPRESSION_ERROR) {
    return HPACK_ERROR_COMPRESSION_ERROR;
  }

  p += len;

  Arena arena;

  // Decode header field name
  if (index) {
    indexing_table.get_header_field(index, header);
  } else {
    char *name_str        = nullptr;
    uint64_t name_str_len = 0;

    len = xpack_decode_string(arena, &name_str, name_str_len, p, buf_end);
    if (len == XPACK_ERROR_COMPRESSION_ERROR) {
      return HPACK_ERROR_COMPRESSION_ERROR;
    }

    // Check whether header field name is lower case
    // XXX This check shouldn't be here because this rule is not a part of HPACK but HTTP2.
    for (uint32_t i = 0; i < name_str_len; i++) {
      if (ParseRules::is_upalpha(name_str[i])) {
        has_http2_violation = true;
        break;
      }
    }

    p += len;
    header.name_set(name_str, name_str_len);
  }

  // Decode header field value
  char *value_str        = nullptr;
  uint64_t value_str_len = 0;

  len = xpack_decode_string(arena, &value_str, value_str_len, p, buf_end);
  if (len == XPACK_ERROR_COMPRESSION_ERROR) {
    return HPACK_ERROR_COMPRESSION_ERROR;
  }

  p += len;
  header.value_set(value_str, value_str_len);

  // Incremental Indexing adds header to header table as new entry
  if (isIncremental) {
    indexing_table.add_header_field(header.field_get());
  }

  // Print decoded header field
  if (is_debug_tag_set("hpack_decode")) {
    int decoded_name_len;
    const char *decoded_name = header.name_get(&decoded_name_len);
    int decoded_value_len;
    const char *decoded_value = header.value_get(&decoded_value_len);

    Debug("hpack_decode", "Decoded field: %s: %s", arena.str_store(decoded_name, decoded_name_len),
          arena.str_store(decoded_value, decoded_value_len));
  }

  if (has_http2_violation) {
    // XXX Need to return the length to continue decoding
    return -(p - buf_start);
  } else {
    return p - buf_start;
  }
}

//
// [RFC 7541] 6.3. Dynamic Table Size Update
//
int64_t
update_dynamic_table_size(const uint8_t *buf_start, const uint8_t *buf_end, HPACK &indexing_table, uint32_t maximum_table_size)
{
  if (buf_start == buf_end) {
    return HPACK_ERROR_COMPRESSION_ERROR;
  }

  // Update header table size if its required.
  uint64_t size = 0;
  int64_t len   = xpack_decode_integer(size, buf_start, buf_end, 5);
  if (len == XPACK_ERROR_COMPRESSION_ERROR) {
    return HPACK_ERROR_COMPRESSION_ERROR;
  }

  if (size > maximum_table_size) {
    return HPACK_ERROR_COMPRESSION_ERROR;
  }

  if (indexing_table.update_maximum_size(size) == false) {
    return HPACK_ERROR_COMPRESSION_ERROR;
  }

  return len;
}

//
// High level interfaces
//
int64_t
hpack_decode_header_block(HPACK &indexing_table, HTTPHdr *hdr, const uint8_t *in_buf, const size_t in_buf_len,
                          uint32_t max_header_size, uint32_t maximum_table_size)
{
  const uint8_t *cursor           = in_buf;
  const uint8_t *const in_buf_end = in_buf + in_buf_len;
  HdrHeap *heap                   = hdr->m_heap;
  HTTPHdrImpl *hh                 = hdr->m_http;
  bool header_field_started       = false;
  bool has_http2_violation        = false;
  uint32_t total_header_size      = 0;

  while (cursor < in_buf_end) {
    int64_t read_bytes = 0;

    // decode a header field encoded by HPACK
    MIMEField *field = mime_field_create(heap, hh->m_fields_impl);
    MIMEFieldWrapper header(field, heap, hh->m_fields_impl);
    HpackField ftype = hpack_parse_field_type(*cursor);

    switch (ftype) {
    case HpackField::INDEX:
      read_bytes = decode_indexed_header_field(header, cursor, in_buf_end, indexing_table);
      if (read_bytes == HPACK_ERROR_COMPRESSION_ERROR) {
        return HPACK_ERROR_COMPRESSION_ERROR;
      }
      cursor += read_bytes;
      header_field_started = true;
      break;
    case HpackField::INDEXED_LITERAL:
    case HpackField::NOINDEX_LITERAL:
    case HpackField::NEVERINDEX_LITERAL:
      read_bytes = decode_literal_header_field(header, cursor, in_buf_end, indexing_table);
      if (read_bytes == HPACK_ERROR_COMPRESSION_ERROR) {
        return HPACK_ERROR_COMPRESSION_ERROR;
      }
      if (read_bytes < 0) {
        has_http2_violation = true;
        read_bytes          = -read_bytes;
      }
      cursor += read_bytes;
      header_field_started = true;
      break;
    case HpackField::TABLESIZE_UPDATE:
      if (header_field_started) {
        return HPACK_ERROR_COMPRESSION_ERROR;
      }
      read_bytes = update_dynamic_table_size(cursor, in_buf_end, indexing_table, maximum_table_size);
      if (read_bytes == HPACK_ERROR_COMPRESSION_ERROR) {
        return HPACK_ERROR_COMPRESSION_ERROR;
      }
      cursor += read_bytes;
      continue;
    }

    int name_len  = 0;
    int value_len = 0;

    field->name_get(&name_len);
    field->value_get(&value_len);
    total_header_size += name_len + value_len;

    if (total_header_size > max_header_size) {
      return HPACK_ERROR_SIZE_EXCEEDED_ERROR;
    }

    // Store to HdrHeap
    mime_hdr_field_attach(hh->m_fields_impl, field, 1, nullptr);
  }
  // Parsing all headers is done
  if (has_http2_violation) {
    return -(cursor - in_buf);
  } else {
    return cursor - in_buf;
  }
}

int64_t
hpack_encode_header_block(HPACK &indexing_table, uint8_t *out_buf, const size_t out_buf_len, HTTPHdr *hdr,
                          int32_t maximum_table_size)
{
  uint8_t *cursor                  = out_buf;
  const uint8_t *const out_buf_end = out_buf + out_buf_len;
  int64_t written                  = 0;

  ink_assert(http_hdr_type_get(hdr->m_http) != HTTP_TYPE_UNKNOWN);

  // Update dynamic table size
  if (maximum_table_size >= 0) {
    indexing_table.update_maximum_size(maximum_table_size);
    written = encode_dynamic_table_size_update(cursor, out_buf_end, maximum_table_size);
    if (written == HPACK_ERROR_COMPRESSION_ERROR) {
      return HPACK_ERROR_COMPRESSION_ERROR;
    }
    cursor += written;
  }

  MIMEFieldIter field_iter;
  for (MIMEField *field = hdr->iter_get_first(&field_iter); field != nullptr; field = hdr->iter_get_next(&field_iter)) {
    HpackField field_type;
    MIMEFieldWrapper header(field, hdr->m_heap, hdr->m_http->m_fields_impl);
    int name_len;
    int value_len;
    const char *name  = header.name_get(&name_len);
    const char *value = header.value_get(&value_len);
    // Choose field representation (See RFC7541 7.1.3)
    // - Authorization header obviously should not be indexed
    // - Short Cookie header should not be indexed because of low entropy
    if ((ptr_len_casecmp(name, name_len, MIME_FIELD_COOKIE, MIME_LEN_COOKIE) == 0 && value_len < 20) ||
        (ptr_len_casecmp(name, name_len, MIME_FIELD_AUTHORIZATION, MIME_LEN_AUTHORIZATION) == 0)) {
      field_type = HpackField::NEVERINDEX_LITERAL;
    } else {
      field_type = HpackField::INDEXED_LITERAL;
    }

    Debug("hpack_encode", "name=%.*s value=%.*s", name_len, name, value_len, value);

    const HpackLookupResult result = indexing_table.lookup(header);
    switch (result.match_type) {
    case HpackMatch::NONE:
      Debug("hpack_encode", "no match");
      written = encode_literal_header_field_with_new_name(cursor, out_buf_end, header, indexing_table, field_type);
      break;
    case HpackMatch::NAME:
      Debug("hpack_encode", "name only match");
      written =
        encode_literal_header_field_with_indexed_name(cursor, out_buf_end, header, result.index, indexing_table, field_type);
      break;
    case HpackMatch::EXACT:
      Debug("hpack_encode", "exact match");
      written = encode_indexed_header_field(cursor, out_buf_end, result.index);
      break;
    default:
      // Does it happen?
      written = 0;
      break;
    }
    if (written == HPACK_ERROR_COMPRESSION_ERROR) {
      return HPACK_ERROR_COMPRESSION_ERROR;
    }
    cursor += written;
  }
  return cursor - out_buf;
}

int32_t
hpack_get_maximum_table_size(HPACK &indexing_table)
{
  return indexing_table.maximum_size();
}
