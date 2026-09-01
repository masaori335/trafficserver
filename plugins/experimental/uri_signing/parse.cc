/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common.h"
#include "parse.h"
#include "config.h"
#include "jwt.h"
#include "cookie.h"
#include "timing.h"
#include <cjose/cjose.h>
#include <jansson.h>
#include <cstring>
#include <cinttypes>
#include <tsutil/PostScript.h>

cjose_jws_t *
get_jws_from_uri(const char *uri, size_t uri_ct, const char *paramName, char *strip_uri, size_t buff_ct, size_t *strip_ct)
{
  /* Reserved characters as defined by the URI Generic Syntax RFC: https://tools.ietf.org/html/rfc3986#section-2.2 */
  static char const *const reserved_string  = ":/?#[]@!$&\'()*+,;=";
  static char const *const sub_delim_string = "!$&\'()*+,;=";

  /* If param name ends in reserved character this will be treated as the termination symbol when parsing for package. Default is
   * '='. */
  char   termination_symbol;
  size_t termination_ct;
  size_t param_ct = strlen(paramName);

  if (param_ct <= 0) {
    PluginDebug("URI signing package name cannot be empty");
    return nullptr;
  }

  if (strchr(reserved_string, paramName[param_ct - 1])) {
    termination_symbol = paramName[param_ct - 1];
    termination_ct     = param_ct - 1;
  } else {
    termination_symbol = '=';
    termination_ct     = param_ct;
  }

  PluginDebug("Parsing JWS from query string: %.*s", (int)uri_ct, uri);
  const char *param = uri;
  const char *end   = uri + uri_ct;
  const char *key, *key_end;
  const char *value, *value_end;

  for (;;) {
    /* Search the URI for a reserved character. */
    while (param != end && strchr(reserved_string, *param) == nullptr) {
      ++param;
    }
    if (param == end) {
      break;
    }

    ++param;

    /* Parse the parameter for a key value pair separated by the termination symbol. */
    key   = param;
    value = param;
    while (value != end && *value != termination_symbol) {
      ++value;
    }
    if (value == end) {
      break;
    }
    key_end = value;

    /* If the Parameter key is our target parameter name, attempt to import a JWS from the value. */
    if (static_cast<size_t>(key_end - key) == termination_ct && !strncmp(paramName, key, static_cast<size_t>(key_end - key))) {
      value_end = ++value;
      while (value_end != end && strchr(reserved_string, *value_end) == nullptr) {
        ++value_end;
      }
      PluginDebug("Decoding JWS: %.*s", (int)(key_end - key), key);
      cjose_err err;
      memset(&err, 0, sizeof(cjose_err));
      cjose_jws_t *jws = cjose_jws_import(value, (size_t)(value_end - value), &err);
      if (!jws) {
        PluginDebug("Unable to read JWS: %.*s, %s", (int)(key_end - key), key, err.message ? err.message : "");
      } else {
        PluginDebug("Parsed JWS: %.*s (%16p)", (int)(key_end - key), key, jws);

        /* Strip token */
        /* Check that passed buffer is large enough */
        *strip_ct = ((key - uri) + (end - value_end));
        if (buff_ct <= *strip_ct) {
          PluginDebug("Strip URI buffer is not large enough");
          return nullptr;
        }

        if (value_end != end && strchr(sub_delim_string, *value_end)) {
          /*Strip from first char of package name to sub-delimeter that terminates the signed JWT */
          memcpy(strip_uri, uri, (key - uri));
          memcpy(strip_uri + (key - uri), value_end + 1, end - value_end - 1);
        } else {
          /*Strip from reserved char to the last char of the JWT */
          memcpy(strip_uri, uri, (key - uri - 1));
          memcpy(strip_uri + (key - uri - 1), value_end, (end - value_end));
        }

        if (strip_uri[*strip_ct - 1] != '\0') {
          strip_uri[*strip_ct - 1] = '\0';
        }
        PluginDebug("Stripped URI: %s", strip_uri);
      }
      return jws;
    }
  }
  PluginDebug("Unable to locate signing key in uri: %.*s", (int)uri_ct, uri);
  return nullptr;
}

cjose_jws_t *
get_jws_from_cookie(const char **cookie, size_t *cookie_ct, const char *paramName)
{
  PluginDebug("Parsing JWS from cookie: %.*s", (int)*cookie_ct, *cookie);
  size_t      value_ct;
  const char *value = get_cookie_value(cookie, cookie_ct, paramName, &value_ct);
  PluginDebug("Got jws string: (%p) %.*s", value, (int)value_ct, value);
  if (!value || !value_ct) {
    return nullptr;
  }
  cjose_err err;
  memset(&err, 0, sizeof(cjose_err));
  cjose_jws_t *jws = cjose_jws_import(value, value_ct, &err);
  if (!jws) {
    PluginDebug("Unable to read JWS: %.*s, %s", (int)value_ct, value, err.message ? err.message : "");
  } else {
    PluginDebug("Parsed JWS: %.*s (%16p)", (int)value_ct, value, jws);
  }
  return jws;
}

static bool
header_matches_configured_key(char const *const alg, char const *const kid, struct config_key_binding const &key)
{
  if (strcmp(alg, key.alg) != 0) {
    return false;
  }

  if (kid != nullptr) {
    return key.kid != nullptr && strcmp(kid, key.kid) == 0;
  }

  return true;
}

struct jwt *
validate_jws(cjose_jws_t *jws, struct config *cfg, const char *uri, size_t /* uri_ct ATS_UNUSED */)
{
  struct timer t;
  int64_t      last_mark = 0;
  start_timer(&t);

#define TimerDebug(msg)                                             \
  do {                                                              \
    int64_t new_mark = mark_timer(&t);                              \
    PluginDebug("Spent %" PRId64 " ns " msg, new_mark - last_mark); \
    last_mark = new_mark;                                           \
  } while (0)

  PluginDebug("Validating JWS for %16p", jws);

  cjose_header_t *hdr = cjose_jws_get_protected(jws);
  TimerDebug("getting header of jws");
  if (!hdr) {
    PluginDebug("Cannot get protected header for %16p", jws);
    return nullptr;
  }

  /* Reject tokens that carry no algorithm or use the "none" algorithm.
   * The protected header drives candidate selection. Unverified payload
   * claims must not influence verification. */
  char const *const alg = cjose_header_get(hdr, CJOSE_HDR_ALG, nullptr);
  TimerDebug("getting alg of jws header");
  if (!alg) {
    PluginDebug("Missing alg in protected header for %16p", jws);
    return nullptr;
  }
  if (strcmp(alg, CJOSE_HDR_ALG_NONE) == 0) {
    PluginDebug("Rejecting JWS with 'none' algorithm for %16p", jws);
    return nullptr;
  }

  char const *const kid = cjose_header_get(hdr, "kid", nullptr);
  TimerDebug("getting kid of jws header");

  struct config_key_binding const *matched_key  = nullptr;
  struct config_key_binding const *keys         = config_keys(cfg);
  size_t const                     key_count    = config_key_count(cfg);
  json_t                          *payload_json = nullptr;
  struct jwt                      *jwt          = nullptr;

  if (kid) {
    PluginDebug("Searching all configured keys for kid %s alg %s for %16p", kid, alg, jws);
  } else {
    PluginDebug("Searching all configured keys for alg %s for %16p", alg, jws);
  }

  for (size_t idx = 0; idx < key_count; ++idx) {
    struct config_key_binding const &candidate = keys[idx];

    if (!header_matches_configured_key(alg, kid, candidate)) {
      continue;
    }

    cjose_err err;
    memset(&err, 0, sizeof(cjose_err));
    if (!cjose_jws_verify(jws, candidate.jwk, &err)) {
      PluginDebug("Key validation failed for issuer %s kid %s alg %s: '%s'", candidate.issuer,
                  candidate.kid ? candidate.kid : "<no kid>", candidate.alg, (err.message ? err.message : ""));
      continue;
    }

    /* Signature verified under this candidate. Parse the payload on the first
     * successful verification — the payload bytes are the same regardless of
     * which key verified, so parse once and reuse across candidates. */
    if (payload_json == nullptr) {
      cjose_err cerr;
      memset(&cerr, 0, sizeof(cjose_err));
      size_t      pt_ct;
      char const *pt;
      if (!cjose_jws_get_plaintext(jws, (uint8_t **)&pt, &pt_ct, &cerr)) {
        PluginDebug("Cannot get plaintext for %16p", jws);
        return nullptr;
      }
      TimerDebug("getting jws plaintext");

      json_error_t jerr;
      memset(&jerr, 0, sizeof(json_error_t));
      payload_json = json_loadb(pt, pt_ct, 0, &jerr);
      if (!payload_json) {
        if (jerr.text[0]) {
          PluginDebug("Cannot load json for %16p: %.*s '%s'", jws, (int)pt_ct, pt, jerr.text);
        } else {
          PluginDebug("Cannot load json for %16p: %.*s", jws, (int)pt_ct, pt);
        }
        return nullptr;
      }
      jwt = parse_jwt(payload_json);
      TimerDebug("parsing jwt");
      if (!jwt) {
        json_decref(payload_json);
        return nullptr;
      }
    }

    /* Require the verified key's configured issuer to match the payload iss.
     * If they disagree, continue searching so that shared keys across
     * issuers are handled correctly. */
    if (!jwt->iss) {
      PluginDebug("Missing issuer in verified JWT for %16p", jws);
      jwt_delete(jwt);
      return nullptr;
    }
    if (strcmp(jwt->iss, candidate.issuer) != 0) {
      PluginDebug("Verified key issuer %s does not match payload iss %s for %16p", candidate.issuer, jwt->iss, jws);
      continue;
    }

    matched_key = &candidate;
    break;
  }
  TimerDebug("checking crypto signature for jwt");

  if (matched_key == nullptr) {
    jwt_delete(jwt);
    if (kid) {
      PluginDebug("No valid configured key for alg %s kid %s found for %16p", alg, kid, jws);
    } else {
      PluginDebug("No valid configured key for alg %s found for %16p", alg, jws);
    }
    return nullptr;
  }

  ts::PostScript ps([&jwt]() -> void { jwt_delete(jwt); });
  TimerDebug("post-signature JWT validation");

  if (!jwt_validate(jwt)) {
    PluginDebug("Initial validation of JWT failed for %16p", jws);
    return nullptr;
  }
  TimerDebug("initial validation of jwt");

  if (!jwt_check_aud(jwt->aud, config_get_id(cfg))) {
    PluginDebug("Valid key for %16p that does not match aud.", jws);
    return nullptr;
  }

  if (!jwt_check_uri(jwt->cdniuc, uri)) {
    PluginDebug("Valid key for %16p that does not match uri.", jws);
    return nullptr;
  }
  TimerDebug("verifying sub claim");

  ps.release();
  return jwt;
}
