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
#include "config.h"
#include "timing.h"
#include "jwt.h"

#include <cjose/cjose.h>
#include <jansson.h>

#include <cstring>
#include <search.h>
#include <cerrno>

#define JSONError(err) PluginError("json-err: %s:%d:%d: %s", (err).source, (err).line, (err).column, (err).text)

#define AUTH_DENY  0
#define AUTH_ALLOW 1
struct auth_directive {
  char  auth;
  char *container;
};

struct config {
  struct hsearch_data       *issuers;
  cjose_jwk_t             ***jwkis;
  char                     **issuer_names;
  struct config_key_binding *keys;
  size_t                     key_count;
  struct signer              signer;
  struct auth_directive     *auth_directives;
  char                      *id;
  bool                       strip_token;
};

const char *
config_get_id(struct config *cfg)
{
  return cfg->id;
}

bool
config_strip_token(struct config *cfg)
{
  return cfg->strip_token;
}

static size_t
count_keys(json_t *const issuer_json)
{
  size_t      key_count = 0;
  const char *json_issuer;
  json_t     *jwks;

  json_object_foreach(issuer_json, json_issuer, jwks)
  {
    (void)json_issuer;
    json_t *key_ary = json_object_get(jwks, "keys");
    if (key_ary && json_is_array(key_ary)) {
      key_count += json_array_size(key_ary);
    }
  }

  return key_count;
}

struct config *
config_new(size_t n, size_t key_count)
{
  if (key_count == 0) {
    PluginError("Config has no verification keys.");
    return nullptr;
  }

  PluginDebug("Creating new config object with size %zu", n);
  config *cfg = static_cast<config *>(malloc(sizeof *cfg));
  if (!cfg) {
    PluginError("Unable to allocate config!");
    return nullptr;
  }

  cfg->issuers = static_cast<hsearch_data *>(calloc(1, sizeof *cfg->issuers));
  if (!cfg->issuers) {
    PluginError("Unable to allocate config table!");
    free(cfg);
    return nullptr;
  }
  if (!hcreate_r(n * 2, cfg->issuers)) {
    PluginError("Unable to create config table (%d)!", errno);
    free(cfg->issuers);
    free(cfg);
    return nullptr;
  }
  PluginDebug("Created table with size %d", cfg->issuers->size);

  cfg->jwkis = static_cast<cjose_jwk_t ***>(calloc(n + 1, sizeof *cfg->jwkis));
  if (!cfg->jwkis) {
    PluginError("Unable to allocate config jwkis!");
    hdestroy_r(cfg->issuers);
    free(cfg->issuers);
    free(cfg);
    return nullptr;
  }

  cfg->issuer_names = static_cast<char **>(calloc(n + 1, sizeof *cfg->issuer_names));
  if (!cfg->issuer_names) {
    PluginError("Unable to allocate config issuer names!");
    hdestroy_r(cfg->issuers);
    free(cfg->issuers);
    free(cfg->jwkis);
    free(cfg);
    return nullptr;
  }

  cfg->keys = static_cast<config_key_binding *>(calloc(key_count, sizeof *cfg->keys));
  if (!cfg->keys) {
    PluginError("Unable to allocate config key bindings!");
    hdestroy_r(cfg->issuers);
    free(cfg->issuers);
    free(cfg->jwkis);
    free(cfg->issuer_names);
    free(cfg);
    return nullptr;
  }
  cfg->key_count = 0;

  cfg->signer.issuer = nullptr;
  cfg->signer.jwk    = nullptr;
  cfg->signer.alg    = nullptr;

  cfg->auth_directives = nullptr;
  cfg->id              = nullptr;

  cfg->strip_token = false;

  PluginDebug("New config object created at %p", cfg);
  return cfg;
}

void
config_delete(struct config *cfg)
{
  if (!cfg) {
    return;
  }
  hdestroy_r(cfg->issuers);
  free(cfg->issuers);

  for (cjose_jwk_t ***jwkis = cfg->jwkis; *jwkis; ++jwkis) {
    for (cjose_jwk_t **jwks = *jwkis; *jwks; ++jwks) {
      cjose_jwk_release(*jwks);
    }
    free(*jwkis);
  }
  free(cfg->jwkis);

  if (cfg->id) {
    free(cfg->id);
  }

  for (size_t idx = 0; idx < cfg->key_count; ++idx) {
    free(cfg->keys[idx].alg);
    free(cfg->keys[idx].kid);
  }
  free(cfg->keys);

  for (char **name = cfg->issuer_names; *name; ++name) {
    free(*name);
  }
  free(cfg->issuer_names);

  if (cfg->signer.alg) {
    free(cfg->signer.alg);
  }

  if (cfg->auth_directives) {
    for (struct auth_directive *ad = cfg->auth_directives; ad->container; ++ad) {
      free(ad->container);
    }
    free(cfg->auth_directives);
  }
  free(cfg);
}

cjose_jwk_t *
load_jwk(json_t *obj, cjose_err *err)
{
  char *s = json_dumps(obj, JSON_COMPACT);
  if (!s) {
    PluginError("Failed to re-serialize JSON sub-object.");
    return nullptr;
  }

  cjose_jwk_t *jwk = cjose_jwk_import(s, strlen(s), err);
  free(s);
  return jwk;
}

static struct config *
read_config_from_json(json_t *const issuer_json)
{
  struct config *cfg        = nullptr;
  size_t         issuers_ct = 0;

  if (!json_is_object(issuer_json)) {
    PluginError("Config file is not a valid JSON object");
    goto issuer_fail;
  }

  issuers_ct = json_object_size(issuer_json);
  if (!issuers_ct) {
    PluginError("Config file contains no issuers.");
    goto issuer_fail;
  }

  {
    size_t key_count = count_keys(issuer_json);

    cfg = config_new(issuers_ct, key_count);
    if (!cfg) {
      goto issuer_fail;
    }

    cjose_jwk_t ***jwkis  = cfg->jwkis;
    char         **issuer = cfg->issuer_names;
    const char    *json_issuer;
    json_t        *jwks;
    json_object_foreach(issuer_json, json_issuer, jwks)
    {
      *issuer = strdup(json_issuer);

      json_t *ad_json = json_object_get(jwks, "auth_directives");
      if (ad_json) {
        PluginDebug("Loading auth_directives.");
        size_t ad_ct = json_array_size(ad_json);
        if (ad_ct) {
          PluginDebug("Loading %d new auth_directives.", (int)ad_ct);
          struct auth_directive *ad = cfg->auth_directives;
          if (cfg->auth_directives) {
            /* We've already got directives, so extend them. */
            PluginDebug("Extending existing auth_directives.");
            size_t ad_old_ct = 0;
            while (ad->container) {
              ++ad;
              ++ad_old_ct;
            }
            cfg->auth_directives =
              static_cast<auth_directive *>(realloc(cfg->auth_directives, (ad_ct + ad_old_ct + 1) * sizeof *cfg->auth_directives));
            ad = cfg->auth_directives + ad_old_ct;
          } else {
            ad = cfg->auth_directives = static_cast<auth_directive *>(malloc((ad_ct + 1) * sizeof *cfg->auth_directives));
          }
          json_t *ad_obj;
          for (size_t idx = 0; (idx < ad_ct) && (ad_obj = json_array_get(ad_json, idx)); ++idx, ++ad) {
            json_t *uri_json  = json_object_get(ad_obj, "uri");
            json_t *auth_json = json_object_get(ad_obj, "auth");
            if (uri_json) {
              const char *uri = json_string_value(uri_json);
              ad->container   = strdup(uri ? uri : "");
              ad->auth        = AUTH_DENY;
              if (auth_json) {
                const char *auth = json_string_value(auth_json);
                if (!auth) {
                  auth = "";
                }
                if (!strcmp(auth, "allow")) {
                  ad->auth = AUTH_ALLOW;
                } else if (!strcmp(auth, "deny")) {
                  ad->auth = AUTH_DENY;
                } else {
                  PluginError("auth_directive has unknown auth parameter '%s', defaulting to deny: %s", auth, uri);
                }
              } else {
                PluginError("auth_directive is missing auth parameter, defaulting to deny: %s", uri);
              }
              PluginDebug("Adding auth_directive %d for %s.", (int)ad->auth, ad->container);
            }
          }
          ad->container = nullptr;
        }
      } else {
        PluginDebug("No auth_directives to load for %s.", *issuer);
      }

      json_t *key_ary = json_object_get(jwks, "keys");
      if (!key_ary) {
        PluginError("Failed to get keys member from jwk for issuer %s", *issuer);
        *jwkis = nullptr;
        goto cfg_fail;
      }
      if (!json_is_array(key_ary)) {
        PluginError("Keys member for issuer %s is not an array.", *issuer);
        *jwkis = nullptr;
        goto cfg_fail;
      }
      PluginDebug("Created table with size %d", cfg->issuers->size);

      const char *renewal_kid      = nullptr;
      json_t     *renewal_kid_json = json_object_get(jwks, "renewal_kid");
      if (renewal_kid_json) {
        renewal_kid = json_string_value(renewal_kid_json);
      }

      json_t     *id_json = json_object_get(jwks, "id");
      const char *id;
      if (id_json) {
        id = json_string_value(id_json);
        if (id) {
          cfg->id = static_cast<char *>(malloc(strlen(id) + 1));
          strcpy(cfg->id, id);
          PluginDebug("Found Id in the config: %s", cfg->id);
        }
      }

      json_t *strip_json = json_object_get(jwks, "strip_token");
      if (strip_json) {
        cfg->strip_token = json_boolean_value(strip_json);
      }

      size_t        jwks_ct = json_array_size(key_ary);
      cjose_jwk_t **jwks = *jwkis++ = static_cast<cjose_jwk_t **>(calloc(jwks_ct + 1, sizeof *jwks));
      if (!jwks) {
        PluginError("Unable to allocate jwks array for issuer %s.", *issuer);
        goto cfg_fail;
      }
      PluginDebug("Created table with size %d", cfg->issuers->size);
      ENTRY *dummy;
      if (!hsearch_r(((ENTRY){*issuer, jwks}), ENTER, &dummy, cfg->issuers)) {
        PluginDebug("Failed to store keys for issuer %s", *issuer);
      } else {
        PluginDebug("Stored keys for %s at %16p", *issuer, jwks);
      }

      json_t   *jwk_obj;
      cjose_err jwk_err;
      memset(&jwk_err, 0, sizeof(cjose_err));
      for (size_t idx = 0; (idx < jwks_ct) && (jwk_obj = json_array_get(key_ary, idx)); ++idx, ++jwks) {
        if ((*jwks = load_jwk(jwk_obj, &jwk_err))) {
          char const *const kid     = cjose_jwk_get_kid(*jwks, nullptr);
          char const *const jwk_alg = json_string_value(json_object_get(jwk_obj, "alg"));
          PluginDebug("Stored jwk %zu for issuer %s, kid %s, cfg %p->%p", idx, *issuer, kid ? kid : "<no kid>", cfg, cfg->issuers);
          if (!jwk_alg) {
            PluginError("Cannot load JWK algorithm for issuer %s key %zu.", *issuer, idx);
            goto cfg_fail;
          }

          char *alg_copy = strdup(jwk_alg);
          char *kid_copy = kid ? strdup(kid) : nullptr;
          if (!alg_copy || (kid && !kid_copy)) {
            PluginError("Unable to allocate key metadata for issuer %s key %zu.", *issuer, idx);
            free(alg_copy);
            free(kid_copy);
            goto cfg_fail;
          }

          cfg->keys[cfg->key_count++] = {
            .issuer = *issuer,
            .alg    = alg_copy,
            .kid    = kid_copy,
            .jwk    = *jwks,
          };

          if (renewal_kid && kid && !strcmp(kid, renewal_kid)) {
            if (cfg->signer.issuer) {
              PluginError("Cannot load multiple renewal keys for a single remap. iss:\"%s\", kid:\"%s\"; iss:\"%s\", kid:\"%s\"",
                          cfg->signer.issuer, cjose_jwk_get_kid(cfg->signer.jwk, nullptr), *issuer, kid);
              goto cfg_fail;
            } else {
              char *signer_alg = strdup(jwk_alg);
              if (!signer_alg) {
                PluginError("Unable to allocate signer algorithm for issuer %s key %zu.", *issuer, idx);
                free(signer_alg);
                goto cfg_fail;
              }

              cfg->signer.issuer = *issuer;
              cfg->signer.jwk    = *jwks;
              cfg->signer.alg    = signer_alg;
            }
          }
        } else {
          PluginError("Failed to load jwk %zu for issuer %s: %s", idx, *issuer, jwk_err.message);
          goto cfg_fail;
        }
      }
      *jwks = nullptr;
      ++issuer;
    }
    if (!cfg->signer.issuer) {
      PluginError("Cannot load remap without signing key.");
      goto cfg_fail;
    }
    json_decref(issuer_json);
    PluginDebug("Loaded config file successfully.");
    return cfg;
  }
cfg_fail:
  config_delete(cfg);
issuer_fail:
  json_decref(issuer_json);
  return nullptr;
}

struct config *
read_config_from_path(char const *const path)
{
  json_error_t err;
  memset(&err, 0, sizeof(json_error_t));
  json_t *issuer_json = json_load_file(path, 0, &err);
  if (!issuer_json) {
    JSONError(err);
    return nullptr;
  }
  return read_config_from_json(issuer_json);
}

struct config *
read_config_from_string(char const *const buffer)
{
  json_error_t err;
  memset(&err, 0, sizeof(json_error_t));
  json_t *issuer_json = json_loads(buffer, 0, &err);
  if (!issuer_json) {
    JSONError(err);
    return nullptr;
  }
  return read_config_from_json(issuer_json);
}

struct config_key_binding const *
config_keys(struct config *cfg)
{
  return cfg ? cfg->keys : nullptr;
}

size_t
config_key_count(struct config *cfg)
{
  return cfg ? cfg->key_count : 0;
}

struct signer *
config_signer(struct config *cfg)
{
  if (!cfg) {
    return nullptr;
  }
  return &cfg->signer;
}

bool
uri_matches_auth_directive(struct config *cfg, const char *uri, size_t uri_ct)
{
  if (!cfg || !cfg->auth_directives || !uri) {
    return false;
  }

  char *uri_s = static_cast<char *>(malloc(uri_ct + 1));
  memcpy(uri_s, uri, uri_ct);
  uri_s[uri_ct] = 0;
  for (const struct auth_directive *ad = cfg->auth_directives; ad->container; ++ad) {
    if (jwt_check_uri(ad->container, uri_s)) {
      free(uri_s);
      return (ad->auth == AUTH_ALLOW);
    }
  }
  free(uri_s);
  return false;
}
