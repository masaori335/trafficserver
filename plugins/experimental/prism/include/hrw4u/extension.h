/** @file

  The C ABI between prism.so and an extension .so.

  Plain C and fixed layouts, so an extension built separately agrees with the host on every byte. Authors
  normally use hrw4u/extension.hpp instead of writing to this directly.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one or more contributor license
  agreements.  See the NOTICE file distributed with this work for additional information regarding
  copyright ownership.  The ASF licenses this file to you under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with the License.  You may obtain
  a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software distributed under the License
  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
  or implied. See the License for the specific language governing permissions and limitations under
  the License.
*/

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HRW4U_EXT_ABI_VERSION 1u

/* Every builtin has this one signature. A bool is one word (0 or 1); an i64 is one word, an int64_t's bits; an
   sview is two consecutive words, pointer then length, and the pointer may be NULL only when the length is 0. The
   result goes in ret[0], or ret[0] and ret[1] for an sview, which the function keeps valid until its next call on the
   same thread: the host copies it before then. A non-zero return is a fault: ret[0] and ret[1] then hold an sview of
   the error message, valid as long. */
typedef struct hrw4u_rule_ctx hrw4u_rule_ctx; /* the transaction the call runs in, valid only during the call, or
                                                 NULL when the Instance section calls it; opaque to an extension */
typedef int (*hrw4u_fn)(hrw4u_rule_ctx *ctx, const uint64_t *args, uint64_t *ret);

/* The host always passes at least this many result words, so a fault message fits. */
#define HRW4U_RET_WORDS 2

typedef enum {
  HRW4U_TYPE_BOOL  = 1,
  HRW4U_TYPE_SVIEW = 2,
  HRW4U_TYPE_I64   = 3,
} hrw4u_type;

typedef enum {
  HRW4U_EFFECT_PURE   = 1, /* no effect on the transaction */
  HRW4U_EFFECT_EFFECT = 2,
  HRW4U_EFFECT_LOAD   = 3, /* runs only while the instance loads, with a NULL rule context, as reading a key file once */
} hrw4u_effect;

typedef struct {
  const char       *name;
  hrw4u_type        ret;
  uint32_t          nparams;
  const hrw4u_type *params;
  hrw4u_effect      effect;
  hrw4u_fn          fn;
} hrw4u_fn_decl;

/* One per prism instance: two remap rules loading the same .so share its globals, so init and fini are
   told which instance they serve. */
typedef struct {
  uint32_t abi_version;
  void    *instance;
  int (*def)(void *instance, const hrw4u_fn_decl *decl); /* 0 = registered */
  void (*log)(void *instance, const char *message);
} hrw4u_host_api;

/* Where a module's signatures are written in the .so, so a tool reads them from the file without loading it.
   The section holds one block per module, possibly with NUL padding between blocks:

     hrw4u-manifest 1
     module <module name>
     fn <name> <pure|effect|load> <result type> [<parameter type> ...]
     end

   with one fn line per function, in registration order, bool, i64 or sview as the type names, and names made of letters,
   digits, '_', '-' and ':'. */
#define HRW4U_MANIFEST_HEADER        "hrw4u-manifest 1"
#define HRW4U_MANIFEST_ELF_SECTION   ".hrw4u_manifest"
#define HRW4U_MANIFEST_MACHO_SEGMENT "__TEXT"
#define HRW4U_MANIFEST_MACHO_SECTION "__hrw4u_manifest"

/* An extension exports these. */
#define HRW4U_EXT_ABI_SYMBOL  "hrw4u_ext_abi_version" /* const uint32_t */
#define HRW4U_EXT_INIT_SYMBOL "hrw4u_ext_init"        /* int (const hrw4u_host_api *), 0 = ok */
#define HRW4U_EXT_FINI_SYMBOL "hrw4u_ext_fini"        /* void (const hrw4u_host_api *), optional */

#ifdef __cplusplus
}
#endif
