/*
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

/**
 * @file common.cc
 * @brief Common declarations and definitions.
 * @see common.h
 */

#include "common.h"
#include "tsutil/LocalBuffer.h"

namespace
{
// Bitmap (one bit per byte value, MSB-first within each byte) of characters
// that must be percent-encoded by cachekey_encode_value. Mirrors the table
// historically passed to TSStringPercentEncode in cachekey.cc.
constexpr unsigned char kEncodeMap[32] = {
  0xFF, 0xFF, 0xFF, 0xFF, // control chars (0-31)
  0xB4,                   // space, ", #, %
  0x08,                   // ,
  0x00,                   //
  0x0A,                   // <, >
  0x00, 0x00,             //
  0x00,                   //
  0x1E, 0x80,             // [, \, ], ^, `
  0x00, 0x00,             //
  0x1F,                   // {, |, }, ~, DEL
  0x00, 0x00, 0x00, 0x00, //
  0x00, 0x00, 0x00, 0x00, //
  0x00, 0x00, 0x00, 0x00, //
  0x00, 0x00, 0x00,       //
};

bool
should_encode(unsigned char c)
{
  return (kEncodeMap[c >> 3] >> (7 - (c & 0x7))) & 0x1;
}
} // namespace

bool
cachekey_encode_value(const char *s, std::size_t len, char *dst, std::size_t dst_size, std::size_t *written)
{
  static const char hex[] = "0123456789ABCDEF";
  std::size_t       out   = 0;

  *written = 0;
  for (std::size_t i = 0; i < len; ++i) {
    auto c = static_cast<unsigned char>(s[i]);
    if (should_encode(c)) {
      if (out + 3 > dst_size) {
        return false;
      }
      dst[out++] = '%';
      dst[out++] = hex[c >> 4];
      dst[out++] = hex[c & 0xF];
    } else {
      if (out + 1 > dst_size) {
        return false;
      }
      dst[out++] = static_cast<char>(c);
    }
  }
  *written = out;
  return true;
}

String
buildCanonicalUrlPrefix(const String &scheme, const String &host, const String &port, bool canonicalPrefix, bool provideDefaultKey)
{
  // CacheKey::appendPrefix appends the result either raw (useSeparator=false)
  // or through appendEncoded (useSeparator=true), depending on the shape:
  //   (false, false) --capture-prefix, non-canonical: regex input, captures
  //                   appended via appendEncoded. Encoding here would
  //                   double-encode (%2f -> %252f -> %25252f), so leave raw.
  //   (true,  false) --capture-prefix, canonical: regex input, captures
  //                   appended raw. Encode the host here.
  //   (false, true)  default key, non-canonical: appended raw. Encode here.
  //   (true,  true)  default key, canonical: appended raw. Encode here.
  // So encode the host for every shape except the one appended via the
  // encoded path.
  const bool encodeHost = canonicalPrefix || provideDefaultKey;

  ts::LocalBuffer<char, 1024> tmp(host.size() * 3);
  std::size_t                 written     = 0;
  const char                 *encodedData = host.data();
  std::size_t                 encodedLen  = host.size();
  if (encodeHost && host.size() > 0 && cachekey_encode_value(host.data(), host.size(), tmp.data(), tmp.size(), &written)) {
    encodedData = tmp.data();
    encodedLen  = written;
  }

  String result;
  if (canonicalPrefix) {
    result.reserve(scheme.size() + 3 + encodedLen + 1 + port.size());
    result.append(scheme).append("://").append(encodedData, encodedLen).append(":").append(port);
  } else if (provideDefaultKey) {
    result.reserve(1 + encodedLen + 1 + port.size());
    result.append(1, '/').append(encodedData, encodedLen).append("/").append(port);
  } else {
    result.reserve(encodedLen + 1 + port.size());
    result.append(encodedData, encodedLen).append(":").append(port);
  }
  return result;
}

#ifdef CACHEKEY_UNIT_TEST

void
PrintToStdErr(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
}

#else

DbgCtl CacheKey_dbg_ctl{PLUGIN_NAME};

#endif /* CACHEKEY_UNIT_TEST */
