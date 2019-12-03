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

#pragma once

#include "tscore/ink_platform.h"
#include "tscore/Diags.h"
#include "HTTP.h"
#include "../hdrs/XPACK.h"

#include <deque>
#include <unordered_map>

// It means that any header field can be compressed/decompressed by ATS
const static int HPACK_ERROR_COMPRESSION_ERROR   = -1;
const static int HPACK_ERROR_SIZE_EXCEEDED_ERROR = -2;

enum class HpackField {
  INDEX,              // [RFC 7541] 6.1. Indexed Header Field Representation
  INDEXED_LITERAL,    // [RFC 7541] 6.2.1. Literal Header Field with Incremental Indexing
  NOINDEX_LITERAL,    // [RFC 7541] 6.2.2. Literal Header Field without Indexing
  NEVERINDEX_LITERAL, // [RFC 7541] 6.2.3. Literal Header Field never Indexed
  TABLESIZE_UPDATE,   // [RFC 7541] 6.3. Dynamic Table Size Update
};

enum class HpackIndex {
  NONE,
  STATIC,
  DYNAMIC,
};

enum class HpackMatch {
  NONE,
  NAME,
  EXACT,
};

enum class HpackStaticTableIndex : uint32_t {
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

// Result of looking for a header field in IndexingTable
struct HpackLookupResult {
  HpackLookupResult() {}
  HpackLookupResult(uint32_t i, HpackIndex it, HpackMatch mt) : index(i), index_type(it), match_type(mt) {}

  uint32_t index        = 0;
  HpackIndex index_type = HpackIndex::NONE;
  HpackMatch match_type = HpackMatch::NONE;
};

class MIMEFieldWrapper
{
public:
  MIMEFieldWrapper(MIMEField *f, HdrHeap *hh, MIMEHdrImpl *impl) : _field(f), _heap(hh), _mh(impl) {}
  void
  name_set(const char *name, int name_len)
  {
    _field->name_set(_heap, _mh, name, name_len);
  }

  void
  value_set(const char *value, int value_len)
  {
    _field->value_set(_heap, _mh, value, value_len);
  }

  const char *
  name_get(int *length) const
  {
    return _field->name_get(length);
  }

  const char *
  value_get(int *length) const
  {
    return _field->value_get(length);
  }

  const MIMEField *
  field_get() const
  {
    return _field;
  }

private:
  MIMEField *_field;
  HdrHeap *_heap;
  MIMEHdrImpl *_mh;
};

// [RFC 7541] 2.3. Indexing Table
class HpackIndexingTable
{
public:
  enum class Context {
    NONE,
    DECODING,
    ENCODING,
  };

  // [RFC 7541] 2.3.2. Dynamic Table
  class HpackDynamicTable
  {
  public:
    explicit HpackDynamicTable(uint32_t size, Context c);
    ~HpackDynamicTable();

    // noncopyable
    HpackDynamicTable(HpackDynamicTable &) = delete;
    HpackDynamicTable &operator=(const HpackDynamicTable &) = delete;

    const MIMEField *get_header_field(uint32_t index) const;
    void add_header_field(const MIMEField *field);
    HpackLookupResult lookup(const char *name, int name_len, const char *value, int value_len) const;

    uint32_t maximum_size() const;
    uint32_t size() const;
    bool update_maximum_size(uint32_t new_size);
    uint32_t length() const;

  private:
    bool _evict_overflowed_entries();
    void _mime_hdr_gc();
    uint32_t _index(uint32_t index) const;

    uint32_t _current_size = 0;
    uint32_t _maximum_size = 0;
    Context _context       = Context::NONE;

    MIMEHdr *_mhdr = nullptr;
    MIMEHdr _mhdr_buf[2]; /// MIMHdr ring buffer
    int _mhdr_index = 0;

    std::deque<MIMEField *> _headers;

    std::unordered_multimap<std::string_view, std::pair<std::string_view, uint32_t>> _lookup_table;
    uint32_t _abs_index = 0;
    uint32_t _offset    = 0;
  };

  explicit HpackIndexingTable(uint32_t size, Context c)
  {
    // TODO: Make DynamicTable a member of Hpack
    _dynamic_table = new HpackDynamicTable(size, c);
  }
  ~HpackIndexingTable() { delete _dynamic_table; }

  // noncopyable
  HpackIndexingTable(HpackIndexingTable &) = delete;
  HpackIndexingTable &operator=(const HpackIndexingTable &) = delete;

  HpackLookupResult lookup(const MIMEFieldWrapper &field) const;
  HpackLookupResult lookup(const char *name, int name_len, const char *value, int value_len) const;
  int get_header_field(uint32_t index, MIMEFieldWrapper &header_field) const;

  void add_header_field(const MIMEField *field);
  uint32_t maximum_size() const;
  uint32_t size() const;
  bool update_maximum_size(uint32_t new_size);

private:
  HpackLookupResult _lookup_static_table(const char *name, int name_len, const char *value, int value_len) const;
  HpackStaticTableIndex _lookup_name(const char *name, int name_len) const;
  HpackStaticTableIndex _lookup_value(HpackStaticTableIndex begin, HpackStaticTableIndex end, const char *value,
                                      int value_len) const;

  HpackDynamicTable *_dynamic_table;
};

// Low level interfaces
int64_t encode_indexed_header_field(uint8_t *buf_start, const uint8_t *buf_end, uint32_t index);
int64_t encode_literal_header_field_with_indexed_name(uint8_t *buf_start, const uint8_t *buf_end, const MIMEFieldWrapper &header,
                                                      uint32_t index, HpackIndexingTable &indexing_table, HpackField type);
int64_t encode_literal_header_field_with_new_name(uint8_t *buf_start, const uint8_t *buf_end, const MIMEFieldWrapper &header,
                                                  HpackIndexingTable &indexing_table, HpackField type);
int64_t decode_indexed_header_field(MIMEFieldWrapper &header, const uint8_t *buf_start, const uint8_t *buf_end,
                                    HpackIndexingTable &indexing_table);
int64_t decode_literal_header_field(MIMEFieldWrapper &header, const uint8_t *buf_start, const uint8_t *buf_end,
                                    HpackIndexingTable &indexing_table);
int64_t update_dynamic_table_size(const uint8_t *buf_start, const uint8_t *buf_end, HpackIndexingTable &indexing_table,
                                  uint32_t maximum_table_size);

// High level interfaces
typedef HpackIndexingTable HpackHandle;
int64_t hpack_decode_header_block(HpackHandle &handle, HTTPHdr *hdr, const uint8_t *in_buf, const size_t in_buf_len,
                                  uint32_t max_header_size, uint32_t maximum_table_size);
int64_t hpack_encode_header_block(HpackHandle &handle, uint8_t *out_buf, const size_t out_buf_len, HTTPHdr *hdr,
                                  int32_t maximum_table_size = -1);
int32_t hpack_get_maximum_table_size(HpackHandle &handle);
