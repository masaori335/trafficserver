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

static constexpr uint32_t TS_HPACK_STATIC_TABLE_ENTRY_NUM = static_cast<uint32_t>(HpackStaticTableIndex::MAX);

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
HpackField
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

/************************
 * HpackIndexingTable
 ************************/
HpackLookupResult
HpackIndexingTable::lookup(const MIMEFieldWrapper &field) const
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
HpackIndexingTable::lookup(const char *name, int name_len, const char *value, int value_len) const
{
  // static table
  HpackLookupResult result = this->_lookup_static_table(name, name_len, value, value_len);

  // if match type is NAME, lookup dynamic table for exact match
  if (result.match_type == HpackMatch::EXACT) {
    return result;
  }

  // dynamic table
  if (HpackLookupResult dt_result = this->_dynamic_table->lookup(name, name_len, value, value_len);
      dt_result.match_type == HpackMatch::EXACT) {
    // Convert index from dynamic table space to indexing table space
    dt_result.index += TS_HPACK_STATIC_TABLE_ENTRY_NUM;

    return dt_result;
  }

  return result;
}

int
HpackIndexingTable::get_header_field(uint32_t index, MIMEFieldWrapper &field) const
{
  // Index Address Space starts at 1, so index == 0 is invalid.
  if (!index) {
    return HPACK_ERROR_COMPRESSION_ERROR;
  }

  if (index < TS_HPACK_STATIC_TABLE_ENTRY_NUM) {
    // static table
    field.name_set(STATIC_TABLE[index].name, STATIC_TABLE[index].name_size);
    field.value_set(STATIC_TABLE[index].value, STATIC_TABLE[index].value_size);
  } else if (index < TS_HPACK_STATIC_TABLE_ENTRY_NUM + _dynamic_table->length()) {
    // dynamic table
    const MIMEField *m_field = _dynamic_table->get_header_field(index - TS_HPACK_STATIC_TABLE_ENTRY_NUM);

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
HpackIndexingTable::add_header_field(const MIMEField *field)
{
  _dynamic_table->add_header_field(field);
}

uint32_t
HpackIndexingTable::maximum_size() const
{
  return _dynamic_table->maximum_size();
}

uint32_t
HpackIndexingTable::size() const
{
  return _dynamic_table->size();
}

bool
HpackIndexingTable::update_maximum_size(uint32_t new_size)
{
  return _dynamic_table->update_maximum_size(new_size);
}

HpackLookupResult
HpackIndexingTable::_lookup_static_table(const char *name, int name_len, const char *value, int value_len) const
{
  HpackStaticTableIndex index = this->_lookup_name(name, name_len);
  if (index == HpackStaticTableIndex::NONE) {
    return {0, HpackIndex::NONE, HpackMatch::NONE};
  }

  HpackLookupResult result;

  switch (index) {
  case HpackStaticTableIndex::METHOD_GET:
    if (HpackStaticTableIndex r = this->_lookup_value(index, HpackStaticTableIndex::METHOD_POST, value, value_len);
        r != HpackStaticTableIndex::NONE) {
      return {static_cast<uint32_t>(r), HpackIndex::STATIC, HpackMatch::EXACT};
    }
    break;
  case HpackStaticTableIndex::PATH_ROOT:
    if (HpackStaticTableIndex r = this->_lookup_value(index, HpackStaticTableIndex::PATH_INDEX, value, value_len);
        r != HpackStaticTableIndex::NONE) {
      return {static_cast<uint32_t>(r), HpackIndex::STATIC, HpackMatch::EXACT};
    }
    break;
  case HpackStaticTableIndex::SCHEME_HTTP:
    if (HpackStaticTableIndex r = this->_lookup_value(index, HpackStaticTableIndex::SCHEME_HTTPS, value, value_len);
        r != HpackStaticTableIndex::NONE) {
      return {static_cast<uint32_t>(r), HpackIndex::STATIC, HpackMatch::EXACT};
    }
    break;
  case HpackStaticTableIndex::STATUS_200:
    if (HpackStaticTableIndex r = this->_lookup_value(index, HpackStaticTableIndex::STATUS_500, value, value_len);
        r != HpackStaticTableIndex::NONE) {
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
HpackStaticTableIndex
HpackIndexingTable::_lookup_name(const char *name, int name_len) const
{
  switch (name_len) {
  case 3:
    switch (name[2]) {
    case 'a':
      if (strncasecmp("vi", name, 2) == 0) {
        return HpackStaticTableIndex::VIA;
      }
      break;
    case 'e':
      if (strncasecmp("ag", name, 2) == 0) {
        return HpackStaticTableIndex::AGE;
      }
      break;
    }
    break;
  case 4:
    switch (name[3]) {
    case 'e':
      if (strncasecmp("dat", name, 3) == 0) {
        return HpackStaticTableIndex::DATE;
      }
      break;
    case 'g':
      if (strncasecmp("eta", name, 3) == 0) {
        return HpackStaticTableIndex::ETAG;
      }
      break;
    case 'k':
      if (strncasecmp("lin", name, 3) == 0) {
        return HpackStaticTableIndex::LINK;
      }
      break;
    case 'm':
      if (strncasecmp("fro", name, 3) == 0) {
        return HpackStaticTableIndex::FROM;
      }
      break;
    case 't':
      if (strncasecmp("hos", name, 3) == 0) {
        return HpackStaticTableIndex::HOST;
      }
      break;
    case 'y':
      if (strncasecmp("var", name, 3) == 0) {
        return HpackStaticTableIndex::VARY;
      }
      break;
    }
    break;
  case 5:
    switch (name[4]) {
    case 'e':
      if (strncasecmp("rang", name, 4) == 0) {
        return HpackStaticTableIndex::RANGE;
      }
      break;
    case 'h':
      if (strncasecmp(":pat", name, 4) == 0) {
        return HpackStaticTableIndex::PATH_ROOT;
      }
      break;
    case 'w':
      if (strncasecmp("allo", name, 4) == 0) {
        return HpackStaticTableIndex::ALLOW;
      }
      break;
    }
    break;
  case 6:
    switch (name[5]) {
    case 'e':
      if (strncasecmp("cooki", name, 5) == 0) {
        return HpackStaticTableIndex::COOKIE;
      }
      break;
    case 'r':
      if (strncasecmp("serve", name, 5) == 0) {
        return HpackStaticTableIndex::SERVER;
      }
      break;
    case 't':
      if (strncasecmp("accep", name, 5) == 0) {
        return HpackStaticTableIndex::ACCEPT;
      }
      if (strncasecmp("expec", name, 5) == 0) {
        return HpackStaticTableIndex::EXPECT;
      }
      break;
    }
    break;
  case 7:
    switch (name[6]) {
    case 'd':
      if (strncasecmp(":metho", name, 6) == 0) {
        return HpackStaticTableIndex::METHOD_GET;
      }
      break;
    case 'e':
      if (strncasecmp(":schem", name, 6) == 0) {
        return HpackStaticTableIndex::SCHEME_HTTP;
      }
      break;
    case 'h':
      if (strncasecmp("refres", name, 6) == 0) {
        return HpackStaticTableIndex::REFRESH;
      }
      break;
    case 'r':
      if (strncasecmp("refere", name, 6) == 0) {
        return HpackStaticTableIndex::REFERER;
      }
      break;
    case 's':
      if (strncasecmp(":statu", name, 6) == 0) {
        // TODO: check value
        return HpackStaticTableIndex::STATUS_200;
      }
      if (strncasecmp("expire", name, 6) == 0) {
        return HpackStaticTableIndex::EXPIRES;
      }
      break;
    }
    break;
  case 8:
    switch (name[7]) {
    case 'e':
      if (strncasecmp("if-rang", name, 7) == 0) {
        return HpackStaticTableIndex::IF_RANGE;
      }
      break;
    case 'h':
      if (strncasecmp("if-matc", name, 7) == 0) {
        return HpackStaticTableIndex::IF_MATCH;
      }
      break;
    case 'n':
      if (strncasecmp("locatio", name, 7) == 0) {
        return HpackStaticTableIndex::LOCATION;
      }
      break;
    }
    break;
  case 10:
    switch (name[9]) {
    case 'e':
      if (strncasecmp("set-cooki", name, 9) == 0) {
        return HpackStaticTableIndex::SET_COOKIE;
      }
      break;
    case 't':
      if (strncasecmp("user-agen", name, 9) == 0) {
        return HpackStaticTableIndex::USER_AGENT;
      }
      break;
    case 'y':
      if (strncasecmp(":authorit", name, 9) == 0) {
        return HpackStaticTableIndex::AUTHORITY;
      }
      break;
    }
    break;
  case 11:
    switch (name[10]) {
    case 'r':
      if (strncasecmp("retry-afte", name, 10) == 0) {
        return HpackStaticTableIndex::RETRY_AFTER;
      }
      break;
    }
    break;
  case 12:
    switch (name[11]) {
    case 'e':
      if (strncasecmp("content-typ", name, 11) == 0) {
        return HpackStaticTableIndex::CONTENT_TYPE;
      }
      break;
    case 's':
      if (strncasecmp("max-forward", name, 11) == 0) {
        return HpackStaticTableIndex::MAX_FORWARDS;
      }
      break;
    }
    break;
  case 13:
    switch (name[12]) {
    case 'd':
      if (strncasecmp("last-modifie", name, 12) == 0) {
        return HpackStaticTableIndex::LAST_MODIFIED;
      }
      break;
    case 'e':
      if (strncasecmp("content-rang", name, 12) == 0) {
        return HpackStaticTableIndex::CONTENT_RANGE;
      }
      break;
    case 'h':
      if (strncasecmp("if-none-matc", name, 12) == 0) {
        return HpackStaticTableIndex::IF_NONE_MATCH;
      }
      break;
    case 'l':
      if (strncasecmp("cache-contro", name, 12) == 0) {
        return HpackStaticTableIndex::CACHE_CONTROL;
      }
      break;
    case 'n':
      if (strncasecmp("authorizatio", name, 12) == 0) {
        return HpackStaticTableIndex::AUTHORIZATION;
      }
      break;
    case 's':
      if (strncasecmp("accept-range", name, 12) == 0) {
        return HpackStaticTableIndex::ACCEPT_RANGES;
      }
      break;
    }
    break;
  case 14:
    switch (name[13]) {
    case 'h':
      if (strncasecmp("content-lengt", name, 13) == 0) {
        return HpackStaticTableIndex::CONTENT_LENGTH;
      }
      break;
    case 't':
      if (strncasecmp("accept-charse", name, 13) == 0) {
        return HpackStaticTableIndex::ACCEPT_CHARSET;
      }
      break;
    }
    break;
  case 15:
    switch (name[14]) {
    case 'e':
      if (strncasecmp("accept-languag", name, 14) == 0) {
        return HpackStaticTableIndex::ACCEPT_LANGUAGE;
      }
      break;
    case 'g':
      if (strncasecmp("accept-encodin", name, 14) == 0) {
        return HpackStaticTableIndex::ACCEPT_ENCODING;
      }
      break;
    }
    break;
  case 16:
    switch (name[15]) {
    case 'e':
      if (strncasecmp("content-languag", name, 15) == 0) {
        return HpackStaticTableIndex::CONTENT_LANGUAGE;
      }
      if (strncasecmp("www-authenticat", name, 15) == 0) {
        return HpackStaticTableIndex::WWW_AUTHENTICATE;
      }
      break;
    case 'g':
      if (strncasecmp("content-encodin", name, 15) == 0) {
        return HpackStaticTableIndex::CONTENT_ENCODING;
      }
      break;
    case 'n':
      if (strncasecmp("content-locatio", name, 15) == 0) {
        return HpackStaticTableIndex::CONTENT_LOCATION;
      }
      break;
    }
    break;
  case 17:
    switch (name[16]) {
    case 'e':
      if (strncasecmp("if-modified-sinc", name, 16) == 0) {
        return HpackStaticTableIndex::IF_MODIFIED_SINCE;
      }
      break;
    case 'g':
      if (strncasecmp("transfer-encodin", name, 16) == 0) {
        return HpackStaticTableIndex::TRANSFER_ENCODING;
      }
      break;
    }
    break;
  case 18:
    switch (name[17]) {
    case 'e':
      if (strncasecmp("proxy-authenticat", name, 17) == 0) {
        return HpackStaticTableIndex::PROXY_AUTHENTICATE;
      }
      break;
    }
    break;
  case 19:
    switch (name[18]) {
    case 'e':
      if (strncasecmp("if-unmodified-sinc", name, 18) == 0) {
        return HpackStaticTableIndex::IF_UNMODIFIED_SINCE;
      }
      break;
    case 'n':
      if (strncasecmp("content-dispositio", name, 18) == 0) {
        return HpackStaticTableIndex::CONTENT_DISPOSITION;
      }
      if (strncasecmp("proxy-authorizatio", name, 18) == 0) {
        return HpackStaticTableIndex::PROXY_AUTHORIZATION;
      }
      break;
    }
    break;
  case 25:
    switch (name[24]) {
    case 'y':
      if (strncasecmp("strict-transport-securit", name, 24) == 0) {
        return HpackStaticTableIndex::STRICT_TRANSPORT_SECURITY;
      }
      break;
    }
    break;
  case 27:
    switch (name[26]) {
    case 'n':
      if (strncasecmp("access-control-allow-origi", name, 26) == 0) {
        return HpackStaticTableIndex::ACCESS_CONTROL_ALLOW_ORIGIN;
      }
      break;
    }
    break;
  }

  return HpackStaticTableIndex::NONE;
}

/**
   Lookup given rage (from @begin to @end) of static table by value
 */
HpackStaticTableIndex
HpackIndexingTable::_lookup_value(HpackStaticTableIndex begin, HpackStaticTableIndex end, const char *value, int value_len) const
{
  for (uint32_t i = static_cast<uint32_t>(begin); i <= static_cast<uint32_t>(end); ++i) {
    if (STATIC_TABLE[i].value_size == value_len && strncasecmp(STATIC_TABLE[i].value, value, value_len) == 0) {
      return static_cast<HpackStaticTableIndex>(i);
    }
  }

  return HpackStaticTableIndex::NONE;
}

//
// HpackDynamicTable
//
HpackIndexingTable::HpackDynamicTable::HpackDynamicTable(uint32_t size, Context c) : _maximum_size(size), _context(c)
{
  this->_mhdr = new (&this->_mhdr_buf[0]) MIMEHdr;
  this->_mhdr->create();

  this->_lookup_table.reserve(1000);
}

HpackIndexingTable::HpackDynamicTable::~HpackDynamicTable()
{
  this->_headers.clear();

  for (int i = 0; i < 2; ++i) {
    if (this->_mhdr_buf[i].m_heap) {
      this->_mhdr_buf[i].fields_clear();
      this->_mhdr_buf[i].destroy();
    }
  }
}

const MIMEField *
HpackIndexingTable::HpackDynamicTable::get_header_field(uint32_t index) const
{
  return this->_headers.at(index);
}

void
HpackIndexingTable::HpackDynamicTable::add_header_field(const MIMEField *field)
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
    if (this->_context == HpackIndexingTable::Context::ENCODING) {
      uint32_t index = this->_abs_index++;

      // Get pointers of pushed header field
      std::string_view new_name  = new_field->name_get();
      std::string_view new_value = new_field->value_get();

      Debug("hpack_encode", "name=%.*s value=%.*s index=%" PRId32, static_cast<int>(new_name.size()), new_name.data(),
            static_cast<int>(new_value.size()), new_value.data(), index);

      this->_lookup_table.insert(std::make_pair(new_name, std::make_pair(new_value, index)));
    }
  }
}

HpackLookupResult
HpackIndexingTable::HpackDynamicTable::lookup(const char *name, int name_len, const char *value, int value_len) const
{
  ink_assert(this->_context == HpackIndexingTable::Context::ENCODING);

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
HpackIndexingTable::HpackDynamicTable::maximum_size() const
{
  return _maximum_size;
}

uint32_t
HpackIndexingTable::HpackDynamicTable::size() const
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
HpackIndexingTable::HpackDynamicTable::update_maximum_size(uint32_t new_size)
{
  this->_maximum_size = new_size;
  return this->_evict_overflowed_entries();
}

uint32_t
HpackIndexingTable::HpackDynamicTable::length() const
{
  return this->_headers.size();
}

bool
HpackIndexingTable::HpackDynamicTable::_evict_overflowed_entries()
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
    this->_offset++;

    if (this->_context == HpackIndexingTable::Context::ENCODING) {
      auto range = this->_lookup_table.equal_range(name);
      for (auto it = range.first; it != range.second; ++it) {
        if (it->second.first.compare(value) == 0) {
          this->_lookup_table.erase(it);
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
HpackIndexingTable::HpackDynamicTable::_mime_hdr_gc()
{
  if (this->_mhdr->m_heap->total_used_size() >= HPACK_HDR_HEAP_THRESHOLD) {
    this->_mhdr = new (&this->_mhdr_buf[++this->_mhdr_index & 1]) MIMEHdr;
    this->_mhdr->create();
  } else {
    if (this->_mhdr_index > 1) {
      int i = (this->_mhdr_index - 1) & 1;
      if (this->_mhdr_buf[i].m_heap && this->_mhdr_buf[i].fields_count() == 0) {
        this->_mhdr_buf[i].fields_clear();
        this->_mhdr_buf[i].destroy();
      }
    }
  }
}

/**
   Calculate dynamic table index from absolute @index & offset
 */
uint32_t
HpackIndexingTable::HpackDynamicTable::_index(uint32_t index) const
{
  ink_assert(this->_offset + this->length() >= index + 1);

  return this->_offset + this->length() - index - 1;
}

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
                                              uint32_t index, HpackIndexingTable &indexing_table, HpackField type)
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
                                          HpackIndexingTable &indexing_table, HpackField type)
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
  int name_len;
  const char *name = header.name_get(&name_len);
  char lower_name[name_len];
  for (int i = 0; i < name_len; i++) {
    lower_name[i] = ParseRules::ink_tolower(name[i]);
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
decode_indexed_header_field(MIMEFieldWrapper &header, const uint8_t *buf_start, const uint8_t *buf_end,
                            HpackIndexingTable &indexing_table)
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
decode_literal_header_field(MIMEFieldWrapper &header, const uint8_t *buf_start, const uint8_t *buf_end,
                            HpackIndexingTable &indexing_table)
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
update_dynamic_table_size(const uint8_t *buf_start, const uint8_t *buf_end, HpackIndexingTable &indexing_table,
                          uint32_t maximum_table_size)
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

int64_t
hpack_decode_header_block(HpackIndexingTable &indexing_table, HTTPHdr *hdr, const uint8_t *in_buf, const size_t in_buf_len,
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
hpack_encode_header_block(HpackIndexingTable &indexing_table, uint8_t *out_buf, const size_t out_buf_len, HTTPHdr *hdr,
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
hpack_get_maximum_table_size(HpackIndexingTable &indexing_table)
{
  return indexing_table.maximum_size();
}
