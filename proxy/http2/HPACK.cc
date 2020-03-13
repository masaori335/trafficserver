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

namespace
{
// [RFC 7541] 4.1. Calculating Table Size
// The size of an entry is the sum of its name's length in octets (as defined in Section 5.2),
// its value's length in octets, and 32.
const static unsigned ADDITIONAL_OCTETS = 32;

const HpackHeaderField STATIC_TABLE[] = {{"", ""},
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

//
// Local functions
//
bool
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

//
// HpackStaticTable
//
namespace HpackStaticTable
{
  enum class Index : uint32_t {
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

  /**
    This is based on lookup function of nghttp2.

    ```
    static int32_t lookup_token(const uint8_t *name, size_t namelen)
    ```

    https://github.com/nghttp2/nghttp2/blob/v1.40.0/lib/nghttp2_hd.c#L120
   */
  Index
  lookup_by_name(const char *name, int name_len)
  {
    switch (name_len) {
    case 3:
      switch (name[2]) {
      case 'a':
        if (memcmp("vi", name, 2) == 0) {
          return Index::VIA;
        }
        break;
      case 'e':
        if (memcmp("ag", name, 2) == 0) {
          return Index::AGE;
        }
        break;
      }
      break;
    case 4:
      switch (name[3]) {
      case 'e':
        if (memcmp("dat", name, 3) == 0) {
          return Index::DATE;
        }
        break;
      case 'g':
        if (memcmp("eta", name, 3) == 0) {
          return Index::ETAG;
        }
        break;
      case 'k':
        if (memcmp("lin", name, 3) == 0) {
          return Index::LINK;
        }
        break;
      case 'm':
        if (memcmp("fro", name, 3) == 0) {
          return Index::FROM;
        }
        break;
      case 't':
        if (memcmp("hos", name, 3) == 0) {
          return Index::HOST;
        }
        break;
      case 'y':
        if (memcmp("var", name, 3) == 0) {
          return Index::VARY;
        }
        break;
      }
      break;
    case 5:
      switch (name[4]) {
      case 'e':
        if (memcmp("rang", name, 4) == 0) {
          return Index::RANGE;
        }
        break;
      case 'h':
        if (memcmp(":pat", name, 4) == 0) {
          return Index::PATH_ROOT;
        }
        break;
      case 'w':
        if (memcmp("allo", name, 4) == 0) {
          return Index::ALLOW;
        }
        break;
      }
      break;
    case 6:
      switch (name[5]) {
      case 'e':
        if (memcmp("cooki", name, 5) == 0) {
          return Index::COOKIE;
        }
        break;
      case 'r':
        if (memcmp("serve", name, 5) == 0) {
          return Index::SERVER;
        }
        break;
      case 't':
        if (memcmp("accep", name, 5) == 0) {
          return Index::ACCEPT;
        }
        if (memcmp("expec", name, 5) == 0) {
          return Index::EXPECT;
        }
        break;
      }
      break;
    case 7:
      switch (name[6]) {
      case 'd':
        if (memcmp(":metho", name, 6) == 0) {
          return Index::METHOD_GET;
        }
        break;
      case 'e':
        if (memcmp(":schem", name, 6) == 0) {
          return Index::SCHEME_HTTP;
        }
        break;
      case 'h':
        if (memcmp("refres", name, 6) == 0) {
          return Index::REFRESH;
        }
        break;
      case 'r':
        if (memcmp("refere", name, 6) == 0) {
          return Index::REFERER;
        }
        break;
      case 's':
        if (memcmp(":statu", name, 6) == 0) {
          return Index::STATUS_200;
        }
        if (memcmp("expire", name, 6) == 0) {
          return Index::EXPIRES;
        }
        break;
      }
      break;
    case 8:
      switch (name[7]) {
      case 'e':
        if (memcmp("if-rang", name, 7) == 0) {
          return Index::IF_RANGE;
        }
        break;
      case 'h':
        if (memcmp("if-matc", name, 7) == 0) {
          return Index::IF_MATCH;
        }
        break;
      case 'n':
        if (memcmp("locatio", name, 7) == 0) {
          return Index::LOCATION;
        }
        break;
      }
      break;
    case 10:
      switch (name[9]) {
      case 'e':
        if (memcmp("set-cooki", name, 9) == 0) {
          return Index::SET_COOKIE;
        }
        break;
      case 't':
        if (memcmp("user-agen", name, 9) == 0) {
          return Index::USER_AGENT;
        }
        break;
      case 'y':
        if (memcmp(":authorit", name, 9) == 0) {
          return Index::AUTHORITY;
        }
        break;
      }
      break;
    case 11:
      switch (name[10]) {
      case 'r':
        if (memcmp("retry-afte", name, 10) == 0) {
          return Index::RETRY_AFTER;
        }
        break;
      }
      break;
    case 12:
      switch (name[11]) {
      case 'e':
        if (memcmp("content-typ", name, 11) == 0) {
          return Index::CONTENT_TYPE;
        }
        break;
      case 's':
        if (memcmp("max-forward", name, 11) == 0) {
          return Index::MAX_FORWARDS;
        }
        break;
      }
      break;
    case 13:
      switch (name[12]) {
      case 'd':
        if (memcmp("last-modifie", name, 12) == 0) {
          return Index::LAST_MODIFIED;
        }
        break;
      case 'e':
        if (memcmp("content-rang", name, 12) == 0) {
          return Index::CONTENT_RANGE;
        }
        break;
      case 'h':
        if (memcmp("if-none-matc", name, 12) == 0) {
          return Index::IF_NONE_MATCH;
        }
        break;
      case 'l':
        if (memcmp("cache-contro", name, 12) == 0) {
          return Index::CACHE_CONTROL;
        }
        break;
      case 'n':
        if (memcmp("authorizatio", name, 12) == 0) {
          return Index::AUTHORIZATION;
        }
        break;
      case 's':
        if (memcmp("accept-range", name, 12) == 0) {
          return Index::ACCEPT_RANGES;
        }
        break;
      }
      break;
    case 14:
      switch (name[13]) {
      case 'h':
        if (memcmp("content-lengt", name, 13) == 0) {
          return Index::CONTENT_LENGTH;
        }
        break;
      case 't':
        if (memcmp("accept-charse", name, 13) == 0) {
          return Index::ACCEPT_CHARSET;
        }
        break;
      }
      break;
    case 15:
      switch (name[14]) {
      case 'e':
        if (memcmp("accept-languag", name, 14) == 0) {
          return Index::ACCEPT_LANGUAGE;
        }
        break;
      case 'g':
        if (memcmp("accept-encodin", name, 14) == 0) {
          return Index::ACCEPT_ENCODING;
        }
        break;
      }
      break;
    case 16:
      switch (name[15]) {
      case 'e':
        if (memcmp("content-languag", name, 15) == 0) {
          return Index::CONTENT_LANGUAGE;
        }
        if (memcmp("www-authenticat", name, 15) == 0) {
          return Index::WWW_AUTHENTICATE;
        }
        break;
      case 'g':
        if (memcmp("content-encodin", name, 15) == 0) {
          return Index::CONTENT_ENCODING;
        }
        break;
      case 'n':
        if (memcmp("content-locatio", name, 15) == 0) {
          return Index::CONTENT_LOCATION;
        }
        break;
      }
      break;
    case 17:
      switch (name[16]) {
      case 'e':
        if (memcmp("if-modified-sinc", name, 16) == 0) {
          return Index::IF_MODIFIED_SINCE;
        }
        break;
      case 'g':
        if (memcmp("transfer-encodin", name, 16) == 0) {
          return Index::TRANSFER_ENCODING;
        }
        break;
      }
      break;
    case 18:
      switch (name[17]) {
      case 'e':
        if (memcmp("proxy-authenticat", name, 17) == 0) {
          return Index::PROXY_AUTHENTICATE;
        }
        break;
      }
      break;
    case 19:
      switch (name[18]) {
      case 'e':
        if (memcmp("if-unmodified-sinc", name, 18) == 0) {
          return Index::IF_UNMODIFIED_SINCE;
        }
        break;
      case 'n':
        if (memcmp("content-dispositio", name, 18) == 0) {
          return Index::CONTENT_DISPOSITION;
        }
        if (memcmp("proxy-authorizatio", name, 18) == 0) {
          return Index::PROXY_AUTHORIZATION;
        }
        break;
      }
      break;
    case 25:
      switch (name[24]) {
      case 'y':
        if (memcmp("strict-transport-securit", name, 24) == 0) {
          return Index::STRICT_TRANSPORT_SECURITY;
        }
        break;
      }
      break;
    case 27:
      switch (name[26]) {
      case 'n':
        if (memcmp("access-control-allow-origi", name, 26) == 0) {
          return Index::ACCESS_CONTROL_ALLOW_ORIGIN;
        }
        break;
      }
      break;
    }

    return Index::NONE;
  }

  bool
  is_value_eq(Index index, const char *value, int value_len)
  {
    return memcmp(STATIC_TABLE[static_cast<uint32_t>(index)].value, value, value_len) == 0;
  }

  /**
     Special cases for name is not unique

     @return Index if value is exactly matched.
   */
  Index
  lookup_by_value(Index name_index, const char *value, int value_len)
  {
    switch (name_index) {
    case Index::METHOD_GET:
      switch (value_len) {
      case 3:
        if (is_value_eq(Index::METHOD_GET, value, value_len)) {
          return Index::METHOD_GET;
        }
        break;
      case 4:
        if (is_value_eq(Index::METHOD_POST, value, value_len)) {
          return Index::METHOD_POST;
        }
      }
      break;
    case Index::PATH_ROOT:
      switch (value_len) {
      case 1:
        if (is_value_eq(Index::PATH_ROOT, value, value_len)) {
          return Index::PATH_ROOT;
        }
        break;
      case 11:
        if (is_value_eq(Index::PATH_INDEX, value, value_len)) {
          return Index::PATH_INDEX;
        }
      }
      break;
    case Index::SCHEME_HTTP:
      switch (value_len) {
      case 4:
        if (is_value_eq(Index::SCHEME_HTTP, value, value_len)) {
          return Index::SCHEME_HTTP;
        }
        break;
      case 5:
        if (is_value_eq(Index::SCHEME_HTTPS, value, value_len)) {
          return Index::SCHEME_HTTPS;
        }
      }
      break;
    case Index::STATUS_200:
      switch (value_len) {
      case 3:
        switch (value[0]) {
        case '2':
          switch (value[2]) {
          case '0':
            if (is_value_eq(Index::STATUS_200, value, value_len)) {
              return Index::STATUS_200;
            }
            break;
          case '4':
            if (is_value_eq(Index::STATUS_204, value, value_len)) {
              return Index::STATUS_204;
            }
            break;
          case '6':
            if (is_value_eq(Index::STATUS_206, value, value_len)) {
              return Index::STATUS_206;
            }
            break;
          }
          break;
        case '3':
          if (is_value_eq(Index::STATUS_304, value, value_len)) {
            return Index::STATUS_304;
          }
          break;
        case '4':
          switch (value[2]) {
          case '0':
            if (is_value_eq(Index::STATUS_400, value, value_len)) {
              return Index::STATUS_200;
            }
          case '4':
            if (is_value_eq(Index::STATUS_404, value, value_len)) {
              return Index::STATUS_200;
            }
            break;
          case '5':
            if (is_value_eq(Index::STATUS_500, value, value_len)) {
              return Index::STATUS_500;
            }
            break;
          }
          break;
        }
        break;
      }
      break;
    default:
      // do nothing
      break;
    }

    return Index::NONE;
  }

  /**
    Lookup HPACK Static Table

    1. lookup static table by name
    2. if found entry "name" is not unique, lookup by value
   */
  HpackLookupResult
  lookup(const HpackHeaderField &header)
  {
    HpackLookupResult result;
    Index index = lookup_by_name(header.name, header.name_len);

    if (index == Index::NONE) {
      return result;
    }

    // Check value to see match type is EXACT or NAME
    switch (index) {
    case Index::METHOD_GET:
    case Index::PATH_ROOT:
    case Index::SCHEME_HTTP:
    case Index::STATUS_200:
      // Name is not unique
      if (Index r = lookup_by_value(index, header.value, header.value_len); r != Index::NONE) {
        return {static_cast<uint32_t>(r), HpackIndex::STATIC, HpackMatch::EXACT};
      }
      break;
    default:
      // Name is unique
      uint32_t i = static_cast<uint32_t>(index);
      if (STATIC_TABLE[i].value_len == header.value_len && is_value_eq(index, header.value, header.value_len)) {
        return {i, HpackIndex::STATIC, HpackMatch::EXACT};
      }
    }

    return {static_cast<uint32_t>(index), HpackIndex::STATIC, HpackMatch::NAME};
  }
} // namespace HpackStaticTable

const int TS_HPACK_STATIC_TABLE_ENTRY_NUM = static_cast<int>(HpackStaticTable::Index::MAX);

const char *HPACK_HDR_FIELD_COOKIE        = STATIC_TABLE[static_cast<int>(HpackStaticTable::Index::COOKIE)].name;
const int HPACK_HDR_LEN_COOKIE            = STATIC_TABLE[static_cast<int>(HpackStaticTable::Index::COOKIE)].name_len;
const char *HPACK_HDR_FIELD_AUTHORIZATION = STATIC_TABLE[static_cast<int>(HpackStaticTable::Index::AUTHORIZATION)].name;
const int HPACK_HDR_LEN_AUTHORIZATION     = STATIC_TABLE[static_cast<int>(HpackStaticTable::Index::AUTHORIZATION)].name_len;

} // namespace

//
// HpackIndexingTable
//
HpackLookupResult
HpackIndexingTable::lookup(const HpackHeaderField &header) const
{
  // static table
  HpackLookupResult result = HpackStaticTable::lookup(header);

  // if result is not EXACT match, lookup dynamic table
  if (result.match_type == HpackMatch::EXACT) {
    return result;
  }

  // dynamic table
  if (HpackLookupResult dt_result = this->_dynamic_table.lookup(header); dt_result.match_type == HpackMatch::EXACT) {
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
    field.name_set(STATIC_TABLE[index].name, STATIC_TABLE[index].name_len);
    field.value_set(STATIC_TABLE[index].value, STATIC_TABLE[index].value_len);
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
HpackIndexingTable::add_header_field(const MIMEField *field)
{
  int name_len, value_len;
  const char *name  = field->name_get(&name_len);
  const char *value = field->value_get(&value_len);

  _dynamic_table.add_header_field({name, name_len, value, value_len});
}

void
HpackIndexingTable::add_header_field(const HpackHeaderField &header)
{
  _dynamic_table.add_header_field(header);
}

uint32_t
HpackIndexingTable::maximum_size() const
{
  return _dynamic_table.maximum_size();
}

uint32_t
HpackIndexingTable::size() const
{
  return _dynamic_table.size();
}

bool
HpackIndexingTable::update_maximum_size(uint32_t new_size)
{
  return _dynamic_table.update_maximum_size(new_size);
}

//
// HpackDynamicTable
//
HpackDynamicTable::HpackDynamicTable(uint32_t size) : _maximum_size(size)
{
  _mhdr = new MIMEHdr();
  _mhdr->create();
}

HpackDynamicTable::~HpackDynamicTable()
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
HpackDynamicTable::get_header_field(uint32_t index) const
{
  return this->_headers.at(index);
}

void
HpackDynamicTable::add_header_field(const HpackHeaderField &header)
{
  uint32_t header_size = ADDITIONAL_OCTETS + header.name_len + header.value_len;

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

    MIMEField *new_field = this->_mhdr->field_create(header.name, header.name_len);
    new_field->value_set(this->_mhdr->m_heap, this->_mhdr->m_mime, header.value, header.value_len);
    this->_mhdr->field_attach(new_field);
    this->_headers.push_front(new_field);
  }
}

HpackLookupResult
HpackDynamicTable::lookup(const HpackHeaderField &header) const
{
  HpackLookupResult result;
  const unsigned int entry_num = TS_HPACK_STATIC_TABLE_ENTRY_NUM + this->length();

  for (unsigned int index = TS_HPACK_STATIC_TABLE_ENTRY_NUM; index < entry_num; ++index) {
    const MIMEField *m_field = this->_headers.at(index - TS_HPACK_STATIC_TABLE_ENTRY_NUM);

    int table_name_len      = 0;
    const char *table_name  = m_field->name_get(&table_name_len);
    int table_value_len     = 0;
    const char *table_value = m_field->value_get(&table_value_len);

    // TODO: replace `ptr_len_casecmp()` with `memcmp()`
    // Check whether name (and value) are matched
    if (ptr_len_casecmp(header.name, header.name_len, table_name, table_name_len) == 0) {
      if (header.value_len == table_value_len && memcmp(header.value, table_value, table_value_len) == 0) {
        result.index      = index;
        result.index_type = HpackIndex::DYNAMIC;
        result.match_type = HpackMatch::EXACT;
        break;
      } else if (!result.index) {
        result.index      = index;
        result.index_type = HpackIndex::DYNAMIC;
        result.match_type = HpackMatch::NAME;
      }
    }
  }

  return result;
}

uint32_t
HpackDynamicTable::maximum_size() const
{
  return _maximum_size;
}

uint32_t
HpackDynamicTable::size() const
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
HpackDynamicTable::update_maximum_size(uint32_t new_size)
{
  this->_maximum_size = new_size;
  return this->_evict_overflowed_entries();
}

uint32_t
HpackDynamicTable::length() const
{
  return this->_headers.size();
}

bool
HpackDynamicTable::_evict_overflowed_entries()
{
  if (this->_current_size <= this->_maximum_size) {
    // Do nothing
    return true;
  }

  for (auto h = this->_headers.rbegin(); h != this->_headers.rend(); ++h) {
    int name_len, value_len;
    (*h)->name_get(&name_len);
    (*h)->value_get(&value_len);

    this->_current_size -= ADDITIONAL_OCTETS + name_len + value_len;
    this->_mhdr->field_delete(*h, false);
    this->_headers.pop_back();

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
HpackDynamicTable::_mime_hdr_gc()
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

//
// Global functions
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
encode_literal_header_field_with_indexed_name(uint8_t *buf_start, const uint8_t *buf_end, uint32_t index,
                                              const HpackHeaderField &header, HpackField type)
{
  uint8_t *p = buf_start;
  int64_t len;
  uint8_t prefix = 0, flag = 0;

  ink_assert(hpack_field_is_literal(type));

  switch (type) {
  case HpackField::INDEXED_LITERAL:
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
  len = xpack_encode_string(p, buf_end, header.value, header.value_len);
  if (len == -1) {
    return -1;
  }
  p += len;

  Debug("hpack_encode", "Encoded field: %d: %.*s", index, header.value_len, header.value);
  return p - buf_start;
}

int64_t
encode_literal_header_field_with_new_name(uint8_t *buf_start, const uint8_t *buf_end, const HpackHeaderField &header,
                                          HpackField type)
{
  uint8_t *p = buf_start;
  int64_t len;
  uint8_t flag = 0;

  ink_assert(hpack_field_is_literal(type));

  switch (type) {
  case HpackField::INDEXED_LITERAL:
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

  // Name String
  len = xpack_encode_string(p, buf_end, header.name, header.name_len);
  if (len == -1) {
    return -1;
  }
  p += len;

  // Value String
  len = xpack_encode_string(p, buf_end, header.value, header.value_len);
  if (len == -1) {
    return -1;
  }

  p += len;

  Debug("hpack_encode", "Encoded field: %.*s: %.*s", header.name_len, header.name, header.value_len, header.value);
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

  ink_assert(http_hdr_type_get(hdr->m_http) != HTTP_TYPE_UNKNOWN);

  // Update dynamic table size
  if (maximum_table_size >= 0) {
    indexing_table.update_maximum_size(maximum_table_size);
    int64_t written = encode_dynamic_table_size_update(cursor, out_buf_end, maximum_table_size);
    if (written == HPACK_ERROR_COMPRESSION_ERROR) {
      return HPACK_ERROR_COMPRESSION_ERROR;
    }
    cursor += written;
  }

  // TODO: get rid of Arena
  Arena arena;
  MIMEFieldIter field_iter;
  for (MIMEField *field = hdr->iter_get_first(&field_iter); field != nullptr; field = hdr->iter_get_next(&field_iter)) {
    int name_len;
    const char *original_name = field->name_get(&name_len);

    // Convert field name to lower case to follow HTTP2 spec.
    // This conversion is needed because WKSs in MIMEFields is old fashioned
    char *name = arena.str_alloc(name_len);
    for (int i = 0; i < name_len; i++) {
      name[i] = ParseRules::ink_tolower(original_name[i]);
    }

    int value_len;
    const char *value = field->value_get(&value_len);

    HpackHeaderField header{name, name_len, value, value_len};

    // Choose field representation (See RFC7541 7.1.3)
    // - Authorization header obviously should not be indexed
    // - Short Cookie header should not be indexed because of low entropy
    HpackField field_type;
    if ((header.name_len == HPACK_HDR_LEN_COOKIE && memcmp(header.name, HPACK_HDR_FIELD_COOKIE, HPACK_HDR_LEN_COOKIE) == 0 &&
         value_len < 20) ||
        (header.name_len == HPACK_HDR_LEN_AUTHORIZATION &&
         memcmp(header.name, HPACK_HDR_FIELD_AUTHORIZATION, HPACK_HDR_LEN_AUTHORIZATION) == 0)) {
      field_type = HpackField::NEVERINDEX_LITERAL;
    } else {
      field_type = HpackField::INDEXED_LITERAL;
    }

    const HpackLookupResult result = indexing_table.lookup(header);

    if (result.match_type != HpackMatch::EXACT && field_type == HpackField::INDEXED_LITERAL) {
      indexing_table.add_header_field(header);
    }

    int64_t written = 0;
    switch (result.match_type) {
    case HpackMatch::NONE:
      written = encode_literal_header_field_with_new_name(cursor, out_buf_end, header, field_type);
      break;
    case HpackMatch::NAME:
      written = encode_literal_header_field_with_indexed_name(cursor, out_buf_end, result.index, header, field_type);
      break;
    case HpackMatch::EXACT:
      written = encode_indexed_header_field(cursor, out_buf_end, result.index);
      break;
    default:
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
