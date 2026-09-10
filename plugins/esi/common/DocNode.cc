/** @file

  A brief file description

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

#include <ts/ts.h>

#include <cstring>
#include <iterator>

#include "DocNode.h"
#include "Utils.h"

using std::string;
using namespace EsiLib;

const char *DocNode::type_names_[] = {"UNKNOWN", "PRE",       "INCLUDE", "COMMENT", "REMOVE", "VARS",         "CHOOSE",
                                      "WHEN",    "OTHERWISE", "TRY",     "ATTEMPT", "EXCEPT", "HTML_COMMENT", "SPECIAL_INCLUDE"};
static_assert(std::size(DocNode::type_names_) == DocNode::TYPE_SPECIAL_INCLUDE + 1,
              "type_names_ must have an entry for every TYPE");

// helper functions

namespace
{
// The smallest node pack() emits: version byte, node size, type, data length
// of an empty string, attribute count of zero and child count of zero.
constexpr int32_t MIN_NODE_SIZE =
  sizeof(char) + sizeof(int32_t) + sizeof(DocNode::TYPE) + sizeof(int32_t) + sizeof(int32_t) + sizeof(int32_t);

// EsiProcessor calls attr_list.front() on nodes of these types without checking
// that the list is populated, because EsiParser never emits them without their
// mandatory attribute. A packed node has to carry at least that attribute too.
// Every type is listed so that adding one forces a decision here.
int32_t
min_attribute_count(DocNode::TYPE type)
{
  switch (type) {
  case DocNode::TYPE_INCLUDE:
  case DocNode::TYPE_WHEN:
  case DocNode::TYPE_SPECIAL_INCLUDE:
    return 1;
  case DocNode::TYPE_UNKNOWN:
  case DocNode::TYPE_PRE:
  case DocNode::TYPE_COMMENT:
  case DocNode::TYPE_REMOVE:
  case DocNode::TYPE_VARS:
  case DocNode::TYPE_CHOOSE:
  case DocNode::TYPE_OTHERWISE:
  case DocNode::TYPE_TRY:
  case DocNode::TYPE_ATTEMPT:
  case DocNode::TYPE_EXCEPT:
  case DocNode::TYPE_HTML_COMMENT:
    return 0;
  }
  return 0;
}

// EsiProcessor::_handleTry dereferences the attempt and except children of a
// try node without checking that they exist, because EsiParser::_processTryTag
// only emits a try node holding exactly one of each and nothing else.
bool
has_valid_try_children(const DocNodeList &children)
{
  int n_attempt = 0;
  int n_except  = 0;

  for (const auto &child : children) {
    if (child.type == DocNode::TYPE_ATTEMPT) {
      ++n_attempt;
    } else if (child.type == DocNode::TYPE_EXCEPT) {
      ++n_except;
    } else {
      return false;
    }
  }
  return n_attempt == 1 && n_except == 1;
}
} // namespace

inline void
packString(const char *str, int32_t str_len, string &buffer)
{
  buffer.append(reinterpret_cast<const char *>(&str_len), sizeof(str_len));
  if (str_len) {
    buffer.append(str, str_len);
  }
}

inline bool
unpackString(const char *&packed_data, const char *packed_data_end, const char *&item, int32_t &item_len)
{
  if (packed_data_end - packed_data < static_cast<ptrdiff_t>(sizeof(int32_t))) {
    return false;
  }
  // packed_data is not int32_t-aligned: the length fields sit at byte offsets
  // determined by DOCNODE_VERSION and the preceding strings, so dereferencing a
  // cast pointer here is undefined behavior.
  memcpy(&item_len, packed_data, sizeof(item_len));
  packed_data += sizeof(int32_t);
  if (item_len < 0 || packed_data_end - packed_data < item_len) {
    return false;
  }
  item         = item_len ? packed_data : nullptr;
  packed_data += item_len;
  return true;
}

template <typename T>
inline bool
unpackItem(const char *&packed_data, const char *packed_data_end, T &item)
{
  if (packed_data_end - packed_data < static_cast<ptrdiff_t>(sizeof(T))) {
    return false;
  }
  // See unpackString(): packed_data carries no alignment guarantee.
  memcpy(&item, packed_data, sizeof(item));
  packed_data += sizeof(T);
  return true;
}

void
DocNode::pack(string &buffer) const
{
  int32_t orig_buf_size  = buffer.size();
  buffer                += DOCNODE_VERSION;
  buffer.append(sizeof(int32_t), ' '); // reserve space for length
  buffer.append(reinterpret_cast<const char *>(&type), sizeof(type));
  packString(data, data_len, buffer);
  int32_t n_elements = attr_list.size();
  buffer.append(reinterpret_cast<const char *>(&n_elements), sizeof(n_elements));
  for (const auto &iter : attr_list) {
    packString(iter.name, iter.name_len, buffer);
    packString(iter.value, iter.value_len, buffer);
  }
  child_nodes.packToBuffer(buffer);
  int32_t node_size = buffer.size() - orig_buf_size;
  // The length field is stored 1 byte past orig_buf_size (after DOCNODE_VERSION), so its
  // address is not int32_t-aligned; use memcpy to avoid a misaligned store (UB).
  memcpy(&buffer[orig_buf_size + 1], &node_size, sizeof(node_size));
}

bool
DocNode::unpack(const char *packed_data, int packed_data_len, int &node_len)
{
  // Callers reuse one DocNode across nodes, so a rejected node must not keep
  // the previous node's attributes or children.
  attr_list.clear();
  child_nodes.clear();

  if (!packed_data || packed_data_len < static_cast<int>(sizeof(DOCNODE_VERSION))) {
    TSError("[%s] Invalid arguments (%p, %d)", __FUNCTION__, packed_data, packed_data_len);
    return false;
  }
  const char *packed_data_start = packed_data;
  const char *packed_data_end   = packed_data + packed_data_len;

  if (*packed_data != DOCNODE_VERSION) {
    TSError("[%s] Version %d not in supported set (%d)", __FUNCTION__, static_cast<int>(*packed_data),
            static_cast<int>(DOCNODE_VERSION));
    return false;
  }
  ++packed_data;

  int32_t node_size;
  if (!unpackItem(packed_data, packed_data_end, node_size)) {
    TSError("[%s] Data size (%d) not sufficient to hold node size field", __FUNCTION__, packed_data_len);
    return false;
  }
  if (node_size < MIN_NODE_SIZE) {
    TSError("[%s] Invalid node size (%d)", __FUNCTION__, node_size);
    return false;
  }
  if (node_size > packed_data_len) {
    TSError("[%s] Data size (%d) not sufficient to hold node of size %d", __FUNCTION__, packed_data_len, node_size);
    return false;
  }

  // Bound all field reads to this node's declared extent so a corrupt length
  // cannot make a read stray past the bytes this node claims for itself.
  const char *node_end = packed_data_start + node_size;

  // TYPE is an unscoped enum with no fixed underlying type, so converting an out
  // of range integer to it is unspecified. Read the raw value and range check it
  // before assigning: type_names_ is indexed directly by type, so an out of
  // range value must never reach the processor.
  static_assert(sizeof(TYPE) == sizeof(int32_t), "pack() writes sizeof(TYPE) bytes for the type field");
  int32_t raw_type;
  if (!unpackItem(packed_data, node_end, raw_type)) {
    TSError("[%s] Could not unpack node type", __FUNCTION__);
    return false;
  }
  if (raw_type < TYPE_UNKNOWN || raw_type > TYPE_SPECIAL_INCLUDE) {
    TSError("[%s] Invalid node type (%d)", __FUNCTION__, raw_type);
    return false;
  }
  type = static_cast<TYPE>(raw_type);

  if (!unpackString(packed_data, node_end, data, data_len)) {
    TSError("[%s] Could not unpack node data", __FUNCTION__);
    return false;
  }

  int32_t n_elements;
  if (!unpackItem(packed_data, node_end, n_elements)) {
    TSError("[%s] Could not unpack attribute count", __FUNCTION__);
    return false;
  }
  if (n_elements < 0) {
    // A negative count would skip the loop and report success for a buffer that
    // is known to be malformed.
    TSError("[%s] Invalid attribute count (%d)", __FUNCTION__, n_elements);
    return false;
  }
  if (n_elements < min_attribute_count(type)) {
    TSError("[%s] Node of type %s requires %d attribute(s) but declares %d", __FUNCTION__, type_names_[type],
            min_attribute_count(type), n_elements);
    return false;
  }
  Attribute attr;
  for (int i = 0; i < n_elements; ++i) {
    if (!unpackString(packed_data, node_end, attr.name, attr.name_len) ||
        !unpackString(packed_data, node_end, attr.value, attr.value_len)) {
      TSError("[%s] Could not unpack attribute %d", __FUNCTION__, i);
      return false;
    }
    attr_list.push_back(attr);
  }

  if (!child_nodes.unpack(packed_data, node_end - packed_data)) {
    TSError("[%s] Could not unpack child nodes", __FUNCTION__);
    return false;
  }
  if (type == TYPE_TRY && !has_valid_try_children(child_nodes)) {
    TSError("[%s] try node must contain exactly one attempt and one except child", __FUNCTION__);
    return false;
  }
  node_len = node_size;
  return true;
}

void
DocNodeList::packToBuffer(string &buffer) const
{
  int32_t n_elements = size();
  buffer.append(reinterpret_cast<const char *>(&n_elements), sizeof(n_elements));
  for (const auto &iter : *this) {
    iter.pack(buffer);
  }
}

bool
DocNodeList::unpack(const char *data, int data_len)
{
  clear();
  if (!data || data_len < 0) {
    TSError("[%s] Invalid arguments (%p, %d)", __FUNCTION__, data, data_len);
    return false;
  }
  const char *data_start = data;
  const char *data_end   = data + data_len;
  int32_t     n_elements;
  if (!unpackItem(data, data_end, n_elements)) {
    TSError("[%s] Data size (%d) not sufficient to hold node count", __FUNCTION__, data_len);
    return false;
  }
  if (n_elements < 0) {
    TSError("[%s] Invalid node count (%d)", __FUNCTION__, n_elements);
    return false;
  }
  int     data_offset = data - data_start, node_size;
  DocNode node;
  for (int i = 0; i < n_elements; ++i) {
    if (!node.unpack(data_start + data_offset, data_len - data_offset, node_size)) {
      TSError("[%s] Could not unpack node", __FUNCTION__);
      return false;
    }
    data_offset += node_size;
    push_back(node);
  }
  if (data_offset != data_len) {
    // pack() writes nothing after the last node, so leftover bytes mean the
    // count or a node size does not describe this buffer.
    TSError("[%s] %d byte(s) left after the last node", __FUNCTION__, data_len - data_offset);
    return false;
  }
  return true;
}
