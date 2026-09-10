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

#include <cstring>
#include <initializer_list>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "EsiParser.h"
#include "Utils.h"

using std::string;
using namespace EsiLib;

void
check_node_attr(const Attribute &attr, const char *name, const char *value)
{
  int name_len  = strlen(name);
  int value_len = strlen(value);
  REQUIRE(attr.name_len == name_len);
  REQUIRE(attr.value_len == value_len);
  REQUIRE(strncmp(attr.name, name, name_len) == 0);
  REQUIRE(strncmp(attr.value, value, value_len) == 0);
}

void
checkNodeList1(const DocNodeList &node_list)
{
  DocNodeList::const_iterator list_iter = node_list.begin();
  REQUIRE(list_iter->type == DocNode::TYPE_PRE);
  REQUIRE(list_iter->data_len == 4);
  REQUIRE(strncmp(list_iter->data, "foo ", list_iter->data_len) == 0);
  ++list_iter;
  REQUIRE(list_iter->type == DocNode::TYPE_INCLUDE);
  REQUIRE(list_iter->data_len == 0);
  REQUIRE(list_iter->attr_list.size() == 1);
  check_node_attr(list_iter->attr_list.front(), "src", "blah");
  ++list_iter;
  REQUIRE(list_iter->type == DocNode::TYPE_PRE);
  REQUIRE(list_iter->data_len == 4);
  REQUIRE(strncmp(list_iter->data, " bar", list_iter->data_len) == 0);
  REQUIRE((list_iter->child_nodes).size() == 0);
}

void
checkNodeList2(const DocNodeList &node_list)
{
  REQUIRE(node_list.size() == 1);
  DocNodeList::const_iterator list_iter = node_list.begin(), list_iter2, list_iter3;
  REQUIRE(list_iter->type == DocNode::TYPE_CHOOSE);

  list_iter2 = list_iter->child_nodes.begin();
  REQUIRE(list_iter2->type == DocNode::TYPE_WHEN);
  REQUIRE(list_iter2->attr_list.size() == 1);
  check_node_attr(list_iter2->attr_list.front(), "test", "c1");
  list_iter2 = list_iter2->child_nodes.begin();
  REQUIRE(list_iter2->type == DocNode::TYPE_TRY);
  list_iter2 = list_iter2->child_nodes.begin();
  REQUIRE(list_iter2->type == DocNode::TYPE_ATTEMPT);
  REQUIRE(list_iter2->child_nodes.size() == 2);
  list_iter3 = list_iter2->child_nodes.begin();
  REQUIRE(list_iter3->type == DocNode::TYPE_INCLUDE);
  REQUIRE(list_iter3->data_len == 0);
  REQUIRE(list_iter3->attr_list.size() == 1);
  check_node_attr(list_iter3->attr_list.front(), "src", "foo1");
  ++list_iter3;
  REQUIRE(list_iter3->type == DocNode::TYPE_PRE);
  REQUIRE(list_iter3->data_len == static_cast<int>(strlen("raw1")));
  REQUIRE(strncmp(list_iter3->data, "raw1", list_iter3->data_len) == 0);
  ++list_iter2;
  REQUIRE(list_iter2->type == DocNode::TYPE_EXCEPT);
  list_iter3 = list_iter2->child_nodes.begin();
  REQUIRE(list_iter3->type == DocNode::TYPE_INCLUDE);
  REQUIRE(list_iter3->data_len == 0);
  REQUIRE(list_iter3->attr_list.size() == 1);
  check_node_attr(list_iter3->attr_list.front(), "src", "bar1");

  list_iter2 = list_iter->child_nodes.begin();
  ++list_iter2;
  REQUIRE(list_iter2->type == DocNode::TYPE_WHEN);
  REQUIRE(list_iter2->attr_list.size() == 1);
  check_node_attr(list_iter2->attr_list.front(), "test", "c2");
  list_iter2 = list_iter2->child_nodes.begin();
  REQUIRE(list_iter2->type == DocNode::TYPE_TRY);
  list_iter2 = list_iter2->child_nodes.begin();
  REQUIRE(list_iter2->type == DocNode::TYPE_ATTEMPT);
  list_iter3 = list_iter2->child_nodes.begin();
  REQUIRE(list_iter3->type == DocNode::TYPE_INCLUDE);
  REQUIRE(list_iter3->data_len == 0);
  REQUIRE(list_iter3->attr_list.size() == 1);
  check_node_attr(list_iter3->attr_list.front(), "src", "foo2");
  ++list_iter2;
  REQUIRE(list_iter2->type == DocNode::TYPE_EXCEPT);
  REQUIRE(list_iter2->child_nodes.size() == 2);
  list_iter3 = list_iter2->child_nodes.begin();
  REQUIRE(list_iter3->type == DocNode::TYPE_PRE);
  REQUIRE(list_iter3->data_len == static_cast<int>(strlen("raw2")));
  REQUIRE(strncmp(list_iter3->data, "raw2", list_iter3->data_len) == 0);
  ++list_iter3;
  REQUIRE(list_iter3->type == DocNode::TYPE_INCLUDE);
  REQUIRE(list_iter3->data_len == 0);
  REQUIRE(list_iter3->attr_list.size() == 1);
  check_node_attr(list_iter3->attr_list.front(), "src", "bar2");

  list_iter2 = list_iter->child_nodes.begin();
  ++list_iter2;
  ++list_iter2;
  REQUIRE(list_iter2->type == DocNode::TYPE_OTHERWISE);
  REQUIRE(list_iter2->attr_list.size() == 0);
  list_iter2 = list_iter2->child_nodes.begin();
  REQUIRE(list_iter2->type == DocNode::TYPE_TRY);
  list_iter2 = list_iter2->child_nodes.begin();
  REQUIRE(list_iter2->type == DocNode::TYPE_ATTEMPT);
  list_iter3 = list_iter2->child_nodes.begin();
  REQUIRE(list_iter3->type == DocNode::TYPE_INCLUDE);
  REQUIRE(list_iter3->data_len == 0);
  REQUIRE(list_iter3->attr_list.size() == 1);
  check_node_attr(list_iter3->attr_list.front(), "src", "foo3");
  ++list_iter2;
  REQUIRE(list_iter2->type == DocNode::TYPE_EXCEPT);
  list_iter3 = list_iter2->child_nodes.begin();
  REQUIRE(list_iter3->type == DocNode::TYPE_INCLUDE);
  REQUIRE(list_iter3->data_len == 0);
  REQUIRE(list_iter3->attr_list.size() == 1);
  check_node_attr(list_iter3->attr_list.front(), "src", "bar3");
}

TEST_CASE("esi docnode test")
{
  SECTION("Test 1")
  {
    EsiParser parser{1024 * 1024};
    string    input_data = "foo <esi:include src=blah /> bar";

    DocNodeList node_list;
    REQUIRE(parser.completeParse(node_list, input_data) == true);
    checkNodeList1(node_list);
    REQUIRE(node_list.size() == 3);
    string packed = node_list.pack();
    node_list.clear();

    DocNodeList node_list2;
    REQUIRE(node_list2.unpack(packed) == true);
    REQUIRE(node_list2.size() == 3);
    checkNodeList1(node_list2);

    DocNodeList node_list3;
    CHECK(node_list3.unpack(nullptr, 90) == false);
    CHECK(node_list3.unpack(packed.data(), 3) == false);
    // A negative node count is malformed input. It used to be accepted as an
    // empty list, which reported success for a buffer that could not be parsed.
    int32_t node_count = -1;
    memcpy(&packed[0], &node_count, sizeof(node_count));
    CHECK(node_list3.unpack(packed) == false);
    node_count = 3;
    memcpy(&packed[0], &node_count, sizeof(node_count));

    DocNodeList node_list4;
    REQUIRE(node_list4.unpack(packed) == true);
    REQUIRE(node_list4.size() == 3);
    checkNodeList1(node_list4);
  }

  SECTION("Test 2")
  {
    EsiParser parser{1024 * 1024};
    string    input_data("<esi:choose>"
                            "<esi:when test=c1>"
                            "<esi:try>"
                            "<esi:attempt>"
                            "<esi:include src=foo1 />"
                            "raw1"
                            "</esi:attempt>"
                            "<esi:except>"
                            "<esi:include src=bar1 />"
                            "</esi:except>"
                            "</esi:try>"
                            "</esi:when>"
                            "<esi:when test=c2>"
                            "<esi:try>"
                            "<esi:attempt>"
                            "<esi:include src=foo2 />"
                            "</esi:attempt>"
                            "<esi:except>"
                            "raw2"
                            "<esi:include src=bar2 />"
                            "</esi:except>"
                            "</esi:try>"
                            "</esi:when>"
                            "<esi:otherwise>"
                            "<esi:try>"
                            "<esi:attempt>"
                            "<esi:include src=foo3 />"
                            "</esi:attempt>"
                            "<esi:except>"
                            "<esi:include src=bar3 />"
                            "</esi:except>"
                            "</esi:try>"
                            "</esi:otherwise>"
                            "</esi:choose>");

    DocNodeList node_list;
    REQUIRE(parser.completeParse(node_list, input_data) == true);
    checkNodeList2(node_list);

    string      packed = node_list.pack();
    DocNodeList node_list2;
    REQUIRE(node_list2.unpack(packed) == true);
    checkNodeList2(node_list2);

    string packed2;
    node_list.pack(packed2);
    REQUIRE(packed == packed2);
    node_list2.clear();
    REQUIRE(node_list2.unpack(packed2) == true);
    checkNodeList2(node_list2);

    string packed3("hello");
    node_list.pack(packed3, true);
    REQUIRE(packed3.size() == (packed.size() + 5));
    node_list2.clear();
    REQUIRE(node_list2.unpack(packed3) == false);
    REQUIRE(node_list2.unpack(packed3.data() + 5, packed3.size() - 5) == true);
    checkNodeList2(node_list2);
  }
}

TEST_CASE("esi docnode malformed unpack")
{
  EsiParser   parser{1024 * 1024};
  string      input_data = "foo <esi:include src=blah /> bar";
  DocNodeList node_list;
  REQUIRE(parser.completeParse(node_list, input_data) == true);
  string packed = node_list.pack();

  // Node 0 begins right after the top-level int32 element count. Its layout is
  // [version:char][node_size:int32][type:DocNode::TYPE][data_len:int32]...
  // The type field is sized by the implementation's sizeof(type), so use the
  // same expression here rather than assuming the enum is 32 bits wide.
  const size_t node0_off          = sizeof(int32_t);
  const size_t node0_size_off     = node0_off + sizeof(char);
  const size_t node0_data_len_off = node0_size_off + sizeof(int32_t) + sizeof(DocNode::TYPE);

  // These offsets are not int32_t-aligned, so the packed fields have to be read
  // and written with memcpy rather than through a cast pointer.
  auto poke_int32 = [](string &buf, size_t offset, int32_t value) { memcpy(&buf[offset], &value, sizeof(value)); };
  auto peek_int32 = [](const string &buf, size_t offset) {
    int32_t value = 0;
    memcpy(&value, &buf[offset], sizeof(value));
    return value;
  };

  // Node 1 is the include node. Its single attribute follows its (empty) data
  // string and the attribute count.
  const size_t node0_size           = peek_int32(packed, node0_size_off);
  const size_t node1_off            = node0_off + node0_size;
  const size_t node1_size_off       = node1_off + sizeof(char);
  const size_t node1_type_off       = node1_size_off + sizeof(int32_t);
  const size_t node1_data_len_off   = node1_type_off + sizeof(DocNode::TYPE);
  const size_t node1_attr_count_off = node1_data_len_off + sizeof(int32_t) + peek_int32(packed, node1_data_len_off);
  const size_t node1_name_len_off   = node1_attr_count_off + sizeof(int32_t);
  const size_t node1_value_len_off  = node1_name_len_off + sizeof(int32_t) + peek_int32(packed, node1_name_len_off);

  // A length that runs from just after the given length field up to the last
  // n_trailing int32 fields of the buffer. Every byte it covers is inside the
  // buffer, so only a check against the declaring node's own extent rejects it.
  // Those trailing fields are the final node's attribute count and child count,
  // both zero, so a reader that only honours whole buffer bounds parses them as
  // an empty remainder and accepts the document.
  auto len_to_trailing_fields = [](const string &buf, size_t len_off, size_t n_trailing) {
    return static_cast<int32_t>(buf.size() - (len_off + sizeof(int32_t)) - n_trailing * sizeof(int32_t));
  };

  SECTION("node_size larger than buffer is rejected")
  {
    string corrupt = packed;
    poke_int32(corrupt, node0_size_off, 0x7fffffff);
    DocNodeList out;
    CHECK(out.unpack(corrupt) == false);
  }

  SECTION("negative node_size is rejected")
  {
    string corrupt = packed;
    poke_int32(corrupt, node0_size_off, -8);
    DocNodeList out;
    CHECK(out.unpack(corrupt) == false);
  }

  SECTION("node_size below the smallest packable node is rejected")
  {
    // The smallest node pack() emits is the version byte plus five int32 sized
    // fields. Anything shorter cannot hold a node, however the buffer is sized.
    const int32_t min_node_size = sizeof(char) + sizeof(int32_t) + sizeof(DocNode::TYPE) + 3 * sizeof(int32_t);
    string        corrupt       = packed;
    poke_int32(corrupt, node0_size_off, min_node_size - 1);
    DocNodeList out;
    CHECK(out.unpack(corrupt) == false);
  }

  SECTION("string length within the buffer but past the node's extent is rejected")
  {
    string corrupt = packed;
    poke_int32(corrupt, node0_data_len_off, len_to_trailing_fields(packed, node0_data_len_off, 2));
    DocNodeList out;
    CHECK(out.unpack(corrupt) == false);
  }

  SECTION("attribute name length within the buffer but past the node's extent is rejected")
  {
    string corrupt = packed;
    poke_int32(corrupt, node1_name_len_off, len_to_trailing_fields(packed, node1_name_len_off, 2));
    DocNodeList out;
    CHECK(out.unpack(corrupt) == false);
  }

  SECTION("attribute value length within the buffer but past the node's extent is rejected")
  {
    string corrupt = packed;
    poke_int32(corrupt, node1_value_len_off, len_to_trailing_fields(packed, node1_value_len_off, 1));
    DocNodeList out;
    CHECK(out.unpack(corrupt) == false);
  }

  SECTION("negative attribute value length is rejected")
  {
    string corrupt = packed;
    poke_int32(corrupt, node1_value_len_off, -1);
    DocNodeList out;
    CHECK(out.unpack(corrupt) == false);
  }

  SECTION("node type outside the defined range is rejected")
  {
    string corrupt = packed;
    poke_int32(corrupt, node1_type_off, DocNode::TYPE_SPECIAL_INCLUDE + 1);
    DocNodeList out;
    CHECK(out.unpack(corrupt) == false);

    corrupt = packed;
    poke_int32(corrupt, node1_type_off, -1);
    CHECK(out.unpack(corrupt) == false);
  }

  SECTION("node types with a mandatory attribute are rejected without one")
  {
    // EsiProcessor reads attr_list.front() on these types unconditionally, so a
    // packed node of one of them with no attributes must not unpack. Each blob
    // here is otherwise well formed, so nothing but the attribute check rejects
    // it.
    for (DocNode::TYPE type : {DocNode::TYPE_INCLUDE, DocNode::TYPE_WHEN, DocNode::TYPE_SPECIAL_INCLUDE}) {
      DocNodeList bare;
      bare.push_back(DocNode(type));
      const string bare_packed = bare.pack();
      DocNodeList  out;
      CHECK(out.unpack(bare_packed) == false);
    }

    // A type with no mandatory attribute still unpacks without any.
    DocNodeList plain;
    plain.push_back(DocNode(DocNode::TYPE_PRE, "text", 4));
    const string plain_packed = plain.pack();
    DocNodeList  out;
    REQUIRE(out.unpack(plain_packed) == true);
    CHECK(out.front().attr_list.empty());
  }

  SECTION("try node without exactly one attempt and one except child is rejected")
  {
    // EsiProcessor::_handleTry dereferences both children unconditionally, since
    // EsiParser only ever emits a try node holding exactly one of each.
    auto packed_try = [](std::initializer_list<DocNode::TYPE> child_types) {
      DocNodeList list;
      list.push_back(DocNode(DocNode::TYPE_TRY));
      for (DocNode::TYPE child_type : child_types) {
        list.back().child_nodes.push_back(DocNode(child_type));
      }
      return list.pack();
    };
    DocNodeList out;

    const string well_formed = packed_try({DocNode::TYPE_ATTEMPT, DocNode::TYPE_EXCEPT});
    REQUIRE(out.unpack(well_formed) == true);
    CHECK(out.front().child_nodes.size() == 2);

    const string no_children = packed_try({});
    CHECK(out.unpack(no_children) == false);

    const string no_except = packed_try({DocNode::TYPE_ATTEMPT});
    CHECK(out.unpack(no_except) == false);

    const string no_attempt = packed_try({DocNode::TYPE_EXCEPT});
    CHECK(out.unpack(no_attempt) == false);

    const string two_attempts = packed_try({DocNode::TYPE_ATTEMPT, DocNode::TYPE_ATTEMPT, DocNode::TYPE_EXCEPT});
    CHECK(out.unpack(two_attempts) == false);

    const string stray_child = packed_try({DocNode::TYPE_ATTEMPT, DocNode::TYPE_EXCEPT, DocNode::TYPE_PRE});
    CHECK(out.unpack(stray_child) == false);
  }

  SECTION("bytes left after the last node are rejected")
  {
    DocNodeList out;
    string      corrupt = packed + '\0';
    CHECK(out.unpack(corrupt) == false);

    // A zero count followed by anything is the same shape: the count does not
    // describe the buffer.
    string empty_list(sizeof(int32_t), '\0');
    REQUIRE(out.unpack(empty_list) == true);
    CHECK(out.empty());
    empty_list += "junk";
    CHECK(out.unpack(empty_list) == false);
  }

  SECTION("a rejected node does not keep the previous node's attributes")
  {
    DocNode node;
    int     node_len = 0;
    REQUIRE(node.unpack(packed.data() + node1_off, packed.size() - node1_off, node_len) == true);
    REQUIRE(node.attr_list.size() == 1);

    string corrupt = packed;
    poke_int32(corrupt, node1_value_len_off, -1);
    CHECK(node.unpack(corrupt.data() + node1_off, corrupt.size() - node1_off, node_len) == false);
    CHECK(node.attr_list.empty());
  }

  SECTION("child node length within the buffer but past the child's extent is rejected")
  {
    // The pre-fix bug compounded at each level of nesting, since every child
    // read was checked against the whole buffer instead of its own node. Two
    // raw text children under one parent: the first child's data length is
    // stretched to the last two fields of the second, so it stays inside the
    // parent and the buffer while crossing the child that declares it.
    DocNodeList nested;
    nested.push_back(DocNode(DocNode::TYPE_PRE, "abcd", 4));
    nested.back().child_nodes.push_back(DocNode(DocNode::TYPE_PRE, "efgh", 4));
    nested.back().child_nodes.push_back(DocNode(DocNode::TYPE_PRE, "ijkl", 4));
    string nested_packed = nested.pack();

    // The first child starts after the parent's data, attribute count and
    // child count fields.
    const size_t child0_off =
      node0_data_len_off + sizeof(int32_t) + peek_int32(nested_packed, node0_data_len_off) + sizeof(int32_t) + sizeof(int32_t);
    const size_t child0_data_len_off = child0_off + sizeof(char) + sizeof(int32_t) + sizeof(DocNode::TYPE);
    string       corrupt             = nested_packed;
    poke_int32(corrupt, child0_data_len_off, len_to_trailing_fields(nested_packed, child0_data_len_off, 2));
    DocNodeList out;
    CHECK(out.unpack(corrupt) == false);
  }

  SECTION("string length prefix past buffer is rejected")
  {
    string corrupt = packed;
    poke_int32(corrupt, node0_data_len_off, 0x7fffffff);
    DocNodeList out;
    CHECK(out.unpack(corrupt) == false);
  }

  SECTION("negative string length prefix is rejected")
  {
    string corrupt = packed;
    poke_int32(corrupt, node0_data_len_off, -100);
    DocNodeList out;
    CHECK(out.unpack(corrupt) == false);
  }

  SECTION("negative attribute count is rejected")
  {
    // The attribute count follows the node's data string, so its offset depends
    // on the packed data length.
    const size_t node0_attr_count_off = node0_data_len_off + sizeof(int32_t) + peek_int32(packed, node0_data_len_off);
    string       corrupt              = packed;
    poke_int32(corrupt, node0_attr_count_off, -1);
    DocNodeList out;
    CHECK(out.unpack(corrupt) == false);
  }

  SECTION("truncated node buffer is rejected")
  {
    DocNode node;
    int     node_len = 0;
    // Offer one byte fewer than node 0's own declared size so the truncation
    // clips this node rather than a later one.
    int32_t node0_size = peek_int32(packed, node0_size_off);
    CHECK(node.unpack(packed.data() + node0_off, node0_size - 1, node_len) == false);
  }
}
