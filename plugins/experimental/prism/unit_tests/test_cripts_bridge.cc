/** @file

  Unit tests for the prism builtins on Cripts, run against the real plugin API and header heaps.

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

#include "ir_reader.h"
#include "test_txn.h"

#include <string>
#include <string_view>
#include <variant>
#include <vector>

using cripts_test::Txn;
using namespace hrw4u;

namespace
{
constexpr std::string_view REQUEST = "GET /a HTTP/1.1\r\nHost: example.com\r\nX-Foo: bar\r\nX-Dup: 1\r\nX-Dup: 2\r\n\r\n";
constexpr std::string_view SERVER_REQUEST =
  "GET http://origin.example:8081/o?x=9&z=1 HTTP/1.1\r\nHost: origin.example\r\nX-Foo: bar\r\nX-Dup: 1\r\nX-Dup: 2\r\n\r\n";
constexpr std::string_view RESPONSE = "HTTP/1.1 200 OK\r\nX-Foo: bar\r\nX-Dup: 1\r\nX-Dup: 2\r\nContent-Length: 0\r\n\r\n";

Program
parse(std::string_view ir)
{
  std::string error;
  auto        prog = parse_ir(ir, error);

  INFO(error);
  REQUIRE(prog.has_value());
  return std::move(*prog);
}

void
run_hook(Txn &txn, const Program &prog, Hook hook)
{
  std::string fault;
  bool        ran = run_on(txn, prog, hook, fault, CriptsBridge::vars(txn.context()));

  INFO(fault);
  CHECK(ran);
}

void
run_section(Txn &txn, Hook hook, std::string_view ir)
{
  run_hook(txn, parse(ir), hook);
}
} // namespace

TEST_CASE("The client header builtins write the client request the core holds", "[prism][bridge]")
{
  Txn txn{REQUEST};

  run_section(txn, Hook::Remap, R"(hrw4u-ir 1.0

Section[REMAP]:
  consts = [K0:"X-New", K1:"new", K2:"X-Foo", K3:"baz", K4:"X-Dup"]
  IR:
    %1:sview = const.s K0 @1:1
    %2:sview = const.s K1 @1:1
    call.eff BI_SET_CLIENT_HEADER, %1, %2 @1:1
    %3:sview = const.s K2 @2:1
    %4:sview = const.s K3 @2:1
    call.eff BI_ADD_CLIENT_HEADER, %3, %4 @2:1
    %5:sview = const.s K4 @3:1
    call.eff BI_RM_CLIENT_HEADER, %5 @3:1
    ret @3:1
)");

  CHECK(txn.client_request_field("X-New") == "new");
  CHECK(field_values(txn.sm().t_state.hdr_info.client_request, "X-Foo") == std::vector<std::string>{"bar", "baz"});
  CHECK(txn.client_request_field_count("X-Dup") == 0);
}

TEST_CASE("BI_SET_CLIENT_HEADER replaces the field's duplicates", "[prism][bridge]")
{
  Txn txn{REQUEST};

  run_section(txn, Hook::Remap, R"(hrw4u-ir 1.0

Section[REMAP]:
  consts = [K0:"X-Dup", K1:"new"]
  IR:
    %1:sview = const.s K0 @1:1
    %2:sview = const.s K1 @1:1
    call.eff BI_SET_CLIENT_HEADER, %1, %2 @1:1
    ret @1:1
)");

  CHECK(txn.client_request_field_count("X-Dup") == 1);
  CHECK(txn.client_request_field("X-Dup") == "new");
}

TEST_CASE("BI_ADD_CLIENT_HEADER adds a line after the field's duplicates, as add-header does", "[prism][bridge]")
{
  Txn txn{REQUEST};

  run_section(txn, Hook::Remap, R"(hrw4u-ir 1.0

Section[REMAP]:
  consts = [K0:"X-Dup", K1:"3"]
  IR:
    %1:sview = const.s K0 @1:1
    %2:sview = const.s K1 @1:1
    call.eff BI_ADD_CLIENT_HEADER, %1, %2 @1:1
    ret @1:1
)");

  CHECK(field_values(txn.sm().t_state.hdr_info.client_request, "X-Dup") == std::vector<std::string>{"1", "2", "3"});
}

TEST_CASE("BI_SET_CLIENT_HEADER with an empty value leaves the field, as set-header does", "[prism][bridge]")
{
  Txn txn{REQUEST};

  run_section(txn, Hook::Remap, R"(hrw4u-ir 1.0

Section[REMAP]:
  consts = [K0:"X-Foo", K1:""]
  IR:
    %1:sview = const.s K0 @1:1
    %2:sview = const.s K1 @1:1
    call.eff BI_SET_CLIENT_HEADER, %1, %2 @1:1
    ret @1:1
)");

  CHECK(txn.client_request_field("X-Foo") == "bar");
}

TEST_CASE("BI_CLIENT_HEADER reads the client request", "[prism][bridge]")
{
  Txn txn{REQUEST};

  run_section(txn, Hook::Remap, R"(hrw4u-ir 1.0

Section[REMAP]:
  consts = [K0:"X-Foo", K1:"X-Copy"]
  IR:
    %1:sview = const.s K0 @1:1
    %2:sview = call.pure BI_CLIENT_HEADER, %1 @1:1
    %3:sview = const.s K1 @1:1
    call.eff BI_SET_CLIENT_HEADER, %3, %2 @1:1
    ret @1:1
)");

  CHECK(txn.client_request_field("X-Copy") == "bar");
}

TEST_CASE("The header builtins on a message the transaction does not have do nothing", "[prism][bridge]")
{
  Txn txn{REQUEST};

  run_section(txn, Hook::ReadResponse, R"(hrw4u-ir 1.0

Section[READ_RESPONSE]:
  consts = [K0:"X-New", K1:"new"]
  IR:
    %1:sview = const.s K0 @1:1
    %2:sview = const.s K1 @1:1
    call.eff BI_SET_SERVER_RESP_HEADER, %1, %2 @1:1
    call.eff BI_ADD_SERVER_RESP_HEADER, %1, %2 @2:1
    call.eff BI_RM_SERVER_RESP_HEADER, %1 @3:1
    %3:sview = call.pure BI_SERVER_RESP_HEADER, %1 @4:1
    ret @4:1
)");
}

TEST_CASE("The server header builtins write the request to the origin", "[prism][bridge]")
{
  Txn txn{REQUEST};

  txn.set_server_request(SERVER_REQUEST);
  run_section(txn, Hook::SendRequest, R"(hrw4u-ir 1.0

Section[SEND_REQUEST]:
  consts = [K0:"X-New", K1:"new", K2:"X-Foo", K3:"baz", K4:"X-Dup"]
  IR:
    %1:sview = const.s K0 @1:1
    %2:sview = const.s K1 @1:1
    call.eff BI_SET_SERVER_HEADER, %1, %2 @1:1
    %3:sview = const.s K2 @2:1
    %4:sview = const.s K3 @2:1
    call.eff BI_ADD_SERVER_HEADER, %3, %4 @2:1
    %5:sview = const.s K4 @3:1
    call.eff BI_RM_SERVER_HEADER, %5 @3:1
    ret @3:1
)");

  auto const &sent = txn.sm().t_state.hdr_info.server_request;

  CHECK(field_values(sent, "X-New") == std::vector<std::string>{"new"});
  CHECK(field_values(sent, "X-Foo") == std::vector<std::string>{"bar", "baz"});
  CHECK(field_values(sent, "X-Dup").empty());
  CHECK(txn.client_request_field_count("X-New") == 0);
  CHECK(txn.client_request_field_count("X-Dup") == 2);
}

TEST_CASE("The server response header builtins read and write the response from the origin", "[prism][bridge]")
{
  Txn txn{REQUEST};

  txn.set_server_response(RESPONSE);
  run_section(txn, Hook::ReadResponse, R"(hrw4u-ir 1.0

Section[READ_RESPONSE]:
  consts = [K0:"Content-Length", K1:"X-Copy", K2:"X-Foo", K3:"baz", K4:"X-Dup"]
  IR:
    %1:sview = const.s K0 @1:1
    %2:sview = call.pure BI_SERVER_RESP_HEADER, %1 @1:1
    %3:sview = const.s K1 @1:1
    call.eff BI_SET_SERVER_RESP_HEADER, %3, %2 @1:1
    %4:sview = const.s K2 @2:1
    %5:sview = const.s K3 @2:1
    call.eff BI_ADD_SERVER_RESP_HEADER, %4, %5 @2:1
    %6:sview = const.s K4 @3:1
    call.eff BI_RM_SERVER_RESP_HEADER, %6 @3:1
    ret @3:1
)");

  auto const &resp = txn.sm().t_state.hdr_info.server_response;

  CHECK(field_values(resp, "X-Copy") == std::vector<std::string>{"0"});
  CHECK(field_values(resp, "X-Foo") == std::vector<std::string>{"bar", "baz"});
  CHECK(field_values(resp, "X-Dup").empty());
}

TEST_CASE("The client response header builtins read and write the response to the client", "[prism][bridge]")
{
  Txn txn{REQUEST};

  txn.set_client_response(RESPONSE);
  run_section(txn, Hook::SendResponse, R"(hrw4u-ir 1.0

Section[SEND_RESPONSE]:
  consts = [K0:"Content-Length", K1:"X-Copy", K2:"X-Foo", K3:"baz", K4:"X-Dup"]
  IR:
    %1:sview = const.s K0 @1:1
    %2:sview = call.pure BI_CLIENT_RESP_HEADER, %1 @1:1
    %3:sview = const.s K1 @1:1
    call.eff BI_SET_CLIENT_RESP_HEADER, %3, %2 @1:1
    %4:sview = const.s K2 @2:1
    %5:sview = const.s K3 @2:1
    call.eff BI_ADD_CLIENT_RESP_HEADER, %4, %5 @2:1
    %6:sview = const.s K4 @3:1
    call.eff BI_RM_CLIENT_RESP_HEADER, %6 @3:1
    ret @3:1
)");

  auto const &resp = txn.sm().t_state.hdr_info.client_response;

  CHECK(field_values(resp, "X-Copy") == std::vector<std::string>{"0"});
  CHECK(field_values(resp, "X-Foo") == std::vector<std::string>{"bar", "baz"});
  CHECK(field_values(resp, "X-Dup").empty());
}

TEST_CASE("A transaction's variables last from begin_txn() to end_txn(), across hooks", "[prism][bridge]")
{
  Txn  txn{REQUEST};
  auto prog = parse(R"(hrw4u-ir 1.0

Section[REMAP]:
  vars   = [v0:bool]
  consts = [K0:"X-V"]
  ints   = [I0:1]
  fmt    = [F0:"{v0}" arity=1 lits=["", ""]]
  IR:
    %1:bool = const.i I0 @1:1
    store.v v0:bool, %1 @1:1
    ret @1:1

Section[SEND_RESPONSE]:
  IR:
    %1:bool = load.v v0:bool @2:1
    %2:sview = fmt F0, %1 @2:1
    %3:sview = const.s K0 @2:1
    call.eff BI_SET_CLIENT_RESP_HEADER, %3, %2 @2:1
    ret @2:1
)");

  CriptsBridge::begin_txn(txn.context(), prog);
  CHECK(CriptsBridge::vars(txn.context()).size() == 1);

  run_hook(txn, prog, Hook::Remap);
  txn.set_client_response(RESPONSE);
  run_hook(txn, prog, Hook::SendResponse);
  CHECK(field_values(txn.sm().t_state.hdr_info.client_response, "X-V") == std::vector<std::string>{"TRUE"});

  CriptsBridge::end_txn(txn.context());
  CHECK(CriptsBridge::vars(txn.context()).empty());
}

TEST_CASE("begin_txn() keeps no memory for a program without variables", "[prism][bridge]")
{
  Txn  txn{REQUEST};
  auto prog = parse(R"(hrw4u-ir 1.0

Section[REMAP]:
  IR:
    ret @1:1
)");

  CriptsBridge::begin_txn(txn.context(), prog);
  CHECK(std::get_if<void *>(&txn.context()->data[CriptsBridge::MEMORY_SLOT]) == nullptr);
  CHECK(CriptsBridge::vars(txn.context()).empty());
  CriptsBridge::end_txn(txn.context());
}
