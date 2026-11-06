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
constexpr std::string_view ABSOLUTE_REQUEST = "GET http://example.com:8080/a/b?x=1&y=2 HTTP/1.1\r\nHost: example.com\r\n\r\n";
constexpr std::string_view RESPONSE         = "HTTP/1.1 200 OK\r\nX-Foo: bar\r\nX-Dup: 1\r\nX-Dup: 2\r\nContent-Length: 0\r\n\r\n";

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

TEST_CASE("BI_SERVER_HEADER reads the request to the origin in the response hooks, and empty on a cache hit", "[prism][bridge]")
{
  auto prog = parse(R"(hrw4u-ir 1.0

Section[READ_RESPONSE]:
  consts = [K0:"Host", K1:"X-Sent"]
  fmt    = [F0:"[{host}]" arity=1 lits=["[", "]"]]
  IR:
    %1:sview = const.s K0 @1:1
    %2:sview = call.pure BI_SERVER_HEADER, %1 @1:1
    %3:sview = fmt F0, %2 @1:1
    %4:sview = const.s K1 @1:1
    call.eff BI_SET_SERVER_RESP_HEADER, %4, %3 @1:1
    ret @1:1

Section[SEND_RESPONSE]:
  IR:
    %1:sview = const.s K0 @2:1
    %2:sview = call.pure BI_SERVER_HEADER, %1 @2:1
    %3:sview = fmt F0, %2 @2:1
    %4:sview = const.s K1 @2:1
    call.eff BI_SET_CLIENT_RESP_HEADER, %4, %3 @2:1
    ret @2:1
)");

  SECTION("from the origin")
  {
    Txn txn{REQUEST};

    txn.set_server_request(SERVER_REQUEST);
    txn.set_server_response(RESPONSE);
    run_hook(txn, prog, Hook::ReadResponse);
    CHECK(field_values(txn.sm().t_state.hdr_info.server_response, "X-Sent") == std::vector<std::string>{"[origin.example]"});

    txn.set_client_response(RESPONSE);
    run_hook(txn, prog, Hook::SendResponse);
    CHECK(field_values(txn.sm().t_state.hdr_info.client_response, "X-Sent") == std::vector<std::string>{"[origin.example]"});
  }
  SECTION("from the cache, without failing the transaction")
  {
    Txn txn{REQUEST};

    txn.set_client_response(RESPONSE);
    run_hook(txn, prog, Hook::SendResponse);
    CHECK(field_values(txn.sm().t_state.hdr_info.client_response, "X-Sent") == std::vector<std::string>{"[]"});
    CHECK_FALSE(txn.context()->state.error.Failed());
  }
}

TEST_CASE("BI_SERVER_URL reads the request to the origin, not the client's, and empty before there is one", "[prism][bridge]")
{
  Txn  txn{ABSOLUTE_REQUEST};
  auto prog = parse(R"(hrw4u-ir 1.0

Section[REMAP]:
  consts = [K0:"X-Sent", K1:"X-Path", K2:"X-Query"]
  ints   = [I0:5, I1:2, I2:3, I3:4]
  fmt    = [F0:"[{url}][{port}]" arity=2 lits=["[", "][", "]"]]
  IR:
    %1:i64 = const.i I0 @1:1
    %2:sview = call.pure BI_SERVER_URL, %1 @1:1
    %3:i64 = const.i I1 @2:1
    %4:sview = call.pure BI_SERVER_URL, %3 @2:1
    %5:sview = fmt F0, %2, %4 @3:1
    %6:sview = const.s K0 @3:1
    call.eff BI_SET_CLIENT_HEADER, %6, %5 @3:1
    ret @3:1

Section[SEND_REQUEST]:
  IR:
    %1:i64 = const.i I2 @4:1
    %2:sview = call.pure BI_SERVER_URL, %1 @4:1
    %3:sview = const.s K1 @4:1
    call.eff BI_SET_SERVER_HEADER, %3, %2 @4:1
    %4:i64 = const.i I3 @5:1
    %5:sview = call.pure BI_SERVER_URL, %4 @5:1
    %6:sview = const.s K2 @5:1
    call.eff BI_SET_SERVER_HEADER, %6, %5 @5:1
    ret @5:1
)");

  run_hook(txn, prog, Hook::Remap);
  CHECK(txn.client_request_field("X-Sent") == "[][]");

  txn.set_server_request(SERVER_REQUEST);
  run_hook(txn, prog, Hook::SendRequest);

  auto const &sent = txn.sm().t_state.hdr_info.server_request;

  CHECK(field_values(sent, "X-Path") == std::vector<std::string>{"o"});
  CHECK(field_values(sent, "X-Query") == std::vector<std::string>{"x=9&z=1"});
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

TEST_CASE("The status builtins read the status of the response they name, and 0 where there is none", "[prism][bridge]")
{
  constexpr std::string_view NOT_FOUND = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

  Txn  txn{REQUEST};
  auto prog = parse(R"(hrw4u-ir 1.0

Section[READ_RESPONSE]:
  vars   = [v0:u16]
  IR:
    %1:i64 = call.pure BI_SERVER_RESP_STATUS @1:1
    store.v v0:u16, %1 @1:1
    ret @1:1

Section[SEND_RESPONSE]:
  IR:
    %1:i64 = call.pure BI_CLIENT_RESP_STATUS @2:1
    store.v v0:u16, %1 @2:1
    ret @2:1
)");

  CriptsBridge::begin_txn(txn.context(), prog);

  auto status = [&txn]() { return CriptsBridge::vars(txn.context())[0]; };

  SECTION("of the response from the origin")
  {
    txn.set_server_response(RESPONSE);
    run_hook(txn, prog, Hook::ReadResponse);
    CHECK(status() == 200);
  }
  SECTION("of the response to the client")
  {
    txn.set_client_response(NOT_FOUND);
    run_hook(txn, prog, Hook::SendResponse);
    CHECK(status() == 404);
  }
  SECTION("of a response the transaction does not have")
  {
    CriptsBridge::vars(txn.context())[0] = 1;
    run_hook(txn, prog, Hook::ReadResponse);
    CHECK(status() == 0);
  }
  CriptsBridge::end_txn(txn.context());
}

TEST_CASE("BI_CLIENT_URL and BI_CLIENT_URL_PARAM read the URL from before remap, as %{CLIENT-URL} does", "[prism][bridge]")
{
  Txn   txn{ABSOLUTE_REQUEST};
  auto &st = txn.sm().t_state;

  // As HttpTransact keeps it once it has read the request.
  st.unmapped_url.create(txn.client_url().m_heap);
  st.unmapped_url.copy(&txn.client_url());
  txn.client_url().path_set("mapped");
  txn.client_url().query_set("y=mapped");

  run_section(txn, Hook::Remap, R"(hrw4u-ir 1.0

Section[REMAP]:
  consts = [K0:"X-0", K1:"X-1", K2:"X-2", K3:"X-3", K4:"X-4", K5:"X-5", K6:"y", K7:"X-Y"]
  ints   = [I0:0, I1:1, I2:2, I3:3, I4:4, I5:5]
  IR:
    %1:i64 = const.i I0 @1:1
    %2:sview = call.pure BI_CLIENT_URL, %1 @1:1
    %3:sview = const.s K0 @1:1
    call.eff BI_SET_CLIENT_HEADER, %3, %2 @1:1
    %4:i64 = const.i I1 @2:1
    %5:sview = call.pure BI_CLIENT_URL, %4 @2:1
    %6:sview = const.s K1 @2:1
    call.eff BI_SET_CLIENT_HEADER, %6, %5 @2:1
    %7:i64 = const.i I2 @3:1
    %8:sview = call.pure BI_CLIENT_URL, %7 @3:1
    %9:sview = const.s K2 @3:1
    call.eff BI_SET_CLIENT_HEADER, %9, %8 @3:1
    %10:i64 = const.i I3 @4:1
    %11:sview = call.pure BI_CLIENT_URL, %10 @4:1
    %12:sview = const.s K3 @4:1
    call.eff BI_SET_CLIENT_HEADER, %12, %11 @4:1
    %13:i64 = const.i I4 @5:1
    %14:sview = call.pure BI_CLIENT_URL, %13 @5:1
    %15:sview = const.s K4 @5:1
    call.eff BI_SET_CLIENT_HEADER, %15, %14 @5:1
    %16:i64 = const.i I5 @6:1
    %17:sview = call.pure BI_CLIENT_URL, %16 @6:1
    %18:sview = const.s K5 @6:1
    call.eff BI_SET_CLIENT_HEADER, %18, %17 @6:1
    %19:sview = const.s K6 @7:1
    %20:sview = call.pure BI_CLIENT_URL_PARAM, %19 @7:1
    %21:sview = const.s K7 @7:1
    call.eff BI_SET_CLIENT_HEADER, %21, %20 @7:1
    ret @7:1
)");

  CHECK(txn.client_request_field("X-0") == "http");
  CHECK(txn.client_request_field("X-1") == "example.com");
  CHECK(txn.client_request_field("X-2") == "8080");
  CHECK(txn.client_request_field("X-3") == "a/b");
  CHECK(txn.client_request_field("X-4") == "x=1&y=2");
  CHECK(txn.client_request_field("X-5") == "http://example.com:8080/a/b?x=1&y=2");
  CHECK(txn.client_request_field("X-Y") == "2");
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
