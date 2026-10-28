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

#include "CriptsTestTxn.h"

#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using cripts_test::str;
using cripts_test::Txn;

namespace
{
constexpr std::string_view REQUEST = "GET /a HTTP/1.1\r\nHost: example.com\r\nX-Foo: bar\r\nX-Dup: 1\r\nX-Dup: 2\r\n\r\n";

// HdrHeap.cc's limit on dead string space, which is file local there.
constexpr int MAX_LOST_STR_SPACE = 1024;

// Leaves more dead string space than MAX_LOST_STR_SPACE, so the next string allocation coalesces the string heaps and
// frees the ones the fields were read from. Reading those afterwards is only caught by ASan.
void
lose_string_space(Txn &txn, auto &req)
{
  req["X-Junk"] = std::string(MAX_LOST_STR_SPACE + 1, 'x');
  req["X-Junk"] = "";
  REQUIRE(txn.sm().t_state.hdr_info.client_request.m_heap->m_lost_string_space > MAX_LOST_STR_SPACE);
}
} // namespace

TEST_CASE("Header: read fields", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  borrow req = cripts::Client::Request::Get();

  CHECK(str(req["X-Foo"]) == "bar");
  CHECK(str(req["x-foo"]) == "bar");
  CHECK(str(req["Host"]) == "example.com");
  CHECK(str(req["X-Missing"]).empty());
  CHECK(str(req.method) == "GET");
  CHECK((req.method == cripts::Method::GET));
  CHECK((req.method != cripts::Method::POST));
}

TEST_CASE("Header: add a field", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  borrow req = cripts::Client::Request::Get();

  req["X-New"] = "value";
  CHECK(txn.client_request_field("X-New") == "value");
  CHECK(str(req["X-New"]) == "value");
}

TEST_CASE("Header: replacing a field removes its duplicates", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  borrow req = cripts::Client::Request::Get();

  req["X-Dup"] = "3";
  CHECK(txn.client_request_field_count("X-Dup") == 1);
  CHECK(txn.client_request_field("X-Dup") == "3");
}

TEST_CASE("Header: assigning an empty value erases the field and its duplicates", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  borrow req = cripts::Client::Request::Get();

  req["X-Dup"] = "";
  CHECK(txn.client_request_field_count("X-Dup") == 0);

  req.Erase("X-Foo");
  CHECK(txn.client_request_field_count("X-Foo") == 0);

  req["X-Missing"] = "";
  CHECK(txn.client_request_field_count("X-Missing") == 0);
}

TEST_CASE("Header: integer values", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  borrow req = cripts::Client::Request::Get();

  req["X-Int"] = integer(42);
  CHECK(txn.client_request_field("X-Int") == "42");

  req["X-Foo"] = integer(-7);
  CHECK(txn.client_request_field("X-Foo") == "-7");
  CHECK(req["X-Int"].ToInteger() == 42);
}

TEST_CASE("Header: += adds another field line", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  borrow req = cripts::Client::Request::Get();

  req["X-Foo"] += "baz";
  CHECK(txn.client_request_field_count("X-Foo") == 2);

  req["X-Other"] += "first";
  CHECK(txn.client_request_field("X-Other") == "first");
}

TEST_CASE("Header: repeated field lines read as one comma joined value", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  borrow req = cripts::Client::Request::Get();

  CHECK(str(req["X-Dup"]) == "1,2");
  CHECK_FALSE(req["X-Dup"] == "1");
  CHECK(req["X-Dup"].Count() == 2);
  CHECK(req["X-Dup"].Values() == std::vector<cripts::string_view>{"1", "2"});

  CHECK(req["X-Foo"].Count() == 1);
  CHECK(req["X-Foo"].Values() == std::vector<cripts::string_view>{"bar"});
  CHECK(req["X-Missing"].Count() == 0);
  CHECK(req["X-Missing"].Values().empty());
}

// A view must outlive its proxy and any later reads. The long values catch a buffer owned by the proxy, the short ones a
// container that moves its SSO strings as it grows; either way the stale read is only caught by ASan.
TEST_CASE("Header: joined values stay valid across later reads", "[cripts][Headers]")
{
  std::string const a(64, 'a');
  std::string const b(64, 'b');
  Txn               txn{"GET / HTTP/1.1\r\nHost: example.com\r\nX-A: " + a + "\r\nX-A: " + b + "\r\nX-B: " + a + "\r\nX-B: " + b +
          "\r\nX-Dup: 1\r\nX-Dup: 2\r\n\r\n"};
  auto              context = txn.context();

  borrow                    req = cripts::Client::Request::Get();
  cripts::string_view const long_view{req["X-A"]};
  cripts::string_view const short_view{req["X-Dup"]};

  CHECK(req["X-A"] == req["X-B"]);
  for (int i = 0; i < 16; ++i) {
    CHECK(str(req["X-B"]) == a + "," + b);
  }
  CHECK(std::string{long_view} == a + "," + b);
  CHECK(std::string{short_view} == "1,2");
}

TEST_CASE("Header: += keeps the value readable, and = collapses it again", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  borrow req   = cripts::Client::Request::Get();
  auto   built = req["X-Built"];

  built  = "x";
  built += "y";
  CHECK(str(built) == "x,y");
  CHECK(built.Count() == 2);
  CHECK(str(req["X-Built"]) == "x,y");

  built = "z";
  CHECK(str(built) == "z");
  CHECK(built.Count() == 1);
  CHECK(txn.client_request_field_count("X-Built") == 1);
  CHECK(txn.client_request_field("X-Built") == "z");
}

TEST_CASE("Header: assigning another field copies its value", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  borrow req = cripts::Client::Request::Get();

  req["X-New"] = req["X-Foo"];
  CHECK(txn.client_request_field("X-New") == "bar");

  req["X-Foo"] = req["Host"];
  CHECK(txn.client_request_field("X-Foo") == "example.com");
  CHECK(txn.client_request_field("Host") == "example.com");

  req["X-New"] = req["X-Missing"];
  CHECK(txn.client_request_field_count("X-New") == 0);
}

TEST_CASE("Header: assigning a field of another header copies its value", "[cripts][Headers]")
{
  Txn txn{REQUEST};

  txn.set_server_response("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

  auto context = txn.context();

  context->state.hook = TS_HTTP_READ_RESPONSE_HDR_HOOK;

  borrow req  = cripts::Client::Request::Get();
  borrow resp = cripts::Server::Response::Get();

  resp["X-Copy"] = req["X-Foo"];

  auto const *field = txn.sm().t_state.hdr_info.server_response.field_find("X-Copy"sv);

  REQUIRE(field != nullptr);
  CHECK(field->value_get() == "bar");
  CHECK(txn.client_request_field("X-Foo") == "bar");
}

TEST_CASE("Header: assigning another field to a new one survives a heap coalesce", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  borrow req = cripts::Client::Request::Get();

  lose_string_space(txn, req);

  req["X-New"] = req["X-Foo"];
  CHECK(txn.client_request_field("X-New") == "bar");
}

TEST_CASE("Header: += another field survives a heap coalesce", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  borrow req = cripts::Client::Request::Get();

  lose_string_space(txn, req);

  req["X-Dup"] += req["X-Foo"];

  std::vector<std::string> values;

  for (auto const *f = txn.sm().t_state.hdr_info.client_request.field_find("X-Dup"sv); f != nullptr; f = f->m_next_dup) {
    values.emplace_back(f->value_get());
  }
  CHECK(values == std::vector<std::string>{"1", "2", "bar"});
}

// The set keeps its source heap alive while it copies, so replacing a field needs no copy of the value.
TEST_CASE("Header: replacing a field with itself survives a heap coalesce", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  borrow req = cripts::Client::Request::Get();

  lose_string_space(txn, req);

  req["X-Foo"] = req["X-Foo"];
  CHECK(txn.client_request_field("X-Foo") == "bar");
}

static_assert(!std::is_copy_constructible_v<cripts::Header::String>);

TEST_CASE("Header: a moved field releases its handle once", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  borrow req = cripts::Client::Request::Get();

  {
    auto from = req["X-Foo"];
    auto to   = std::move(from);

    to = "baz";
  }
  CHECK(txn.client_request_field("X-Foo") == "baz");
}

TEST_CASE("Header: iterate over the field names", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  borrow                   req = cripts::Client::Request::Get();
  std::vector<std::string> names;

  for (auto name : req) {
    names.emplace_back(name.GetSV());
  }
  CHECK(names == std::vector<std::string>{"Host", "X-Foo", "X-Dup", "X-Dup"});
}

TEST_CASE("Header: erasing the current field while iterating", "[cripts][Headers]")
{
  Txn  txn{"GET / HTTP/1.1\r\nHost: example.com\r\nX-Internal-A: 1\r\nX-Internal-B: 2\r\nX-Keep: 3\r\n\r\n"};
  auto context = txn.context();

  borrow                   req = cripts::Client::Request::Get();
  std::vector<std::string> names;

  for (auto name : req) {
    names.emplace_back(name.GetSV());
    if (name.starts_with("X-Internal")) {
      req.Erase(name);
    }
  }
  CHECK(names == std::vector<std::string>{"Host", "X-Internal-A", "X-Internal-B", "X-Keep"});
  CHECK(txn.client_request_field_count("X-Internal-A") == 0);
  CHECK(txn.client_request_field_count("X-Internal-B") == 0);
  CHECK(txn.client_request_field("X-Keep") == "3");
}

TEST_CASE("Header: erasing a later field while iterating", "[cripts][Headers]")
{
  Txn  txn{"GET / HTTP/1.1\r\nHost: example.com\r\nX-A: 1\r\nX-B: 2\r\nX-C: 3\r\n\r\n"};
  auto context = txn.context();

  borrow                   req = cripts::Client::Request::Get();
  std::vector<std::string> names;

  for (auto name : req) {
    names.emplace_back(name.GetSV());
    if (name == "X-A") {
      req.Erase("X-B");
    }
  }
  CHECK(names == std::vector<std::string>{"Host", "X-A", "X-C"});
}

TEST_CASE("Header: the next hook sees the current headers", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  CHECK(str(cripts::Client::Request::Get()["X-Foo"]) == "bar");
  context->reset();

  txn.sm().t_state.hdr_info.client_request.value_set("X-Foo"sv, "changed"sv);

  CHECK(str(cripts::Client::Request::Get()["X-Foo"]) == "changed");
}

// Only ASan sees the stale read.
TEST_CASE("Header: a joined value outlives the hook", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  cripts::string_view const view{cripts::Client::Request::Get()["X-Dup"]};

  context->reset();

  CHECK(str(cripts::Client::Request::Get()["X-Foo"]) == "bar");
  CHECK(std::string{view} == "1,2");
}

TEST_CASE("Header: server response status", "[cripts][Headers]")
{
  Txn txn{REQUEST};

  txn.set_server_response("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");

  auto context = txn.context();

  context->state.hook = TS_HTTP_READ_RESPONSE_HDR_HOOK;

  borrow resp = cripts::Server::Response::Get();

  CHECK(integer(resp.status) == 404);
  resp.status = 200;
  CHECK(static_cast<int>(txn.sm().t_state.hdr_info.server_response.status_get()) == 200);
}

TEST_CASE("Header: the next hook reads the status and method again", "[cripts][Headers]")
{
  Txn txn{REQUEST};

  txn.set_server_response("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");

  auto context = txn.context();

  context->state.hook = TS_HTTP_READ_RESPONSE_HDR_HOOK;
  CHECK(integer(cripts::Server::Response::Get().status) == 404);
  CHECK(str(cripts::Client::Request::Get().method) == "GET");

  context->reset();
  txn.sm().t_state.hdr_info.server_response.status_set(HTTPStatus::OK);
  txn.sm().t_state.hdr_info.client_request.method_set("POST"sv);

  CHECK(integer(cripts::Server::Response::Get().status) == 200);
  CHECK(str(cripts::Client::Request::Get().method) == "POST");
}

TEST_CASE("Header: an empty body", "[cripts][Headers]")
{
  Txn txn{REQUEST};

  txn.set_server_response("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");

  auto  context = txn.context();
  auto &state   = txn.sm().t_state;

  context->state.hook = TS_HTTP_READ_RESPONSE_HDR_HOOK;

  borrow resp = cripts::Server::Response::Get();

  resp.body = "gone";
  CHECK(std::string_view(state.internal_msg_buffer, state.internal_msg_buffer_size) == "gone");
  resp.body = "";
  CHECK(state.internal_msg_buffer == nullptr);
  CHECK(state.internal_msg_buffer_size == 0);
}

TEST_CASE("Server::Request: read after the request is sent", "[cripts][Headers]")
{
  Txn txn{REQUEST};

  txn.set_server_request("GET /o HTTP/1.1\r\nHost: origin.example\r\n\r\n");

  auto context = txn.context();

  context->state.hook = TS_HTTP_READ_RESPONSE_HDR_HOOK;

  borrow sent = cripts::Server::Request::Get();

  CHECK(str(sent["Host"]) == "origin.example");
  CHECK_FALSE(context->state.error.Failed());
}

TEST_CASE("Server::Request: Present() tells there is no request without failing", "[cripts][Headers]")
{
  Txn  txn{REQUEST};
  auto context = txn.context();

  context->state.hook = TS_HTTP_SEND_RESPONSE_HDR_HOOK;

  {
    borrow sent = cripts::Server::Request::Get();

    CHECK_FALSE(sent.Present());
    CHECK_FALSE(context->state.error.Failed());
  }

  SECTION("using it fails the transaction, as before")
  {
    borrow sent = cripts::Server::Request::Get();

    CHECK(sent.BufP() == nullptr);
    CHECK(context->state.error.Failed());
  }
  SECTION("a request made since is found")
  {
    txn.set_server_request("GET /o HTTP/1.1\r\nHost: origin.example\r\n\r\n");

    borrow sent = cripts::Server::Request::Get();

    CHECK(sent.Present());
    CHECK(str(sent["Host"]) == "origin.example");
  }
}
