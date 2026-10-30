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

using cripts_test::str;
using cripts_test::Txn;

namespace
{
constexpr std::string_view ABSOLUTE_REQUEST = "GET http://example.com:8080/a/b/c?x=1&y=2 HTTP/1.1\r\nHost: example.com\r\n\r\n";
constexpr std::string_view SEGMENTS_REQUEST = "GET http://example.com/version1//item/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
constexpr std::string_view REPEATED_REQUEST = "GET http://example.com/q?a=1&a=2&e=&f HTTP/1.1\r\nHost: example.com\r\n\r\n";
constexpr std::string_view LONG_KEY_REQUEST =
  "GET http://example.com/q?x=1&kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk=2 HTTP/1.1\r\nHost: example.com\r\n\r\n";

// Enough rewrites that the request heap coalesces, moving every string in it.
void
churn(cripts::Client::Request &req)
{
  for (int i = 0; i < 20; ++i) {
    req["X-Churn"] = std::string(200, static_cast<char>('a' + i));
  }
  req["X-Fill"] = std::string(2000, 'z');
}

} // namespace

TEST_CASE("Url: components read from the request", "[cripts][Urls]")
{
  Txn  txn{ABSOLUTE_REQUEST};
  auto context = txn.context();

  borrow url = cripts::Client::URL::Get();

  CHECK(str(url.scheme) == "http");
  CHECK(str(url.host) == "example.com");
  CHECK(integer(url.port) == 8080);
  CHECK(str(url.path) == "a/b/c");
  CHECK(str(url.query) == "x=1&y=2");
  CHECK(str(url.query["y"]) == "2");
  CHECK(str(url.query["z"]).empty());
  CHECK(str(url.path[1]) == "b");
  CHECK_FALSE(url.Modified());
}

TEST_CASE("Url: whole component assignment reaches the core", "[cripts][Urls]")
{
  Txn  txn{ABSOLUTE_REQUEST};
  auto context = txn.context();

  borrow url = cripts::Client::URL::Get();

  url.host  = "other.example.com";
  url.path  = "z";
  url.query = "q=9";
  CHECK(url.Modified());
  CHECK(txn.client_url().host_get() == "other.example.com");
  CHECK(txn.client_url().path_get() == "z");
  CHECK(txn.client_url().query_get() == "q=9");
  CHECK(str(url.host) == "other.example.com");
  CHECK(str(url.path) == "z");
  CHECK(str(url.query) == "q=9");
}

TEST_CASE("Url: string helpers load a component on first use", "[cripts][Urls]")
{
  Txn  txn{ABSOLUTE_REQUEST};
  auto context = txn.context();

  borrow url = cripts::Client::URL::Get();

  CHECK(url.scheme.find("tt") == 1);
  CHECK(url.host.ends_with(".com"));
  CHECK(url.path.starts_with("a/"));
  CHECK(url.query.contains("y=2"));
}

TEST_CASE("Url: the next hook reads the components again", "[cripts][Urls]")
{
  Txn  txn{ABSOLUTE_REQUEST};
  auto context = txn.context();

  {
    borrow url = cripts::Client::URL::Get();

    CHECK(str(url.host) == "example.com");
    CHECK(integer(url.port) == 8080);
    CHECK(str(url.path) == "a/b/c");
    CHECK(str(url.query["x"]) == "1");
  }

  context->reset();
  txn.client_url().host_set("other.example.com");
  txn.client_url().port_set(81);
  txn.client_url().path_set("d");
  txn.client_url().query_set("x=2");

  borrow url = cripts::Client::URL::Get();

  CHECK(str(url.host) == "other.example.com");
  CHECK(integer(url.port) == 81);
  CHECK(str(url.path) == "d");
  CHECK(str(url.query["x"]) == "2");
}

TEST_CASE("Url: a header write that moves the heap reloads cached components", "[cripts][Urls]")
{
  Txn  txn{ABSOLUTE_REQUEST};
  auto context = txn.context();

  borrow url    = cripts::Client::URL::Get();
  borrow req    = cripts::Client::Request::Get();
  auto   before = url.path.GetSV().data();

  churn(req);
  REQUIRE(txn.client_url().path_get().data() != before);
  CHECK(url.path.GetSV().data() == txn.client_url().path_get().data());
  CHECK(str(url.path) == "a/b/c");
}

TEST_CASE("Url: segment edits are flushed, empty segments included", "[cripts][Urls]")
{
  Txn  txn{SEGMENTS_REQUEST};
  auto context = txn.context();

  borrow url = cripts::Client::URL::Get();

  url.path[1];
  CHECK(url.path.ends_with("/"));
  CHECK_FALSE(url.Modified());

  url.path[0] = "v2";
  CHECK(str(url.path) == "v2//item/");
  url.path.Push("next");
  CHECK(str(url.path) == "v2//item/next");
  url.path.Erase(1);
  CHECK(str(url.path) == "v2/item/next");
  url.path.Insert(99, "end");
  CHECK(str(url.path) == "v2/item/next/end");

  CHECK(url.Modified());
  url._update();
  CHECK(txn.client_url().path_get() == "v2/item/next/end");
}

TEST_CASE("Url: a held segment survives a heap move and an Erase()", "[cripts][Urls]")
{
  Txn  txn{ABSOLUTE_REQUEST};
  auto context = txn.context();

  borrow url     = cripts::Client::URL::Get();
  borrow req     = cripts::Client::Request::Get();
  auto   first   = url.path[0];
  auto   last    = url.path[2];
  auto   missing = url.path[9];

  churn(req);
  CHECK(url.path.starts_with("a/"));
  first = "z";
  CHECK(str(url.path) == "z/b/c");

  url.path.Erase(0);
  last    = "x";
  missing = "x";
  CHECK(str(url.path) == "b/c");
}

TEST_CASE("Url: query edits keep repeated keys, bare keys and empty values", "[cripts][Urls]")
{
  Txn  txn{REPEATED_REQUEST};
  auto context = txn.context();

  borrow url = cripts::Client::URL::Get();

  CHECK(str(url.query["a"]) == "2");
  CHECK(url.query.contains("a=1"));
  CHECK_FALSE(url.Modified());

  url.query["b"] = "x";
  CHECK(str(url.query) == "a=1&a=2&e=&f&b=x");
  url.query["a"] = "3";
  CHECK(str(url.query) == "a=3&e=&f&b=x");
  url.query.Erase("f");
  CHECK(str(url.query) == "a=3&e=&b=x");

  CHECK(url.Modified());
  url._update();
  CHECK(txn.client_url().query_get() == "a=3&e=&b=x");
}

TEST_CASE("Url: edits outlive the strings they were made from", "[cripts][Urls]")
{
  Txn  txn{ABSOLUTE_REQUEST};
  auto context = txn.context();

  borrow url = cripts::Client::URL::Get();

  {
    std::string value(40, 'v');
    std::string segment(40, 's');

    url.query["sig"] = value;
    url.path[1]      = segment;
  }
  // These take over the freed memory, so a view still pointing at it reads 'o'.
  std::string reuse_v(40, 'o');
  std::string reuse_s(40, 'o');

  url._update();
  CHECK(txn.client_url().query_get() == "x=1&y=2&sig=" + std::string(40, 'v'));
  CHECK(txn.client_url().path_get() == "a/" + std::string(40, 's') + "/c");
}

TEST_CASE("Url: Keep() can empty the query", "[cripts][Urls]")
{
  Txn  txn{ABSOLUTE_REQUEST};
  auto context = txn.context();

  borrow url = cripts::Client::URL::Get();

  url.query.Keep({"z"});
  CHECK(str(url.query).empty());
  CHECK(url.Modified());
  url._update();
  CHECK(txn.client_url().query_get().empty());

  cripts::Url::Query standalone("a=1&b=2");

  standalone.Keep({"z"});
  CHECK(str(standalone).empty());
}

TEST_CASE("Url: a copy keeps its edits after the original is flushed", "[cripts][Urls]")
{
  Txn  txn{ABSOLUTE_REQUEST};
  auto context = txn.context();

  borrow url = cripts::Client::URL::Get();

  url.query["n"] = std::string(40, 'n');
  url.path[0]    = std::string(40, 'p');

  cripts::Url::Query query = url.query;
  cripts::Url::Path  path  = url.path;

  url._update();
  // These take over the freed memory, so a view still pointing at it reads 'o'.
  std::string reuse_q(40, 'o');
  std::string reuse_p(40, 'o');

  CHECK(str(query) == "x=1&y=2&n=" + std::string(40, 'n'));
  CHECK(str(path) == std::string(40, 'p') + "/b/c");
}

TEST_CASE("Url: in-place helpers see a pending edit", "[cripts][Urls]")
{
  Txn  txn{ABSOLUTE_REQUEST};
  auto context = txn.context();

  borrow url = cripts::Client::URL::Get();

  url.path[0] = "  z";
  CHECK(std::string{url.path.ltrim(' ')} == "z/b/c");
}

TEST_CASE("Url: a Parameter held across a heap move", "[cripts][Urls]")
{
  Txn  txn{ABSOLUTE_REQUEST};
  auto context = txn.context();

  borrow url   = cripts::Client::URL::Get();
  borrow req   = cripts::Client::Request::Get();
  auto   param = url.query["y"];

  churn(req);
  param = "9";
  CHECK(str(url.query) == "x=1&y=9");
}

TEST_CASE("Url: a Parameter looked up with a temporary key", "[cripts][Urls]")
{
  Txn  txn{LONG_KEY_REQUEST};
  auto context = txn.context();

  borrow url   = cripts::Client::URL::Get();
  auto   param = url.query[std::string(40, 'k')];

  // Takes over the temporary key's freed memory, so a view still pointing at it reads 'o'.
  std::string reuse(40, 'o');

  param = "9";
  CHECK(str(url.query) == "x=1&" + std::string(40, 'k') + "=9");
}

TEST_CASE("Url: the port set from a string", "[cripts][Urls]")
{
  Txn  txn{ABSOLUTE_REQUEST};
  auto context = txn.context();

  borrow url = cripts::Client::URL::Get();

  url.port = "8081";
  CHECK(integer(url.port) == 8081);
  url.port = "x8082";
  url.port = "8083x";
  url.port = "70000";
  CHECK(integer(url.port) == 8081);
  CHECK(txn.client_url().port_get() == 8081);
}
