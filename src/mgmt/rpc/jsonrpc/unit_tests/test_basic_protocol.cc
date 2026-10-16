/**
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

#include <catch2/catch_test_macros.hpp> /* catch unit-test framework */

#include <tsutil/ts_bw_format.h>

#include "mgmt/rpc/jsonrpc/JsonRPCManager.h"
#include "mgmt/rpc/jsonrpc/JsonRPC.h"
#include "mgmt/rpc/handlers/records/Records.h"
#include "tsutil/Metrics.h"
#include "mgmt/rpc/handlers/common/ErrorUtils.h"

namespace
{
// Not using the singleton logic.
struct JsonRpcUnitTest : rpc::JsonRPCManager {
  JsonRpcUnitTest() : JsonRPCManager() {}
  using base = JsonRPCManager;
  bool
  remove_handler(std::string const &name)
  {
    return base::remove_handler(name);
  }
  template <typename Func>
  bool
  add_notification_handler(const std::string &name, Func &&call)
  {
    return base::add_notification_handler(name, std::forward<Func>(call), nullptr, {});
  }
  template <typename Func>
  bool
  add_method_handler(const std::string &name, Func &&call)
  {
    return base::add_method_handler(name, std::forward<Func>(call), nullptr, {});
  }
  template <typename Func>
  bool
  add_method_handler_with_budget(const std::string &name, Func &&call)
  {
    return base::add_method_handler_with_budget(name, std::forward<Func>(call), nullptr, {});
  }

  std::optional<std::string>
  handle_call(std::string const &jsonString)
  {
    return base::handle_call(rpc::Context{}, jsonString);
  }
};

enum class TestErrors { ERR1 = 9999, ERR2 };
static const std::error_code ERR1{ts::make_errno_code(9999)};
static const std::error_code ERR2{ts::make_errno_code(10000)};
static std::string_view      err{"Just an error message to add more meaning to the failure"};

inline swoc::Rv<YAML::Node>
test_callback_ok_or_error(std::string_view const & /* id ATS_UNUSED */, YAML::Node const &params)
{
  swoc::Rv<YAML::Node> resp;

  // play with the req.id if needed.
  if (YAML::Node n = params["return_error"]) {
    auto yesOrNo = n.as<std::string>();
    if (yesOrNo == "yes") {
      resp.errata().assign(ERR1).note(err);
    } else {
      resp.result()["ran"] = "ok";
    }
  }
  return resp;
}

static int notificationCallCount{0};
inline void
test_nofitication(YAML::Node const & /* params ATS_UNUSED */)
{
  notificationCallCount++;
}
} // namespace
TEST_CASE("Multiple Registrations - methods", "[methods]")
{
  JsonRpcUnitTest rpc;
  SECTION("More than  one method")
  {
    REQUIRE(rpc.add_method_handler("test_callback_ok_or_error", &test_callback_ok_or_error));
    REQUIRE(rpc.add_method_handler("test_callback_ok_or_error", &test_callback_ok_or_error) == false);
  }
}

TEST_CASE("Multiple Registrations - notifications", "[notifications]")
{
  JsonRpcUnitTest rpc;
  SECTION("inserting several notifications with the same name")
  {
    REQUIRE(rpc.add_notification_handler("test_nofitication", &test_nofitication));
    REQUIRE(rpc.add_notification_handler("test_nofitication", &test_nofitication) == false);
  }
}

TEST_CASE("Register/call method", "[method]")
{
  JsonRpcUnitTest rpc;

  SECTION("Registering the method")
  {
    REQUIRE(rpc.add_method_handler("test_callback_ok_or_error", &test_callback_ok_or_error));

    SECTION("Calling the method")
    {
      const auto json = rpc.handle_call(
        R"({"jsonrpc": "2.0", "method": "test_callback_ok_or_error", "params": {"return_error": "no"}, "id": "13"})");
      REQUIRE(json);
      const std::string_view expected = R"({"jsonrpc": "2.0", "result": {"ran": "ok"}, "id": "13"})";
      REQUIRE(*json == expected);
    }
  }
}

// VALID RESPONSES WITH CUSTOM ERRORS
TEST_CASE("Register/call method - respond with errors (data field)", "[method][error.data]")
{
  JsonRpcUnitTest rpc;

  SECTION("Registering the method")
  {
    REQUIRE(rpc.add_method_handler("test_callback_ok_or_error", &test_callback_ok_or_error));

    SECTION("Calling the method")
    {
      const auto json = rpc.handle_call(
        R"({"jsonrpc": "2.0", "method": "test_callback_ok_or_error", "params": {"return_error": "yes"}, "id": "14"})");
      REQUIRE(json);
      const std::string_view expected =
        R"({"jsonrpc": "2.0", "error": {"code": 9, "message": "Error during execution", "data": [{"code": 9999, "message": "Just an error message to add more meaning to the failure"}]}, "id": "14"})";
      REQUIRE(*json == expected);
    }
  }
}

TEST_CASE("Register/call notification", "[notifications]")
{
  JsonRpcUnitTest rpc;

  SECTION("Registering the notification")
  {
    REQUIRE(rpc.add_notification_handler("test_nofitication", &test_nofitication));

    SECTION("Calling the notification")
    {
      // Set rather than assumed: the counter is file scope. ctest registers one case per process, so it is always zero there,
      // but running the binary directly runs every case in one process, in a random order -- Catch2's ConfigData defaults
      // runOrder to Randomized (lib/Catch2/src/catch2/catch_config.hpp), whatever its --help text says, so a case that
      // increments the counter can run first.
      notificationCallCount = 0;
      rpc.handle_call(R"({"jsonrpc": "2.0", "method": "test_nofitication", "params": {"json": "rpc"}})");
      REQUIRE(notificationCallCount == 1);
      notificationCallCount = 0; // for further use.
    }
  }
}

TEST_CASE("Basic test, batch calls", "[methods][notifications]")
{
  JsonRpcUnitTest rpc;

  SECTION("inserting multiple functions, mixed method and notifications.")
  {
    const auto f1_added = rpc.add_method_handler("test_callback_ok_or_error", &test_callback_ok_or_error);
    const bool f2_added = rpc.add_notification_handler("test_nofitication", &test_nofitication);

    REQUIRE(f1_added);
    REQUIRE(f2_added);

    SECTION("we call in batch, two functions and one notification")
    {
      const auto resp1 = rpc.handle_call(
        R"([{"jsonrpc": "2.0", "method": "test_callback_ok_or_error", "params": {"return_error": "no"}, "id": "13"}
      ,{"jsonrpc": "2.0", "method": "test_callback_ok_or_error", "params": {"return_error": "yes"}, "id": "14"}
      ,{"jsonrpc": "2.0", "method": "test_nofitication", "params": {"name": "damian"}}])");

      REQUIRE(resp1);
      const std::string_view expected =
        R"([{"jsonrpc": "2.0", "result": {"ran": "ok"}, "id": "13"}, {"jsonrpc": "2.0", "error": {"code": 9, "message": "Error during execution", "data": [{"code": 9999, "message": "Just an error message to add more meaning to the failure"}]}, "id": "14"}])";
      REQUIRE(*resp1 == expected);
    }
  }
}

TEST_CASE("Single registered notification", "[notifications]")
{
  notificationCallCount = 0;
  JsonRpcUnitTest rpc;
  SECTION("Single notification, only notifications in the batch.")
  {
    REQUIRE(rpc.add_notification_handler("test_nofitication", &test_nofitication));

    SECTION("Call the notifications in batch")
    {
      const auto should_be_no_response = rpc.handle_call(
        R"([{"jsonrpc": "2.0", "method": "test_nofitication", "params": {"name": "JSON"}},
              {"jsonrpc": "2.0", "method": "test_nofitication", "params": {"name": "RPC"}},
              {"jsonrpc": "2.0", "method": "test_nofitication", "params": {"name": "2.0"}}])");

      REQUIRE(!should_be_no_response);
      REQUIRE(notificationCallCount == 3);
    }
  }
}

TEST_CASE("Valid json but invalid messages", "[errors]")
{
  JsonRpcUnitTest rpc;

  SECTION("Valid json but invalid protocol {}")
  {
    const auto resp = rpc.handle_call(R"({})");
    REQUIRE(resp);
    std::string_view expected = R"({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}})";
    REQUIRE(*resp == expected);
  }

  SECTION("Valid json but invalid protocol [{},{}] - batch response")
  {
    const auto resp = rpc.handle_call(R"([{},{}])");
    REQUIRE(resp);
    std::string_view expected =
      R"([{"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}}, {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}}])";
    REQUIRE(*resp == expected);
  }
}

TEST_CASE("Invalid json messages", "[errors][invalid json]")
{
  JsonRpcUnitTest rpc;
  SECTION("Invalid json in an attempt of batch")
  {
    const auto resp = rpc.handle_call(
      R"([{"jsonrpc": "2.0", "method": "test_callback_ok_or_error", "params": {"return_error": "no"}, "id": "13"}
      ,{"jsonrpc": "2.0", "method": "test_callback_ok_or_error", "params": {"return_error": "yes
      ,{"jsonrpc": "2.0", "method": "test_nofitication", "params": {"name": "damian"}}])");

    REQUIRE(resp);

    std::string_view expected = R"({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}})";
    REQUIRE(*resp == expected);
  }
}

TEST_CASE("Invalid parameters base on the jsonrpc 2.0 protocol", "[protocol]")
{
  JsonRpcUnitTest rpc;

  REQUIRE(rpc.add_method_handler("test_callback_ok_or_error", &test_callback_ok_or_error));
  REQUIRE(rpc.add_notification_handler("test_nofitication", &test_nofitication));

  SECTION("version field")
  {
    SECTION("number instead of a string")
    {
      // THIS WILL FAIL BASE ON THE YAMLCPP WAY TO TEST TYPES. We can get the number first, which will be ok and then fail, but
      // seems not the right way to do it. ok for now.
      [[maybe_unused]] const auto resp =
        rpc.handle_call(R"({"jsonrpc": 2.0, "method": "test_callback_ok_or_error", "params": {"return_error": "no"}, "id": "13"})");

      // REQUIRE(resp);

      [[maybe_unused]] const std::string_view expected =
        R"({"jsonrpc": "2.0", "error": {"code": 2, "message": "Invalid version type, should be a string"}, "id": "13"})";
      // REQUIRE(*resp == expected);
    }

    SECTION("2.8 instead of 2.0")
    {
      const auto resp = rpc.handle_call(
        R"({"jsonrpc": "2.8", "method": "test_callback_ok_or_error", "params": {"return_error": "no"}, "id": "15"})");

      REQUIRE(resp);
      const std::string_view expected =
        R"({"jsonrpc": "2.0", "error": {"code": 1, "message": "Invalid version, 2.0 only"}, "id": "15"})";
      REQUIRE(*resp == expected);
    }
  }
  SECTION("method field")
  {
    SECTION("using a number")
    {
      // THIS WILL FAIL BASE ON THE YAMLCPP WAY TO TEST TYPES, there is no explicit way to test for a particular type, we can get
      // the number first, then as it should not be converted we get the string instead, this seems rather not the best way to do
      // it. ok for now.
      [[maybe_unused]] const auto resp =
        rpc.handle_call(R"({"jsonrpc": "2.0", "method": 123, "params": {"return_error": "no"}, "id": "14"})");

      // REQUIRE(resp);
      [[maybe_unused]] const std::string_view expected =
        R"({"jsonrpc": "2.0", "error": {"code": 4, "message": "Invalid method type, should be a string"}, "id": "14"})";
      // REQUIRE(*resp == expected);
    }
  }
  SECTION("param field")
  {
    SECTION("Invalidtype")
    {
      const auto resp = rpc.handle_call(R"({"jsonrpc": "2.0", "method": "test_callback_ok_or_error", "params": 13, "id": "13"})");

      REQUIRE(resp);
      const std::string_view expected =
        R"({"jsonrpc": "2.0", "error": {"code": 6, "message": "Invalid params type. A Structured value is expected"}, "id": "13"})";
      REQUIRE(*resp == expected);
    }
  }

  SECTION("id field")
  {
    SECTION("null id")
    {
      const auto resp = rpc.handle_call(
        R"({"jsonrpc": "2.0", "method": "test_callback_ok_or_error", "params": {"return_error": "no"}, "id": null})");
      REQUIRE(resp);
      const std::string_view expected =
        R"({"jsonrpc": "2.0", "error": {"code": 8, "message": "Use of null as id is discouraged"}})";
      REQUIRE(*resp == expected);
    }
  }
}

TEST_CASE("Basic test with member functions(add, remove)", "[basic][member_functions]")
{
  struct TestMemberFunctionCall {
    TestMemberFunctionCall() {}
    bool
    register_member_function_as_callback(JsonRpcUnitTest &rpc)
    {
      return rpc.add_method_handler(
        "member_function",
        [this](std::string_view const &id, const YAML::Node &req) -> swoc::Rv<YAML::Node> { return test(id, req); });
    }
    swoc::Rv<YAML::Node>
    test(std::string_view const & /* id ATS_UNUSED */, const YAML::Node & /* req ATS_UNUSED */)
    {
      swoc::Rv<YAML::Node> resp;
      resp.result() = "grand!";
      return resp;
    }

    // TODO: test notification as well.
  };

  SECTION("A RPC object and a custom class")
  {
    JsonRpcUnitTest        rpc;
    TestMemberFunctionCall tmfc;

    REQUIRE(tmfc.register_member_function_as_callback(rpc) == true);
    SECTION("call the member function")
    {
      const auto response = rpc.handle_call(R"({"jsonrpc": "2.0", "method": "member_function", "id": "AbC"})");
      REQUIRE(response);
      REQUIRE(*response == R"({"jsonrpc": "2.0", "result": "grand!", "id": "AbC"})");
    }

    SECTION("We remove the callback handler")
    {
      REQUIRE(rpc.remove_handler("member_function") == true);

      const auto response = rpc.handle_call(R"({"jsonrpc": "2.0", "method": "member_function", "id": "AbC"})");
      REQUIRE(response);
      REQUIRE(*response == R"({"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": "AbC"})");
    }
  }
}

TEST_CASE("Test Dispatcher rpc method", "[dispatcher]")
{
  JsonRpcUnitTest rpc;
  const auto      response = rpc.handle_call(R"({"jsonrpc": "2.0", "method": "show_registered_handlers", "id": "AbC"})");
  REQUIRE(*response ==
          R"({"jsonrpc": "2.0", "result": {"methods": ["get_service_descriptor", "show_registered_handlers"]}, "id": "AbC"})");
}

[[maybe_unused]] static swoc::Rv<YAML::Node>
subtract(std::string_view const & /* id ATS_UNUSED */, YAML::Node const &numbers)
{
  swoc::Rv<YAML::Node> res;

  if (numbers.Type() == YAML::NodeType::Sequence) {
    auto it    = numbers.begin();
    int  total = it->as<int>();
    ++it;
    for (; it != numbers.end(); ++it) {
      total -= it->as<int>();
    }

    res.result() = total;
  } else if (numbers.Type() == YAML::NodeType::Map) {
    if (numbers["subtrahend"] && numbers["minuend"]) {
      int total    = numbers["minuend"].as<int>() - numbers["subtrahend"].as<int>();
      res.result() = total;
    }
  }
  return res;
}

[[maybe_unused]] static swoc::Rv<YAML::Node>
sum(std::string_view const & /* id ATS_UNUSED */, YAML::Node const &params)
{
  swoc::Rv<YAML::Node> res;
  int                  total{0};
  for (auto n : params) {
    total += n.as<int>();
  }
  res.result() = total;
  return res;
}

[[maybe_unused]] static swoc::Rv<YAML::Node>
get_data(std::string_view const & /* id ATS_UNUSED */, YAML::Node const & /* params ATS_UNUSED */)
{
  swoc::Rv<YAML::Node> res;
  res.result().push_back("hello");
  res.result().push_back("5");
  return res;
}

[[maybe_unused]] static void
update(YAML::Node const & /* params ATS_UNUSED */)
{
}
[[maybe_unused]] static void
foobar(YAML::Node const & /* params ATS_UNUSED */)
{
}
[[maybe_unused]] static void
notify_hello(YAML::Node const & /* params ATS_UNUSED */)
{
}

// TODO: add tests base on the protocol example doc.
TEST_CASE("Basic tests from the jsonrpc 2.0 doc.")
{
  SECTION("rpc call with positional parameters")
  {
    JsonRpcUnitTest rpc;

    REQUIRE(rpc.add_method_handler("subtract", &subtract));
    const auto resp = rpc.handle_call(R"({"jsonrpc": "2.0", "method": "subtract", "params": [42, 23], "id": "1"})");
    REQUIRE(resp);
    REQUIRE(*resp == R"({"jsonrpc": "2.0", "result": "19", "id": "1"})");

    const auto resp1 = rpc.handle_call(R"({"jsonrpc": "2.0", "method": "subtract", "params": [23, 42], "id": "1"})");
    REQUIRE(resp1);
    REQUIRE(*resp1 == R"({"jsonrpc": "2.0", "result": "-19", "id": "1"})");
  }

  SECTION("rpc call with named parameters")
  {
    JsonRpcUnitTest rpc;

    REQUIRE(rpc.add_method_handler("subtract", &subtract));
    const auto resp =
      rpc.handle_call(R"({"jsonrpc": "2.0", "method": "subtract", "params": {"subtrahend": 23, "minuend": 42}, "id": "3"})");
    REQUIRE(resp);
    REQUIRE(*resp == R"({"jsonrpc": "2.0", "result": "19", "id": "3"})");

    const auto resp1 =
      rpc.handle_call(R"({"jsonrpc": "2.0", "method": "subtract", "params": {"minuend": 42, "subtrahend": 23}, "id": "3"})");
    REQUIRE(resp1);
    REQUIRE(*resp1 == R"({"jsonrpc": "2.0", "result": "19", "id": "3"})");
  }

  SECTION("A notification")
  {
    JsonRpcUnitTest rpc;

    REQUIRE(rpc.add_notification_handler("update", &update));
    const auto resp = rpc.handle_call(R"({"jsonrpc": "2.0", "method": "update", "params": [1,2,3,4,5]})");
    REQUIRE(!resp);

    REQUIRE(rpc.add_notification_handler("foobar", &foobar));
    const auto resp1 = rpc.handle_call(R"({"jsonrpc": "2.0", "method": "foobar"})");
    REQUIRE(!resp1);
  }

  SECTION("rpc call of non-existent method")
  {
    JsonRpcUnitTest rpc;

    const auto resp = rpc.handle_call(R"({"jsonrpc": "2.0", "method": "foobar", "id": "1"})");
    REQUIRE(resp);
    REQUIRE(*resp == R"({"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": "1"})");
  }
  SECTION("rpc call with invalid JSON")
  {
    JsonRpcUnitTest rpc;

    const auto resp = rpc.handle_call(R"({"jsonrpc": "2.0", "method": "foobar, "params": "bar", "baz])");
    REQUIRE(resp);
    REQUIRE(*resp == R"({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}})");
  }
  SECTION("rpc call with invalid Request object")
  {
    // We do have a custom object here, which will return invalid param object.
    // skip it
  }
  SECTION("rpc call Batch, invalid JSON")
  {
    JsonRpcUnitTest rpc;

    const auto resp =
      rpc.handle_call(R"( {"jsonrpc": "2.0", "method": "sum", "params": [1,2,4], "id": "1"}, {"jsonrpc": "2.0", "method")");
    REQUIRE(resp);
    REQUIRE(*resp == R"({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}})");
  }
  SECTION("rpc call with an empty Array")
  {
    JsonRpcUnitTest rpc;
    const auto      resp = rpc.handle_call(R"([])");
    REQUIRE(resp);
    std::string_view expected = R"({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}})";
    REQUIRE(*resp == expected);
  }
  SECTION("rpc call with an invalid Batch")
  {
    JsonRpcUnitTest rpc;
    const auto      resp = rpc.handle_call(R"([1])");
    REQUIRE(resp);
    std::string_view expected = R"([{"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}}])";
    REQUIRE(*resp == expected);
  }
  SECTION("rpc call with invalid Batch")
  {
    JsonRpcUnitTest rpc;
    const auto      resp = rpc.handle_call(R"([1,2,3])");
    REQUIRE(resp);
    std::string expected = R"([{"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}})"
                           R"(, {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}})"
                           R"(, {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}}])";
    REQUIRE(*resp == expected);
  }

  SECTION("rpc call Batch(all notifications")
  {
    JsonRpcUnitTest rpc;
    REQUIRE(rpc.add_notification_handler("notify_hello", &notify_hello));
    REQUIRE(rpc.add_notification_handler("notify_sum", &notify_hello));
    const auto resp = rpc.handle_call(
      R"( [{"jsonrpc": "2.0", "method": "notify_sum", "params": [1,2,4]}, {"jsonrpc": "2.0", "method": "notify_hello", "params": [7]}])");
    REQUIRE(!resp);
  }
}

TEST_CASE("Handle un-handle handler's error", "[throw]")
{
  JsonRpcUnitTest rpc;
  SECTION("Basic exception thrown")
  {
    REQUIRE(rpc.add_method_handler("oops_i_did_it_again",
                                   [](std::string_view const & /* id ATS_UNUSED */, const YAML::Node & /* params ATS_UNUSED */)
                                     -> swoc::Rv<YAML::Node> { throw std::runtime_error("Oops, I did it again"); }));
    const auto       resp     = rpc.handle_call(R"({"jsonrpc": "2.0", "method": "oops_i_did_it_again", "id": "1"})");
    std::string_view expected = R"({"jsonrpc": "2.0", "error": {"code": 9, "message": "Error during execution"}, "id": "1"})";
    REQUIRE(*resp == expected);
  }
}

TEST_CASE("Call registered method with no ID", "[no-id]")
{
  JsonRpcUnitTest rpc;
  SECTION("Basic test, no id on method call")
  {
    REQUIRE(rpc.add_method_handler("call_me_with_no_id",
                                   [](std::string_view const & /* id ATS_UNUSED */, const YAML::Node & /* params ATS_UNUSED */)
                                     -> swoc::Rv<YAML::Node> { throw std::runtime_error("Oops, I did it again"); }));
    const auto       resp     = rpc.handle_call(R"({"jsonrpc": "2.0", "method": "call_me_with_no_id"})");
    std::string_view expected = R"({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}})";
    REQUIRE(*resp == expected);
  }
}

TEST_CASE("Call registered notification with ID", "[notification_and_id]")
{
  JsonRpcUnitTest rpc;
  SECTION("Basic test, id on a notification call")
  {
    REQUIRE(rpc.add_notification_handler("call_me_with_id", [](const YAML::Node & /* params ATS_UNUSED */) -> void {
      throw std::runtime_error("Oops, I did it again");
    }));
    const auto       resp     = rpc.handle_call(R"({"jsonrpc": "2.0", "method": "call_me_with_id", "id": "1"})");
    std::string_view expected = R"({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": "1"})";
    REQUIRE(*resp == expected);
  }
}

TEST_CASE("Call method with invalid ID", "[invalid_id]")
{
  JsonRpcUnitTest rpc;
  SECTION("Basic test, invalid ids")
  {
    std::string req  = R"([{"id": "", "jsonrpc": "2.0", "method": "will_not_pass_the_validation"},)"
                       R"({"id": {}, "jsonrpc": "2.0", "method": "will_not_pass_the_validation"}])";
    auto        resp = rpc.handle_call(req);
    std::string expected =
      R"([{"jsonrpc": "2.0", "error": {"code": 11, "message": "Use of an empty string as id is discouraged"}}, )"
      R"({"jsonrpc": "2.0", "error": {"code": 7, "message": "Invalid id type"}}])";
    REQUIRE(*resp == expected);
  }
}

namespace
{
int limitsCallCount{0};

swoc::Rv<YAML::Node>
count_calls(std::string_view const & /* id ATS_UNUSED */, YAML::Node const & /* params ATS_UNUSED */)
{
  ++limitsCallCount;
  swoc::Rv<YAML::Node> resp;
  resp.result()["ran"] = "ok";
  return resp;
}

// One count_calls request, with id @a id and a params array of @a nparams elements when @a nparams is not negative.
std::string
count_calls_request(int id, int nparams = -1)
{
  std::string req = R"({"jsonrpc": "2.0", "method": "count_calls", "id": ")" + std::to_string(id) + R"(")";
  if (nparams >= 0) {
    req += R"(, "params": [)";
    for (int i = 0; i < nparams; ++i) {
      req += i ? ",1" : "1";
    }
    req += "]";
  }
  return req + "}";
}

std::string
batch_of(int n)
{
  std::string req = "[";
  for (int i = 0; i < n; ++i) {
    req += (i ? "," : "") + count_calls_request(i + 1);
  }
  return req + "]";
}

// The whole refusal, data included: the protocol code alone does not say which limit was hit, since INVALID_REQUEST also
// answers a malformed message, so the detail naming the limit is part of what a client is promised.
constexpr std::string_view BATCH_REFUSED =
  R"({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request", "data": [{"code": -32600, "message": "A batch may carry at most 64 messages."}]}})";
constexpr std::string_view PARAMS_REFUSED =
  R"({"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params", "data": [{"code": -32602, "message": "A request may carry at most 1024 params elements in total across its messages."}]}})";

// A single refused message is answered with its own id; a batch has no one id to answer with.
std::string
params_refused(int id)
{
  return R"({"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params", "data": [{"code": -32602, "message": "A )"
         R"(request may carry at most 1024 params elements in total across its messages."}]}, "id": ")" +
         std::to_string(id) + R"("})";
}
} // namespace

// The decoder bounds how many messages one batch carries, and handle_call bounds how many params elements they add up to, so
// that a single request cannot repeat a costly handler without limit. Each refusal answers for the whole request, and no
// handler runs: the call counter is what shows that a refused request had no partial effect.
TEST_CASE("Request size limits", "[limits]")
{
  JsonRpcUnitTest rpc;
  REQUIRE(rpc.add_method_handler("count_calls", &count_calls));
  limitsCallCount = 0;

  SECTION("a batch at the limit runs every message")
  {
    auto const resp = rpc.handle_call(batch_of(64));
    REQUIRE(resp);
    CHECK(resp->front() == '[');
    CHECK(limitsCallCount == 64);
  }

  SECTION("a batch over the limit is refused whole")
  {
    auto const resp = rpc.handle_call(batch_of(65));
    REQUIRE(resp);
    CHECK(*resp == BATCH_REFUSED);
    CHECK(limitsCallCount == 0);
  }

  SECTION("aliases count once per reference toward the batch limit")
  {
    // One anchored message referenced 64 more times is 65 messages, though it is written only once.
    std::string req = "[&m " + count_calls_request(1);
    for (int i = 0; i < 64; ++i) {
      req += ", *m";
    }
    req += "]";

    auto const resp = rpc.handle_call(req);
    REQUIRE(resp);
    CHECK(*resp == BATCH_REFUSED);
    CHECK(limitsCallCount == 0);
  }

  SECTION("a request at the params limit runs")
  {
    auto const resp = rpc.handle_call(count_calls_request(1, 1024));
    REQUIRE(resp);
    CHECK(*resp == R"({"jsonrpc": "2.0", "result": {"ran": "ok"}, "id": "1"})");
    CHECK(limitsCallCount == 1);
  }

  SECTION("a request over the params limit is refused whole, and answered with its id")
  {
    auto const resp = rpc.handle_call(count_calls_request(1, 1025));
    REQUIRE(resp);
    CHECK(*resp == params_refused(1));
    CHECK(limitsCallCount == 0);
  }

  // A batch is answered without an id whatever its length, because the one id it would carry is one message's. The guard that
  // decides this reads the batch flag as well as the message count, and a batch of one is the only shape where the two
  // disagree: dropping the flag from the condition passes every other case here and starts answering a batch with a message's
  // id.
  SECTION("a one-message batch over the params limit is refused without an id")
  {
    auto const resp = rpc.handle_call("[" + count_calls_request(1, 1025) + "]");
    REQUIRE(resp);
    CHECK(*resp == PARAMS_REFUSED);
    CHECK(limitsCallCount == 0);
  }

  SECTION("a one-message batch at the params limit runs")
  {
    auto const resp = rpc.handle_call("[" + count_calls_request(1, 1024) + "]");
    REQUIRE(resp);
    CHECK(*resp == R"([{"jsonrpc": "2.0", "result": {"ran": "ok"}, "id": "1"}])");
    CHECK(limitsCallCount == 1);
  }

  SECTION("object members count as params elements")
  {
    std::string req = R"({"jsonrpc": "2.0", "method": "count_calls", "id": "1", "params": {)";
    for (int i = 0; i < 1025; ++i) {
      req += (i ? ", \"k" : "\"k") + std::to_string(i) + "\": 1";
    }
    req += "}}";

    auto const resp = rpc.handle_call(req);
    REQUIRE(resp);
    CHECK(*resp == params_refused(1));
    CHECK(limitsCallCount == 0);
  }

  SECTION("params elements are summed across a batch")
  {
    auto const at_limit = rpc.handle_call("[" + count_calls_request(1, 512) + "," + count_calls_request(2, 512) + "]");
    REQUIRE(at_limit);
    CHECK(at_limit->front() == '[');
    CHECK(limitsCallCount == 2);

    limitsCallCount = 0;
    auto const over = rpc.handle_call("[" + count_calls_request(1, 512) + "," + count_calls_request(2, 513) + "]");
    REQUIRE(over);
    CHECK(*over == PARAMS_REFUSED);
    CHECK(limitsCallCount == 0);
  }

  SECTION("aliased params count once per reference")
  {
    // The second message reuses the first one's 513 element params through an alias: 1026 elements, written once.
    std::string params = "[";
    for (int i = 0; i < 513; ++i) {
      params += i ? ",1" : "1";
    }
    params                += "]";
    std::string const req  = R"([{"jsonrpc": "2.0", "method": "count_calls", "id": "1", "params": &p )" + params +
                            R"(}, {"jsonrpc": "2.0", "method": "count_calls", "id": "2", "params": *p}])";

    auto const resp = rpc.handle_call(req);
    REQUIRE(resp);
    CHECK(*resp == PARAMS_REFUSED);
    CHECK(limitsCallCount == 0);
  }
}

namespace
{
int limitsNotificationCount{0};

void
count_notifications(YAML::Node const & /* params ATS_UNUSED */)
{
  ++limitsNotificationCount;
}
} // namespace

// The batch-sum case above crosses the budget on its last message, so the running total never lands
// exactly on the limit with more messages behind it. An early exit taken at the limit rather than
// past it stops counting there and lets everything after it through uncounted, which is the whole
// amplification back.
TEST_CASE("Request size limits: elements after a total that lands exactly on the limit", "[limits]")
{
  JsonRpcUnitTest rpc;
  REQUIRE(rpc.add_method_handler("count_calls", &count_calls));
  limitsCallCount = 0;

  SECTION("512 + 512 + 1")
  {
    auto const resp = rpc.handle_call("[" + count_calls_request(1, 512) + "," + count_calls_request(2, 512) + "," +
                                      count_calls_request(3, 1) + "]");
    REQUIRE(resp);
    CHECK(*resp == PARAMS_REFUSED);
    CHECK(limitsCallCount == 0);
  }

  SECTION("1024 + 1")
  {
    auto const resp = rpc.handle_call("[" + count_calls_request(1, 1024) + "," + count_calls_request(2, 1) + "]");
    REQUIRE(resp);
    CHECK(*resp == PARAMS_REFUSED);
    CHECK(limitsCallCount == 0);
  }

  SECTION("64 messages of 1024, which is 64 times the budget")
  {
    std::string req = "[";
    for (int i = 0; i < 64; ++i) {
      req += (i ? "," : "") + count_calls_request(i + 1, 1024);
    }
    req += "]";

    auto const resp = rpc.handle_call(req);
    REQUIRE(resp);
    CHECK(*resp == PARAMS_REFUSED);
    CHECK(limitsCallCount == 0);
  }
}

// Notifications get no answer at all, so a refusal is the one case where the client's view changes
// from silence to an error. What matters either way is that no handler ran.
TEST_CASE("Request size limits apply to notifications", "[limits]")
{
  JsonRpcUnitTest rpc;
  REQUIRE(rpc.add_notification_handler("count_notifications", &count_notifications));
  limitsNotificationCount = 0;

  SECTION("a batch of 65 notifications")
  {
    std::string req = "[";
    for (int i = 0; i < 65; ++i) {
      req += std::string(i ? "," : "") + R"({"jsonrpc": "2.0", "method": "count_notifications"})";
    }
    req += "]";

    auto const resp = rpc.handle_call(req);
    REQUIRE(resp);
    CHECK(*resp == BATCH_REFUSED);
    CHECK(limitsNotificationCount == 0);
  }

  SECTION("one notification carrying 1025 params elements")
  {
    std::string req = R"({"jsonrpc": "2.0", "method": "count_notifications", "params": [)";
    for (int i = 0; i < 1025; ++i) {
      req += i ? ",1" : "1";
    }
    req += "]}";

    auto const resp = rpc.handle_call(req);
    REQUIRE(resp);
    CHECK(*resp == PARAMS_REFUSED);
    CHECK(limitsNotificationCount == 0);
  }
}

// A message that fails validation is answered with its own error and never dispatched, and the
// decoder stores params only once every other field has validated. So its params must not consume
// the budget of the valid messages beside it.
TEST_CASE("Request size limits do not count an invalid message's params", "[limits]")
{
  JsonRpcUnitTest rpc;
  REQUIRE(rpc.add_method_handler("count_calls", &count_calls));
  limitsCallCount = 0;

  std::string bad = R"({"jsonrpc": "1.0", "method": "count_calls", "id": "9", "params": [)";
  for (int i = 0; i < 1024; ++i) {
    bad += i ? ",1" : "1";
  }
  bad += "]}";

  auto const resp = rpc.handle_call("[" + bad + "," + count_calls_request(1, 1024) + "]");
  REQUIRE(resp);
  CHECK(resp->front() == '[');
  CHECK(limitsCallCount == 1);
}

namespace
{
// A lookup can match the whole record store, and a request may carry many of them, so what bounds the response is the request's
// record budget rather than the element count. Reaching it needs more records than a default store holds; metrics are not
// bounded by REC_DEFAULT_ELEMENTS_SIZE the way librecords is, so the fixture registers them directly.
constexpr size_t OVER_BUDGET  = rpc::JsonRPCManager::MAX_RECORDS_PER_REQUEST + 1;
constexpr size_t UNDER_BUDGET = 10;

std::string_view const OVER_PREFIX{"proxy.process.test.budget.over."};
std::string_view const UNDER_PREFIX{"proxy.process.test.budget.under."};

// Registered once for the whole binary: the metric store is process global, and re-creating a name relists the same slot.
void
register_budget_metrics()
{
  static bool once = []() -> bool {
    for (size_t i = 0; i < OVER_BUDGET; ++i) {
      ts::Metrics::Counter::createPtr(std::string{OVER_PREFIX} + std::to_string(i));
    }
    for (size_t i = 0; i < UNDER_BUDGET; ++i) {
      ts::Metrics::Counter::createPtr(std::string{UNDER_PREFIX} + std::to_string(i));
    }
    return true;
  }();
  (void)once;
}

std::string
lookup_request(std::string_view id, std::string_view prefix)
{
  return R"({"jsonrpc": "2.0", "method": "admin_lookup_records", "id": ")" + std::string{id} +
         R"(", "params": [{"record_name_regex": "^)" + std::string{prefix} + R"("}]})";
}

/// Records in one message's result, and whether it reported the list as truncated.
struct Answer {
  size_t records{0};
  bool   truncated{false};
};

Answer
read_answer(YAML::Node const &message)
{
  Answer      a;
  auto const &result = message["result"];
  a.records          = result["recordList"].size();
  for (auto &&e : result["errorList"]) {
    // 2012 is RecordError::RESPONSE_TRUNCATED, spelled out rather than taken from the enum so that a renumbering fails here
    // the way it would fail a client.
    if (e["code"] && e["code"].as<std::string>() == "2012") {
      a.truncated = true;
    }
  }
  return a;
}
} // namespace

// The element and batch caps bound how many lookups a request may ask for. They do not bound how much each one answers with:
// one element can match the whole store, so without a budget the response grows with elements x store. Measured before this
// budget existed, 1024 broad elements in a 28KB request produced a 501MB response and 9.8GB of peak RSS, on a build without a
// sanitizer.
TEST_CASE("admin_lookup_records bounds the records one request may return", "[limits][records]")
{
  register_budget_metrics();

  JsonRpcUnitTest rpc;
  REQUIRE(rpc.add_method_handler_with_budget("admin_lookup_records", &rpc::handlers::records::lookup_records));

  SECTION("one element matching more than the budget is cut off and says so")
  {
    auto const resp = rpc.handle_call(lookup_request("1", OVER_PREFIX));
    REQUIRE(resp);

    auto const answer = read_answer(YAML::Load(*resp));
    CHECK(answer.records == rpc::JsonRPCManager::MAX_RECORDS_PER_REQUEST);
    CHECK(answer.truncated);
  }

  SECTION("the budget is one per request, not one per message")
  {
    // Both messages ask for the same over-budget set. A budget held per message would answer each in full and return twice the
    // limit; one per request means the second message finds it already spent.
    auto const resp = rpc.handle_call("[" + lookup_request("1", OVER_PREFIX) + "," + lookup_request("2", OVER_PREFIX) + "]");
    REQUIRE(resp);

    auto const batch = YAML::Load(*resp);
    REQUIRE(batch.IsSequence());
    REQUIRE(batch.size() == 2);

    auto const first  = read_answer(batch[0]);
    auto const second = read_answer(batch[1]);

    CHECK(first.records + second.records == rpc::JsonRPCManager::MAX_RECORDS_PER_REQUEST);
    CHECK(second.records == 0);
    CHECK(first.truncated);
    CHECK(second.truncated);
  }

  SECTION("a lookup inside the budget is answered in full and reports nothing")
  {
    auto const resp = rpc.handle_call(lookup_request("1", UNDER_PREFIX));
    REQUIRE(resp);

    auto const answer = read_answer(YAML::Load(*resp));
    CHECK(answer.records == UNDER_BUDGET);
    CHECK_FALSE(answer.truncated);
  }
}
