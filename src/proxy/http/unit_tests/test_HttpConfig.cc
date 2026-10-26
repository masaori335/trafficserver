/** @file

  Catch-based tests for HttpConfig.cc.

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

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <string>

#include "proxy/http/HttpConfig.h"
#include "iocore/net/SessionSharingAPIEnums.h"
#include "swoc/swoc_ip.h"

// The pooled outbound-session lookup only evaluates a validator when its bit is
// set in the match mask. A mask without MASK_CERT therefore never compares the
// client certificate of a pooled TLS session against the certificate the new
// transaction would present, so a session authenticated with one client
// certificate can be handed to a transaction configured for another. Because
// the outbound certificate is per-transaction overridable, that is an identity
// confusion at the origin, so the default value has to carry the bit.
TEST_CASE("server_session_sharing.match parsing", "[HttpConfig]")
{
  MgmtByte mask = 0;

  // Each section pins the whole mask rather than individual bits, so a validator
  // that is silently added to or dropped from a value is a test failure.

  SECTION("the default value matches address, host, host/SNI sync, and the client certificate")
  {
    REQUIRE(HttpConfig::load_server_session_sharing_match("both", mask) == true);
    CHECK(mask == (TS_SERVER_SESSION_SHARING_MATCH_MASK_IP | TS_SERVER_SESSION_SHARING_MATCH_MASK_HOSTONLY |
                   TS_SERVER_SESSION_SHARING_MATCH_MASK_HOSTSNISYNC | TS_SERVER_SESSION_SHARING_MATCH_MASK_CERT));
  }

  SECTION("an explicit list selects exactly the named validators")
  {
    REQUIRE(HttpConfig::load_server_session_sharing_match("ip,sni,cert", mask) == true);
    CHECK(mask == (TS_SERVER_SESSION_SHARING_MATCH_MASK_IP | TS_SERVER_SESSION_SHARING_MATCH_MASK_SNI |
                   TS_SERVER_SESSION_SHARING_MATCH_MASK_CERT));
  }

  SECTION("none disables every validator")
  {
    REQUIRE(HttpConfig::load_server_session_sharing_match("none", mask) == true);
    CHECK(mask == 0);
  }

  SECTION("ip,host selects what the default selected before cert was added")
  {
    MgmtByte explicit_mask = 0;
    REQUIRE(HttpConfig::load_server_session_sharing_match("ip,host", explicit_mask) == true);
    CHECK(explicit_mask == (TS_SERVER_SESSION_SHARING_MATCH_MASK_IP | TS_SERVER_SESSION_SHARING_MATCH_MASK_HOSTONLY |
                            TS_SERVER_SESSION_SHARING_MATCH_MASK_HOSTSNISYNC));
  }

  SECTION("an unknown value is rejected")
  {
    CHECK(HttpConfig::load_server_session_sharing_match("nonsense", mask) == false);
  }
}

// parse_redirect_actions marks the special-purpose ranges with their class action and then fills
// everything left over with the routable action. A range that is not marked therefore inherits
// the routable action, which by default is follow. These cases pin the class of 0.0.0.0/8 and of
// IPv4-mapped addresses, which are classified by the IPv4 address they embed.
TEST_CASE("redirect.actions address classes", "[HttpConfig]")
{
  using RedirectEnabled::Action;

  Action                                      self_action = Action::INVALID;
  std::unique_ptr<RedirectEnabled::ActionMap> actions;

  auto load = [&](char const *value) {
    std::string text{value}; // parse_redirect_actions tokenizes a writable buffer.
    actions.reset(HttpConfig::parse_redirect_actions(text.data(), self_action));
    REQUIRE(actions != nullptr);
  };
  // The action the map gives a redirect to @a addr, classified the way the transaction classifies
  // it. The transaction checks for a self address first; that check is covered by the urtest.
  auto action_for = [&](swoc::IPAddr const &addr) {
    auto spot = actions->find(RedirectEnabled::classified_address(addr));
    REQUIRE(spot != actions->end());
    return std::get<1>(*spot);
  };
  // The IPv4-mapped IPv6 form of @a addr. The text parser misreads the dotted form
  // "::ffff:a.b.c.d" (it yields ::ffff), so build it from the IPv4 address.
  auto mapped = [](char const *addr) { return swoc::IPAddr{swoc::IP6Addr{swoc::IP4Addr{addr}}}; };

  // In its own section so that a broken unmapping does not stop the sections that do not use it.
  SECTION("a mapped address is classified by its IPv4 address")
  {
    REQUIRE(mapped("127.0.0.1").ip6().is_mapped_ip4());
    CHECK(RedirectEnabled::classified_address(mapped("127.0.0.1")) == swoc::IPAddr{swoc::IP4Addr{INADDR_LOOPBACK}});
  }

  SECTION("the default value returns a redirect into 0.0.0.0/8 instead of following it")
  {
    load("routable:follow");
    CHECK(action_for(swoc::IPAddr{"0.0.0.0"}) == Action::RETURN);
    CHECK(action_for(swoc::IPAddr{"0.0.0.1"}) == Action::RETURN);
    CHECK(action_for(swoc::IPAddr{"0.255.255.255"}) == Action::RETURN);
    // The first address past 0.0.0.0/8 is routable and is still followed.
    CHECK(action_for(swoc::IPAddr{"1.0.0.0"}) == Action::FOLLOW);
  }

  SECTION("0.0.0.0/8 takes the loopback action")
  {
    load("loopback:follow,routable:return,default:reject");
    CHECK(action_for(swoc::IPAddr{"0.0.0.1"}) == Action::FOLLOW);
    CHECK(action_for(swoc::IPAddr{"127.0.0.1"}) == Action::FOLLOW);
    CHECK(action_for(swoc::IPAddr{"1.0.0.1"}) == Action::RETURN);
    CHECK(action_for(swoc::IPAddr{"10.0.0.1"}) == Action::REJECT);
  }

  SECTION("the default value returns a redirect to a mapped special-purpose address instead of following it")
  {
    load("routable:follow");
    CHECK(action_for(mapped("127.0.0.1")) == Action::RETURN);
    CHECK(action_for(mapped("10.0.0.1")) == Action::RETURN);
    CHECK(action_for(mapped("0.0.0.0")) == Action::RETURN);
    CHECK(action_for(mapped("0.0.0.1")) == Action::RETURN);
    // A mapped routable address is still followed.
    CHECK(action_for(mapped("8.8.8.8")) == Action::FOLLOW);
  }

  SECTION("a mapped address takes the action of the IPv4 address it embeds")
  {
    load("loopback:reject,private:follow,routable:return,default:reject");
    CHECK(action_for(mapped("127.0.0.1")) == Action::REJECT);
    CHECK(action_for(mapped("10.0.0.1")) == Action::FOLLOW);
    CHECK(action_for(mapped("192.168.1.1")) == Action::FOLLOW);
    CHECK(action_for(mapped("8.8.8.8")) == Action::RETURN);
    // Addresses that are not mapped are unchanged.
    CHECK(action_for(swoc::IPAddr{"::1"}) == Action::REJECT);
    CHECK(action_for(swoc::IPAddr{"fc00::1"}) == Action::FOLLOW);
    CHECK(action_for(swoc::IPAddr{"2001:db8::1"}) == Action::RETURN);
    // Other IPv6 forms that carry an IPv4 address are not IPv4-mapped and keep their own class.
    CHECK(action_for(swoc::IPAddr{"::7f00:1"}) == Action::RETURN);
    CHECK(action_for(swoc::IPAddr{"::ffff:0:7f00:1"}) == Action::RETURN);
  }
}
