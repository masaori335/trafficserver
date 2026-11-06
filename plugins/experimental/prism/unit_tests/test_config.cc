/** @file

  Unit tests for prism.so's YAML settings.

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

#include "config.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>

using namespace hrw4u;

TEST_CASE("read_config sets the transaction memory limit in bytes")
{
  Settings    settings;
  std::string error;

  REQUIRE(read_config("prism:\n  txn_memory_limit: 4096\n", settings, error));
  CHECK(settings.txn_memory_limit == 4096);

  REQUIRE(read_config("prism:\n  txn_memory_limit: 0\n", settings, error));
  CHECK(settings.txn_memory_limit == 0);

  REQUIRE(read_config("prism:\n  txn_memory_limit: 18446744073709551615\n", settings, error));
  CHECK(settings.txn_memory_limit == SIZE_MAX);
}

TEST_CASE("read_config keeps the default of a setting left out")
{
  Settings    settings;
  std::string error;

  REQUIRE(read_config("prism: {}\n", settings, error));
  CHECK(settings.txn_memory_limit == 64 * 1024);

  SECTION("even over settings set before")
  {
    REQUIRE(read_config("prism:\n  txn_memory_limit: 1\n", settings, error));
    REQUIRE(read_config("prism: {}\n", settings, error));
    CHECK(settings.txn_memory_limit == 64 * 1024);
  }
}

TEST_CASE("read_config leaves the settings as they were when it refuses")
{
  Settings    settings;
  std::string error;

  settings.txn_memory_limit = 1;
  CHECK_FALSE(read_config("prism:\n  txn_memory_limit: 2\n  timezone: GMT\n", settings, error));
  CHECK(settings.txn_memory_limit == 1);
}

TEST_CASE("read_config refuses what it does not know")
{
  auto refused = [](std::string_view yaml) {
    Settings    settings;
    std::string error;

    INFO(yaml);
    CHECK_FALSE(read_config(yaml, settings, error));
    return error;
  };

  CHECK(refused("prism:\n  timezone: GMT\n") == "unknown setting prism.timezone");
  CHECK(refused("prism:\n  txn_memory_limit: [1]\n") == "prism.txn_memory_limit is not a value");
  CHECK(refused("prism:\n  txn_memory_limit: 1\n  txn_memory_limit: 2\n") == "prism.txn_memory_limit is set twice");
  CHECK(refused("prism:\n  txn_memory_limit: -1\n") == "prism.txn_memory_limit: not a byte count: -1");
  CHECK(refused("prism:\n  txn_memory_limit: +1\n") == "prism.txn_memory_limit: not a byte count: +1");
  CHECK(refused("prism:\n  txn_memory_limit: 64K\n") == "prism.txn_memory_limit: not a byte count: 64K");
  CHECK(refused("prism:\n  txn_memory_limit: 0x40\n") == "prism.txn_memory_limit: not a byte count: 0x40");
  CHECK(refused("prism:\n  txn_memory_limit: 18446744073709551616\n") ==
        "prism.txn_memory_limit: not a byte count: 18446744073709551616");
  CHECK(refused("prism:\n  txn_memory_limit: \"\"\n") == "prism.txn_memory_limit: not a byte count: ");
  CHECK(refused("prism:\n  txn_memory_limit:\n") == "prism.txn_memory_limit is not a value");
  CHECK(refused("prism:\n  ~: 1\n") == "a key of prism is not a name");
  CHECK(refused("prism:\n  ? [a]\n  : 1\n") == "a key of prism is not a name");
  CHECK(refused("txn_memory_limit: 1\n") == "the configuration has no prism map");
  CHECK(refused("hrw4u:\n  txn_memory_limit: 1\n") == "the configuration has no prism map");
  CHECK(refused("prism: 1\n") == "the configuration has no prism map");
  CHECK(refused("") == "the configuration has no prism map");
  CHECK(refused("prism: [\n").starts_with("the configuration does not parse: "));
}

TEST_CASE("read_config_file names the file it could not read or use")
{
  Settings    settings;
  std::string error;

  CHECK_FALSE(read_config_file("/nonexistent/prism.yaml", settings, error));
  CHECK(error == "cannot read /nonexistent/prism.yaml");

  auto path = (std::filesystem::temp_directory_path() / "test_prism_config.yaml").string();

  std::ofstream(path) << "prism:\n  txn_memory_limit: 64K\n";
  CHECK_FALSE(read_config_file(path, settings, error));
  CHECK(error == path + ": prism.txn_memory_limit: not a byte count: 64K");

  std::ofstream(path) << "prism:\n  txn_memory_limit: 4096\n";
  CHECK(read_config_file(path, settings, error));
  CHECK(settings.txn_memory_limit == 4096);
  std::filesystem::remove(path);
}
