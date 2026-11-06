/** @file

  hrw4u-extern: writes the functions a .so's HRW4U_MODULE tables declare as hrw4u extern declarations, the
  manifest the compiler checks a script's calls against. It reads the .so as a file and runs nothing from it.

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

#include "manifest.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

int
main(int argc, char *argv[])
{
  if (argc != 2) {
    std::cerr << "usage: hrw4u-extern <file.so>\n";
    return 2;
  }

  std::string path = argv[1];

  if (!std::filesystem::is_regular_file(path)) {
    std::cerr << "hrw4u-extern: " << path << ": not a regular file\n";
    return 1;
  }

  std::ifstream in(path, std::ios::binary);

  if (!in) {
    std::cerr << "hrw4u-extern: " << path << ": cannot open\n";
    return 1;
  }

  std::string image{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
  std::string error;
  auto        section = hrw4u::manifest::find_section(image, error);

  if (!section) {
    std::cerr << "hrw4u-extern: " << path << ": " << error << "\n";
    return 1;
  }

  auto modules = hrw4u::manifest::parse(*section, error);

  if (!modules) {
    std::cerr << "hrw4u-extern: " << path << ": manifest " << error << "\n";
    return 1;
  }
  std::cout << hrw4u::manifest::render(*modules, std::filesystem::path(path).filename().string());
  return 0;
}
