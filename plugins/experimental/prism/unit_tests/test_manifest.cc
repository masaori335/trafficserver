/** @file

  Unit tests for reading the manifest section of a .so.

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

#include "hrw4u/extension.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>

namespace
{
using namespace std::string_view_literals;

constexpr std::string_view UA_MANIFEST = "hrw4u-manifest 1\n"
                                         "module example::ua\n"
                                         "fn Example::UA::IsBot pure bool sview\n"
                                         "end\n";

void
put_le(std::string &image, size_t at, size_t width, uint64_t value)
{
  for (size_t i = 0; i < width; ++i) {
    image[at + i] = static_cast<char>(value >> (8 * i));
  }
}

// A 64-bit little-endian ELF file holding a string table and one section, as a linker lays them out.
std::string
elf_image(std::string_view section_name, std::string_view contents)
{
  std::string shstrtab    = std::string("\0.shstrtab\0"sv) + std::string(section_name) + '\0';
  size_t      strtab_at   = 64;
  size_t      contents_at = strtab_at + shstrtab.size();
  size_t      shoff       = contents_at + contents.size();
  std::string image(shoff + 3 * 64, '\0');

  image.replace(0, 4,
                "\x7f"
                "ELF");
  image[4] = 2; // ELFCLASS64
  image[5] = 1; // ELFDATA2LSB
  image[6] = 1; // EV_CURRENT
  put_le(image, 0x28, 8, shoff);
  put_le(image, 0x3A, 2, 64); // e_shentsize
  put_le(image, 0x3C, 2, 3);  // e_shnum: the null section, .shstrtab, the manifest
  put_le(image, 0x3E, 2, 1);  // e_shstrndx

  size_t strtab_hdr = shoff + 64;
  put_le(image, strtab_hdr, 4, 1);
  put_le(image, strtab_hdr + 4, 4, 3); // SHT_STRTAB
  put_le(image, strtab_hdr + 0x18, 8, strtab_at);
  put_le(image, strtab_hdr + 0x20, 8, shstrtab.size());

  size_t section_hdr = shoff + 128;
  put_le(image, section_hdr, 4, 11);
  put_le(image, section_hdr + 4, 4, 1); // SHT_PROGBITS
  put_le(image, section_hdr + 0x18, 8, contents_at);
  put_le(image, section_hdr + 0x20, 8, contents.size());

  image.replace(strtab_at, shstrtab.size(), shstrtab);
  image.replace(contents_at, contents.size(), contents);
  return image;
}

// A 64-bit Mach-O file with one segment holding one section.
std::string
macho_image(std::string_view segment_name, std::string_view section_name, std::string_view contents)
{
  size_t      segment_at  = 32;
  size_t      section_at  = segment_at + 72;
  size_t      contents_at = section_at + 80;
  std::string image(contents_at + contents.size(), '\0');

  put_le(image, 0, 4, 0xfeedfacf); // MH_MAGIC_64
  put_le(image, 16, 4, 1);         // ncmds
  put_le(image, 20, 4, 72 + 80);   // sizeofcmds

  put_le(image, segment_at, 4, 0x19); // LC_SEGMENT_64
  put_le(image, segment_at + 4, 4, 72 + 80);
  image.replace(segment_at + 8, segment_name.size(), segment_name);
  put_le(image, segment_at + 64, 4, 1); // nsects

  image.replace(section_at, section_name.size(), section_name);
  image.replace(section_at + 16, segment_name.size(), segment_name);
  put_le(image, section_at + 40, 8, contents.size());
  put_le(image, section_at + 48, 4, contents_at);

  image.replace(contents_at, contents.size(), contents);
  return image;
}

std::string
read_file(const char *path)
{
  std::ifstream in(path, std::ios::binary);

  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::string
dump(std::string_view image, std::string_view source)
{
  std::string error;
  auto        section = hrw4u::manifest::find_section(image, error);

  REQUIRE(section.has_value());
  auto modules = hrw4u::manifest::parse(*section, error);

  REQUIRE(modules.has_value());
  return hrw4u::manifest::render(*modules, source);
}
} // namespace

TEST_CASE("a manifest renders as extern declarations")
{
  std::string error;
  auto        modules = hrw4u::manifest::parse("hrw4u-manifest 1\n"
                                                      "module m::one\n"
                                                      "fn A::Pure pure bool sview\n"
                                                      "fn A::Effect effect sview bool sview\n"
                                                      "fn A::NoArgs pure bool\n"
                                                      "fn A::Count pure i64 sview i64\n"
                                                      "end\n"
                                                      "\0\0\0"
                                                      "hrw4u-manifest 1\n"
                                                      "module m::two\n"
                                                      "fn B::Twice pure sview sview\n"
                                                      "end\n"
                                                      "\0"sv,
                                               error);

  REQUIRE(modules.has_value());
  CHECK(hrw4u::manifest::render(*modules, "lib.so") == "# generated by hrw4u-extern from lib.so; do not edit\n"
                                                       "\n"
                                                       "# module m::one\n"
                                                       "extern A::Pure(string) -> bool pure;\n"
                                                       "extern A::Effect(bool, string) -> string;\n"
                                                       "extern A::NoArgs() -> bool pure;\n"
                                                       "extern A::Count(string, int64) -> int64 pure;\n"
                                                       "\n"
                                                       "# module m::two\n"
                                                       "extern B::Twice(string) -> string pure;\n");
}

TEST_CASE("a load function renders with its keyword")
{
  std::string error;
  auto        modules = hrw4u::manifest::parse("hrw4u-manifest 1\nmodule m\nfn T::Load load sview sview\nend\n", error);

  REQUIRE(modules.has_value());
  CHECK(hrw4u::manifest::render(*modules, "lib.so") == "# generated by hrw4u-extern from lib.so; do not edit\n"
                                                       "\n"
                                                       "# module m\n"
                                                       "extern T::Load(string) -> string load;\n");
}

TEST_CASE("a malformed manifest names the line")
{
  std::string error;

  CHECK_FALSE(hrw4u::manifest::parse("hrw4u-manifest 2\nmodule m\nend\n", error).has_value());
  CHECK(error == "line 1: unsupported manifest version: hrw4u-manifest 2");

  CHECK_FALSE(hrw4u::manifest::parse("hrw4u-manifest 1\nfn A pure bool\nend\n", error).has_value());
  CHECK(error == "line 2: expected 'module <name>'");

  CHECK_FALSE(hrw4u::manifest::parse("hrw4u-manifest 1\nmodule m\nfn A pure int\nend\n", error).has_value());
  CHECK(error == "line 3: unknown type: int");

  CHECK_FALSE(hrw4u::manifest::parse("hrw4u-manifest 1\nmodule m\nfn A sometimes bool\nend\n", error).has_value());
  CHECK(error == "line 3: unknown effect: sometimes");

  CHECK_FALSE(hrw4u::manifest::parse("hrw4u-manifest 1\nmodule m\nfn A pure\nend\n", error).has_value());
  CHECK(error == "line 3: expected 'fn <name> <effect> <result> [<parameter> ...]'");

  CHECK_FALSE(hrw4u::manifest::parse("hrw4u-manifest 1\nmodule m\nfn A pure bool\n", error).has_value());
  CHECK(error == "line 4: module m has no 'end'");

  CHECK_FALSE(hrw4u::manifest::parse("module m\n", error).has_value());
  CHECK(error == "line 1: expected 'hrw4u-manifest 1'");

  CHECK_FALSE(hrw4u::manifest::parse("hrw4u-manifest 1\nmodule a\nend\nhrw4u-manifest 1\n", error).has_value());
  CHECK(error == "line 5: expected 'module <name>'");

  CHECK_FALSE(hrw4u::manifest::parse("hrw4u-manifest 1\nmodule a\nfn  pure bool\nend\n", error).has_value());
  CHECK(error == "line 3: bad function name: ");

  CHECK_FALSE(hrw4u::manifest::parse("hrw4u-manifest 1\nmodule a\nfn F(x) pure bool\nend\n", error).has_value());
  CHECK(error == "line 3: bad function name: F(x)");

  CHECK_FALSE(hrw4u::manifest::parse("hrw4u-manifest 1\nmodule a;b\nend\n", error).has_value());
  CHECK(error == "line 2: bad module name: a;b");
}

TEST_CASE("a module with no functions is kept")
{
  std::string error;
  auto        modules = hrw4u::manifest::parse("hrw4u-manifest 1\nmodule empty\nend\n", error);

  REQUIRE(modules.has_value());
  REQUIRE(modules->size() == 1);
  CHECK((*modules)[0].functions.empty());
}

TEST_CASE("the manifest section is found in an ELF file")
{
  CHECK(dump(elf_image(HRW4U_MANIFEST_ELF_SECTION, UA_MANIFEST), "ua.so") == "# generated by hrw4u-extern from ua.so; do not edit\n"
                                                                             "\n"
                                                                             "# module example::ua\n"
                                                                             "extern Example::UA::IsBot(string) -> bool pure;\n");
}

TEST_CASE("the manifest section is found in a Mach-O file")
{
  CHECK(dump(macho_image(HRW4U_MANIFEST_MACHO_SEGMENT, HRW4U_MANIFEST_MACHO_SECTION, UA_MANIFEST), "ua.so") ==
        "# generated by hrw4u-extern from ua.so; do not edit\n"
        "\n"
        "# module example::ua\n"
        "extern Example::UA::IsBot(string) -> bool pure;\n");
}

TEST_CASE("a file without the section, or not an object file, is refused")
{
  std::string error;

  CHECK_FALSE(hrw4u::manifest::find_section(elf_image(".data", UA_MANIFEST), error).has_value());
  CHECK(error == "no " HRW4U_MANIFEST_ELF_SECTION " section");

  CHECK_FALSE(hrw4u::manifest::find_section(macho_image("__DATA", "__data", UA_MANIFEST), error).has_value());
  CHECK(error == "no " HRW4U_MANIFEST_MACHO_SEGMENT "," HRW4U_MANIFEST_MACHO_SECTION " section");

  CHECK_FALSE(hrw4u::manifest::find_section("#!/bin/sh\n", error).has_value());
  CHECK(error == "not a 64-bit little-endian ELF or Mach-O file");
}

TEST_CASE("a truncated file is refused, not read past its end")
{
  std::string error;
  std::string elf   = elf_image(HRW4U_MANIFEST_ELF_SECTION, UA_MANIFEST);
  std::string macho = macho_image(HRW4U_MANIFEST_MACHO_SEGMENT, HRW4U_MANIFEST_MACHO_SECTION, UA_MANIFEST);

  // The last size cuts into the manifest's section header, in the middle of its size field.
  for (size_t size : {size_t{5}, size_t{40}, size_t{100}, elf.size() - 64 + 0x24}) {
    CHECK_FALSE(hrw4u::manifest::find_section(std::string_view(elf).substr(0, size), error).has_value());
  }
  for (size_t size : {size_t{5}, size_t{40}, size_t{120}, macho.size() - 1}) {
    CHECK_FALSE(hrw4u::manifest::find_section(std::string_view(macho).substr(0, size), error).has_value());
  }

  // With no load commands, only the header's own size check sees a cut inside the header.
  put_le(macho, 16, 4, 0);
  CHECK_FALSE(hrw4u::manifest::find_section(std::string_view(macho).substr(0, 24), error).has_value());
  CHECK(error == "truncated or corrupt object file");
}

TEST_CASE("headers that point outside the file are refused")
{
  std::string error;
  std::string elf = elf_image(HRW4U_MANIFEST_ELF_SECTION, UA_MANIFEST);

  put_le(elf, 0x28, 8, UINT64_MAX - 8); // e_shoff, which a later sum would wrap
  CHECK_FALSE(hrw4u::manifest::find_section(elf, error).has_value());
  CHECK(error == "truncated or corrupt object file");

  elf = elf_image(HRW4U_MANIFEST_ELF_SECTION, UA_MANIFEST);
  put_le(elf, 0x3C, 2, 0); // e_shnum 0: the count is in section 0
  CHECK_FALSE(hrw4u::manifest::find_section(elf, error).has_value());
  CHECK(error == "extended ELF section numbering is not supported");

  std::string macho = macho_image(HRW4U_MANIFEST_MACHO_SEGMENT, HRW4U_MANIFEST_MACHO_SECTION, UA_MANIFEST);

  put_le(macho, 32 + 64, 4, 2); // nsects past the segment command's size
  CHECK_FALSE(hrw4u::manifest::find_section(macho, error).has_value());
  CHECK(error == "truncated or corrupt object file");

  macho = macho_image(HRW4U_MANIFEST_MACHO_SEGMENT, HRW4U_MANIFEST_MACHO_SECTION, UA_MANIFEST);
  put_le(macho, 20, 4, 8); // sizeofcmds smaller than the segment command
  CHECK_FALSE(hrw4u::manifest::find_section(macho, error).has_value());
  CHECK(error == "truncated or corrupt object file");
}

TEST_CASE("a section with no bytes in the file is refused")
{
  std::string error;
  std::string elf = elf_image(HRW4U_MANIFEST_ELF_SECTION, UA_MANIFEST);

  put_le(elf, elf.size() - 64 + 4, 4, 8); // SHT_NOBITS
  CHECK_FALSE(hrw4u::manifest::find_section(elf, error).has_value());
  CHECK(error == HRW4U_MANIFEST_ELF_SECTION " holds no bytes in the file");

  std::string macho = macho_image(HRW4U_MANIFEST_MACHO_SEGMENT, HRW4U_MANIFEST_MACHO_SECTION, UA_MANIFEST);

  put_le(macho, 32 + 72 + 64, 4, 0x1); // S_ZEROFILL
  CHECK_FALSE(hrw4u::manifest::find_section(macho, error).has_value());
  CHECK(error == HRW4U_MANIFEST_MACHO_SEGMENT "," HRW4U_MANIFEST_MACHO_SECTION " holds no bytes in the file");
}

TEST_CASE("the example extension's manifest is read from its .so")
{
  CHECK(dump(read_file(EXAMPLE_UA_SO), "prism_ext_example_ua.so") ==
        "# generated by hrw4u-extern from prism_ext_example_ua.so; do not edit\n"
        "\n"
        "# module example::ua\n"
        "extern Example::UA::IsBot(string) -> bool pure;\n"
        "extern Example::UA::Family(string) -> string pure;\n");
}

#ifdef PRISM_SO
TEST_CASE("prism.so's bindings are read from its .so")
{
  CHECK(dump(read_file(PRISM_SO), "prism.so") == "# generated by hrw4u-extern from prism.so; do not edit\n"
                                                 "\n"
                                                 "# module prism\n"
                                                 "extern prism::Crypto::Base64::Encode(string) -> string pure;\n"
                                                 "extern prism::Crypto::HMAC::SHA256::Sign(string, string) -> string pure;\n"
                                                 "extern prism::File::Line::Read(string) -> string load;\n"
                                                 "extern prism::Crypto::Hex::Decode(string) -> string pure;\n");
}
#endif
