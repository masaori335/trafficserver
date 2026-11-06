/** @file

  Reads the manifest section HRW4U_MODULE writes into a .so, from the file, without loading it.

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

#include <algorithm>
#include <cstdint>

namespace hrw4u::manifest
{
namespace
{
  // Decoded byte by byte, so a big-endian host reads a little-endian file too.
  bool
  read_le(std::string_view image, uint64_t at, size_t width, uint64_t &value)
  {
    if (at > image.size() || image.size() - at < width) {
      return false;
    }
    value = 0;
    for (size_t i = 0; i < width; ++i) {
      value |= static_cast<uint64_t>(static_cast<unsigned char>(image[at + i])) << (8 * i);
    }
    return true;
  }

  std::optional<std::string_view>
  slice(std::string_view image, uint64_t at, uint64_t size)
  {
    if (at > image.size() || image.size() - at < size) {
      return std::nullopt;
    }
    return image.substr(at, size);
  }

  constexpr std::string_view TRUNCATED = "truncated or corrupt object file";

  std::optional<std::string_view>
  find_elf_section(std::string_view image, std::string &error)
  {
    constexpr uint32_t SHT_NOBITS = 8;
    constexpr uint64_t SHDR_SIZE  = 0x40;
    uint64_t           shoff, shentsize, shnum, shstrndx;

    if (!read_le(image, 0x28, 8, shoff) || !read_le(image, 0x3A, 2, shentsize) || !read_le(image, 0x3C, 2, shnum) ||
        !read_le(image, 0x3E, 2, shstrndx)) {
      error = TRUNCATED;
      return std::nullopt;
    }
    if (shnum == 0) {
      error = "extended ELF section numbering is not supported";
      return std::nullopt;
    }
    // Checked once here, so no section header offset below can wrap past the end of the file.
    if (shentsize < SHDR_SIZE || shoff > image.size() || shnum > (image.size() - shoff) / shentsize || shstrndx >= shnum) {
      error = TRUNCATED;
      return std::nullopt;
    }

    uint64_t strtab_at, strtab_size;

    if (!read_le(image, shoff + shstrndx * shentsize + 0x18, 8, strtab_at) ||
        !read_le(image, shoff + shstrndx * shentsize + 0x20, 8, strtab_size)) {
      error = TRUNCATED;
      return std::nullopt;
    }
    auto strtab = slice(image, strtab_at, strtab_size);

    if (!strtab) {
      error = TRUNCATED;
      return std::nullopt;
    }

    for (uint64_t i = 0; i < shnum; ++i) {
      uint64_t hdr = shoff + i * shentsize;
      uint64_t name, type, at, size;

      if (!read_le(image, hdr, 4, name) || !read_le(image, hdr + 4, 4, type) || !read_le(image, hdr + 0x18, 8, at) ||
          !read_le(image, hdr + 0x20, 8, size) || name >= strtab->size()) {
        error = TRUNCATED;
        return std::nullopt;
      }

      std::string_view section_name = strtab->substr(name);

      section_name = section_name.substr(0, section_name.find('\0'));
      if (section_name != HRW4U_MANIFEST_ELF_SECTION) {
        continue;
      }
      if (type == SHT_NOBITS) {
        error = HRW4U_MANIFEST_ELF_SECTION " holds no bytes in the file";
        return std::nullopt;
      }
      auto contents = slice(image, at, size);

      if (!contents) {
        error = TRUNCATED;
      }
      return contents;
    }
    error = "no " HRW4U_MANIFEST_ELF_SECTION " section";
    return std::nullopt;
  }

  // Mach-O pads a segment or section name to 16 bytes with NULs.
  std::string_view
  macho_name(std::string_view field)
  {
    return field.substr(0, field.find('\0'));
  }

  std::optional<std::string_view>
  find_macho_section(std::string_view image, std::string &error)
  {
    constexpr uint64_t LC_SEGMENT_64     = 0x19;
    constexpr uint64_t HEADER_SIZE       = 32;
    constexpr uint64_t SEGMENT_SIZE      = 72;
    constexpr uint64_t SECTION_SIZE      = 80;
    constexpr uint64_t SECTION_TYPE      = 0xff;
    constexpr uint64_t S_ZEROFILL        = 0x1;
    constexpr uint64_t S_GB_ZEROFILL     = 0xc;
    constexpr uint64_t S_THREAD_LOCAL_ZF = 0x12;
    uint64_t           ncmds, sizeofcmds;

    if (image.size() < HEADER_SIZE || !read_le(image, 16, 4, ncmds) || !read_le(image, 20, 4, sizeofcmds) ||
        sizeofcmds > image.size() - HEADER_SIZE) {
      error = TRUNCATED;
      return std::nullopt;
    }

    uint64_t cmds_end = HEADER_SIZE + sizeofcmds;
    uint64_t cmd_at   = HEADER_SIZE;

    for (uint64_t i = 0; i < ncmds; ++i) {
      uint64_t cmd, cmdsize;

      if (cmds_end - cmd_at < 8 || !read_le(image, cmd_at, 4, cmd) || !read_le(image, cmd_at + 4, 4, cmdsize) || cmdsize < 8 ||
          cmdsize > cmds_end - cmd_at) {
        error = TRUNCATED;
        return std::nullopt;
      }
      if (cmd == LC_SEGMENT_64) {
        uint64_t nsects;

        if (cmdsize < SEGMENT_SIZE || !read_le(image, cmd_at + 64, 4, nsects) || nsects > (cmdsize - SEGMENT_SIZE) / SECTION_SIZE) {
          error = TRUNCATED;
          return std::nullopt;
        }
        for (uint64_t s = 0; s < nsects; ++s) {
          uint64_t sect_at  = cmd_at + SEGMENT_SIZE + s * SECTION_SIZE;
          auto     sectname = slice(image, sect_at, 16);
          auto     segname  = slice(image, sect_at + 16, 16);
          uint64_t size, at, flags;

          if (!sectname || !segname || !read_le(image, sect_at + 40, 8, size) || !read_le(image, sect_at + 48, 4, at) ||
              !read_le(image, sect_at + 64, 4, flags)) {
            error = TRUNCATED;
            return std::nullopt;
          }
          if (macho_name(*segname) == HRW4U_MANIFEST_MACHO_SEGMENT && macho_name(*sectname) == HRW4U_MANIFEST_MACHO_SECTION) {
            uint64_t type = flags & SECTION_TYPE;

            if (type == S_ZEROFILL || type == S_GB_ZEROFILL || type == S_THREAD_LOCAL_ZF) {
              error = HRW4U_MANIFEST_MACHO_SEGMENT "," HRW4U_MANIFEST_MACHO_SECTION " holds no bytes in the file";
              return std::nullopt;
            }
            auto contents = slice(image, at, size);

            if (!contents) {
              error = TRUNCATED;
            }
            return contents;
          }
        }
      }
      cmd_at += cmdsize;
    }
    error = "no " HRW4U_MANIFEST_MACHO_SEGMENT "," HRW4U_MANIFEST_MACHO_SECTION " section";
    return std::nullopt;
  }

  std::vector<std::string_view>
  split_words(std::string_view line)
  {
    std::vector<std::string_view> words;

    while (!line.empty()) {
      size_t end = line.find(' ');

      words.push_back(line.substr(0, end));
      if (end == std::string_view::npos) {
        break;
      }
      line.remove_prefix(end + 1);
    }
    return words;
  }

  // The rule HRW4U_DEF enforces on the names it writes.
  bool
  is_name(std::string_view word)
  {
    return !word.empty() && std::ranges::all_of(word, [](char c) {
      return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == ':';
    });
  }

  bool
  is_type(std::string_view word)
  {
    return word == "bool" || word == "sview" || word == "i64";
  }

  std::string_view
  script_type(std::string_view type)
  {
    if (type == "sview") {
      return "string";
    }
    if (type == "i64") {
      return "int64";
    }
    return type;
  }
} // namespace

std::optional<std::string_view>
find_section(std::string_view image, std::string &error)
{
  if (image.starts_with("\x7f"
                        "ELF") &&
      image.size() > 5 && image[4] == 2 && image[5] == 1) {
    return find_elf_section(image, error);
  }

  uint64_t magic;

  if (read_le(image, 0, 4, magic) && magic == 0xfeedfacf) {
    return find_macho_section(image, error);
  }
  error = "not a 64-bit little-endian ELF or Mach-O file";
  return std::nullopt;
}

std::optional<std::vector<Module>>
parse(std::string_view section, std::string &error)
{
  enum class State { Outside, Header, Inside };

  std::vector<Module> modules;
  State               state  = State::Outside;
  size_t              number = 0;

  auto fail = [&](std::string_view what) {
    error = "line " + std::to_string(number) + ": " + std::string(what);
    return std::nullopt;
  };

  while (!section.empty()) {
    size_t           end  = section.find('\n');
    std::string_view line = section.substr(0, end);

    if (end == std::string_view::npos) {
      section = {};
    } else {
      section.remove_prefix(end + 1);
    }
    ++number;

    switch (state) {
    case State::Outside:
      // Blocks from separate tables may be padded apart with NULs.
      line.remove_prefix(std::min(line.find_first_not_of('\0'), line.size()));
      if (line.empty()) {
        continue;
      }
      if (line != HRW4U_MANIFEST_HEADER) {
        if (line.starts_with("hrw4u-manifest ")) {
          return fail("unsupported manifest version: " + std::string(line));
        }
        return fail("expected '" HRW4U_MANIFEST_HEADER "'");
      }
      state = State::Header;
      break;
    case State::Header: {
      auto words = split_words(line);

      if (words.size() != 2 || words[0] != "module") {
        return fail("expected 'module <name>'");
      }
      if (!is_name(words[1])) {
        return fail("bad module name: " + std::string(words[1]));
      }
      modules.push_back({std::string(words[1]), {}});
      state = State::Inside;
      break;
    }
    case State::Inside: {
      if (line == "end") {
        state = State::Outside;
        break;
      }

      auto words = split_words(line);

      if (words.size() < 4 || words[0] != "fn") {
        return fail("expected 'fn <name> <effect> <result> [<parameter> ...]'");
      }
      if (!is_name(words[1])) {
        return fail("bad function name: " + std::string(words[1]));
      }
      if (words[2] != "pure" && words[2] != "effect" && words[2] != "load") {
        return fail("unknown effect: " + std::string(words[2]));
      }

      Function fn{std::string(words[1]), std::string(words[2]), std::string(words[3]), {}};

      for (size_t i = 3; i < words.size(); ++i) {
        if (!is_type(words[i])) {
          return fail("unknown type: " + std::string(words[i]));
        }
        if (i > 3) {
          fn.params.emplace_back(words[i]);
        }
      }
      modules.back().functions.push_back(std::move(fn));
      break;
    }
    }
  }

  ++number;
  if (state == State::Header) {
    return fail("expected 'module <name>'");
  }
  if (state == State::Inside) {
    return fail("module " + modules.back().name + " has no 'end'");
  }
  return modules;
}

std::string
render(const std::vector<Module> &modules, std::string_view source)
{
  std::string out = "# generated by hrw4u-extern from " + std::string(source) + "; do not edit\n";

  for (const Module &module : modules) {
    out += "\n# module " + module.name + "\n";
    for (const Function &fn : module.functions) {
      out += "extern " + fn.name + "(";
      for (size_t i = 0; i < fn.params.size(); ++i) {
        if (i > 0) {
          out += ", ";
        }
        out += script_type(fn.params[i]);
      }
      out += ") -> ";
      out += script_type(fn.result);
      // An effect is the default, so it has no keyword.
      if (fn.effect != "effect") {
        out += " " + fn.effect;
      }
      out += ";\n";
    }
  }
  return out;
}
} // namespace hrw4u::manifest
