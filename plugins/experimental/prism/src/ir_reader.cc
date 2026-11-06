/** @file

  Reads the hrw4u-ir text format into a Program.

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

#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>

namespace hrw4u
{
namespace
{
  struct Cursor {
    std::string_view s;

    bool
    eat(std::string_view lit)
    {
      if (!s.starts_with(lit)) {
        return false;
      }
      s.remove_prefix(lit.size());
      return true;
    }

    bool
    eat_uint(uint32_t &out)
    {
      auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), out);

      if (ec != std::errc{} || end == s.data()) {
        return false;
      }
      s.remove_prefix(end - s.data());
      return true;
    }

    bool
    eat_int(int64_t &out)
    {
      auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), out);

      if (ec != std::errc{} || end == s.data()) {
        return false;
      }
      s.remove_prefix(end - s.data());
      return true;
    }

    bool
    eat_hex_byte(char &out)
    {
      unsigned value = 0;

      if (s.size() < 2) {
        return false;
      }
      auto [end, ec] = std::from_chars(s.data(), s.data() + 2, value, 16);

      if (ec != std::errc{} || end != s.data() + 2) {
        return false;
      }
      out = static_cast<char>(value);
      s.remove_prefix(2);
      return true;
    }

    bool
    eat_qstr(std::string &out)
    {
      return eat_delimited(out, '"');
    }

    // A body between two @a delim, with the escapes emit_ir.py writes: \\ \<delim> \n \r \t \xHH.
    bool
    eat_delimited(std::string &out, char delim)
    {
      if (s.empty() || s.front() != delim) {
        return false;
      }
      s.remove_prefix(1);
      while (!s.empty()) {
        char c = s.front();

        s.remove_prefix(1);
        if (c == delim) {
          return true;
        }
        if (c != '\\') {
          out += c;
          continue;
        }
        if (s.empty()) {
          return false;
        }
        char e = s.front();

        s.remove_prefix(1);
        if (e == delim) {
          out += e;
          continue;
        }
        switch (e) {
        case '\\':
          out += e;
          break;
        case 'n':
          out += '\n';
          break;
        case 'r':
          out += '\r';
          break;
        case 't':
          out += '\t';
          break;
        case 'x': {
          char byte = 0;

          if (!eat_hex_byte(byte)) {
            return false;
          }
          out += byte;
          break;
        }
        default:
          return false;
        }
      }
      return false;
    }
  };

  struct HookName {
    std::string_view header;
    Hook             hook;
  };
  constexpr HookName HOOKS[] = {
    {"Section[TXN_START]:",     Hook::TxnStart    },
    {"Section[READ_REQUEST]:",  Hook::ReadRequest },
    {"Section[PRE_REMAP]:",     Hook::PreRemap    },
    {"Section[REMAP]:",         Hook::Remap       },
    {"Section[SEND_REQUEST]:",  Hook::SendRequest },
    {"Section[READ_RESPONSE]:", Hook::ReadResponse},
    {"Section[SEND_RESPONSE]:", Hook::SendResponse},
    {"Section[TXN_CLOSE]:",     Hook::TxnClose    },
  };

  constexpr unsigned
  hook_bit(Hook hook)
  {
    return 1u << static_cast<unsigned>(hook);
  }

  enum class State { ExpectSection, BeforeIR, InIR };

  class Reader
  {
  public:
    std::optional<Program>
    read(std::string_view text, std::string &error)
    {
      size_t line_no = 0;

      while (!text.empty()) {
        auto             nl   = text.find('\n');
        std::string_view line = text.substr(0, nl);

        if (nl == std::string_view::npos) {
          text = {};
        } else {
          text.remove_prefix(nl + 1);
        }
        ++line_no;
        _line_no = line_no;

        bool ok = true;

        if (line_no == 1) {
          ok = read_version(line);
        } else if (line.find_first_not_of(' ') != std::string_view::npos) {
          ok = read_line(line);
        }
        if (!ok) {
          error = "line " + std::to_string(_line_no) + ": " + _what;
          return std::nullopt;
        }
      }

      if (!end_section()) {
        error = "line " + std::to_string(_line_no) + ": " + _what;
        return std::nullopt;
      }
      return std::move(_prog);
    }

  private:
    bool
    fail(std::string what)
    {
      _what = std::move(what);
      return false;
    }

    // A version that names only its major is <major>.0.
    bool
    read_version(std::string_view line)
    {
      Cursor   c{line};
      uint32_t major = 0;
      uint32_t minor = 0;

      if (!c.eat("hrw4u-ir ") || !c.eat_uint(major) || (c.eat(".") && !c.eat_uint(minor)) || !c.s.empty()) {
        return fail("expected 'hrw4u-ir <major>.<minor>'");
      }

      std::string version = std::to_string(major) + "." + std::to_string(minor);
      std::string reads   = std::to_string(IR_VERSION_MAJOR) + "." + std::to_string(IR_VERSION_MINOR);

      if (major != IR_VERSION_MAJOR) {
        return fail("IR version " + version + " has another major than " + reads + ", which this prism.so reads");
      }
      if (minor > IR_VERSION_MINOR) {
        return fail("IR version " + version + " is newer than " + reads + ", which this prism.so reads");
      }
      _minor = minor;
      return true;
    }

    // A construct an IR of an older minor cannot hold: the emitter that wrote the version line was wrong about it.
    bool
    since_1_1(std::string_view construct)
    {
      if (_minor >= 1) {
        return true;
      }
      return fail(std::string(construct) + " needs hrw4u-ir 1.1");
    }

    // geo.COUNTRY, geo.ASN and geo.ASN-NAME have a .conf spelling (%{GEO}), so they are 1.0 features and stay readable
    // at 1.0; a call to any other binding is a 1.1 feature.
    static bool
    is_geo_binding(std::string_view name)
    {
      static constexpr std::string_view GEO_BINDINGS[] = {"cripts::Geo::Country", "cripts::Geo::ASN", "cripts::Geo::ASNName"};

      return std::ranges::find(GEO_BINDINGS, name) != std::end(GEO_BINDINGS);
    }

    Section &
    section()
    {
      return *_sec;
    }

    bool
    in_instance() const
    {
      return _prog.instance && _sec == &*_prog.instance;
    }

    bool
    read_line(std::string_view line)
    {
      Cursor c{line};

      switch (_state) {
      case State::ExpectSection:
        return begin_section(c);
      case State::BeforeIR:
        if (c.eat("  IR:") && c.s.empty()) {
          _state = State::InIR;
          return true;
        }
        // The pools come under the first section, shared by all, in the order the emitter writes them, each at
        // most once.
        if (_sec != first_section()) {
          return fail("expected 'IR:'; the pools come under the first section only");
        }
        if (c.eat("  ivars  = [") && _pools_read < 1) {
          if (!in_instance()) {
            return fail("the ivars pool comes under 'Instance:' only");
          }
          _pools_read = 1;
          return read_ivars(c);
        }
        if (c.eat("  vars   = [") && _pools_read < 2) {
          _pools_read = 2;
          return read_vars(c);
        }
        if (c.eat("  consts = [") && _pools_read < 3) {
          _pools_read = 3;
          return read_consts(c);
        }
        if (c.eat("  ints   = [") && _pools_read < 4) {
          _pools_read = 4;
          return read_ints(c);
        }
        if (c.eat("  regex  = [") && _pools_read < 5) {
          _pools_read = 5;
          return read_regexes(c);
        }
        if (c.eat("  fmt    = [") && _pools_read < 6) {
          _pools_read = 6;
          return read_fmts(c);
        }
        if (c.eat("  sets   = [") && _pools_read < 7) {
          _pools_read = 7;
          return read_sets(c);
        }
        return fail("expected a pool ('ivars', 'vars', 'consts', 'ints', 'regex', 'fmt', then 'sets') or 'IR:'");
      case State::InIR:
        if (c.s.starts_with("Section[") || c.s == "Instance:") {
          return end_section() && begin_section(c);
        }
        return read_inst(c);
      }
      return fail("unreachable");
    }

    const Section *
    first_section() const
    {
      if (_prog.instance) {
        return &*_prog.instance;
      }
      return &_prog.sections.front();
    }

    bool
    begin_section(Cursor &c)
    {
      if (c.s == "Instance:") {
        return begin_instance();
      }
      for (const HookName &h : HOOKS) {
        if (c.s == h.header) {
          if (_prog.find(h.hook) != nullptr) {
            return fail("a second section for the same hook");
          }
          enter_section(_prog.sections.emplace_back(Section{h.hook, {}, 0, {}}));
          return true;
        }
      }
      return fail("expected 'Section[HOOK]:' for a supported hook");
    }

    // Before the hooks, so the instance variables they load are stored when the first one is read.
    bool
    begin_instance()
    {
      if (!since_1_1("'Instance:'")) {
        return false;
      }
      if (_prog.instance) {
        return fail("a second 'Instance:' section");
      }
      if (!_prog.sections.empty()) {
        return fail("'Instance:' comes before every hook's section");
      }
      enter_section(_prog.instance.emplace());
      return true;
    }

    void
    enter_section(Section &sec)
    {
      _sec = &sec;
      _branches.clear();
      _written.emplace();
      _written_at.clear();
      _state = State::BeforeIR;
    }

    // A failure names the line being read, except a branch target past the section, which names the branch.
    bool
    end_section()
    {
      if (_state != State::InIR || section().insts.empty() || section().insts.back().op != Op::Ret) {
        return fail("the section must end with 'ret'");
      }
      for (const auto &[index, branch_line] : _branches) {
        uint32_t target = section().insts[index].target;

        if (target >= section().insts.size()) {
          _line_no = branch_line;
          return fail("branch target .L" + std::to_string(target) + " is past the section");
        }
      }
      if (in_instance()) {
        for (size_t k = 0; k < _stored.size(); ++k) {
          if (!_stored[k]) {
            return fail("i" + std::to_string(k) + " is never stored");
          }
        }
      }
      return true;
    }

    bool
    read_var_type(Cursor &c, VarType &type)
    {
      if (c.eat("bool")) {
        type = VarType::Bool;
      } else if (c.eat("u8")) {
        type = VarType::U8;
      } else if (c.eat("u16")) {
        type = VarType::U16;
      } else {
        return false;
      }
      return true;
    }

    // i<k>:sview, k counting from 0 in order.
    bool
    read_ivars(Cursor &c)
    {
      while (true) {
        uint32_t index = 0;

        if (!c.eat("i") || !c.eat_uint(index) || !c.eat(":")) {
          return fail("malformed instance variable");
        }
        if (index != _prog.ivars.size()) {
          return fail("instance variable i" + std::to_string(index) + " out of order");
        }
        if (!c.eat("sview")) {
          return fail("instance variable i" + std::to_string(index) + " must be an sview");
        }
        _prog.ivars.emplace_back();
        if (c.eat("]")) {
          break;
        }
        if (!c.eat(", ")) {
          return fail("malformed instance variable pool");
        }
      }
      if (!c.s.empty()) {
        return fail("trailing text after the instance variable pool");
      }
      _stored.assign(_prog.ivars.size(), false);
      return true;
    }

    // v<k>:bool, v<k>:u8 or v<k>:u16: k numbers the variables of each type from 0, in order, and the types may
    // interleave.
    bool
    read_vars(Cursor &c)
    {
      std::array<uint32_t, 3> count{}; // per VarType

      while (true) {
        Var var{VarType::Bool, 0};

        if (!c.eat("v") || !c.eat_uint(var.slot) || !c.eat(":")) {
          return fail("malformed variable");
        }
        if (!read_var_type(c, var.type) || c.s.starts_with("@") || (!c.s.starts_with(",") && !c.s.starts_with("]"))) {
          return fail("variable v" + std::to_string(var.slot) +
                      ": a type of bool, u8 or u16; session variables are not "
                      "supported yet");
        }

        uint32_t &next = count[static_cast<size_t>(var.type)];

        if (var.slot != next) {
          return fail("variable v" + std::to_string(var.slot) + " out of order");
        }
        ++next;
        _prog.vars.push_back(var);
        if (c.eat("]")) {
          break;
        }
        if (!c.eat(", ")) {
          return fail("malformed variable pool");
        }
      }
      if (!c.s.empty()) {
        return fail("trailing text after the variable pool");
      }
      return true;
    }

    bool
    read_consts(Cursor &c)
    {
      while (true) {
        uint32_t    index = 0;
        std::string value;

        if (!c.eat("K") || !c.eat_uint(index) || !c.eat(":") || !c.eat_qstr(value)) {
          return fail("malformed constant");
        }
        if (index != _prog.consts.size()) {
          return fail("constant K" + std::to_string(index) + " out of order");
        }
        _prog.consts.push_back(std::move(value));
        if (c.eat("]")) {
          break;
        }
        if (!c.eat(", ")) {
          return fail("malformed constant pool");
        }
      }
      if (!c.s.empty()) {
        return fail("trailing text after the constant pool");
      }
      return true;
    }

    bool
    read_ints(Cursor &c)
    {
      while (true) {
        uint32_t index = 0;
        int64_t  value = 0;

        if (!c.eat("I") || !c.eat_uint(index) || !c.eat(":") || !c.eat_int(value)) {
          return fail("malformed integer constant");
        }
        if (index != _prog.ints.size()) {
          return fail("integer constant I" + std::to_string(index) + " out of order");
        }
        _prog.ints.push_back(value);
        if (c.eat("]")) {
          break;
        }
        if (!c.eat(", ")) {
          return fail("malformed integer pool");
        }
      }
      if (!c.s.empty()) {
        return fail("trailing text after the integer pool");
      }
      return true;
    }

    // R<i>:/body/ or R<i>:/body/i, compiled here so a bad pattern fails the load, not a request.
    bool
    read_regexes(Cursor &c)
    {
      while (true) {
        uint32_t    index = 0;
        std::string body;
        uint32_t    flags = 0;

        if (!c.eat("R") || !c.eat_uint(index) || !c.eat(":") || !c.eat_delimited(body, '/')) {
          return fail("malformed regex");
        }
        if (index != _prog.regexes.size()) {
          return fail("regex R" + std::to_string(index) + " out of order");
        }
        if (c.eat("i")) {
          flags = RE_CASE_INSENSITIVE;
        }

        std::string error;
        int         offset = 0;
        Regex      &re     = _prog.regexes.emplace_back();

        if (!re.compile(body, error, offset, flags)) {
          return fail("regex R" + std::to_string(index) + " does not compile: " + error + " at " + std::to_string(offset));
        }
        if (c.eat("]")) {
          break;
        }
        if (!c.eat(", ")) {
          return fail("malformed regex pool");
        }
      }
      if (!c.s.empty()) {
        return fail("trailing text after the regex pool");
      }
      return true;
    }

    // False only for a match mode on a set other than a string set.
    bool
    read_match(Cursor &c, Set &set)
    {
      struct Mode {
        std::string_view word;
        Set::Match       match;
      };
      static constexpr Mode MODES[] = {
        {" pre", Set::Match::Prefix   },
        {" suf", Set::Match::Suffix   },
        {" mid", Set::Match::Substring},
        {" ext", Set::Match::Extension},
      };

      for (const Mode &mode : MODES) {
        if (c.eat(mode.word)) {
          set.match = mode.match;
          return set.kind == Set::Kind::String;
        }
      }
      return true;
    }

    // S<i>:s("item", ...) [pre|suf|mid|ext] [nocase] or S<i>:ip("range", ...). Not yet: integer sets (i(...)).
    bool
    read_sets(Cursor &c)
    {
      while (true) {
        uint32_t index = 0;
        Set      set;

        if (!c.eat("S") || !c.eat_uint(index) || !c.eat(":")) {
          return fail("malformed set");
        }
        if (index != _prog.sets.size()) {
          return fail("set S" + std::to_string(index) + " out of order");
        }
        if (c.eat("ip(")) {
          set.kind   = Set::Kind::Ip;
          set.ranges = std::make_unique<swoc::IPRangeSet>();
        } else if (c.eat("i(")) {
          set.kind = Set::Kind::Int;
        } else if (!c.eat("s(")) {
          return fail("set S" + std::to_string(index) + ": a set is s(...), i(...) or ip(...)");
        }
        do {
          std::string item;

          if (set.kind == Set::Kind::Int) {
            int64_t value = 0;

            if (!c.eat_int(value)) {
              return fail("set S" + std::to_string(index) + ": malformed integer");
            }
            set.ints.push_back(value);
            continue;
          }
          if (!c.eat_qstr(item)) {
            return fail("malformed set items");
          }
          if (set.kind == Set::Kind::Ip) {
            swoc::IPRange range;

            if (!range.load(item)) {
              return fail("set S" + std::to_string(index) + ": \"" + item + "\" is not an IP range");
            }
            set.ranges->mark(range);
          } else {
            set.items.push_back(std::move(item));
          }
        } while (c.eat(", "));
        if (!c.eat(")")) {
          return fail("malformed set items");
        }
        if (!read_match(c, set)) {
          return fail("set S" + std::to_string(index) + ": only a string set has a match mode");
        }
        if (c.eat(" nocase")) {
          if (set.kind != Set::Kind::String) {
            return fail("set S" + std::to_string(index) + ": only a string set has a case");
          }
          set.nocase = true;
        }
        _prog.sets.push_back(std::move(set));
        if (c.eat("]")) {
          break;
        }
        if (c.s.starts_with(" ")) {
          return fail("set S" + std::to_string(index) + ": an unknown match mode");
        }
        if (!c.eat(", ")) {
          return fail("malformed set pool");
        }
      }
      if (!c.s.empty()) {
        return fail("trailing text after the set pool");
      }
      return true;
    }

    // F<i>:"source" arity=<n> lits=["lit", ...], the lits being one more than the arity.
    bool
    read_fmts(Cursor &c)
    {
      while (true) {
        uint32_t index = 0;
        uint32_t arity = 0;
        Format   fmt;

        if (!c.eat("F") || !c.eat_uint(index) || !c.eat(":") || !c.eat_qstr(fmt.source) || !c.eat(" arity=") ||
            !c.eat_uint(arity) || !c.eat(" lits=[")) {
          return fail("malformed format");
        }
        if (index != _prog.fmts.size()) {
          return fail("format F" + std::to_string(index) + " out of order");
        }
        do {
          std::string lit;

          if (!c.eat_qstr(lit)) {
            return fail("malformed format literals");
          }
          fmt.lits.push_back(std::move(lit));
        } while (c.eat(", "));
        if (!c.eat("]")) {
          return fail("malformed format literals");
        }
        if (fmt.lits.size() != static_cast<size_t>(arity) + 1) {
          return fail("format F" + std::to_string(index) + " has arity " + std::to_string(arity) + " but " +
                      std::to_string(fmt.lits.size()) + " literals");
        }
        _prog.fmts.push_back(std::move(fmt));
        if (c.eat("]")) {
          break;
        }
        if (!c.eat(", ")) {
          return fail("malformed format pool");
        }
      }
      if (!c.s.empty()) {
        return fail("trailing text after the format pool");
      }
      return true;
    }

    bool
    read_inst(Cursor &c)
    {
      Section &sec = section();
      Inst     inst;

      if (!c.eat("    ")) {
        return fail("expected an instruction");
      }
      if (!sec.insts.empty() && sec.insts.back().op == Op::Ret) {
        return fail("instruction after 'ret'");
      }

      auto at = c.s.rfind(" @");

      if (at == std::string_view::npos) {
        return fail("missing '@line:col'");
      }
      Cursor span{c.s.substr(at + 2)};

      if (!span.eat_uint(inst.line) || !span.eat(":") || !span.eat_uint(inst.col) || !span.s.empty()) {
        return fail("malformed '@line:col'");
      }
      c.s = c.s.substr(0, at);

      uint32_t index = sec.insts.size();

      if (c.eat(".L")) {
        uint32_t label = 0;

        if (!c.eat_uint(label) || !c.eat(": ")) {
          return fail("malformed label");
        }
        if (label != index) {
          return fail("label .L" + std::to_string(label) + " is on instruction " + std::to_string(index));
        }
      }
      enter(index);

      std::string_view opcode = opcode_of(c.s);

      if (c.eat("%")) {
        if (!read_def(c, inst)) {
          return false;
        }
      } else if (c.eat("call.eff ")) {
        if (!read_call_eff(c, inst)) {
          return false;
        }
      } else if (c.eat("store.v v")) {
        if (!read_store_v(c, inst)) {
          return false;
        }
      } else if (c.eat("store.i i")) {
        if (!read_store_i(c, inst)) {
          return false;
        }
      } else if (c.eat("br.t ")) {
        inst.op = Op::BrT;
        if (!read_cond_branch(c, inst, index)) {
          return false;
        }
      } else if (c.eat("br.f ")) {
        inst.op = Op::BrF;
        if (!read_cond_branch(c, inst, index)) {
          return false;
        }
      } else if (c.eat("br ")) {
        inst.op = Op::Br;
        if (!read_target(c, inst, index)) {
          return false;
        }
      } else if (c.eat("break") && c.s.empty()) {
        inst.op = Op::Break;
      } else if (c.eat("ret") && c.s.empty()) {
        inst.op = Op::Ret;
      } else {
        return fail("unsupported instruction");
      }
      if (in_instance() && !runs_at_load(inst.op)) {
        return fail(std::string(opcode) + " does not run in the Instance section");
      }
      leave(inst);
      sec.insts.push_back(std::move(inst));
      return true;
    }

    // The opcode of an instruction's text, after any label.
    static std::string_view
    opcode_of(std::string_view text)
    {
      if (auto eq = text.find(" = "); text.starts_with("%") && eq != std::string_view::npos) {
        text.remove_prefix(eq + 3);
      }
      return text.substr(0, text.find(' '));
    }

    // The Instance section runs once at load, straight through, with no transaction: it builds strings from constants
    // and from functions, and stores them.
    static bool
    runs_at_load(Op op)
    {
      switch (op) {
      case Op::ConstS:
      case Op::ConstI:
      case Op::Fmt:
      case Op::CallPure:
      case Op::CallLoad:
      case Op::StoreI:
      case Op::Ret:
        return true;
      default:
        return false;
      }
    }

    // Every branch goes forward, so all the paths into instruction @a index are read before it: the fall-through from
    // the one before, and the branches to it.
    void
    enter(uint32_t index)
    {
      auto branched = _written_at.extract(index);

      if (branched.empty()) {
        return;
      }
      if (!_written) {
        _written = std::move(branched.mapped());
        return;
      }
      meet(*_written, branched.mapped());
    }

    void
    leave(const Inst &inst)
    {
      if (!_written) {
        return;
      }
      if (inst.op == Op::BrT || inst.op == Op::BrF || inst.op == Op::Br) {
        auto [it, first] = _written_at.try_emplace(inst.target, *_written);

        if (!first) {
          meet(it->second, *_written);
        }
      }
      if (inst.op == Op::Br || inst.op == Op::Break || inst.op == Op::Ret) {
        _written.reset();
      }
    }

    // Keeps in @a into only the registers @a other has written too.
    static void
    meet(std::vector<bool> &into, const std::vector<bool> &other)
    {
      if (other.size() < into.size()) {
        into.resize(other.size());
      }
      for (size_t reg = 0; reg < into.size(); ++reg) {
        into[reg] = into[reg] && other[reg];
      }
    }

    // `K:type` after load.v's or store.v's `v`: the variable's index in the pool goes in the operand, and the register
    // type it loads or stores in @a held.
    bool
    read_var_ref(Cursor &c, Inst &inst, Type &held, std::string_view op)
    {
      Var var{VarType::Bool, 0};

      if (!c.eat_uint(var.slot) || !c.eat(":") || !read_var_type(c, var.type)) {
        return fail("malformed " + std::string(op));
      }

      auto it = std::ranges::find(_prog.vars, var);

      if (it == _prog.vars.end()) {
        return fail("variable v" + std::to_string(var.slot) + " of that type is not in the pool");
      }
      inst.operand = it - _prog.vars.begin();
      held         = Type::I64;
      if (var.type == VarType::Bool) {
        held = Type::Bool;
      }
      return true;
    }

    // `store.v vK:type, %N`: the register must hold what the variable keeps.
    bool
    read_store_v(Cursor &c, Inst &inst)
    {
      Type     held = Type::Sview;
      uint32_t reg  = 0;

      if (!read_var_ref(c, inst, held, "store.v")) {
        return false;
      }
      if (!c.eat(", %") || !c.eat_uint(reg) || !c.s.empty()) {
        return fail("malformed store.v");
      }
      if (!defined(reg)) {
        return fail("register %" + std::to_string(reg) + " read before it is written");
      }
      if (section().reg_types[reg] != held) {
        return fail("register %" + std::to_string(reg) + " does not hold the variable's type");
      }
      inst.op = Op::StoreV;
      inst.args.push_back(reg);
      return true;
    }

    // `store.i iK, %N`: each instance variable is stored once, from a string.
    bool
    read_store_i(Cursor &c, Inst &inst)
    {
      uint32_t reg = 0;

      if (!since_1_1("store.i")) {
        return false;
      }
      if (!in_instance()) {
        return fail("store.i runs only in the Instance section");
      }
      if (!c.eat_uint(inst.operand) || !c.eat(", %") || !c.eat_uint(reg) || !c.s.empty()) {
        return fail("malformed store.i");
      }
      if (inst.operand >= _prog.ivars.size()) {
        return fail("instance variable i" + std::to_string(inst.operand) + " is not in the pool");
      }
      if (!defined(reg)) {
        return fail("register %" + std::to_string(reg) + " read before it is written");
      }
      if (section().reg_types[reg] != Type::Sview) {
        return fail("register %" + std::to_string(reg) + " is not a string, which an instance variable holds");
      }
      if (_stored[inst.operand]) {
        return fail("i" + std::to_string(inst.operand) + " is stored twice");
      }
      _stored[inst.operand] = true;
      inst.op               = Op::StoreI;
      inst.args.push_back(reg);
      return true;
    }

    // `%N:type = ...`: the destination is defined only after its operands are read, so an instruction can
    // never read its own result.
    bool
    read_def(Cursor &c, Inst &inst)
    {
      Type type     = Type::Sview;
      Type produces = Type::Sview;

      if (!c.eat_uint(inst.dest) || !c.eat(":")) {
        return fail("malformed register");
      }
      if (!read_type(c, type) || !c.eat(" = ")) {
        return fail("malformed register type");
      }
      if (c.eat("const.s K")) {
        if (!c.eat_uint(inst.operand) || !c.s.empty()) {
          return fail("malformed const.s");
        }
        if (inst.operand >= _prog.consts.size()) {
          return fail("constant K" + std::to_string(inst.operand) + " out of range");
        }
        inst.op = Op::ConstS;
      } else if (c.eat("const.i I")) {
        if (!c.eat_uint(inst.operand) || !c.s.empty()) {
          return fail("malformed const.i");
        }
        if (inst.operand >= _prog.ints.size()) {
          return fail("integer constant I" + std::to_string(inst.operand) + " out of range");
        }
        inst.op  = Op::ConstI;
        produces = Type::I64;
        // A bool literal is a const.i of 0 or 1 into a bool register: the emitter keeps no pool of bools.
        if (type == Type::Bool && (_prog.ints[inst.operand] == 0 || _prog.ints[inst.operand] == 1)) {
          produces = Type::Bool;
        }
      } else if (c.eat("fmt F")) {
        if (!c.eat_uint(inst.operand) || !read_args(c, inst) || !c.s.empty()) {
          return fail("malformed fmt");
        }
        if (inst.operand >= _prog.fmts.size()) {
          return fail("format F" + std::to_string(inst.operand) + " out of range");
        }
        if (inst.args.size() + 1 != _prog.fmts[inst.operand].lits.size()) {
          return fail("format F" + std::to_string(inst.operand) + " takes " +
                      std::to_string(_prog.fmts[inst.operand].lits.size() - 1) + " arguments, not " +
                      std::to_string(inst.args.size()));
        }
        inst.op = Op::Fmt;
      } else if (c.eat("re.match %")) {
        uint32_t reg = 0;

        if (!c.eat_uint(reg) || !c.eat(", R") || !c.eat_uint(inst.operand) || !c.s.empty()) {
          return fail("malformed re.match");
        }
        if (!defined(reg)) {
          return fail("register %" + std::to_string(reg) + " read before it is written");
        }
        if (section().reg_types[reg] != Type::Sview) {
          return fail("re.match takes a string, and %" + std::to_string(reg) + " is not one");
        }
        if (inst.operand >= _prog.regexes.size()) {
          return fail("regex R" + std::to_string(inst.operand) + " out of range");
        }
        inst.op = Op::ReMatch;
        inst.args.push_back(reg);
        produces = Type::Bool;
      } else if (c.eat("load.v v")) {
        if (!read_var_ref(c, inst, produces, "load.v")) {
          return false;
        }
        if (!c.s.empty()) {
          return fail("malformed load.v");
        }
        inst.op = Op::LoadV;
      } else if (c.eat("load.i i")) {
        if (!since_1_1("load.i")) {
          return false;
        }
        if (!c.eat_uint(inst.operand) || !c.s.empty()) {
          return fail("malformed load.i");
        }
        if (inst.operand >= _prog.ivars.size()) {
          return fail("instance variable i" + std::to_string(inst.operand) + " is not in the pool");
        }
        inst.op = Op::LoadI;
      } else if (c.eat("in.set %")) {
        uint32_t reg = 0;

        if (!c.eat_uint(reg) || !c.eat(", S") || !c.eat_uint(inst.operand) || !c.s.empty()) {
          return fail("malformed in.set");
        }
        if (!defined(reg)) {
          return fail("register %" + std::to_string(reg) + " read before it is written");
        }
        if (inst.operand >= _prog.sets.size()) {
          return fail("set S" + std::to_string(inst.operand) + " out of range");
        }

        Type member = Type::Sview;

        if (_prog.sets[inst.operand].kind == Set::Kind::Int) {
          member = Type::I64;
        } else if (_prog.sets[inst.operand].kind == Set::Kind::Ip) {
          member = Type::Addr;
        }
        if (section().reg_types[reg] != member) {
          return fail("set S" + std::to_string(inst.operand) + " holds another type than %" + std::to_string(reg));
        }
        inst.op = Op::InSet;
        inst.args.push_back(reg);
        produces = Type::Bool;
      } else if (c.eat("cmp.")) {
        produces = Type::Bool;
        if (!read_cmp(c, inst)) {
          return false;
        }
      } else if (c.eat("call.pure ")) {
        inst.op = Op::CallPure;
        if (c.eat("EXT")) {
          if (!read_ext_call(c, inst, type, "call.pure")) {
            return false;
          }
          if (!is_geo_binding(inst.ext_name) && !since_1_1("'call.pure EXT\"" + inst.ext_name + "\"'")) {
            return false;
          }
          produces = type;
        } else if (!read_builtin_call(c, inst, true, produces)) {
          return false;
        }
      } else if (c.eat("call.load ")) {
        if (!since_1_1("call.load")) {
          return false;
        }
        if (!in_instance()) {
          return fail("call.load runs only in the Instance section");
        }
        inst.op = Op::CallLoad;
        if (!c.eat("EXT") || !read_ext_call(c, inst, type, "call.load")) {
          return false;
        }
        produces = type;
      } else {
        return fail("unsupported instruction");
      }
      if (type != produces) {
        return fail("register %" + std::to_string(inst.dest) + " has the wrong type for this instruction");
      }
      return define(inst.dest, type);
    }

    // `"name", %A, ...` after `EXT`, into a register of @a type.
    bool
    read_ext_call(Cursor &c, Inst &inst, Type type, std::string_view op)
    {
      if (!c.eat_qstr(inst.ext_name) || !read_args(c, inst) || !c.s.empty()) {
        return fail("malformed " + std::string(op));
      }
      // The ABI has no address type yet; bind checks any other result type against the function's signature.
      if (type == Type::Addr) {
        return fail("an extension call cannot return an addr");
      }
      return true;
    }

    bool
    read_type(Cursor &c, Type &type)
    {
      struct TypeName {
        std::string_view name;
        Type             type;
      };
      static constexpr TypeName TYPES[] = {
        {"sview", Type::Sview},
        {"bool",  Type::Bool },
        {"i64",   Type::I64  },
        {"addr",  Type::Addr },
      };

      for (const TypeName &t : TYPES) {
        if (c.eat(t.name)) {
          type = t.type;
          return true;
        }
      }
      return false;
    }

    // The part after `cmp.`.
    bool
    read_cmp(Cursor &c, Inst &inst)
    {
      struct Cmp {
        std::string_view name;
        Op               op;
        Type             operand;
      };
      static constexpr Cmp CMPS[] = {
        {"s.eq ",   Op::CmpSEq, Type::Sview},
        {"s.ne ",   Op::CmpSNe, Type::Sview},
        {"i64.eq ", Op::CmpIEq, Type::I64  },
        {"i64.ne ", Op::CmpINe, Type::I64  },
        {"i64.lt ", Op::CmpILt, Type::I64  },
        {"i64.gt ", Op::CmpIGt, Type::I64  },
        {"i64.le ", Op::CmpILe, Type::I64  },
        {"i64.ge ", Op::CmpIGe, Type::I64  },
      };

      for (const Cmp &cmp : CMPS) {
        if (c.eat(cmp.name)) {
          inst.op = cmp.op;
          return read_pair(c, inst, cmp.operand);
        }
      }
      return fail("unsupported comparison");
    }

    // `%A, %B`, both of @a operand type.
    bool
    read_pair(Cursor &c, Inst &inst, Type operand)
    {
      for (int i = 0; i < 2; ++i) {
        uint32_t reg = 0;

        if ((i == 1 && !c.eat(", ")) || !c.eat("%") || !c.eat_uint(reg)) {
          return fail("malformed operands");
        }
        if (!defined(reg)) {
          return fail("register %" + std::to_string(reg) + " read before it is written");
        }
        if (section().reg_types[reg] != operand) {
          return fail("register %" + std::to_string(reg) + " has the wrong type for this comparison");
        }
        inst.args.push_back(reg);
      }
      if (!c.s.empty()) {
        return fail("malformed operands");
      }
      return true;
    }

    bool
    read_args(Cursor &c, Inst &inst)
    {
      while (c.eat(", %")) {
        uint32_t reg = 0;

        if (!c.eat_uint(reg)) {
          return fail("malformed register");
        }
        if (!defined(reg)) {
          return fail("register %" + std::to_string(reg) + " read before it is written");
        }
        inst.args.push_back(reg);
      }
      return true;
    }

    bool
    read_call_eff(Cursor &c, Inst &inst)
    {
      Type unused = Type::Sview;

      inst.op = Op::CallEff;
      return read_builtin_call(c, inst, false, unused);
    }

    // `BI_NAME, %A, ...` after `call.eff ` or `call.pure `. @a produces is what a pure builtin returns.
    bool
    read_builtin_call(Cursor &c, Inst &inst, bool pure, Type &produces)
    {
      struct Signature {
        std::string_view    name;
        Builtin             builtin;
        std::optional<Type> ret; ///< None: an effect, called by call.eff.
        std::array<Type, 2> params;
        size_t              arity;      ///< How many of params it takes.
        unsigned            hooks;      ///< hook_bit()s of the hooks it runs in.
        size_t              consts = 0; ///< How many leading arguments must be constants, which prism.so resolves at load.
      };
      static constexpr std::array<Signature, 0> BUILTINS{};

      std::string_view name = c.s.substr(0, c.s.find(','));
      const Signature *sig  = nullptr;

      for (const Signature &candidate : BUILTINS) {
        if (candidate.name == name) {
          sig = &candidate;
          break;
        }
      }
      if (sig == nullptr) {
        return fail("unsupported builtin");
      }
      if (in_instance()) {
        return fail(std::string(sig->name) + " does not run in the Instance section");
      }
      if (pure && !sig->ret) {
        return fail(std::string(sig->name) + " is an effect, so call.eff calls it");
      }
      if (!pure && sig->ret) {
        return fail(std::string(sig->name) + " returns a value, so call.pure calls it");
      }
      if ((sig->hooks & hook_bit(section().hook)) == 0) {
        return fail(std::string(sig->name) + " does not run in this section's hook");
      }
      if (sig->ret) {
        produces = *sig->ret;
      }
      c.s.remove_prefix(name.size());
      inst.builtin = sig->builtin;
      if (!read_args(c, inst)) {
        return false;
      }
      if (!c.s.empty()) {
        return fail("malformed arguments");
      }
      if (inst.args.size() != sig->arity) {
        return fail(std::string(sig->name) + " takes " + std::to_string(sig->arity) + " arguments, not " +
                    std::to_string(inst.args.size()));
      }
      for (size_t i = 0; i < inst.args.size(); ++i) {
        if (section().reg_types[inst.args[i]] != sig->params[i]) {
          return fail(std::string(sig->name) + ": argument " + std::to_string(i + 1) + " has the wrong type");
        }
        if (i < sig->consts && _prog.const_arg(section(), inst.args[i]) == nullptr) {
          return fail(std::string(sig->name) + ": argument " + std::to_string(i + 1) + " must be a constant");
        }
      }
      return true;
    }

    // br.t / br.f: `%C, .Lk`.
    bool
    read_cond_branch(Cursor &c, Inst &inst, uint32_t index)
    {
      uint32_t reg = 0;

      if (!c.eat("%") || !c.eat_uint(reg) || !c.eat(", ")) {
        return fail("malformed conditional branch");
      }
      if (!defined(reg)) {
        return fail("register %" + std::to_string(reg) + " read before it is written");
      }
      if (section().reg_types[reg] != Type::Bool) {
        return fail("a conditional branch needs a bool register, and %" + std::to_string(reg) + " is not one");
      }
      inst.args.push_back(reg);
      return read_target(c, inst, index);
    }

    // Forward only, so every section ends: rules run on ET_NET threads. Whether the target is inside the
    // section is known only once the section is read.
    bool
    read_target(Cursor &c, Inst &inst, uint32_t index)
    {
      if (!c.eat(".L") || !c.eat_uint(inst.target) || !c.s.empty()) {
        return fail("malformed branch target");
      }
      if (inst.target <= index) {
        return fail("branch target .L" + std::to_string(inst.target) + " is not after the branch");
      }
      _branches.emplace_back(index, _line_no);
      return true;
    }

    // Written on every path here: run() starts the registers zeroed, which is a null string or address.
    bool
    defined(uint32_t reg) const
    {
      if (reg < 1 || reg >= _sec->num_regs) {
        return false;
      }
      return !_written || (reg < _written->size() && (*_written)[reg]);
    }

    // The emitter numbers registers %1, %2, ... in order, so only the next one is accepted. That bounds
    // the register file by the instruction count, whatever number the text spells, and MAX_REGS bounds it below that.
    bool
    define(uint32_t reg, Type type)
    {
      Section &sec  = section();
      uint32_t next = sec.num_regs;

      if (next == 0) {
        next = 1;
      }
      if (reg != next) {
        return fail("expected register %" + std::to_string(next) + ", not %" + std::to_string(reg));
      }
      if (next >= MAX_REGS) {
        return fail("a section has at most " + std::to_string(MAX_REGS - 1) + " registers");
      }
      sec.num_regs = next + 1;
      sec.reg_types.resize(sec.num_regs);
      sec.reg_types[reg] = type;
      if (_written) {
        _written->resize(sec.num_regs);
        (*_written)[reg] = true;
      }
      return true;
    }

    Program           _prog;
    State             _state   = State::ExpectSection;
    uint32_t          _minor   = 0;       ///< The IR's minor version, which says what it may hold.
    Section          *_sec     = nullptr; ///< The section being read: the Instance section or the last of Program::sections.
    size_t            _line_no = 0;
    std::string       _what;
    int               _pools_read = 0; ///< The last pool line read: 0 none, then 1-7 in pool order.
    std::vector<bool> _stored;         ///< Which instance variables the Instance section has stored, by number.
    // (instruction index, .ir line) of each branch, for the end-of-section target check.
    std::vector<std::pair<uint32_t, size_t>> _branches;
    // The registers written on every path to the instruction being read, by number; none where no path reaches it, as
    // after a break.
    std::optional<std::vector<bool>> _written;
    // The same for each branch target not yet read, over the branches to it read so far.
    std::map<uint32_t, std::vector<bool>> _written_at;
  };
} // namespace

std::optional<Program>
parse_ir(std::string_view text, std::string &error)
{
  return Reader{}.read(text, error);
}

std::optional<Program>
load_ir_file(const std::string &path, std::string &error)
{
  std::ifstream in(path);

  if (!in) {
    error = path + ": " + std::strerror(errno);
    return std::nullopt;
  }

  std::stringstream text;

  text << in.rdbuf();

  auto prog = parse_ir(text.str(), error);

  if (!prog) {
    error = path + ": " + error;
  }
  return prog;
}
} // namespace hrw4u
