/** @file

  The in-memory form of an hrw4u-ir program.

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

#pragma once

#include "hrw4u/extension.h"
#include "tsutil/Regex.h"

#include "swoc/IPRange.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace hrw4u
{
// In the order a transaction reaches them. TXN_START, READ_REQUEST and PRE_REMAP run before remap, so only a
// global instance has them; REMAP only a remap instance.
enum class Hook {
  TxnStart,
  ReadRequest,
  PreRemap,
  Remap,
  SendRequest,
  ReadResponse,
  SendResponse,
  TxnClose,
};

// One integer type: integers of other widths (header_rewrite's uint8/uint16 variables, a builtin's uint32) are
// converted where they are loaded or returned, so a comparison never mixes widths or signedness.
enum class Type {
  Sview,
  Bool,
  I64,
  Addr,
};

enum class Op {
  ConstI,   ///< load an integer constant into a register
  ConstS,   ///< load a string constant into a register
  CallEff,  ///< call a function which has side effects
  CallPure, ///< call a pure function and store its result
  CallLoad, ///< IR 1.1: call a function that runs only at load and store its result: the Instance section only
  CmpIEq,   ///< compare two integers: ==
  CmpINe,   ///< compare two integers: !=
  CmpILt,   ///< compare two integers: <
  CmpIGt,   ///< compare two integers: >
  CmpILe,   ///< compare two integers: <=
  CmpIGe,   ///< compare two integers: >=
  Fmt,      ///< build a string from a format's literals and the argument registers
  ReMatch,  ///< match a string against a regex, keeping the captures for this run
  InSet,    ///< test whether a string is in a set
  LoadV,    ///< read a transaction variable
  StoreV,   ///< write a transaction variable
  LoadI,    ///< IR 1.1: read an instance variable: the hooks only
  StoreI,   ///< IR 1.1: write an instance variable: the Instance section only
  CmpSEq,   ///< compare two strings for equality
  CmpSNe,   ///< compare two strings for inequality
  BrT,      ///< jump if a register is true
  BrF,      ///< jump if a register is false
  Br,       ///< jump
  Break,    ///< stop running this hook's rules (`[L]` in header_rewrite)
  Ret,      ///< end the section
};

enum class Builtin {
  None,
  AddClientHeader,
  AddClientRespHeader,
  AddServerHeader,
  AddServerRespHeader,
  ClientHeader,
  ClientRespHeader,
  RmClientHeader,
  RmClientRespHeader,
  RmServerHeader,
  RmServerRespHeader,
  ServerRespHeader,
  SetClientHeader,
  SetClientRespHeader,
  SetServerHeader,
  SetServerRespHeader,
};

/// A transaction variable's type. load.v gives a bool register for Bool and an i64 one for the integers, which keep
/// hrw4u's ranges: U8 0-255, U16 0-65535.
enum class VarType {
  Bool,
  U8,
  U16,
};

/// A variable as the IR names it: its type and its number among the variables of that type, hrw4u's slot.
struct Var {
  VarType  type;
  uint32_t slot;

  bool operator==(const Var &) const = default;
};

struct Inst {
  Op       op;
  uint32_t dest = 0; ///< Register written; 0 = none.
  /// Index into a Program pool: ConstS consts, ConstI ints, Fmt fmts, ReMatch regexes, InSet sets, LoadV and StoreV vars,
  /// LoadI and StoreI ivars. A call of a builtin that takes only constants: the slot prism.so bound it to when the program
  /// loaded.
  uint32_t              operand = 0;
  Builtin               builtin = Builtin::None; ///< CallEff, CallPure: None for an extension call.
  std::vector<uint32_t> args;                    ///< CallEff, CallPure, CallLoad, BrF, StoreI: argument registers.
  std::string           ext_name;                ///< CallPure of an extension, CallLoad: the name inside EXT"...".
  uint32_t              target = 0;              ///< Br, BrF: the instruction index jumped to.
  hrw4u_fn              fn     = nullptr;        ///< CallPure of an extension, CallLoad: set by bind(), never by the reader.
  uint32_t              line   = 0;
  uint32_t              col    = 0;
};

/// The most a section's num_regs can be: run() keeps the registers on the stack, 4 KB of them, and %0 is unused.
inline constexpr uint32_t MAX_REGS = 256;

struct Section {
  Hook              hook; ///< Meaningless for the Instance section, which runs at load.
  std::vector<Inst> insts;
  uint32_t          num_regs = 0; ///< Highest register number + 1.
  std::vector<Type> reg_types;    ///< Indexed by register number; [0] is unused.
};

/// A string with holes: lits[0], arg 0, lits[1], ..., lits[n]. `source` is the expression as written, for reading
/// the .ir; it is not used to build the string.
struct Format {
  std::string              source;
  std::vector<std::string> lits;
};

/// A set a value is tested against: strings, as header_rewrite's `(a,b,c)`; integers, as the same set on an integer
/// condition; or IP ranges an address falls in, as its `{a/n,b/n}`.
struct Set {
  enum class Kind { String, Int, Ip };
  /// How a string item matches, as header_rewrite's [PRE], [SUF], [MID] and [EXT] make it match.
  enum class Match { Whole, Prefix, Suffix, Substring, Extension };

  Kind                              kind = Kind::String;
  std::vector<std::string>          items; ///< String
  std::vector<int64_t>              ints;  ///< Int
  Match                             match  = Match::Whole;
  bool                              nocase = false;
  std::unique_ptr<swoc::IPRangeSet> ranges; ///< Ip. Behind a pointer: an IPRangeSet does not move.
};

struct Program {
  std::vector<Var> vars; ///< A variable's index here is its word in the transaction's variables.
  /// IR 1.1: one per instance variable, empty until run_instance() stores it. load.i views these strings, so they must not
  /// change once the instance runs transactions.
  std::vector<std::string> ivars;
  std::vector<std::string> consts;
  std::vector<int64_t>     ints;
  std::vector<Regex>       regexes;
  std::vector<Format>      fmts;
  std::vector<Set>         sets;
  std::vector<Section>     sections;
  std::optional<Section>   instance; ///< IR 1.1: runs once, when the instance loads, to store the instance variables.

  const Section *find(Hook hook) const;
  /// The constant @a reg holds in @a sec, when a const.s defined it; null otherwise.
  const std::string *const_arg(const Section &sec, uint32_t reg) const;
  /// Whether an instance from plugin.config (@a global) or from a remap rule can run every section, as header_rewrite
  /// allows them: the hooks before remap only the first, REMAP only the second. False with the reason in @a error.
  bool runs_in(bool global, std::string &error) const;
};
} // namespace hrw4u
