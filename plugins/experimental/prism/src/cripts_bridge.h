/** @file

  The bridge between the interpreter and Cripts: what the builtins read from and do to the transaction, each a Cripts
  call.

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

#include "ir.h"

#include "swoc/MemSpan.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace cripts
{
class Context;
class Header;
} // namespace cripts

namespace hrw4u
{
/// The message a header builtin names, as .hrw4u's scopes do: inbound.req., outbound.req., outbound.resp. and
/// inbound.resp.
enum class Message { ClientRequest, ServerRequest, ServerResponse, ClientResponse };

class CriptsBridge
{
public:
  /// The Cripts transaction data slot that points at the transaction's memory.
  static constexpr size_t MEMORY_SLOT = 0;

  explicit CriptsBridge(cripts::Context *ctx) : _ctx(ctx) {}

  /// Add a field line to @a msg after any of the same name, as header_rewrite's add-header. An empty value adds nothing.
  void add_header(Message msg, std::string_view name, std::string_view value);

  /// The value of a header in the client's request, or empty when absent. A copy: a later write can move the header's
  /// strings, and registers hold views.
  std::string client_header(std::string_view name);

  /// The value of a header in @a msg, or empty when absent or when the transaction has no such message. A copy, as
  /// client_header().
  std::string get_header(Message msg, std::string_view name);

  /// Remove every field line of a header from @a msg, as header_rewrite's rm-header.
  void rm_header(Message msg, std::string_view name);

  /// Set a header in @a msg, replacing its field lines, as header_rewrite's set-header.
  void set_header(Message msg, std::string_view name, std::string_view value);

  /// The status of response @a msg.
  int64_t status(Message msg);

  /// Make the transaction's memory at its first hook, when @a prog keeps anything across hooks.
  static void begin_txn(cripts::Context *ctx, const Program &prog);
  /// Free the transaction's memory, once: at TXN_CLOSE after the section there ran, or, from a remap rule, at REMAP when
  /// the context failed, as Cripts then runs no later hook.
  static void end_txn(cripts::Context *ctx);
  /// The transaction's variables, for run(); empty when its program keeps none.
  static swoc::MemSpan<uint64_t> vars(cripts::Context *ctx);

private:
  cripts::Header *message(Message msg);

  cripts::Context *_ctx;
};
} // namespace hrw4u
