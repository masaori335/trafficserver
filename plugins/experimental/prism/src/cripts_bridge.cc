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

#include "cripts_bridge.h"
#include "txn_memory.h"

#include "cripts/Headers.hpp"
// Last: it defines Get()/Set()-style macros.
#include "cripts/Context.hpp"

namespace hrw4u
{
namespace
{
  // Null for a transaction whose program keeps nothing: a new Context holds a default integer in every slot.
  TxnMemory *
  memory_of(cripts::Context *ctx)
  {
    auto *slot = std::get_if<void *>(&ctx->data[CriptsBridge::MEMORY_SLOT]);

    if (slot == nullptr) {
      return nullptr;
    }
    return static_cast<TxnMemory *>(*slot);
  }
} // namespace

void
CriptsBridge::begin_txn(cripts::Context *ctx, const Program &prog)
{
  if (!prog.vars.empty()) {
    ctx->data[MEMORY_SLOT] = static_cast<void *>(TxnMemory::create(prog.vars.size()));
  }
}

void
CriptsBridge::end_txn(cripts::Context *ctx)
{
  TxnMemory::destroy(memory_of(ctx));
  ctx->data[MEMORY_SLOT] = integer{0};
}

swoc::MemSpan<uint64_t>
CriptsBridge::vars(cripts::Context *ctx)
{
  if (TxnMemory *mem = memory_of(ctx); mem != nullptr) {
    return mem->vars();
  }
  return {};
}

void
CriptsBridge::add_header(Message msg, std::string_view name, std::string_view value)
{
  if (auto *hdr = message(msg); hdr != nullptr) {
    (*hdr)[name] += value;
  }
}

std::string
CriptsBridge::client_header(std::string_view name)
{
  return std::string(cripts::Client::Request::_get(_ctx)[name].GetSV());
}

std::string
CriptsBridge::get_header(Message msg, std::string_view name)
{
  auto *hdr = message(msg);

  if (hdr == nullptr) {
    return {};
  }
  return std::string((*hdr)[name].GetSV());
}

void
CriptsBridge::rm_header(Message msg, std::string_view name)
{
  if (auto *hdr = message(msg); hdr != nullptr) {
    hdr->Erase(name);
  }
}

void
CriptsBridge::set_header(Message msg, std::string_view name, std::string_view value)
{
  // As in set-header, an empty value changes nothing; Cripts' assignment would remove the header.
  if (value.empty()) {
    return;
  }
  if (auto *hdr = message(msg); hdr != nullptr) {
    (*hdr)[name] = value;
  }
}

// Null when the transaction has no such message, as at TXN_CLOSE of one that closed before a response: header_rewrite
// does nothing then, and Cripts would assert on the header's first use.
cripts::Header *
CriptsBridge::message(Message msg)
{
  cripts::Header *hdr = nullptr;

  switch (msg) {
  case Message::ClientRequest:
    hdr = &cripts::Client::Request::_get(_ctx);
    break;
  case Message::ServerRequest: {
    auto &req = cripts::Server::Request::_get(_ctx);

    if (!req.Present()) {
      return nullptr;
    }
    hdr = &req;
    break;
  }
  case Message::ServerResponse:
    hdr = &cripts::Server::Response::_get(_ctx);
    break;
  case Message::ClientResponse:
    hdr = &cripts::Client::Response::_get(_ctx);
    break;
  }
  if (!hdr->Initialized()) {
    return nullptr;
  }
  return hdr;
}
} // namespace hrw4u
