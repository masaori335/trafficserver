/** @file

  prism.so: runs an hrw4u-ir program from a remap rule, or for every transaction from plugin.config.

  Written as a cript, so Cripts' Epilogue owns the plugin entry points, the hook scheduling and the
  per-transaction Context. The file name is the Cripts debug tag.

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

// Before Preamble.hpp: it defines macros (instance, transaction, Get(), Set()) that would rewrite these headers.
#include "bind.h"
#include "config.h"
#include "cripts_bridge.h"
#include "ext_loader.h"
#include "interp.h"
#include "ir_reader.h"
#include "registry.h"
#include "txn_memory.h"

#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cripts/Preamble.hpp>

namespace
{
// Members in this order so destruction runs the program, then extensions (fini still reaches the registry through the
// host API), then the registry.
struct InstanceState {
  hrw4u::Registry registry{
    [](std::string_view message) { TSError("[prism] %.*s", static_cast<int>(message.size()), message.data()); }};
  std::vector<std::unique_ptr<hrw4u::LoadedExtension>> extensions;
  hrw4u::Program                                       program;
  std::vector<cripts::Callbacks>                       unused_callbacks;
};

// The pparams are read before the state is stored, so the state can take slot 0.
constexpr size_t STATE_SLOT = 0;

InstanceState *
state_of(cripts::Instance &inst)
{
  auto *slot = std::get_if<void *>(&inst.data[STATE_SLOT]);

  if (slot == nullptr) {
    return nullptr;
  }
  return static_cast<InstanceState *>(*slot);
}

// Until libcripts has File::ConfigDir and PluginDir, a relative path would be relative to the prefix traffic_server runs
// in, and would name another file once they come.
bool
absolute(const std::string &path, std::string &error)
{
  if (!path.starts_with('/')) {
    error = path + ": not an absolute path";
    return false;
  }
  return true;
}

std::unique_ptr<InstanceState>
build_state(const std::string &ir_path, const std::vector<std::string> &ext_paths, const hrw4u::Settings &settings,
            std::string &error)
{
  auto state = std::make_unique<InstanceState>();

  for (const auto &path : ext_paths) {
    auto ext = hrw4u::LoadedExtension::load(path, state->registry.host_api(), error);

    if (ext == nullptr) {
      return nullptr;
    }
    state->extensions.push_back(std::move(ext));
  }

  auto prog = hrw4u::load_ir_file(ir_path, error);

  if (!prog || !hrw4u::bind_calls(*prog, state->registry, error)) {
    return nullptr;
  }
  // A program without variables gets no memory.
  if (!prog->vars.empty() && !hrw4u::TxnMemory::fits(prog->vars.size(), settings.txn_memory_limit, error)) {
    return nullptr;
  }
  state->program = std::move(*prog);
  // In place, so the instance variables load.i views never move.
  if (auto fault = hrw4u::run_instance(state->program, state->program.ivars)) {
    error = std::move(*fault);
    return nullptr;
  }
  return state;
}

// Cripts adds a hook to the transaction for every hook body this file defines, unless the body's callback is disabled
// before do_remap() or glb_txn_start() returns. TXN_CLOSE also frees the transaction's memory, so it stays while the
// program has variables.
std::vector<cripts::Callbacks>
unused_callbacks(const hrw4u::Program &prog, bool global)
{
  struct HookCallbacks {
    hrw4u::Hook       hook;
    cripts::Callbacks remap;
    cripts::Callbacks global;
  };
  static constexpr HookCallbacks hooks[] = {
    {hrw4u::Hook::ReadRequest,  cripts::Callbacks::NONE,             cripts::Callbacks::GLB_READ_REQUEST },
    {hrw4u::Hook::PreRemap,     cripts::Callbacks::NONE,             cripts::Callbacks::GLB_PRE_REMAP    },
    {hrw4u::Hook::SendRequest,  cripts::Callbacks::DO_SEND_REQUEST,  cripts::Callbacks::GLB_SEND_REQUEST },
    {hrw4u::Hook::ReadResponse, cripts::Callbacks::DO_READ_RESPONSE, cripts::Callbacks::GLB_READ_RESPONSE},
    {hrw4u::Hook::SendResponse, cripts::Callbacks::DO_SEND_RESPONSE, cripts::Callbacks::GLB_SEND_RESPONSE},
    {hrw4u::Hook::TxnClose,     cripts::Callbacks::DO_TXN_CLOSE,     cripts::Callbacks::GLB_TXN_CLOSE    },
  };
  std::vector<cripts::Callbacks> unused;

  for (const auto &entry : hooks) {
    cripts::Callbacks callback = entry.remap;

    if (global) {
      callback = entry.global;
    }
    if (callback != cripts::Callbacks::NONE && prog.find(entry.hook) == nullptr &&
        (entry.hook != hrw4u::Hook::TxnClose || prog.vars.empty())) {
      unused.push_back(callback);
    }
  }
  return unused;
}

// The instance's arguments are the .ir path, then any extension .so paths, with --config=<file> anywhere among them.
std::unique_ptr<InstanceState>
load_instance(cripts::Instance &inst, bool global, std::string &error)
{
  // Cripts keeps at most data.size() arguments but counts them all, so Size() can point past the array.
  if (inst.Size() > inst.data.size()) {
    error = "at most " + std::to_string(inst.data.size()) + " arguments, got " + std::to_string(inst.Size());
    return nullptr;
  }

  std::vector<std::string> paths;
  std::string              config_path;

  for (size_t i = 0; i < inst.Size(); ++i) {
    const auto &arg = std::get<cripts::string>(inst.data[i]);

    if (!arg.starts_with("--")) {
      paths.push_back(arg);
    } else if (arg == "--config=") {
      error = "--config= names no file";
      return nullptr;
    } else if (arg.starts_with("--config=") && config_path.empty()) {
      config_path = arg.substr(9);
    } else {
      error = "unknown or repeated option " + std::string(arg);
      return nullptr;
    }
  }

  hrw4u::Settings settings;

  if (!config_path.empty() && (!absolute(config_path, error) || !hrw4u::read_config_file(config_path, settings, error))) {
    return nullptr;
  }
  if (paths.empty()) {
    error = "expected the .ir path, then any extension .so paths";
    return nullptr;
  }
  for (const auto &path : paths) {
    if (!absolute(path, error)) {
      return nullptr;
    }
  }

  std::vector<std::string> ext_paths(paths.begin() + 1, paths.end());
  auto                     state = build_state(paths[0], ext_paths, settings, error);

  if (state == nullptr || !state->program.runs_in(global, error)) {
    return nullptr;
  }
  state->unused_callbacks = unused_callbacks(state->program, global);
  return state;
}

void
begin_txn(cripts::Context *context)
{
  if (const InstanceState *state = state_of(instance); state != nullptr) {
    hrw4u::CriptsBridge::begin_txn(context, state->program);
    for (auto callback : state->unused_callbacks) {
      transaction.DisableCallback(callback);
    }
  }
}

// A global instance whose program did not load still has its hooks, and runs nothing in them.
void
run_hook(cripts::Context *context, hrw4u::Hook hook)
{
  const InstanceState *state = state_of(instance);

  if (state == nullptr) {
    return;
  }

  const hrw4u::Program &prog = state->program;
  const hrw4u::Section *sec  = prog.find(hook);

  if (sec != nullptr) {
    hrw4u::CriptsBridge ops(context);
    std::string         fault;

    if (!hrw4u::run(prog, *sec, ops, fault, hrw4u::CriptsBridge::vars(context))) {
      TSError("[prism] %s", fault.c_str());
    }
  }
}
} // namespace

do_create_instance()
{
  std::string error;
  auto        state = load_instance(instance, false, error);

  if (state == nullptr) {
    TSError("[prism] %s", error.c_str());
    instance.Fail();
    return;
  }
  instance.data[STATE_SLOT] = static_cast<void *>(state.release());
}

do_delete_instance()
{
  delete state_of(instance);
}

do_remap()
{
  begin_txn(context);
  run_hook(context, hrw4u::Hook::Remap);
  if (context->state.error.Failed()) {
    hrw4u::CriptsBridge::end_txn(context);
  }
}

do_send_request()
{
  run_hook(context, hrw4u::Hook::SendRequest);
}

do_read_response()
{
  run_hook(context, hrw4u::Hook::ReadResponse);
}

do_send_response()
{
  run_hook(context, hrw4u::Hook::SendResponse);
}

do_txn_close()
{
  run_hook(context, hrw4u::Hook::TxnClose);
  hrw4u::CriptsBridge::end_txn(context);
}

// From plugin.config. The instance lives as long as the process, so nothing deletes its state.
glb_init()
{
  std::string error;
  auto        state = load_instance(instance, true, error);

  if (state == nullptr) {
    TSError("[prism] %s", error.c_str());
    return;
  }
  instance.data[STATE_SLOT] = static_cast<void *>(state.release());
}

glb_txn_start()
{
  begin_txn(context);
  run_hook(context, hrw4u::Hook::TxnStart);
}

glb_read_request()
{
  run_hook(context, hrw4u::Hook::ReadRequest);
}

glb_pre_remap()
{
  run_hook(context, hrw4u::Hook::PreRemap);
}

glb_send_request()
{
  run_hook(context, hrw4u::Hook::SendRequest);
}

glb_read_response()
{
  run_hook(context, hrw4u::Hook::ReadResponse);
}

glb_send_response()
{
  run_hook(context, hrw4u::Hook::SendResponse);
}

glb_txn_close()
{
  run_hook(context, hrw4u::Hook::TxnClose);
  hrw4u::CriptsBridge::end_txn(context);
}

#include <cripts/Epilogue.hpp>
