/** @file

  Writes the C ABI of hrw4u/extension.h for ordinary C++ functions.

  HRW4U_MODULE("example::ua", HRW4U_DEF(&is_bot, "Example::UA::IsBot", HRW4U_EFFECT_PURE));

  Parameters may be bool, int64_t or std::string_view and the return bool, int64_t or std::string, or std::optional of
  one, whose empty value is a fault; any other type does not compile.
  A class derived from std::string_view or std::string counts as one, so a library's own string types, such as
  Cripts' cripts::string_view (a swoc::TextView) and cripts::string, bind without a wrapper.

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

#include <algorithm>
#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace hrw4u::ext
{
namespace detail
{
  template <typename T> struct Arg; // no definition: an unsupported type is a compile error

  template <> struct Arg<bool> {
    static constexpr hrw4u_type type  = HRW4U_TYPE_BOOL;
    static constexpr size_t     words = 1;

    static bool
    from(const uint64_t *w)
    {
      return w[0] != 0;
    }
  };

  template <> struct Arg<int64_t> {
    static constexpr hrw4u_type type  = HRW4U_TYPE_I64;
    static constexpr size_t     words = 1;

    static int64_t
    from(const uint64_t *w)
    {
      return static_cast<int64_t>(w[0]);
    }
  };

  template <typename T>
    requires std::derived_from<T, std::string_view> && std::constructible_from<T, const char *, size_t>
  struct Arg<T> {
    static constexpr hrw4u_type type  = HRW4U_TYPE_SVIEW;
    static constexpr size_t     words = 2;

    // An empty view may come as NULL, and C APIs commonly want a pointer even for no bytes.
    static T
    from(const uint64_t *w)
    {
      const char *data = reinterpret_cast<const char *>(w[0]);

      if (data == nullptr) {
        data = "";
      }
      return T(data, static_cast<size_t>(w[1]));
    }
  };

  // Backs the message of a fault an exception raised: the wrapper is a plain function pointer with nowhere else
  // to keep it, and per thread is enough because the host reads it before its next call.
  inline thread_local std::string fault_message;

  // Backs a string result as fault_message backs a fault: the host copies it before the next call.
  inline thread_local std::string result;

  // to() writes the result, or a fault message, into ret and returns false for a fault.
  template <typename T> struct Ret; // no definition: an unsupported type is a compile error

  template <> struct Ret<bool> {
    static constexpr hrw4u_type type = HRW4U_TYPE_BOOL;

    static bool
    to(bool value, uint64_t *ret)
    {
      ret[0] = value;
      return true;
    }
  };

  template <> struct Ret<int64_t> {
    static constexpr hrw4u_type type = HRW4U_TYPE_I64;

    static bool
    to(int64_t value, uint64_t *ret)
    {
      ret[0] = static_cast<uint64_t>(value);
      return true;
    }
  };

  template <std::derived_from<std::string> T> struct Ret<T> {
    static constexpr hrw4u_type type = HRW4U_TYPE_SVIEW;

    static bool
    to(T value, uint64_t *ret)
    {
      result = std::move(value);
      ret[0] = reinterpret_cast<uint64_t>(result.data());
      ret[1] = result.size();
      return true;
    }
  };

  // An empty optional is a fault without an exception, for a function that fails on the request path. The message is
  // fixed: the host names the call, and a reason could echo a secret the function was given.
  template <typename T>
    requires std::same_as<T, bool> || std::same_as<T, int64_t> || std::derived_from<T, std::string>
  struct Ret<std::optional<T>> {
    static constexpr hrw4u_type type = Ret<T>::type;

    static bool
    to(std::optional<T> value, uint64_t *ret)
    {
      static constexpr std::string_view no_value = "no value";

      if (!value) {
        ret[0] = reinterpret_cast<uint64_t>(no_value.data());
        ret[1] = no_value.size();
        return false;
      }
      return Ret<T>::to(std::move(*value), ret);
    }
  };

  /// A string literal as a template argument, so a function's name is a compile-time constant.
  template <size_t N> struct Literal {
    char chars[N];

    constexpr Literal(const char (&s)[N]) { std::copy_n(s, N, chars); }

    constexpr std::string_view
    view() const
    {
      return {chars, N - 1};
    }
  };

  // Evaluated while the manifest compiles, where reaching a throw is a compile error.
  constexpr std::string_view
  type_name(hrw4u_type type)
  {
    switch (type) {
    case HRW4U_TYPE_BOOL:
      return "bool";
    case HRW4U_TYPE_SVIEW:
      return "sview";
    case HRW4U_TYPE_I64:
      return "i64";
    }
    throw "a type the manifest cannot name";
  }

  constexpr std::string_view
  effect_name(hrw4u_effect effect)
  {
    switch (effect) {
    case HRW4U_EFFECT_PURE:
      return "pure";
    case HRW4U_EFFECT_EFFECT:
      return "effect";
    case HRW4U_EFFECT_LOAD:
      return "load";
    }
    throw "an effect the manifest cannot name";
  }

  // A name goes into the manifest's space-separated records and from there into an extern declaration, so it holds
  // only what a qualified hrw4u name does.
  constexpr bool
  is_manifest_word(std::string_view s)
  {
    return !s.empty() && std::ranges::all_of(s, [](char c) {
      return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == ':';
    });
  }

  struct ManifestWriter {
    char *at;

    constexpr void
    put(std::string_view s)
    {
      at = std::copy(s.begin(), s.end(), at);
    }
  };

  template <auto Fn, bool TakesCtx, typename R, typename... P> struct WrapOf {
    using Result = Ret<std::remove_cvref_t<R>>;

    static constexpr bool takes_ctx = TakesCtx;

    static constexpr std::array<hrw4u_type, sizeof...(P)> params{Arg<std::remove_cvref_t<P>>::type...};

    static constexpr std::array<size_t, sizeof...(P)>
    offsets()
    {
      std::array<size_t, sizeof...(P)> offs{};
      size_t                           at = 0;
      size_t                           i  = 0;

      ((offs[i++] = at, at += Arg<std::remove_cvref_t<P>>::words), ...);
      return offs;
    }

    template <size_t... I>
    static R
    invoke([[maybe_unused]] hrw4u_rule_ctx *ctx, const uint64_t *args, std::index_sequence<I...>)
    {
      constexpr auto offs = offsets();

      if constexpr (TakesCtx) {
        return Fn(ctx, Arg<std::remove_cvref_t<P>>::from(args + offs[I])...);
      } else {
        return Fn(Arg<std::remove_cvref_t<P>>::from(args + offs[I])...);
      }
    }

    static int
    call(hrw4u_rule_ctx *ctx, const uint64_t *args, uint64_t *ret)
    {
      try {
        if (Result::to(invoke(ctx, args, std::index_sequence_for<P...>{}), ret)) {
          return 0;
        }
        return 1;
      } catch (const std::exception &e) {
        fault_message = e.what();
      } catch (...) {
        fault_message = "unknown exception";
      }
      ret[0] = reinterpret_cast<uint64_t>(fault_message.data());
      ret[1] = fault_message.size();
      return 1;
    }
  };

  template <auto Fn> struct Wrap;

  template <typename R, typename... P, R (*Fn)(P...)> struct Wrap<Fn> : WrapOf<Fn, false, R, P...> {
  };

  // A leading hrw4u_rule_ctx * is the transaction the host passes, not an argument of the script's: it is in neither
  // the declaration nor the manifest.
  template <typename R, typename... P, R (*Fn)(hrw4u_rule_ctx *, P...)> struct Wrap<Fn> : WrapOf<Fn, true, R, P...> {
  };
} // namespace detail

class Module
{
public:
  Module(const hrw4u_host_api *api, const char *module_name) : _api(api), _module_name(module_name) {}

  template <auto Fn>
  void
  def(const char *name, hrw4u_effect effect)
  {
    using W = detail::Wrap<Fn>;

    hrw4u_fn_decl decl{name, W::Result::type, static_cast<uint32_t>(W::params.size()), W::params.data(), effect, &W::call};

    if (_api->def(_api->instance, &decl) != 0) {
      _failed = true;
    }
  }

  bool
  failed() const
  {
    return _failed;
  }

  const char *
  module_name() const
  {
    return _module_name;
  }

private:
  const hrw4u_host_api *_api;
  const char           *_module_name;
  bool                  _failed = false;
};

/// One function of a module table: the C++ function, the name scripts call it by, and its effect.
template <auto Fn, detail::Literal Name, hrw4u_effect Effect> struct Def {
  static_assert(detail::is_manifest_word(Name.view()), "a function name may hold only letters, digits, '_', '-' and ':'");

  using W = detail::Wrap<Fn>;

  static_assert(Effect != HRW4U_EFFECT_LOAD || !W::takes_ctx, "a load function runs with no transaction to take");

  static void
  define(Module &m)
  {
    m.def<Fn>(Name.chars, Effect);
  }

  static constexpr size_t
  manifest_size()
  {
    size_t size = std::string_view("fn ").size() + Name.view().size() + 1 + detail::effect_name(Effect).size() + 1 +
                  detail::type_name(W::Result::type).size() + 1;

    for (hrw4u_type type : W::params) {
      size += 1 + detail::type_name(type).size();
    }
    return size;
  }

  static constexpr void
  write_manifest(detail::ManifestWriter &w)
  {
    w.put("fn ");
    w.put(Name.view());
    w.put(" ");
    w.put(detail::effect_name(Effect));
    w.put(" ");
    w.put(detail::type_name(W::Result::type));
    for (hrw4u_type type : W::params) {
      w.put(" ");
      w.put(detail::type_name(type));
    }
    w.put("\n");
  }
};

/// A module's functions, fixed when it compiles, so every reader of the table sees the same functions.
template <detail::Literal Name, typename... Defs> struct Table {
  static_assert(detail::is_manifest_word(Name.view()), "a module name may hold only letters, digits, '_', '-' and ':'");

  static bool
  define(const hrw4u_host_api *api)
  {
    Module m(api, Name.chars);

    (Defs::define(m), ...);
    return !m.failed();
  }

  static constexpr size_t manifest_size = std::string_view(HRW4U_MANIFEST_HEADER "\nmodule ").size() + Name.view().size() + 1 +
                                          (Defs::manifest_size() + ... + 0) + std::string_view("end\n").size();

  /// The text HRW4U_MODULE_TABLE writes into the manifest section, in the format extension.h describes.
  static constexpr std::array<char, manifest_size> manifest = [] {
    std::array<char, manifest_size> text{};
    detail::ManifestWriter          w{text.data()};

    w.put(HRW4U_MANIFEST_HEADER "\nmodule ");
    w.put(Name.view());
    w.put("\n");
    (Defs::write_manifest(w), ...);
    w.put("end\n");
    if (w.at != text.data() + text.size()) {
      throw "manifest_size does not match what write_manifest wrote";
    }
    return text;
  }();
};
} // namespace hrw4u::ext

#define HRW4U_EXT_EXPORT __attribute__((visibility("default")))

#define HRW4U_DEF(fn, name, effect) ::hrw4u::ext::Def<fn, name, effect>

// used keeps the unreferenced manifest; on ELF, retain also keeps it from --gc-sections.
#if defined(__APPLE__)
#define HRW4U_MANIFEST_ATTR __attribute__((used, section(HRW4U_MANIFEST_MACHO_SEGMENT "," HRW4U_MANIFEST_MACHO_SECTION)))
#elif defined(__ELF__) && __has_attribute(retain)
#define HRW4U_MANIFEST_ATTR __attribute__((used, retain, section(HRW4U_MANIFEST_ELF_SECTION)))
#else
#define HRW4U_MANIFEST_ATTR __attribute__((used, section(HRW4U_MANIFEST_ELF_SECTION)))
#endif

/// Declares a module table named ident, for a host that registers it itself, and writes its manifest into the .so.
/// Use it in one .cc file: every translation unit that expands it writes its own copy into the section.
#define HRW4U_MODULE_TABLE(ident, module_name, ...)                                                           \
  using ident                                                = ::hrw4u::ext::Table<module_name, __VA_ARGS__>; \
  HRW4U_MANIFEST_ATTR static constexpr auto ident##_manifest = ident::manifest

/// Declares the extension's module table and the entry points that register it.
#define HRW4U_MODULE(module_name, ...)                                                      \
  HRW4U_MODULE_TABLE(hrw4u_module_table, module_name, __VA_ARGS__);                         \
  extern "C" HRW4U_EXT_EXPORT const uint32_t hrw4u_ext_abi_version = HRW4U_EXT_ABI_VERSION; \
  extern "C" HRW4U_EXT_EXPORT int            hrw4u_ext_init(const hrw4u_host_api *api)      \
  {                                                                                         \
    if (api->abi_version != HRW4U_EXT_ABI_VERSION) {                                        \
      return 1;                                                                             \
    }                                                                                       \
    try {                                                                                   \
      if (!hrw4u_module_table::define(api)) {                                               \
        return 1;                                                                           \
      }                                                                                     \
      return 0;                                                                             \
    } catch (...) {                                                                         \
      return 1;                                                                             \
    }                                                                                       \
  }                                                                                         \
  extern "C" HRW4U_EXT_EXPORT void hrw4u_ext_fini(const hrw4u_host_api *) {}
