/*
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
#pragma once

#include <algorithm>
#include <deque>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <concepts>

#include "ts/ts.h"
#include "ts/remap.h"

#include "cripts/Headers.hpp"

namespace cripts
{
class Context;

class Url
{
  using self_type = Url;

  class Component
  {
    using self_type = Component;

  public:
    Component() = default;
    Component(Url *owner) : _owner(owner) {}

    virtual cripts::string_view GetSV() = 0;

    std::vector<cripts::string_view> Split(char delim);

    operator cripts::string_view() { return GetSV(); } // Should not be explicit

    bool
    operator==(cripts::string_view const &rhs)
    {
      return GetSV() == rhs;
    }

    bool
    operator!=(cripts::string_view const &rhs)
    {
      return GetSV() != rhs;
    }

    virtual void
    Reset()
    {
      _data.clear();
      _loaded = false;
    }

    cripts::string_view::const_pointer
    data()
    {
      return GetSV().data();
    }

    cripts::string_view::size_type
    size()
    {
      return GetSV().size();
    }

    cripts::string_view::size_type
    length()
    {
      return GetSV().size();
    }

    cripts::string_view::const_pointer
    Data()
    {
      return GetSV().data();
    }

    cripts::string_view::size_type
    Size()
    {
      return GetSV().size();
    }

    cripts::string_view::size_type
    Length()
    {
      return GetSV().size();
    }

    // This is not ideal, but best way I can think of for now to mixin the cripts::string_view mixin class
    // Remember to add things here when added to the Lulu.hpp file for the mixin class... :/
    // GetSV() first, since _data is only loaded on demand.
    [[nodiscard]] cripts::string_view
    substr(cripts::string_view::size_type pos = 0, cripts::string_view::size_type count = cripts::string_view::npos)
    {
      GetSV();
      return _data.substr(pos, count);
    }

    void
    remove_prefix(cripts::string_view::size_type n)
    {
      GetSV();
      _data.remove_prefix(n);
    }

    void
    remove_suffix(cripts::string_view::size_type n)
    {
      GetSV();
      _data.remove_suffix(n);
    }

    cripts::string_view &
    ltrim(char c)
    {
      GetSV();
      return _data.ltrim(c);
    }

    cripts::string_view &
    rtrim(char c)
    {
      GetSV();
      return _data.rtrim(c);
    }

    cripts::string_view &
    trim(char c)
    {
      GetSV();
      return _data.trim(c);
    }

    cripts::string_view &
    ltrim(const char *chars = " \t\r\n")
    {
      GetSV();
      return _data.ltrim(chars);
    }

    cripts::string_view &
    rtrim(const char *chars = " \t\r\n")
    {
      GetSV();
      return _data.rtrim(chars);
    }

    cripts::string_view &
    trim(const char *chars = " \t")
    {
      GetSV();
      return _data.trim(chars);
    }

    [[nodiscard]] char const *
    data_end()
    {
      GetSV();
      return _data.data_end();
    }

    [[nodiscard]] bool
    ends_with(cripts::string_view suffix)
    {
      GetSV();
      return _data.ends_with(suffix);
    }

    [[nodiscard]] bool
    starts_with(cripts::string_view const prefix)
    {
      GetSV();
      return _data.starts_with(prefix);
    }

    [[nodiscard]] cripts::string_view::size_type
    find(cripts::string_view const substr, cripts::string_view::size_type pos = 0)
    {
      GetSV();
      return _data.find(substr, pos);
    }

    [[nodiscard]] cripts::string_view::size_type
    rfind(cripts::string_view const substr, cripts::string_view::size_type pos = 0)
    {
      GetSV();
      return _data.rfind(substr, pos);
    }

    [[nodiscard]] bool
    contains(cripts::string_view const substr)
    {
      GetSV();
      return (_data.find(substr) != _data.npos);
    }

  protected:
    // A Cripts write since _data was loaded may have moved the header heap under it.
    [[nodiscard]] bool
    _moved() const
    {
      return _owner && _loaded && _generation != _owner->_heap_writes();
    }

    mutable cripts::string_view _data;
    Url                        *_owner      = nullptr;
    uint64_t                    _generation = 0; // Transaction::heap_writes when _data was loaded
    bool                        _loaded     = false;

  }; // End class Url::Component

public:
  // Each of the members of a URL has its own class, very convenient. Is this
  // great C++? Dunno.
  class Scheme : public Component
  {
    using super_type = Component;
    using self_type  = Scheme;

  public:
    using Component::Component;

    cripts::string_view GetSV() override;
    self_type           operator=(cripts::string_view scheme);

  }; // End class Url::Scheme

  class Host : public Component
  {
    using super_type = Component;
    using self_type  = Host;

  public:
    using Component::Component;

    cripts::string_view GetSV() override;
    self_type           operator=(cripts::string_view host);

  }; // End class Url::Host

  class Port
  {
    using self_type = Port;

  public:
    Port(Url *owner) : _owner(owner){};

    void
    Reset()
    {
      _port = -1;
    }

    operator integer(); // This should not be explicit, and should not be const
    self_type operator=(int port);

    self_type
    operator=(cripts::string_view str)
    {
      uint32_t port   = 80;
      auto     result = std::from_chars(str.data(), str.data() + str.size(), port);

      if (result.ec != std::errc{} || result.ptr != str.data() + str.size() || port > 65535) {
        return *this;
      } else {
        return operator=(port);
      }
    }

  private:
    Url    *_owner = nullptr;
    integer _port  = -1;
  }; // End class Url::Port

  class Path : public Component
  {
  public:
    using Segments = std::vector<cripts::string_view>;

  private:
    using super_type = Component;
    using self_type  = Path;

    class String : public cripts::StringViewMixin<String>
    {
      using super_type = cripts::StringViewMixin<String>;
      using self_type  = String;

    public:
      String() = default;

      // Implemented in the Urls.cc file, bigger function
      self_type &operator=(const cripts::string_view str) override;

      // These specialized assignment operators all use the above
      template <size_t N>
      self_type &
      operator=(const char (&str)[N])
      {
        return operator=(cripts::string_view(str, str[N - 1] ? N : N - 1));
      }

      self_type &
      operator=(char *&str)
      {
        return operator=(cripts::string_view(str, strlen(str)));
      }

      self_type &
      operator=(char const *&str)
      {
        return operator=(cripts::string_view(str, strlen(str)));
      }

      self_type &
      operator=(const std::string &str)
      {
        return operator=(cripts::string_view(str));
      }

    private:
      friend class Path;

      void
      _initialize(cripts::string_view source, Path *owner, Segments::size_type ix)
      {
        _setSV(source);
        _owner = owner;
        _ix    = ix;
      }

      Path               *_owner = nullptr;
      Segments::size_type _ix    = 0;

    }; // End class Url::Path::String

  public:
    friend struct fmt::formatter<Path::String>;

    using Component::Component;

    // _state is deep-copied, edits included, but unedited segment `string_view`s (and Component::_owner)
    // still reference the source URL. The copy's views dangle if the source URL's path is rewritten,
    // and Flush()/operator= on the copy write back to the source URL via TSUrlPathSet.
    Path(const self_type &o) : Component(o), _state(o._state ? std::make_unique<State>(*o._state) : nullptr) { _own_copy(); }

    self_type &
    operator=(const self_type &o)
    {
      if (this != &o) {
        auto new_state = o._state ? std::make_unique<State>(*o._state) : nullptr;
        Component::operator=(o);
        _state = std::move(new_state);
        _own_copy();
      }
      return *this;
    }

    Path(self_type &&)                 = default;
    self_type &operator=(self_type &&) = default;

    void Reset() override;

    cripts::string_view GetSV() override;
    cripts::string      operator+=(cripts::string_view add);
    self_type          &operator=(cripts::string_view path);
    String              operator[](Segments::size_type ix);

    void
    Erase(Segments::size_type ix)
    {
      _parser();
      CAssert(!_owner->ReadOnly()); // This can not be a read-only URL
      if (ix < _state->segments.size()) {
        _state->segments.erase(_state->segments.begin() + ix);
        _detach();
      }
    }

    void
    Erase()
    {
      operator=("");
    }

    void
    Clear()
    {
      Erase();
    }

    void Push(cripts::string_view val);
    void Insert(Segments::size_type ix, cripts::string_view val);

    void
    Flush()
    {
      if (_state && _state->modified) {
        operator=(GetSV());
      }
    }

    [[nodiscard]] bool
    Modified() const
    {
      return _state && _state->modified;
    }

  private:
    void                _parser();
    void                _detach();
    void                _own_copy();
    cripts::string_view _own(cripts::string_view str);

    struct State {
      bool                       modified = false;
      Segments                   segments; // Ordered list of path segments, empty ones included
      std::deque<cripts::string> owned;    // Edited segments, so none points into a caller's string
      cripts::string             storage;  // Used when recombining the segments into a full path
      cripts::string::size_type  size = 0; // Mostly a guestimate for managing storage
    };

    State &
    _ensure_state()
    {
      if (!_state) {
        _state = std::make_unique<State>();
      }
      return *_state;
    }

    std::unique_ptr<State> _state; // Lazily allocated when path is parsed or modified

  }; // End class Url::Path

  class Query : public Component
  {
    using super_type = Component;
    using self_type  = Query;

    struct Param {
      cripts::string_view key;
      cripts::string_view value;
      bool                has_value = false; // "k=v" or "k=", as opposed to a bare "k"
    };
    using Params = std::vector<Param>;

    class Parameter : public cripts::StringViewMixin<Parameter>
    {
      using super_type = cripts::StringViewMixin<Parameter>;
      using self_type  = Parameter;

    public:
      Parameter() = default;

      [[nodiscard]] cripts::string_view
      Name() const
      {
        return _name;
      }

      void
      Erase()
      {
        _owner->Erase(_name);
      }

      // Implemented in the Urls.cc file, bigger function
      self_type &operator=(const cripts::string_view str) override;

      // These specialized assignment operators all use the above
      template <size_t N>
      self_type &
      operator=(const char (&str)[N])
      {
        return operator=(cripts::string_view(str, str[N - 1] ? N : N - 1));
      }

      self_type &
      operator=(char *&str)
      {
        return operator=(cripts::string_view(str, strlen(str)));
      }

      self_type &
      operator=(char const *&str)
      {
        return operator=(cripts::string_view(str, strlen(str)));
      }

      self_type &
      operator=(const std::string &str)
      {
        return operator=(cripts::string_view(str));
      }

    private:
      friend class Query;

      void
      _initialize(cripts::string_view name, cripts::string_view source, Query *owner)
      {
        _setSV(source);
        _name  = name;
        _owner = owner;
      }

      Query         *_owner = nullptr;
      cripts::string _name; // Owned, since a Parameter can outlive both the caller's key and the URL heap's

    }; // End class Url::Query::Parameter

  public:
    friend struct fmt::formatter<Query::Parameter>;

    using Component::Component;

    Query(cripts::string_view load) : _state(std::make_unique<State>())
    {
      _data              = load;
      _state->size       = load.size();
      _loaded            = true;
      _state->standalone = true;
    }

    // _state is deep-copied, edits included, but unedited parameter `string_view`s (and Component::_owner)
    // still reference the source URL. The copy's views dangle if the source URL's query is rewritten,
    // and Flush()/operator= on the copy write back to the source URL via TSUrlHttpQuerySet.
    Query(const self_type &o) : Component(o), _state(o._state ? std::make_unique<State>(*o._state) : nullptr) { _own_copy(); }

    self_type &
    operator=(const self_type &o)
    {
      if (this != &o) {
        auto new_state = o._state ? std::make_unique<State>(*o._state) : nullptr;
        Component::operator=(o);
        _state = std::move(new_state);
        _own_copy();
      }
      return *this;
    }

    Query(self_type &&)                = default;
    self_type &operator=(self_type &&) = default;

    void Reset() override;

    cripts::string_view GetSV() override;
    self_type          &operator=(cripts::string_view query);
    cripts::string      operator+=(cripts::string_view add);
    Parameter           operator[](cripts::string_view param);
    void                Erase(cripts::string_view param);
    void                Erase(std::initializer_list<cripts::string_view> list, bool keep = false);

    void
    Erase()
    {
      operator=("");
      if (_state) {
        _state->size = 0;
      }
    }

    void
    Keep(std::initializer_list<cripts::string_view> list)
    {
      Erase(list, true);
    }

    void
    Clear()
    {
      return Erase();
    }

    void
    Sort()
    {
      _parser();

      _detach();
      std::stable_sort(_state->params.begin(), _state->params.end(), [](const Param &a, const Param &b) { return a.key < b.key; });
    }

    void
    Flush()
    {
      if (_state && _state->modified) {
        operator=(GetSV());
      }
    }

    [[nodiscard]] bool
    Modified() const
    {
      return _state && _state->modified;
    }

  private:
    void                _parser();
    void                _detach();
    void                _own_copy();
    cripts::string_view _own(cripts::string_view str);

    struct State {
      bool                       modified   = false;
      bool                       standalone = false; // This component is used outside of a URL owner, not common
      Params                     params;             // In query order, repeated keys included; can be sorted etc.
      std::deque<cripts::string> owned;              // Edited keys and values, so none points into a caller's string
      cripts::string             storage;            // Used when recombining the query params into a full query string
      cripts::string::size_type  size = 0;           // Mostly a guesttimate
    };

    State &
    _ensure_state()
    {
      if (!_state) {
        _state = std::make_unique<State>();
      }
      return *_state;
    }

    std::unique_ptr<State> _state; // Lazily allocated when query is parsed or modified

  }; // End class Url::Query

public:
  Url() : scheme(this), host(this), port(this), path(this), query(this) {}

  virtual ~Url() = default;

  // Clear anything "cached" in the Url, this is rather draconian, but it's safe...
  virtual void
  Reset()
  {
    if (_bufp && _urlp) {
      TSHandleMLocRelease(_bufp, TS_NULL_MLOC, _urlp);
      _urlp = nullptr;
      _bufp = nullptr;

      _reset_components();
    }
    _initialized = false;
    _modified    = false;
  }

  [[nodiscard]] bool
  Initialized() const
  {
    return _initialized;
  }

  [[nodiscard]] bool
  Modified() const
  {
    return _modified || path.Modified() || query.Modified();
  }

  [[nodiscard]] TSMLoc
  UrlP() const
  {
    return _urlp;
  }

  [[nodiscard]] virtual bool
  ReadOnly() const
  {
    return false;
  }

  // Some of these URL objects needs the full Context, making life miserable.
  void
  set_context(cripts::Context *context)
  {
    _context = context;
  }

  // This is the full string for a URL, which needs allocations.
  [[nodiscard]] cripts::string String();

  Scheme scheme;
  Host   host;
  Port   port;
  Path   path;
  Query  query;

protected:
  static void
  _ensure_initialized(self_type *ptr)
  {
    if (!ptr->Initialized()) [[unlikely]] {
      ptr->_initialize();
    }
  }

  virtual void
  _initialize()
  {
    _initialized = true;
    _modified    = false;
  }

  [[nodiscard]] uint64_t _heap_writes() const;
  void                   _wrote();

  // The components cache views into the URL's heap, which can change or move between hooks.
  void
  _reset_components()
  {
    scheme.Reset();
    host.Reset();
    port.Reset();
    path.Reset();
    query.Reset();
  }

  TSMBuffer            _bufp        = nullptr; // These two gets setup via initializing, to appropriate headers
  TSMLoc               _hdr_loc     = nullptr; // Do not release any of this within the URL classes!
  TSMLoc               _urlp        = nullptr; // This is owned by us.
  cripts::Transaction *_state       = nullptr; // Pointer into the owning Context's State
  cripts::Context     *_context     = nullptr; // Pointer to the owning Context
  bool                 _modified    = false;   // We have pending changes on the path/query components
  bool                 _initialized = false;   // Have we been initialized ?

}; // End class Url

// The Pristine URL is immutable, we should "delete" the operator= methods
namespace Pristine
{
  class URL : public cripts::Url
  {
    using super_type = cripts::Url;
    using self_type  = URL;

  public:
    URL()                             = default;
    URL(const self_type &)            = delete;
    void operator=(const self_type &) = delete;

    static self_type &_get(cripts::Context *context);

    [[nodiscard]] bool
    ReadOnly() const override
    {
      return true;
    }

  protected:
    void _initialize() override;

  }; // End class Pristine::URL

} // namespace Pristine

namespace Client
{
  class URL : public cripts::Url
  {
    using super_type = cripts::Url;
    using self_type  = URL;

  public:
    URL()                             = default;
    URL(const self_type &)            = delete;
    void operator=(const self_type &) = delete;

    // Release/re-init only when we own _urlp: a borrowed remap handle isn't ours to release.
    void
    Reset() override
    {
      if (_owns_urlp) {
        TSHandleMLocRelease(_bufp, _hdr_loc, _urlp);
        _urlp        = nullptr;
        _bufp        = nullptr;
        _hdr_loc     = nullptr;
        _owns_urlp   = false;
        _initialized = false;
      }
      _reset_components();
      _modified = false;
    }

    static self_type &_get(cripts::Context *context);
    bool              _update();

  protected:
    void _initialize() override;

  private:
    bool _owns_urlp = false;

  }; // End class Client::URL

} // namespace Client

namespace Remap
{
  namespace From
  {
    class URL : public cripts::Url
    {
      using super_type = cripts::Url;
      using self_type  = URL;

    public:
      URL()                             = default;
      URL(const self_type &)            = delete;
      void operator=(const self_type &) = delete;

      // We must not release the bufp etc. since it comes from the RRI structure
      void
      Reset() override
      {
      }

      [[nodiscard]] bool
      ReadOnly() const override
      {
        return true;
      }

      static self_type &_get(cripts::Context *context);
      bool              Update();

    private:
      void _initialize() override;

    }; // End class Client::URL

  } // namespace From

  namespace To
  {
    class URL : public cripts::Url
    {
      using super_type = cripts::Url;
      using self_type  = URL;

    public:
      URL()                             = default;
      URL(const self_type &)            = delete;
      void operator=(const self_type &) = delete;

      // We must not release the bufp etc. since it comes from the RRI structure
      void
      Reset() override
      {
      }

      [[nodiscard]] bool
      ReadOnly() const override
      {
        return true;
      }

      static self_type &_get(cripts::Context *context);
      bool              Update();

    private:
      void _initialize() override;

    }; // End class Client::URL

  } // namespace To

} // namespace Remap

namespace Cache
{
  class URL : public cripts::Url // ToDo: This can maybe be a subclass of Client::URL ?
  {
    using super_type = cripts::Url;
    using self_type  = URL;

  public:
    URL()                             = default;
    URL(const self_type &)            = delete;
    void operator=(const self_type &) = delete;

    static self_type &_get(cripts::Context *context);
    bool              _update();

  protected:
    void _initialize() override;

  }; // End class Cache::URL

} // namespace Cache

namespace Parent
{
  class URL : public cripts::Url
  {
    using super_type = cripts::Url;
    using self_type  = URL;

  public:
    URL()                             = default;
    URL(const self_type &)            = delete;
    void operator=(const self_type &) = delete;

    static self_type &_get(cripts::Context *context);
    bool              Update();

  protected:
    void _initialize() override;

  }; // End class Cache::URL

} // namespace Parent

} // namespace cripts

// Formatters for {fmt}
namespace fmt
{
template <std::derived_from<cripts::Url> T> struct formatter<T> {
  constexpr auto
  parse(format_parse_context &ctx) -> decltype(ctx.begin())
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(T &url, FormatContext &ctx) const -> decltype(ctx.out())
  {
    return fmt::format_to(ctx.out(), "{}", url.String());
  }
};

template <> struct formatter<cripts::Url::Scheme> {
  constexpr auto
  parse(format_parse_context &ctx) -> decltype(ctx.begin())
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(cripts::Url::Scheme &scheme, FormatContext &ctx) const -> decltype(ctx.out())
  {
    return fmt::format_to(ctx.out(), "{}", scheme.GetSV());
  }
};

template <> struct formatter<cripts::Url::Host> {
  constexpr auto
  parse(format_parse_context &ctx) -> decltype(ctx.begin())
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(cripts::Url::Host &host, FormatContext &ctx) const -> decltype(ctx.out())
  {
    return fmt::format_to(ctx.out(), "{}", host.GetSV());
  }
};

template <> struct formatter<cripts::Url::Port> {
  constexpr auto
  parse(format_parse_context &ctx) -> decltype(ctx.begin())
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(cripts::Url::Port &port, FormatContext &ctx) const -> decltype(ctx.out())
  {
    return fmt::format_to(ctx.out(), "{}", integer(port));
  }
};

template <> struct formatter<cripts::Url::Path::String> {
  constexpr auto
  parse(format_parse_context &ctx) -> decltype(ctx.begin())
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(cripts::Url::Path::String &path, FormatContext &ctx) const -> decltype(ctx.out())
  {
    return fmt::format_to(ctx.out(), "{}", path.GetSV());
  }
};

template <> struct formatter<cripts::Url::Path> {
  constexpr auto
  parse(format_parse_context &ctx) -> decltype(ctx.begin())
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(cripts::Url::Path &path, FormatContext &ctx) const -> decltype(ctx.out())
  {
    return fmt::format_to(ctx.out(), "{}", path.GetSV());
  }
};

template <> struct formatter<cripts::Url::Query::Parameter> {
  constexpr auto
  parse(format_parse_context &ctx) -> decltype(ctx.begin())
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(cripts::Url::Query::Parameter &param, FormatContext &ctx) const -> decltype(ctx.out())
  {
    return fmt::format_to(ctx.out(), "{}", param.GetSV());
  }
};

template <> struct formatter<cripts::Url::Query> {
  constexpr auto
  parse(format_parse_context &ctx) -> decltype(ctx.begin())
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(cripts::Url::Query &query, FormatContext &ctx) const -> decltype(ctx.out())
  {
    return fmt::format_to(ctx.out(), "{}", query.GetSV());
  }
};

} // namespace fmt
