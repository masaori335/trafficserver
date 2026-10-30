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
#include <algorithm>
#include <sstream>

#include "cripts/Lulu.hpp"
#include "cripts/Preamble.hpp"

namespace cripts
{

std::vector<cripts::string_view>
Url::Component::Split(const char delim)
{
  return cripts::Splitter(GetSV(), delim);
}

cripts::string_view
Url::Scheme::GetSV()
{
  if (_owner && (!_loaded || _moved())) {
    const char *value = nullptr;
    int         len   = 0;

    _ensure_initialized(_owner);
    value       = TSUrlSchemeGet(_owner->_bufp, _owner->_urlp, &len);
    _data       = cripts::string_view(value, len);
    _loaded     = true;
    _generation = _owner->_heap_writes();
  }

  return _data;
}

Url::Scheme
Url::Scheme::operator=(cripts::string_view scheme)
{
  CAssert(!_owner->ReadOnly()); // This can not be a read-only URL
  _ensure_initialized(_owner);
  TSUrlSchemeSet(_owner->_bufp, _owner->_urlp, scheme.data(), scheme.size());
  _owner->_wrote();
  _owner->_modified = true;
  Reset();

  return *this;
}

cripts::string_view
Url::Host::GetSV()
{
  if (_owner && (!_loaded || _moved())) {
    const char *value = nullptr;
    int         len   = 0;

    _ensure_initialized(_owner);
    value       = TSUrlHostGet(_owner->_bufp, _owner->_urlp, &len);
    _data       = cripts::string_view(value, len);
    _loaded     = true;
    _generation = _owner->_heap_writes();
  }

  return _data;
}

Url::Host
Url::Host::operator=(cripts::string_view host)
{
  _ensure_initialized(_owner);
  CAssert(!_owner->ReadOnly()); // This can not be a read-only URL
  TSUrlHostSet(_owner->_bufp, _owner->_urlp, host.data(), host.size());
  _owner->_wrote();
  _owner->_modified = true;
  Reset();

  return *this;
}

Url::Port::operator integer() // This should not be explicit
{
  _ensure_initialized(_owner);
  if (_owner && _port < 0) {
    _port = TSUrlPortGet(_owner->_bufp, _owner->_urlp);
  }

  return _port;
}

Url::Port
Url::Port::operator=(int port)
{
  _ensure_initialized(_owner);
  CAssert(!_owner->ReadOnly()); // This can not be a read-only URL
  TSUrlPortSet(_owner->_bufp, _owner->_urlp, port);
  _owner->_wrote();
  _owner->_modified = true;
  Reset();

  return *this;
}

cripts::string_view
Url::Path::GetSV()
{
  if (_state && _state->modified) {
    std::ostringstream path;

    std::ranges::copy(_state->segments, std::ostream_iterator<cripts::string_view>(path, "/"));
    _state->storage.reserve(_state->size);
    _state->storage = std::string_view(path.str());
    if (_state->storage.size() > 0) {
      _state->storage.pop_back(); // Removes the trailing /
    }

    _data = _state->storage; // The string helpers work on _data

    return _data;
  }

  if (_moved()) {
    Reset(); // The parsed segments point into the old heap too
  }
  if (_owner && !_loaded) {
    const char *value = nullptr;
    int         len   = 0;

    _ensure_initialized(_owner);
    value = TSUrlPathGet(_owner->_bufp, _owner->_urlp, &len);
    _data = cripts::string_view(value, len);
    if (_state) {
      _state->size = len;
    }
    _loaded     = true;
    _generation = _owner->_heap_writes();
  }

  return _data;
}

Url::Path::String
Url::Path::operator[](Segments::size_type ix)
{
  Url::Path::String ret;

  _ensure_initialized(_owner);
  _parser(); // Make sure the segments are loaded
  ret._initialize(ix < _state->segments.size() ? _state->segments[ix] : cripts::string_view{}, this, ix);

  return ret; // RVO
}

Url::Path &
Url::Path::operator=(cripts::string_view path)
{
  _ensure_initialized(_owner);
  CAssert(!_owner->ReadOnly()); // This can not be a read-only URL
  TSUrlPathSet(_owner->_bufp, _owner->_urlp, path.data(), path.size());
  _owner->_wrote();
  _owner->_modified = true;
  Reset();

  return *this;
}

cripts::string
Url::Path::operator+=(cripts::string_view add)
{
  cripts::string str;

  if (add.size() > 0) {
    str.assign(GetSV());
    str += add;
    operator=(str);
  }

  return str; // RVO
}

Url::Path::String &
Url::Path::String::operator=(const cripts::string_view str)
{
  _ensure_initialized(_owner->_owner);
  CAssert(!_owner->_owner->ReadOnly()); // This can not be a read-only URL
  _owner->_parser();                    // A header write since operator[] may have reset the segments
  if (_ix < _owner->_state->segments.size()) {
    _owner->_detach();
    _owner->_state->segments[_ix] = _owner->_own(str);
  }

  return *this;
}

void
Url::Path::Reset()
{
  Component::Reset();

  _state.reset();
}

void
Url::Path::Push(cripts::string_view val)
{
  _parser();
  _detach();
  auto &s   = *_state;
  auto  seg = _own(val);

  // A trailing slash leaves an empty last segment, which the pushed one takes over.
  if (!s.segments.empty() && s.segments.back().empty()) {
    s.segments.back() = seg;
  } else {
    s.segments.push_back(seg);
  }
}

void
Url::Path::Insert(Segments::size_type ix, cripts::string_view val)
{
  _parser();
  _detach();
  _state->segments.insert(_state->segments.begin() + std::min(ix, _state->segments.size()), _own(val));
}

void
Url::Path::_parser()
{
  if (!Modified() && _moved()) {
    Reset(); // The parsed segments point into the old heap
  }
  if (!_state || _state->segments.empty()) {
    auto  path = GetSV();
    auto &s    = _ensure_state();

    // Empty segments are kept, so a trailing slash or "a//b" survives a rebuild.
    if (!path.empty()) {
      for (cripts::string_view::size_type first = 0;;) {
        auto next = path.find('/', first);

        s.segments.push_back(path.substr(first, next - first));
        if (next == cripts::string_view::npos) {
          break;
        }
        first = next + 1;
      }
    }
  }
}

// The first edit copies every segment, so an edited path no longer points into the header heap.
void
Url::Path::_detach()
{
  auto &s = _ensure_state();

  if (!s.modified) {
    for (auto &segment : s.segments) {
      segment = _own(segment);
    }
    s.modified = true;
  }
}

cripts::string_view
Url::Path::_own(cripts::string_view str)
{
  return _ensure_state().owned.emplace_back(str);
}

// A copy's edits still point into the source's owned strings, which the source frees on Flush() or Reset().
void
Url::Path::_own_copy()
{
  if (_state && _state->modified) {
    _state->owned.clear();
    _state->modified = false;
    _detach();
  }
}

Url::Query::Parameter &
Url::Query::Parameter::operator=(const cripts::string_view str)
{
  CAssert(!_owner->_state || !_owner->_state->standalone);
  _ensure_initialized(_owner->_owner);
  CAssert(!_owner->_owner->ReadOnly()); // This can not be a read-only URL
  _owner->_parser();
  _owner->_detach();

  auto &s     = *_owner->_state;
  auto  value = _owner->_own(str);
  auto  is_us = [this](const Param &p) { return p.key == _name; };
  auto  first = std::find_if(s.params.begin(), s.params.end(), is_us);

  if (first != s.params.end()) {
    first->value     = value;
    first->has_value = !str.empty();
    // Like setting a header, this replaces every occurrence of the key.
    s.params.erase(std::remove_if(std::next(first), s.params.end(), is_us), s.params.end());
  } else {
    s.params.push_back({_owner->_own(_name), value, !str.empty()});
    s.size += _name.size() + str.size() + 2;
  }
  _setSV(value);

  return *this;
}

cripts::string_view
Url::Query::GetSV()
{
  if (!_state || !_state->standalone) {
    _ensure_initialized(_owner);
  }
  if (_state && _state->modified) {
    _state->storage.clear();
    _state->storage.reserve(_state->size);

    for (const auto &param : _state->params) {
      if (!_state->storage.empty()) {
        _state->storage += '&';
      }
      _state->storage += param.key;
      if (param.has_value) {
        _state->storage += '=';
        _state->storage += param.value;
      }
    }

    _data = _state->storage; // The string helpers work on _data

    return _data;
  }

  if (_moved()) {
    Reset(); // The parsed parameters point into the old heap too
  }
  if (_owner && !_loaded) {
    const char *value = nullptr;
    int         len   = 0;

    value = TSUrlHttpQueryGet(_owner->_bufp, _owner->_urlp, &len);
    _data = cripts::string_view(value, len);
    if (_state) {
      _state->size = len;
    }
    _loaded     = true;
    _generation = _owner->_heap_writes();
  }

  return _data;
}

Url::Query &
Url::Query::operator=(cripts::string_view query)
{
  CAssert(!_state || !_state->standalone);
  _ensure_initialized(_owner);
  CAssert(!_owner->ReadOnly()); // This can not be a read-only URL
  TSUrlHttpQuerySet(_owner->_bufp, _owner->_urlp, query.data(), query.size());
  _owner->_wrote();
  _owner->_modified = true;
  Reset();

  return *this;
}

cripts::string
Url::Query::operator+=(cripts::string_view add)
{
  cripts::string str;

  if (add.size() > 0) {
    str.assign(GetSV());
    str += add;
    operator=(str);
  }

  return str; // RVO
}

Url::Query::Parameter
Url::Query::operator[](cripts::string_view param)
{
  // A standalone query has no URL to initialize.
  if (!_state || !_state->standalone) {
    _ensure_initialized(_owner);
  }
  _parser();

  Parameter ret;
  auto      is_param = [param](const Param &p) { return p.key == param; };
  auto      iter     = std::find_if(_state->params.rbegin(), _state->params.rend(), is_param); // The last one wins

  ret._initialize(param, iter != _state->params.rend() ? iter->value : cripts::string_view{}, this);

  return ret;
}

void
Url::Query::Erase(cripts::string_view param)
{
  _parser();

  auto &s    = *_state;
  auto  last = std::remove_if(s.params.begin(), s.params.end(), [param](const Param &p) { return p.key == param; });

  if (last != s.params.end()) {
    s.params.erase(last, s.params.end());
    _detach();
  }
}

void
Url::Query::Erase(std::initializer_list<cripts::string_view> list, bool keep)
{
  if (keep) {
    _parser();

    auto &s       = *_state;
    auto  dropped = [list](const Param &p) { return list.end() == std::find(list.begin(), list.end(), p.key); };
    auto  last    = std::remove_if(s.params.begin(), s.params.end(), dropped);

    if (last != s.params.end()) {
      s.params.erase(last, s.params.end());
      _detach();
    }
  } else {
    for (auto &it : list) {
      Erase(it);
    }
  }
}

void
Url::Query::Reset()
{
  Component::Reset();

  _state.reset();
}

void
Url::Query::_parser()
{
  if (!Modified() && _moved()) {
    Reset(); // The parsed parameters point into the old heap
  }
  if (!_state || _state->params.empty()) {
    auto  params = Split('&');
    auto &s      = _ensure_state();

    for (const auto sv : params) {
      const auto eq = sv.find_first_of('=');

      if (eq == cripts::string_view::npos) {
        s.params.push_back({sv, {}, false});
      } else {
        s.params.push_back({sv.substr(0, eq), sv.substr(eq + 1), true});
      }
    }
  }
}

// The first edit copies every parameter, so an edited query no longer points into the header heap.
void
Url::Query::_detach()
{
  auto &s = _ensure_state();

  if (!s.modified) {
    for (auto &param : s.params) {
      param.key   = _own(param.key);
      param.value = _own(param.value);
    }
    s.modified = true;
  }
}

cripts::string_view
Url::Query::_own(cripts::string_view str)
{
  return _ensure_state().owned.emplace_back(str);
}

// A copy's edits still point into the source's owned strings, which the source frees on Flush() or Reset().
void
Url::Query::_own_copy()
{
  if (_state && _state->modified) {
    _state->owned.clear();
    _state->modified = false;
    _detach();
  }
}

uint64_t
Url::_heap_writes() const
{
  return _context ? _context->state.heap_writes : 0;
}

void
Url::_wrote()
{
  if (_context) {
    ++_context->state.heap_writes;
  }
}

cripts::string
Url::String()
{
  cripts::string ret;

  CAssert(_context);
  _ensure_initialized(this);
  int   full_len = 0;
  char *full_str = TSUrlStringGet(_bufp, _urlp, &full_len);

  if (full_str) {
    ret.assign(full_str, full_len);
    TSfree(static_cast<void *>(full_str));
  }

  return ret;
}

Pristine::URL &
Pristine::URL::_get(cripts::Context *context)
{
  auto &slot = context->_urls.pristine;

  if (!slot) {
    slot = std::make_unique<Pristine::URL>();
    slot->set_context(context);
  }
  _ensure_initialized(slot.get());
  return *slot;
}

void
Pristine::URL::_initialize()
{
  TSAssert(_context->state.txnp);
  if (TSHttpTxnPristineUrlGet(_context->state.txnp, &_bufp, &_urlp) != TS_SUCCESS) {
    _context->state.error.Fail();
  } else {
    super_type::_initialize(); // Only if successful
  }
}

void
Client::URL::_initialize()
{
  if (_context->rriValid()) {
    super_type::_initialize();
    _bufp      = _context->rri->requestBufp;
    _hdr_loc   = _context->rri->requestHdrp;
    _urlp      = _context->rri->requestUrl;
    _owns_urlp = false;
  } else {
    Client::Request &req = Client::Request::_get(_context); // Repurpose / create the shared request object

    _bufp    = req.BufP();
    _hdr_loc = req.MLoc();

    if (TSHttpHdrUrlGet(_bufp, _hdr_loc, &_urlp) != TS_SUCCESS) {
      _context->state.error.Fail();
    } else {
      super_type::_initialize();
      _owns_urlp = true;
    }
  }
}

Client::URL &
Client::URL::_get(cripts::Context *context)
{
  _ensure_initialized(&context->_urls.request);
  return context->_urls.request;
}

bool
Client::URL::_update()
{
  _ensure_initialized(this);
  path.Flush();
  query.Flush();

  return _modified;
}

void
Remap::From::URL::_initialize()
{
  if (_context->rriValid()) {
    super_type::_initialize();
    _bufp    = _context->rri->requestBufp;
    _hdr_loc = _context->rri->requestHdrp;
    _urlp    = _context->rri->mapFromUrl;
  } else {
    _context->state.error.Fail();
  }
}

Remap::From::URL &
Remap::From::URL::_get(cripts::Context *context)
{
  auto &slot = context->_urls.remap.from;

  if (!slot) {
    slot = std::make_unique<Remap::From::URL>();
    slot->set_context(context);
  }
  _ensure_initialized(slot.get());
  return *slot;
}

void
Remap::To::URL::_initialize()
{
  if (_context->rriValid()) {
    super_type::_initialize();
    _bufp    = _context->rri->requestBufp;
    _hdr_loc = _context->rri->requestHdrp;
    _urlp    = _context->rri->mapToUrl;
  } else {
    _context->state.error.Fail();
  }
}

Remap::To::URL &
Remap::To::URL::_get(cripts::Context *context)
{
  auto &slot = context->_urls.remap.to;

  if (!slot) {
    slot = std::make_unique<Remap::To::URL>();
    slot->set_context(context);
  }
  _ensure_initialized(slot.get());
  return *slot;
}

Cache::URL &
Cache::URL::_get(cripts::Context *context)
{
  _ensure_initialized(&context->_cache.url);
  return context->_cache.url;
}

void
Cache::URL::_initialize()
{
  Cache::URL      *url = &_context->_cache.url;
  Client::Request &req = Client::Request::_get(_context); // Repurpose / create the shared request object

  switch (_context->state.hook) {
  // In these hooks, the internal cache-url has been properly set
  case TS_HTTP_SEND_RESPONSE_HDR_HOOK:
  case TS_HTTP_READ_RESPONSE_HDR_HOOK:
  case TS_HTTP_SEND_REQUEST_HDR_HOOK:
  case TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK:
  case TS_HTTP_TXN_CLOSE_HOOK:
    if (TSUrlCreate(req.BufP(), &url->_urlp) == TS_SUCCESS) {
      TSAssert(_context->state.txnp);
      if (TSHttpTxnCacheLookupUrlGet(_context->state.txnp, req.BufP(), url->_urlp) != TS_SUCCESS) {
        _context->state.error.Fail();
        return;
      }
    } else {
      _context->state.error.Fail();
      return;
    }
    break;
  default: { // This means we have to clone. ToDo: For now, this is implicitly using Client::URL
    Client::URL &src = Client::URL::_get(_context);

    if (TSUrlClone(req.BufP(), req.BufP(), src.UrlP(), &url->_urlp) != TS_SUCCESS) {
      _context->state.error.Fail();
      return;
    }
  } break;
  }

  // Only if we succeeded above
  super_type::_initialize();
  _bufp    = req.BufP();
  _hdr_loc = req.MLoc();
  ++_context->state.heap_writes; // Allocated in the client request's heap, which can move its strings
}

// This has to be implemented here, since the cripts::Context is not complete yet
bool
Cache::URL::_update()
{
  // For correctness, we will also make sure the Path and Query objects are flushed
  path.Flush();
  query.Flush();

  if (_modified) {
    _ensure_initialized(&_context->_cache.url);
    TSAssert(_context->state.txnp);
    _modified = false;
    if (TS_SUCCESS == TSHttpTxnCacheLookupUrlSet(_context->state.txnp, _bufp, _urlp)) {
      if (_context->p_instance.DebugOn()) {
        _context->p_instance.debug("Successfully setting cache-key to {}", String());
      }
      return true;
    } else {
      if (_context->p_instance.DebugOn()) {
        _context->p_instance.debug("Could not set the cache key to {}", String());
      }
      _context->state.error.Fail();
      return false;
    }
  }

  return false;
}

// ToDo: This may need more work, to understand which hooks the parent URL is actually available
Parent::URL &
Parent::URL::_get(cripts::Context *context)
{
  auto &slot = context->_urls.parent;

  if (!slot) {
    slot = std::make_unique<Parent::URL>();
    slot->set_context(context);
  }
  _ensure_initialized(slot.get());
  return *slot;
}

void
Parent::URL::_initialize()
{
  Client::Request &req = Client::Request::_get(_context); // Repurpose / create the shared request object

  if (TSUrlCreate(req.BufP(), &_urlp) == TS_SUCCESS) {
    TSAssert(_context->state.txnp);
    if (TSHttpTxnParentSelectionUrlGet(_context->state.txnp, req.BufP(), _urlp) != TS_SUCCESS) {
      _context->state.error.Fail();
      return;
    }
  } else {
    _context->state.error.Fail();
    return;
  }

  // Only if successful above
  super_type::_initialize();
  _bufp    = req.BufP();
  _hdr_loc = req.MLoc();
  ++_context->state.heap_writes; // Allocated in the client request's heap, which can move its strings
}

} // namespace cripts
