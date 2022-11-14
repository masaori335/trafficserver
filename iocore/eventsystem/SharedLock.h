/** @file

  RAII-style self-dead-lock proof unique/shared mutex lock

  @section license License

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

#include "I_EventSystem.h"
#include "I_Thread.h"

#include "tscpp/util/TsSharedMutex.h"

#include <atomic>
#include <shared_mutex>

namespace ts
{
/**
   Example:

   ```
   ts::SharedMutex mutex;

   void
   func1() {
     ts::ScopedUniqueLock lock(mutex); ///< acquire mutex lock and set variables
     func2();
   }

   void
   func2() {
     ts::ScopedUniqueLock lock(mutex);  ///< check variabled and do not acquire mutex lock
   }
   ```
 */
struct SharedMutex {
  ts::shared_mutex mutex;
  std::atomic<EThread *> thread_holding = nullptr;
  bool is_exclusive                     = false;
};

class ScopedUniqueLock
{
public:
  ScopedUniqueLock(SharedMutex &mutex, EThread *ethread) : _mutex(mutex)
  {
    if (_mutex.thread_holding == nullptr || _mutex.thread_holding != ethread) {
      _mutex.mutex.lock();
      _mutex.thread_holding = ethread;
      _mutex.is_exclusive   = true;

      _locked = true;
    } else {
      ink_release_assert(_mutex.is_exclusive == false);
    }
  }

  ~ScopedUniqueLock()
  {
    if (_locked) {
      _mutex.mutex.unlock();
      _mutex.thread_holding = nullptr;
      _mutex.is_exclusive   = false;

      _locked = false;
    }
  }

  bool
  owns_lock()
  {
    return _locked;
  };

private:
  SharedMutex &_mutex;
  bool _locked = false;
};

class ScopedSharedLock
{
public:
  ScopedSharedLock(SharedMutex &mutex, EThread *ethread) : _mutex(mutex)
  {
    if (!_mutex.thread_holding || _mutex.thread_holding != ethread) {
      _mutex.mutex.lock_shared();
      _mutex.thread_holding = ethread;
      _locked               = true;
    }
  }

  ~ScopedSharedLock()
  {
    if (_locked) {
      _mutex.mutex.unlock_shared();
      _mutex.thread_holding = nullptr;
      _locked               = false;
    }
  }

  bool
  owns_lock()
  {
    return _locked;
  };

private:
  SharedMutex &_mutex;
  bool _locked = false;
};

} // namespace ts
