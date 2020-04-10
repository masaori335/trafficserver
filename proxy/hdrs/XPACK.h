/** @file
 *
 *  A brief file description
 *
 *  @section license License
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#pragma once

#include <cstdint>
#include "tscore/Arena.h"

const static int XPACK_ERROR_COMPRESSION_ERROR   = -1;
const static int XPACK_ERROR_SIZE_EXCEEDED_ERROR = -2;

// These primitives are shared with HPACK and QPACK.
int64_t xpack_encode_integer(uint8_t *buf_start, const uint8_t *buf_end, uint64_t value, uint8_t n);
int64_t xpack_decode_integer(uint64_t &dst, const uint8_t *buf_start, const uint8_t *buf_end, uint8_t n);

int64_t xpack_encode_string(uint8_t *buf_start, const uint8_t *buf_end, const char *value, uint64_t value_len, uint8_t n = 7);
int64_t xpack_decode_string(Arena &arena, char **str, uint64_t &str_length, const uint8_t *buf_start, const uint8_t *buf_end,
                            uint8_t n = 7);

/**
  Decode XPACK String Literals without Arena
 */
class XpackStringDecoder
{
public:
  XpackStringDecoder(const uint8_t *s, const uint8_t *e) : _buf_start(s), _buf_end(e) {}
  XpackStringDecoder(const uint8_t *s, const uint8_t *e, uint8_t p) : _buf_start(s), _buf_end(e), _prefix(p) {}

  // Don't allocate on heap
  void *operator new(std::size_t)   = delete;
  void *operator new[](std::size_t) = delete;

  int max_string_len(std::size_t &buf_len);
  int64_t string(char *str, uint64_t &str_len);

private:
  enum class State {
    NONE,
    LENGTH_DECODED,
    DONE,
    ERROR,
  };

  State _state = State::NONE;
  const uint8_t *const _buf_start;
  const uint8_t *const _buf_end;
  uint8_t _prefix           = 7;
  bool _is_huffman          = false;
  int64_t _length_field_len = 0;
  uint64_t _data_field_len  = 0;
};
