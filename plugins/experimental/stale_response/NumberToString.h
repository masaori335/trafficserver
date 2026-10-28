/** @file

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

#include <cstddef>

/**
 *  Convert the base-16 digit <TT>ch</TT> into an integer.  If the
 *  digit is invalid then <TT>-1</TT> is returned.
 *
 *  @param ch           the base-16 digit to convert.
 *  @return             an integer in the range [0, 15] or -1 if the
 *                      character is NOT a base-16 digit.
 **/
int base16_digit(char ch);

/**
 *  Convert <TT>len</TT> bytes of binary data in <TT>src</TT> into
 *  <TT>2 * len + 1</TT> hexadecimal digits stored in <TT>dst</TT>.
 *
 *  @param dst          a buffer of length <TT>2 * len + 1</TT>.
 *  @param src          the source binary data to convert.
 *  @param len          the number of bytes of binary data in src
 *                      to convert into hexadecimal.
 *  @return             the dst pointer.
 **/
char *base16_encode(char *dst, unsigned char const *src, size_t len);

/**
 *  Convert up to <TT>src_len</TT> hexadecimal digits in <TT>src</TT>
 *  into at most <TT>dst_len</TT> bytes of binary data stored in
 *  <TT>dst</TT>.  Decoding stops at whichever of the two limits is
 *  reached first, so an over long <TT>src</TT> is truncated rather
 *  than written past the end of <TT>dst</TT>.
 *
 *  @param dst          the destination buffer.
 *  @param dst_len      the capacity of dst in bytes.
 *  @param src          the source hexadecimal digits to convert.
 *  @param src_len      the number of hexadecimal digits in src to
 *                      convert into binary data.  If this value is
 *                      odd then the last digit is ignored.
 *  @return             the number of bytes written into dst.
 **/
size_t base16_decode(unsigned char *dst, size_t dst_len, char const *src, size_t src_len);

/*-----------------------------------------------------------------------------------------------*/
