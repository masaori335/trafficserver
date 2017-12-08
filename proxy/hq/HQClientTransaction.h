/** @file

  A brief file description

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

#include "VStream.h"
#include "ProxyClientTransaction.h"

class QUICStreamIO;
class HQClientSession;

class HQClientTransaction : public ProxyClientTransaction
{
public:
  using super = ProxyClientTransaction;

  HQClientTransaction(HQClientSession *session, QUICStreamIO *stream_io);

  // Implement ProxyClienTransaction interface
  void set_active_timeout(ink_hrtime timeout_in) override;
  void set_inactivity_timeout(ink_hrtime timeout_in) override;
  void cancel_inactivity_timeout() override;
  void transaction_done() override;
  bool allow_half_open() const override;
  void destroy() override;
  void release(IOBufferReader *r) override;
  int get_transaction_id() const override;

  // VConnection interface
  VIO *do_io_read(Continuation *c, int64_t nbytes = INT64_MAX, MIOBuffer *buf = 0) override;
  VIO *do_io_write(Continuation *c = nullptr, int64_t nbytes = INT64_MAX, IOBufferReader *buf = 0, bool owner = false) override;
  void do_io_close(int lerrno = -1) override;
  void do_io_shutdown(ShutdownHowTo_t) override;
  void reenable(VIO *) override;

  void set_read_vio_nbytes(int64_t nbytes);
  void set_write_vio_nbytes(int64_t nbytes);

  // HQClientTransaction specific methods
  int state_stream_open(int, void *);
  int state_stream_closed(int event, void *data);

private:
  Event *_send_tracked_event(Event *, int, VIO *);
  void _signal_read_event();
  void _signal_write_event();
  int64_t _process_read_vio();
  int64_t _process_write_vio();

  MIOBuffer _read_vio_buf  = CLIENT_CONNECTION_FIRST_READ_BUFFER_SIZE_INDEX;
  QUICStreamIO *_stream_io = nullptr;

  VIO _read_vio;
  VIO _write_vio;
  Event *_read_event  = nullptr;
  Event *_write_event = nullptr;
};
