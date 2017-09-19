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

class QUICStreamIO;

class HQClientTransaction : public ProxyClientTransaction
{
public:
  using super = ProxyClientTransaction;

  HQClientTransaction() : super(), outbound_port(0), outbound_transparent(false)
  {
    SET_HANDLER(&HQClientTransaction::main_event_handler);
  }
  int main_event_handler(int event, void *edata);

  // Implement VConnection interface.
  VIO *do_io_read(Continuation *c, int64_t nbytes = INT64_MAX, MIOBuffer *buf = 0) override;
  VIO *do_io_write(Continuation *c = nullptr, int64_t nbytes = INT64_MAX, IOBufferReader *buf = 0, bool owner = false) override;
  void do_io_close(int lerrno = -1) override;

  // Don't destroy your elements.  Rely on the Http1ClientSession to clean up the
  // Http1ClientTransaction class as necessary.  The super::destroy() clears the
  // mutex, which Http1ClientSession owns.
  void destroy() override;
  void do_io_shutdown(ShutdownHowTo_t howto) override;
  void reenable(VIO *vio) override;

  void set_reader(IOBufferReader *reader);
  void release(IOBufferReader *r) override;
  bool ignore_keep_alive() override;
  bool allow_half_open() const override;
  void set_parent(ProxyClientSession *new_parent) override;

  uint16_t get_outbound_port() const override;
  IpAddr get_outbound_ip4() const override;
  IpAddr get_outbound_ip6() const override;
  void set_outbound_port(uint16_t new_port) override;
  void set_outbound_ip(const IpAddr &new_addr) override;
  void clear_outbound_ip();
  bool is_outbound_transparent() const override;
  void set_outbound_transparent(bool flag) override;

  // Pass on the timeouts to the netvc
  void set_active_timeout(ink_hrtime timeout_in) override;
  void set_inactivity_timeout(ink_hrtime timeout_in) override;
  void cancel_inactivity_timeout() override;
  void transaction_done() override;

protected:
  uint16_t outbound_port;
  IpAddr outbound_ip4;
  IpAddr outbound_ip6;
  bool outbound_transparent;

private:
  VIO _write_vio;
  Event *_write_event = nullptr;
};
