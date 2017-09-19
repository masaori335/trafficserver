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

#include "HQClientTransaction.h"
#include "HQClientSession.h"
#include "HttpSM.h"

int
HQClientTransaction::main_event_handler(int event, void *edata)
{
  switch (event) {
  case VC_EVENT_WRITE_READY:
  case VC_EVENT_WRITE_COMPLETE: {
    uint8_t *buf[1024] = {0};
    size_t buf_len     = 1024;
    int64_t read_len   = this->_write_vio->reader()->read(buf, len);
    this->_write_vio->ndone += read_len;
    this->parent->stream_io()->write(buf, read_len);
  }
  default:
    Debug("hq_trans", "Unknown event %d", event);
    ink_assert(false);
  }

  return EVENT_CONT;
}

void
HQClientTransaction::reenable(VIO *vio)
{
  // if (vio->op == VIO::READ) {
  //   SCOPED_MUTEX_LOCK(lock, this->_read_vio.mutex, this_ethread());

  //   if (this->_read_vio.nbytes > 0) {
  //     int event = (this->_read_vio.ntodo() == 0) ? VC_EVENT_READ_COMPLETE : VC_EVENT_READ_READY;

  //     if (this->_read_event == nullptr) {
  //       this->_read_event = this_ethread()->schedule_imm_local(this, event);
  //     }
  //   }
  // } else
  if (vio->op == VIO::WRITE) {
    SCOPED_MUTEX_LOCK(lock, this->_write_vio.mutex, this_ethread());

    if (this->_write_vio.nbytes > 0) {
      int event = (this->_write_vio.ntodo() == 0) ? VC_EVENT_WRITE_COMPLETE : VC_EVENT_WRITE_READY;

      if (this->_write_event == nullptr) {
        this->_write_event = this_ethread()->schedule_imm_local(this, event);
      }
    }
  }
}

VIO *
HQClientTransaction::do_io_read(Continuation *c, int64_t nbytes = INT64_MAX, MIOBuffer *buf = 0)
{
  return parent->do_io_read(c, nbytes, buf);
}

VIO *
HQClientTransaction::do_io_write(Continuation *c = nullptr, int64_t nbytes = INT64_MAX, IOBufferReader *buf = 0, bool owner = false)
{
  if (buf) {
    this->_write_vio.buffer.reader_for(buf);
  } else {
    this->_write_vio.buffer.clear();
  }

  this->_write_vio.mutex     = c ? c->mutex : this->mutex;
  this->_write_vio._cont     = c;
  this->_write_vio.nbytes    = nbytes;
  this->_write_vio.ndone     = 0;
  this->_write_vio.vc_server = this;
  this->_write_vio.op        = VIO::WRITE;

  this->_write_vio.reenable();

  return &this->_write_vio;
}

void
HQClientTransaction::do_io_close(int lerrno = -1)
{
  parent->do_io_close(lerrno);
  // this->destroy(); Parent owns this data structure.  No need for separate destroy.
}

// Don't destroy your elements.  Rely on the Http1ClientSession to clean up the
// Http1ClientTransaction class as necessary.  The super::destroy() clears the
// mutex, which Http1ClientSession owns.
void
HQClientTransaction::destroy()
{
  current_reader = nullptr;
}

void
HQClientTransaction::do_io_shutdown(ShutdownHowTo_t howto)
{
  parent->do_io_shutdown(howto);
}

void
HQClientTransaction::reenable(VIO *vio)
{
  parent->reenable(vio);
}

void
HQClientTransaction::set_reader(IOBufferReader *reader)
{
  sm_reader = reader;
}

bool
HQClientTransaction::ignore_keep_alive()
{
  return false;
}

bool
HQClientTransaction::allow_half_open() const
{
  return true;
}

uint16_t
HQClientTransaction::get_outbound_port() const
{
  return outbound_port;
}

IpAddr
HQClientTransaction::get_outbound_ip4() const
{
  return outbound_ip4;
}

IpAddr
HQClientTransaction::get_outbound_ip6() const
{
  return outbound_ip6;
}

void
HQClientTransaction::set_outbound_port(uint16_t new_port)
{
  outbound_port = new_port;
}

void
HQClientTransaction::set_outbound_ip(const IpAddr &new_addr)
{
  if (new_addr.isIp4()) {
    outbound_ip4 = new_addr;
  } else if (new_addr.isIp6()) {
    outbound_ip6 = new_addr;
  } else {
    clear_outbound_ip();
  }
}

void
HQClientTransaction::clear_outbound_ip()
{
  outbound_ip4.invalidate();
  outbound_ip6.invalidate();
}

bool
HQClientTransaction::is_outbound_transparent() const
{
  return outbound_transparent;
}

void
HQClientTransaction::set_outbound_transparent(bool flag)
{
  outbound_transparent = flag;
}

void
HQClientTransaction::set_active_timeout(ink_hrtime timeout_in)
{
  if (parent)
    parent->set_active_timeout(timeout_in);
}

void
HQClientTransaction::set_inactivity_timeout(ink_hrtime timeout_in)
{
  if (parent)
    parent->set_inactivity_timeout(timeout_in);
}

void
HQClientTransaction::cancel_inactivity_timeout()
{
  if (parent)
    parent->cancel_inactivity_timeout();
}

void
HQClientTransaction::release(IOBufferReader *r)
{
  // Must set this inactivity count here rather than in the session because the state machine
  // is not availble then
  MgmtInt ka_in = current_reader->t_state.txn_conf->keep_alive_no_activity_timeout_in;
  set_inactivity_timeout(HRTIME_SECONDS(ka_in));

  parent->clear_session_active();
  parent->ssn_last_txn_time = Thread::get_hrtime();

  // Make sure that the state machine is returning
  //  correct buffer reader
  ink_assert(r == sm_reader);
  if (r != sm_reader) {
    this->do_io_close();
  } else {
    super::release(r);
  }
}

void
HQClientTransaction::set_parent(ProxyClientSession *new_parent)
{
  parent                        = new_parent;
  HQClientSession *http1_parent = dynamic_cast<HQClientSession *>(new_parent);
  if (http1_parent) {
    outbound_port        = http1_parent->outbound_port;
    outbound_ip4         = http1_parent->outbound_ip4;
    outbound_ip6         = http1_parent->outbound_ip6;
    outbound_transparent = http1_parent->f_outbound_transparent;
  }
  super::set_parent(new_parent);
}

void
HQClientTransaction::transaction_done()
{
  if (parent) {
    static_cast<HQClientSession *>(parent)->release_transaction();
  }
}
