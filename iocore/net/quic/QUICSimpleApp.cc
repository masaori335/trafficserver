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

#include "QUICSimpleApp.h"

#include "P_Net.h"
#include "QUICDebugNames.h"
#include "HQClientTransaction.h"

static constexpr char tag[] = "quic_simple_app";

// static constexpr uint8_t response[] = "<html>\n"
//                                       "<title>A simple multi-streamed application</title>\n"
//                                       "<p>Apache Traffic Server</p>\n"
//                                       "</html>\n";

//
// DummyClientSession
//
DummyClientSession::DummyClientSession(NetVConnection *vc, QUICStreamIO *stream_io) : _client_vc(vc), _stream_io(stream_io)
{
}

QUICStreamIO *
DummyClientSession::stream_io()
{
  return this->_stream_io;
}

VIO *
DummyClientSession::do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf)
{
  return this->_client_vc->do_io_read(c, nbytes, buf);
}

VIO *
DummyClientSession::do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *buf, bool owner)
{
  return this->_client_vc->do_io_write(c, nbytes, buf, owner);
}

void
DummyClientSession::do_io_close(int lerrno)
{
  return;
}

void
DummyClientSession::do_io_shutdown(ShutdownHowTo_t howto)
{
  return;
}

void
DummyClientSession::reenable(VIO *vio)
{
  return;
}

void
DummyClientSession::destroy()
{
  return;
}

void
DummyClientSession::free()
{
  return;
}

void
DummyClientSession::start()
{
  return;
}

void
DummyClientSession::new_connection(NetVConnection *new_vc, MIOBuffer *iobuf, IOBufferReader *reader, bool backdoor)
{
  return;
}

NetVConnection *
DummyClientSession::get_netvc() const
{
  return this->_client_vc;
}

void
DummyClientSession::release_netvc()
{
  return;
}

int
DummyClientSession::get_transact_count() const
{
  return 0;
}

const char *
DummyClientSession::get_protocol_string() const
{
  return "hq";
}

void
DummyClientSession::release(ProxyClientTransaction *trans)
{
  return;
}

//
// QUICSimpleApp
//
QUICSimpleApp::QUICSimpleApp(QUICConnection *qc) : QUICApplication(qc)
{
  SET_HANDLER(&QUICSimpleApp::main_event_handler);
}

int
QUICSimpleApp::main_event_handler(int event, Event *data)
{
  Debug(tag, "%s", QUICDebugNames::vc_event(event));

  QUICStream *stream      = reinterpret_cast<QUICStream *>(data->cookie);
  QUICStreamIO *stream_io = this->_find_stream_io(stream->id());
  if (stream_io == nullptr) {
    Debug(tag, "Unknown Stream, id: %d", stream->id());
    return -1;
  }

  switch (event) {
  case VC_EVENT_READ_READY:
  case VC_EVENT_READ_COMPLETE: {
    // uint8_t msg[1024] = {0};
    // int64_t msg_len   = 1024;

    // TODO: dump buffer w/ read or consume
    // int64_t read_len = stream_io->read(msg, msg_len);
    // Debug(tag, "[%" PRIx32 "] \n%s\n", stream->id(), msg);
    //
    if (stream_io->read_avail()) {
      // Assuming client sending get of HTTP/0.9
      // Convert HTTP/0.9 it HTTP/1.1
      VIO *read_vio        = stream_io->get_read_vio();
      const char version[] = "Host: localhost\r\n\r\n";
      read_vio->buffer.writer()->write(version, sizeof(version));

      QUICNetVConnection *client_vc = stream->get_client_vc();

      client_vc->set_remote_addr();

      HQClientTransaction trans;
      DummyClientSession *client_session = new DummyClientSession(client_vc, stream_io);
      trans.set_parent(client_session);
      trans.set_reader(stream_io->get_read_buffer_reader());
      trans.new_transaction();

      // TODO: how to write response?

      // stream_io->write(response, sizeof(response));

      // stream->set_fin();
      // stream_io->write_reenable();
    } else {
      Debug(tag, "No MSG");
    }
    break;
  }
  case VC_EVENT_WRITE_READY:
  case VC_EVENT_WRITE_COMPLETE: {
    // Nothing to do
    break;
  }
  case VC_EVENT_EOS:
  case VC_EVENT_ERROR:
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case VC_EVENT_ACTIVE_TIMEOUT: {
    ink_assert(false);
    break;
  }
  default:
    break;
  }

  return EVENT_CONT;
}
