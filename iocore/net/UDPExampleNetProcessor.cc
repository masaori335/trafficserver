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
#ifdef ENABLE_UDP_EXAMPLE

#include "P_Net.h"

//
// Global Data
//

UDPExampleNetProcessor udpExampleNetProcessor;

int
UDPExampleNetProcessor::start(int, size_t)
{
  return 0;
}

NetVConnection *
UDPExampleNetProcessor::allocate_vc(EThread *t)
{
  return nullptr;
}

Action *
UDPExampleNetProcessor::main_accept(Continuation *cont, SOCKET ATS_UNUSED, AcceptOptions const &opt)
{
  Debug("udp_example_processor", "UDPExampleNetProcessor::main_accept - port %d,recv_bufsize %d, send_bufsize %d, sockopt 0x%0x",
        opt.local_port, opt.recv_bufsize, opt.send_bufsize, opt.sockopt_flags);

  IpEndpoint accept_ip; // local binding address.

  if (opt.localhost_only) {
    accept_ip.setToLoopback(opt.ip_family);
  } else if (opt.local_ip.isValid()) {
    accept_ip.assign(opt.local_ip);
  } else {
    accept_ip.setToAnyAddr(opt.ip_family);
  }

  ink_assert(0 < opt.local_port && opt.local_port < 65536);
  accept_ip.port() = htons(opt.local_port);

  UDPEchoServer *echo_server = new UDPEchoServer();

  udpNet.UDPBind((Continuation *)echo_server, &accept_ip.sa, 1024000, 1024000);

  return (Action *)cont;
}

//
// Echo Server
//
int
UDPEchoServer::main_event(int event, void *data)
{
  switch (event) {
  case NET_EVENT_DATAGRAM_OPEN: {
    // Nothing to do.
    break;
  }
  case NET_EVENT_DATAGRAM_READ_READY: {
    Queue<UDPPacket> *queue = reinterpret_cast<Queue<UDPPacket> *>(data);
    UDPPacket *packet_r;
    ip_port_text_buffer ipb;
    while ((packet_r = queue->dequeue())) {
      Debug("udp_echo", "received packet from %s, size=%lld", ats_ip_nptop(&packet_r->from.sa, ipb, sizeof(ipb)),
            packet_r->getPktLength());
      echo(event, packet_r);
    }
    break;
  }
  case NET_EVENT_DATAGRAM_ERROR: {
    ink_abort("UDP Echo received fatal error: errno = %d", -((int)(intptr_t)data));
    break;
  }
  default:
    Debug("udp_echo", "unkown event");
    break;
  }

  return EVENT_DONE;
}

void
UDPEchoServer::echo(int event, UDPPacket *packet_r)
{
  IOBufferBlock *block   = packet_r->getIOBlockChain();
  UDPPacket *packet_s    = new_UDPPacket(&packet_r->from.sa, 0, block, block->size());
  UDPConnection *udp_con = packet_r->getConnection();
  udp_con->send(this, packet_s);
}

#endif // ENABLE_UDP_EXAMPLE
