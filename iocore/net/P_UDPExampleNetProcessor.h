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

#ifndef __P_UDP_EXAMPLE_NET_PROCESSOR_H__
#define __P_UDP_EXAMPLE_NET_PROCESSOR_H__

#include "ts/ink_platform.h"
#include "P_Net.h"

/**
 *  Example Processor of UDP Based Protocol
 */
class UDPExampleNetProcessor : public NetProcessor {
public:
  UDPExampleNetProcessor() {};
  ~UDPExampleNetProcessor() {};

  int start(int, size_t stacksize) override;
  NetVConnection * allocate_vc(EThread *t) override;
  Action *main_accept(Continuation *cont, SOCKET fd, AcceptOptions const &opt) override;
};

extern UDPExampleNetProcessor udpExampleNetProcessor;

/**
 *  Echo Server
 */
class UDPEchoServer : public Continuation {
public:
  UDPEchoServer() {
    this->mutex = new_ProxyMutex();
    SET_HANDLER(&UDPEchoServer::main_event);
  };
  ~UDPEchoServer() {};

  int main_event(int event, void *data);
private:
  void echo(int event, UDPPacket *udpPacket);
};

#endif // __P_UDP_EXAMPLE_NET_PROCESSOR_H__
