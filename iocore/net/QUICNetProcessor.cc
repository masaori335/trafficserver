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

#include "ts/ink_config.h"

#include "P_Net.h"
#include "ts/I_Layout.h"
#include "I_RecHttp.h"
#include "QUICGlobals.h"
#include "QUICConfig.h"
#include "QUICTransportParameters.h"
// #include "P_QUICUtils.h"

//
// Global Data
//

QUICNetProcessor quic_NetProcessor;

QUICNetProcessor::QUICNetProcessor() {}

QUICNetProcessor::~QUICNetProcessor()
{
  cleanup();
}

void
QUICNetProcessor::cleanup()
{
  SSL_CTX_free(this->_ssl_ctx);
}

int
QUICNetProcessor::start(int, size_t stacksize)
{
  QUIC::init();
  // This initialization order matters ...
  // QUICInitializeLibrary();
  QUICConfig::startup();

  // Acquire a QUICConfigParams instance *after* we start QUIC up.
  // QUICConfig::scoped_config params;

  // Initialize QUIC statistics. This depends on an initial set of certificates being loaded above.
  // QUICInitializeStatistics();

  // TODO: load certs from SSLConfig
  this->_ssl_ctx = SSL_CTX_new(TLS_method());
  SSL_CTX_set_min_proto_version(this->_ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(this->_ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_alpn_select_cb(this->_ssl_ctx, QUIC::ssl_select_next_protocol, nullptr);
  SSL_CTX_add_custom_ext(this->_ssl_ctx, QUICTransportParametersHandler::TRANSPORT_PARAMETER_ID,
                         SSL_EXT_TLS_ONLY | SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                         &QUICTransportParametersHandler::add, &QUICTransportParametersHandler::free, nullptr,
                         &QUICTransportParametersHandler::parse, nullptr);

  SSLConfig::scoped_config params;
  SSLParseCertificateConfiguration(params, this->_ssl_ctx);

  if (SSL_CTX_check_private_key(this->_ssl_ctx) != 1) {
    Error("check private key failed");
    // ink_assert(false);
  }

  return 0;
}

NetAccept *
QUICNetProcessor::createNetAccept(const NetProcessor::AcceptOptions &opt)
{
  return (NetAccept *)new QUICPacketHandler(opt, this->_ssl_ctx);
}

NetVConnection *
QUICNetProcessor::allocate_vc(EThread *t)
{
  QUICNetVConnection *vc;

  if (t) {
    vc = THREAD_ALLOC(quicNetVCAllocator, t);
    new (vc) QUICNetVConnection();
  } else {
    if (likely(vc = quicNetVCAllocator.alloc())) {
      new (vc) QUICNetVConnection();
      vc->from_accept_thread = true;
    }
  }

  return vc;
}

Action *
QUICNetProcessor::connect_re(Continuation *cont, sockaddr const *addr, NetVCOptions *opt)
{
  Debug("quic_ps", "connect to server");

  EThread *t = cont->mutex->thread_holding;
  ink_assert(t);

  // Setup UDPConnection
  // FIXME: use udpNet.CreateUDPSocket
  int fd                 = socket(AF_INET, SOCK_DGRAM, 0);
  UnixUDPConnection *con = new UnixUDPConnection(fd);
  AcceptOptions const accept_opt;
  QUICPacketHandler *packet_handler = new QUICPacketHandler(accept_opt, this->_ssl_ctx);
  con->setBinding(addr);
  con->bindToThread(packet_handler);

  PollCont *pc       = get_UDPPollCont(con->ethread);
  PollDescriptor *pd = pc->pollDescriptor;

  // ?
  con->ep.start(pd, con, EVENTIO_READ);

  // Setup QUICNetVConnection
  // TODO: randomize
  QUICConnectionId id    = 0x00;
  QUICNetVConnection *vc = static_cast<QUICNetVConnection *>(this->allocate_vc(t));
  vc->init(id, con, packet_handler);

  if (opt) {
    vc->options = *opt;
  } else {
    opt = &vc->options;
  }

  vc->set_context(NET_VCONNECTION_OUT);
  vc->con.setRemote(addr);
  vc->id          = net_next_connection_number();
  vc->submit_time = Thread::get_hrtime();
  vc->mutex       = cont->mutex;
  vc->action_     = cont;

  vc->start(this->_ssl_ctx);
  vc->connectUp(t, NO_FD);

  return ACTION_RESULT_DONE;
}

Action *
QUICNetProcessor::main_accept(Continuation *cont, SOCKET fd, AcceptOptions const &opt)
{
  // UnixNetProcessor *this_unp = static_cast<UnixNetProcessor *>(this);
  Debug("iocore_net_processor", "NetProcessor::main_accept - port %d,recv_bufsize %d, send_bufsize %d, sockopt 0x%0x",
        opt.local_port, opt.recv_bufsize, opt.send_bufsize, opt.sockopt_flags);

  ProxyMutex *mutex  = this_ethread()->mutex.get();
  int accept_threads = opt.accept_threads; // might be changed.
  IpEndpoint accept_ip;                    // local binding address.
  // char thr_name[MAX_THREAD_NAME_LENGTH];

  NetAccept *na = createNetAccept(opt);
  if (accept_threads < 0) {
    REC_ReadConfigInteger(accept_threads, "proxy.config.accept_threads");
  }
  NET_INCREMENT_DYN_STAT(net_accepts_currently_open_stat);

  if (opt.localhost_only) {
    accept_ip.setToLoopback(opt.ip_family);
  } else if (opt.local_ip.isValid()) {
    accept_ip.assign(opt.local_ip);
  } else {
    accept_ip.setToAnyAddr(opt.ip_family);
  }
  ink_assert(0 < opt.local_port && opt.local_port < 65536);
  accept_ip.port() = htons(opt.local_port);

  na->accept_fn = net_accept;
  na->server.fd = fd;
  ats_ip_copy(&na->server.accept_addr, &accept_ip);

  na->action_         = new NetAcceptAction();
  *na->action_        = cont;
  na->action_->server = &na->server;
  na->init_accept();

  udpNet.UDPBind((Continuation *)na, &na->server.accept_addr.sa, 1048576, 1048576);

  return na->action_.get();
}
