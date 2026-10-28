/*
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

#include "CriptsTestTxn.h"
#include "cripts/Certs.hpp"

#include <openssl/x509v3.h>

#include <vector>

using cripts_test::Txn;

namespace
{
// The certificate a peer presents, without a TLS connection to get it from.
class PresentedCert : public detail::CertBase
{
public:
  PresentedCert(detail::ConnBase &conn, ::X509 *x509) : detail::CertBase(conn) { _x509 = x509; }
};

void
add_san(GENERAL_NAMES *names, int type, const std::vector<unsigned char> &value)
{
  auto *name = GENERAL_NAME_new();
  auto *str  = ASN1_OCTET_STRING_new();

  ASN1_OCTET_STRING_set(str, value.data(), static_cast<int>(value.size()));
  GENERAL_NAME_set0_value(name, type, str);
  sk_GENERAL_NAME_push(names, name);
}
} // namespace

TEST_CASE("Certs: IP address SANs of a bad length are skipped", "[cripts][Certs]")
{
  Txn  txn{"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"};
  auto x509  = X509_new();
  auto names = sk_GENERAL_NAME_new_null();

  add_san(names, GEN_IPADD, {10, 0, 0, 1});
  add_san(names, GEN_IPADD, {0x7f});
  add_san(names, GEN_IPADD, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
  add_san(names, GEN_IPADD, {1, 2, 3, 4, 5});
  REQUIRE(X509_add1_ext_i2d(x509, NID_subject_alt_name, names, 0, 0) == 1);
  sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);

  {
    PresentedCert cert{txn.context()->_client.connection, x509};

    CHECK(cert.san.ipadd.Join(",") == "10.0.0.1,::1");
  }
  X509_free(x509);
}
