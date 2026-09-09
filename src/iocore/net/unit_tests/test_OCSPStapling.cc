/** @file

  Catch based unit tests for OCSP stapling

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

#ifndef LIBINKNET_UNIT_TEST_DIR
#error please set LIBINKNET_UNIT_TEST_DIR
#endif

#define _STR(s)  #s
#define _XSTR(s) _STR(s)

#include "../P_OCSPStapling.h"

#include <catch2/catch_test_macros.hpp>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <unistd.h>

namespace
{
constexpr char   OCSP_TEST_SSL_DIR[] = _XSTR(LIBINKNET_UNIT_TEST_DIR) "/../../../../tests/uranium_tests/tls/ssl";
constexpr size_t STAPLING_DER_LIMIT  = MAX_STAPLING_DER;

struct BioDeleter {
  void
  operator()(BIO *bio) const
  {
    BIO_free(bio);
  }
};

struct SslCtxDeleter {
  void
  operator()(SSL_CTX *ctx) const
  {
    SSL_CTX_free(ctx);
  }
};

struct X509Deleter {
  void
  operator()(X509 *cert) const
  {
    X509_free(cert);
  }
};

using BioPtr    = std::unique_ptr<BIO, BioDeleter>;
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
using X509Ptr   = std::unique_ptr<X509, X509Deleter>;

X509Ptr
load_cert(std::string const &path)
{
  BioPtr bio{BIO_new_file(path.c_str(), "r")};
  REQUIRE(bio != nullptr);

  X509Ptr cert{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
  REQUIRE(cert != nullptr);
  return cert;
}

// Writes contents to a scratch file for the lifetime of the object. The
// constructor cannot assert: a failed REQUIRE would abandon the object before
// it is fully constructed, so the destructor would never remove the file.
// Callers check is_valid() instead.
class TempFile
{
public:
  TempFile(std::string const &name, std::string const &contents)
    : path{std::filesystem::temp_directory_path() / (name + "." + std::to_string(getpid()))}
  {
    std::ofstream out{this->path, std::ios::binary};

    out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    out.close();
    this->valid = out.good();
  }
  TempFile(TempFile const &)            = delete;
  TempFile(TempFile &&)                 = delete;
  TempFile &operator=(TempFile const &) = delete;
  TempFile &operator=(TempFile &&)      = delete;
  ~TempFile()
  {
    std::error_code ec;
    std::filesystem::remove(this->path, ec);
  }

  bool
  is_valid() const
  {
    return this->valid;
  }

  std::string
  get_path() const
  {
    return this->path.string();
  }

private:
  std::filesystem::path path;
  bool                  valid = false;
};

// Minimal DER TLV encoder, just enough to hand-build an RFC 6960
// OCSPResponse without depending on OCSPStapling.cc's internal ASN1 types.
std::string
der_tlv(unsigned char tag, std::string const &content)
{
  std::string out(1, static_cast<char>(tag));
  size_t      len = content.size();
  if (len < 0x80) {
    out.push_back(static_cast<char>(len));
  } else {
    std::string len_bytes;
    for (size_t l = len; l > 0; l >>= 8) {
      len_bytes.insert(len_bytes.begin(), static_cast<char>(l & 0xFF));
    }
    out.push_back(static_cast<char>(0x80 | len_bytes.size()));
    out += len_bytes;
  }
  out += content;
  return out;
}

// Builds a syntactically valid OCSPResponse { responseStatus, responseBytes
// { responseType, response } } whose "response" OCTET STRING is exactly
// payload_len bytes. The inner bytes don't need to be a valid
// BasicOCSPResponse: stapling_cache_response() treats them as opaque and
// only re-encodes the outer structure.
std::string
make_ocsp_response_der(size_t payload_len)
{
  std::string const status             = der_tlv(0x0A, std::string(1, '\0')); // ENUMERATED: successful
  std::string const response_type      = der_tlv(0x06, std::string("\x2B\x06\x01\x05\x05\x07\x30\x01\x01", 9));
  std::string const response           = der_tlv(0x04, std::string(payload_len, '\xAA')); // OCTET STRING
  std::string const response_bytes_seq = der_tlv(0x30, response_type + response);
  std::string const response_bytes     = der_tlv(0xA0, response_bytes_seq); // [0] EXPLICIT
  return der_tlv(0x30, status + response_bytes);
}

} // end anonymous namespace

TEST_CASE("OCSP stapling keeps SSL_CTX certificate map after later init failure", "[ssl][ocsp]")
{
  ssl_stapling_ex_init();

  SslCtxPtr ctx{SSL_CTX_new(TLS_method())};
  REQUIRE(ctx != nullptr);

  auto issuer = load_cert(std::string{OCSP_TEST_SSL_DIR} + "/ca.ocsp.pem");
  auto good   = load_cert(std::string{OCSP_TEST_SSL_DIR} + "/server.ocsp.pem");
  auto bad    = load_cert(std::string{OCSP_TEST_SSL_DIR} + "/signed-foo.pem");

  REQUIRE(SSL_CTX_use_certificate(ctx.get(), good.get()) == 1);

  REQUIRE(SSL_CTX_add_extra_chain_cert(ctx.get(), issuer.get()) == 1);
  issuer.release();

  REQUIRE(ssl_stapling_init_cert(ctx.get(), good.get(), "server.ocsp.pem", nullptr));
  CHECK_FALSE(ssl_stapling_init_cert(ctx.get(), bad.get(), "signed-foo.pem", nullptr));
}

TEST_CASE("OCSP stapling bounds a prefetched response by the stapling cache size", "[ssl][ocsp]")
{
  ssl_stapling_ex_init();

  SslCtxPtr ctx{SSL_CTX_new(TLS_method())};
  REQUIRE(ctx != nullptr);

  auto issuer = load_cert(std::string{OCSP_TEST_SSL_DIR} + "/ca.ocsp.pem");
  auto good   = load_cert(std::string{OCSP_TEST_SSL_DIR} + "/server.ocsp.pem");

  REQUIRE(SSL_CTX_use_certificate(ctx.get(), good.get()) == 1);
  REQUIRE(SSL_CTX_add_extra_chain_cert(ctx.get(), issuer.get()) == 1);
  issuer.release();

  // The TLV headers wrapped around the payload are a constant size for every
  // payload whose length needs two length bytes, so the payload that lands the
  // encoded response exactly on the limit can be derived instead of hard-coded.
  size_t const overhead = make_ocsp_response_der(1024).size() - 1024;

  SECTION("a normally-sized prefetched response is still accepted")
  {
    std::string const path = std::string{OCSP_TEST_SSL_DIR} + "/ocsp_response.der";
    CHECK(ssl_stapling_init_cert(ctx.get(), good.get(), "server.ocsp.pem", path.c_str()));
  }

  // The two sections below differ by a single payload byte, so the only thing
  // that can separate their outcomes is the size check in
  // stapling_cache_response(). Without the accepting side, the rejecting side
  // would also be satisfied by d2i_TS_OCSP_RESPONSE() refusing to parse the
  // hand-built response.
  SECTION("a response that encodes to exactly the cache limit is accepted")
  {
    std::string const der = make_ocsp_response_der(STAPLING_DER_LIMIT - overhead);
    REQUIRE(der.size() == STAPLING_DER_LIMIT);

    TempFile file{"ats_ocsp_at_limit.der", der};
    REQUIRE(file.is_valid());
    CHECK(ssl_stapling_init_cert(ctx.get(), good.get(), "server.ocsp.pem", file.get_path().c_str()));
  }

  SECTION("a response one byte past the cache limit is rejected, not overflowed")
  {
    std::string const der = make_ocsp_response_der(STAPLING_DER_LIMIT - overhead + 1);
    REQUIRE(der.size() == STAPLING_DER_LIMIT + 1);

    TempFile file{"ats_ocsp_over_limit.der", der};
    REQUIRE(file.is_valid());
    CHECK_FALSE(ssl_stapling_init_cert(ctx.get(), good.get(), "server.ocsp.pem", file.get_path().c_str()));
  }
}
