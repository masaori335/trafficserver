/** @file

  Unit test for the X509 Hostname validation functionality

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

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "tscore/ink_apidefs.h"
#include "tscore/Diags.h"
#include "tscore/ink_resource.h"
#include "tscore/ink_queue.h"
#include "tscore/X509HostnameValidator.h"

#include "tsutil/PostScript.h"

// clang-format off

static const char *test_certificate_cn_name = "test.sslheaders.trafficserver.apache.org";

/* The canonical shape: the CN is repeated in a dNSName SAN.
 * SAN: DNS:test.sslheaders.trafficserver.apache.org
 * CN: test.sslheaders.trafficserver.apache.org
 */
static const char *test_certificate_cn =
"-----BEGIN CERTIFICATE-----\n"
"MIICGzCCAYSgAwIBAgIJAN/JvtOlj/5HMA0GCSqGSIb3DQEBBQUAMDMxMTAvBgNV\n"
"BAMMKHRlc3Quc3NsaGVhZGVycy50cmFmZmljc2VydmVyLmFwYWNoZS5vcmcwHhcN\n"
"MTQwNzIzMTc1MTA4WhcNMTcwNTEyMTc1MTA4WjAzMTEwLwYDVQQDDCh0ZXN0LnNz\n"
"bGhlYWRlcnMudHJhZmZpY3NlcnZlci5hcGFjaGUub3JnMIGfMA0GCSqGSIb3DQEB\n"
"AQUAA4GNADCBiQKBgQDNuincV56iMA1E7Ss9BlNvRmUdV3An5S6vXHP/hXSVTSj+\n"
"3o0I7es/2noBM7UmXWTBGNjcQYzBed/QIvqM9p5Q4B7kKFTb1xBOl4EU3LHl9fzz\n"
"hxbZMAc2MHW5X8+eCR6K6IBu5sRuLTPvIZhg63/ffhNJTImyW2+eH8guVGd38QID\n"
"AQABozcwNTAzBgNVHREELDAqgih0ZXN0LnNzbGhlYWRlcnMudHJhZmZpY3NlcnZl\n"
"ci5hcGFjaGUub3JnMA0GCSqGSIb3DQEBBQUAA4GBACayHRw5e0iejNkigLARk9aR\n"
"Wiy0WFkUdffhywjnOKxEGvfZGkNQPFN+0SHk7rAm8SlztOIElSvx/y9DByn4IeSw\n"
"2aU6zZiZUSPi9Stg8/tWv9MvOSU/J7CHaHkWuYbfBTBNDokfqFtqY3UJ7Pn+6ybS\n"
"2RZzwmSjinT8GglE30JR\n"
"-----END CERTIFICATE-----\n";

// A completely wildcard certificate with invalid wildcard format SANs- shouldn't match anything
static const char *test_certificate_bad_sans =
"-----BEGIN CERTIFICATE-----\n"
"MIIB7jCCAZigAwIBAgIJAIECheWAKHNWMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNV\n"
"BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\n"
"aWRnaXRzIFB0eSBMdGQxEDAOBgNVBAMMByouKi4qLiowHhcNMTUwMzA4MTcxOTIy\n"
"WhcNMjUwMzA1MTcxOTIyWjBXMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1T\n"
"dGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRAwDgYDVQQD\n"
"DAcqLiouKi4qMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMeiIvB0e2s7gXc4uxmD\n"
"FeUPjVhjGaGejdkgNoAV/z1sV36G06VGj3JBGkw63fhixVoSfk4MJ/tvuMlu/9E4\n"
"wL0CAwEAAaNHMEUwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwKwYDVR0RBCQwIoIB\n"
"KoIFKi5jb22CCioubG9uZ2xvbmeHBMCoAQGHBMCoRQ4wDQYJKoZIhvcNAQELBQAD\n"
"QQC+zaPBEbJhL/Euaf2slgTMTKhnI3DUo/H5WXj54BKpefv0dtzjPD9rpEPqilhO\n"
"w0LiMuz7rapF/2++9BVPPmBh\n"
"-----END CERTIFICATE-----\n";

/* Multiple wildcard SANs:
 * DNS:*.something.or.other, DNS:*.trafficserver.org, DNS:foo*.trafficserver.com, DNS:*bar.trafficserver.net
 * CN: test.sslheaders.trafficserver.apache.org
 */
static const char *test_certificate_cn_and_SANs =
"-----BEGIN CERTIFICATE-----\n"
"MIICajCCAhSgAwIBAgIJAK5xL+HYV+IuMA0GCSqGSIb3DQEBCwUAMHgxCzAJBgNV\n"
"BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\n"
"aWRnaXRzIFB0eSBMdGQxMTAvBgNVBAMMKHRlc3Quc3NsaGVhZGVycy50cmFmZmlj\n"
"c2VydmVyLmFwYWNoZS5vcmcwHhcNMTUwMzI0MTUyNTEwWhcNMjUwMzIxMTUyNTEw\n"
"WjB4MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwY\n"
"SW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMTEwLwYDVQQDDCh0ZXN0LnNzbGhlYWRl\n"
"cnMudHJhZmZpY3NlcnZlci5hcGFjaGUub3JnMFwwDQYJKoZIhvcNAQEBBQADSwAw\n"
"SAJBAMeiIvB0e2s7gXc4uxmDFeUPjVhjGaGejdkgNoAV/z1sV36G06VGj3JBGkw6\n"
"3fhixVoSfk4MJ/tvuMlu/9E4wL0CAwEAAaOBgDB+MAkGA1UdEwQCMAAwCwYDVR0P\n"
"BAQDAgXgMGQGA1UdEQRdMFuCFCouc29tZXRoaW5nLm9yLm90aGVyghMqLnRyYWZm\n"
"aWNzZXJ2ZXIub3JnghZmb28qLnRyYWZmaWNzZXJ2ZXIuY29tghYqYmFyLnRyYWZm\n"
"aWNzZXJ2ZXIubmV0MA0GCSqGSIb3DQEBCwUAA0EAQmmFmlZQ6lPudkmjJ0K1mSld\n"
"gQP8uiG6cly7NruPZn2Yc1Cha0TycSYfVkRi0dMF2RKtaVvd4uaXDNb4Qpwv3Q==\n"
"-----END CERTIFICATE-----\n";

/* No SAN extension at all:
 * CN: test.sslheaders.trafficserver.apache.org
 */
static const char *test_certificate_cn_no_SAN =
"-----BEGIN CERTIFICATE-----\n"
"MIIB3zCCAUgCCQCiW+Mp1JAYizANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDDCh0\n"
"ZXN0LnNzbGhlYWRlcnMudHJhZmZpY3NlcnZlci5hcGFjaGUub3JnMCAXDTI2MDgw\n"
"NDA2MjcwMVoYDzIxMjYwNzExMDYyNzAxWjAzMTEwLwYDVQQDDCh0ZXN0LnNzbGhl\n"
"YWRlcnMudHJhZmZpY3NlcnZlci5hcGFjaGUub3JnMIGfMA0GCSqGSIb3DQEBAQUA\n"
"A4GNADCBiQKBgQCqBB1M2K/NntwCP1iYJkqQm2oQf9j/z3I35FdFuL8mzUe/IqqL\n"
"wkd7ukWZsJcgPx3jsUf3//ZxeLif3kJvZjrxYAoqIyMK7yqwWgV5swaYLbd1AsHY\n"
"QNQFcu21INeviIjTiKvmZBtlVr4ry5fo50hXW+x94/9aAzS3ekgoZ/lM6QIDAQAB\n"
"MA0GCSqGSIb3DQEBCwUAA4GBAH71xA8ONrVLi4KM4hBCjlJ4+Rv/VtmuckUHYFVF\n"
"PqaJRX7CVrY79O5CZvQvB5YcI7+HXn/Q7iw+PTVkNanaC679QwT0C/7RY5n46ESi\n"
"pLSojayaN8RfY8d08Zris3ZiFZZlTN6YBPpb8VijLX64eUZAdRgrbccpcVX5FfNZ\n"
"oXoY\n"
"-----END CERTIFICATE-----\n";

/* A non-matching iPAddress SAN with a CN that does match the requested IP:
 * SAN: IP:10.0.0.1
 * CN: 192.168.1.1
 */
static const char *test_certificate_cn_ip_and_other_ip_SAN =
"-----BEGIN CERTIFICATE-----\n"
"MIIBvzCCASigAwIBAgIJAKkOGJdkRp3VMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNV\n"
"BAMMCzE5Mi4xNjguMS4xMCAXDTI2MDgwNDA2MjcyNloYDzIxMjYwNzExMDYyNzI2\n"
"WjAWMRQwEgYDVQQDDAsxOTIuMTY4LjEuMTCBnzANBgkqhkiG9w0BAQEFAAOBjQAw\n"
"gYkCgYEA0Mcs3PhjvV5iRd6biF4H8M7Qr29chSJX1mS2Nkxw/v5F9NMHqXKHx1ws\n"
"JjK2NCDSB0FOLkplG1n/FY+gc6UL5xmdXWH/nRzsENKQI7XY5d2soWFZ9Otbqycp\n"
"YL5X5DRuVAPZgO6Ntrgq8JKgiv9wzHBE2owcmATDeZHdiBzLDw0CAwEAAaMTMBEw\n"
"DwYDVR0RBAgwBocECgAAATANBgkqhkiG9w0BAQsFAAOBgQCnMByub3+CNOEZ3uNb\n"
"jDyqcJrnuZFUvVfFgBDdy6gXPKdskpYj+sX3EGujQhLMRGj2es9uADZuzwTNbilG\n"
"3uary1e3quGmFpHMC7fD8i7FO3L9v0gtuqDNtv6pcVIyf5ISg2ztuLYObIxiAkTI\n"
"rIjtMJSF8gMhKPnnOZoKl+428g==\n"
"-----END CERTIFICATE-----\n";

/* No SAN, and the subject CN is a BIT STRING -- a type ASN1_PRINTABLE accepts but
 * ASN1_STRING_to_UTF8() cannot convert. Byte-patched from test_certificate_cn_no_SAN, which
 * invalidates the signature -- irrelevant here, validate_hostname() only parses. The CN spells
 * test_certificate_undecodable_cn_name after its leading BIT STRING "unused bits" octet.
 */
static const char *test_certificate_undecodable_cn_name = "est.sslheaders.trafficserver.apache.org";
static const char *test_certificate_undecodable_cn =
"-----BEGIN CERTIFICATE-----\n"
"MIIB3zCCAUgCCQCiW+Mp1JAYizANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDDCh0\n"
"ZXN0LnNzbGhlYWRlcnMudHJhZmZpY3NlcnZlci5hcGFjaGUub3JnMCAXDTI2MDgw\n"
"NDA2MjcwMVoYDzIxMjYwNzExMDYyNzAxWjAzMTEwLwYDVQQDAygAZXN0LnNzbGhl\n"
"YWRlcnMudHJhZmZpY3NlcnZlci5hcGFjaGUub3JnMIGfMA0GCSqGSIb3DQEBAQUA\n"
"A4GNADCBiQKBgQCqBB1M2K/NntwCP1iYJkqQm2oQf9j/z3I35FdFuL8mzUe/IqqL\n"
"wkd7ukWZsJcgPx3jsUf3//ZxeLif3kJvZjrxYAoqIyMK7yqwWgV5swaYLbd1AsHY\n"
"QNQFcu21INeviIjTiKvmZBtlVr4ry5fo50hXW+x94/9aAzS3ekgoZ/lM6QIDAQAB\n"
"MA0GCSqGSIb3DQEBCwUAA4GBAH71xA8ONrVLi4KM4hBCjlJ4+Rv/VtmuckUHYFVF\n"
"PqaJRX7CVrY79O5CZvQvB5YcI7+HXn/Q7iw+PTVkNanaC679QwT0C/7RY5n46ESi\n"
"pLSojayaN8RfY8d08Zris3ZiFZZlTN6YBPpb8VijLX64eUZAdRgrbccpcVX5FfNZ\n"
"oXoY\n"
"-----END CERTIFICATE-----\n";

/* The reported attack shape: a single plain (non-wildcard) dNSName SAN that does not match,
 * plus a CN that does.
 * SAN: DNS:other.example
 * CN: victim.example
 */
static const char *test_certificate_victim_cn_name = "victim.example";
static const char *test_certificate_victim_cn_other_SAN =
"-----BEGIN CERTIFICATE-----\n"
"MIIB6TCCAVKgAwIBAgIJAMVCyZkXjlfgMA0GCSqGSIb3DQEBCwUAMBkxFzAVBgNV\n"
"BAMMDnZpY3RpbS5leGFtcGxlMCAXDTI2MDgwNDA3MTAzMFoYDzIxMjYwNzExMDcx\n"
"MDMwWjAZMRcwFQYDVQQDDA52aWN0aW0uZXhhbXBsZTCBnzANBgkqhkiG9w0BAQEF\n"
"AAOBjQAwgYkCgYEAy+hnORIPDeZUSR4cff2UBxOxQp36G1iQYoywRsPNijoKzit0\n"
"BqZ0ksiQlxGWnt/wmh6AAamI0Rq8krjYTqKokyk8AQUjRxqWpoMUQrJXuXqi7OOP\n"
"KCD2ttMKGzNjekOWQOhgdWsbu2GFEEx6GjcBkgaKixqf+krdbf9sMGWAd/MCAwEA\n"
"AaM3MDUwGAYDVR0RBBEwD4INb3RoZXIuZXhhbXBsZTAMBgNVHRMBAf8EAjAAMAsG\n"
"A1UdDwQEAwIHgDANBgkqhkiG9w0BAQsFAAOBgQCXRD6E+AvMO/m4u0h1UfVztebH\n"
"xmEMo6jxPNtFRcA0EemmqGNx8kUwK2fXJYggCjGhyxUkxwqCoBy7E6EK4tdG+FC+\n"
"I99yLmKuIRokAoG6pO+na/KLdiSqlYzPFkBq1I9POT9u9ZXe4Zvt9jkwEs8ABVgP\n"
"Z4TatpJXpicg9sVnjQ==\n"
"-----END CERTIFICATE-----\n";

/* No SAN, and a zero-length subject CN. Re-encoded from test_certificate_cn_no_SAN, which
 * invalidates the signature -- irrelevant here, validate_hostname() only parses. OpenSSL will
 * not mint this (CN has a minimum size of 1), but nothing stops a peer from presenting it.
 */
static const char *test_certificate_empty_cn =
"-----BEGIN CERTIFICATE-----\n"
"MIIBtzCCASACCQCiW+Mp1JAYizANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDDCh0\n"
"ZXN0LnNzbGhlYWRlcnMudHJhZmZpY3NlcnZlci5hcGFjaGUub3JnMCAXDTI2MDgw\n"
"NDA2MjcwMVoYDzIxMjYwNzExMDYyNzAxWjALMQkwBwYDVQQDDAAwgZ8wDQYJKoZI\n"
"hvcNAQEBBQADgY0AMIGJAoGBAKoEHUzYr82e3AI/WJgmSpCbahB/2P/PcjfkV0W4\n"
"vybNR78iqovCR3u6RZmwlyA/HeOxR/f/9nF4uJ/eQm9mOvFgCiojIwrvKrBaBXmz\n"
"Bpgtt3UCwdhA1AVy7bUg16+IiNOIq+ZkG2VWvivLl+jnSFdb7H3j/1oDNLd6SChn\n"
"+UzpAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAfvXEDw42tUuLgoziEEKOUnj5G/9W\n"
"2a5yRQdgVUU+polFfsJWtjv07kJm9C8Hlhwjv4def9DuLD49NWQ1qdoLrv1DBPQL\n"
"/tFjmfjoRKKktKiNrJo3xF9jx3TxmuKzdmIVlmVM3pgE+lvxWKMtfrh5RkB1GCtt\n"
"xylxVfkV81mhehg=\n"
"-----END CERTIFICATE-----\n";

// clang-format on

static X509 *
load_cert_from_string(const char *cert_string)
{
  BIO           *bio = BIO_new_mem_buf(cert_string, -1);
  ts::PostScript bio_defer([&]() -> void { BIO_free(bio); });

  return PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
}

// A certificate whose CN is repeated in a dNSName SAN still validates: the SAN supplies the
// match, so the SAN-present rule never reaches the CN. Named for what it exercises -- this was
// previously called CN_match, which the SAN in the fixture made a misnomer.
TEST_CASE("SAN_and_CN_agree", "[libts][X509HostnameValidator]")
{
  char          *matching = nullptr;
  X509          *x        = load_cert_from_string(test_certificate_cn);
  ts::PostScript x_defer([&]() -> void { X509_free(x); });

  REQUIRE(x != nullptr);
  REQUIRE(validate_hostname(x, test_certificate_cn_name, false, &matching) == true);
  REQUIRE(strcmp(test_certificate_cn_name, matching) == 0);
  ats_free(matching);

  // A near miss is still refused.
  REQUIRE(validate_hostname(x, std::string_view{test_certificate_cn_name + 1}, false, nullptr) == false);
}

// Wildcards are honored in every position the matcher supports, and only there.
TEST_CASE("wildcard_SAN_matches", "[libts][X509HostnameValidator]")
{
  char          *matching = nullptr;
  X509          *x        = load_cert_from_string(test_certificate_cn_and_SANs);
  ts::PostScript x_defer([&]() -> void { X509_free(x); });

  REQUIRE(x != nullptr);

  REQUIRE(validate_hostname(x, "a.trafficserver.org", false, &matching) == true);
  REQUIRE(strcmp("*.trafficserver.org", matching) == 0);
  ats_free(matching);

  REQUIRE(validate_hostname(x, "foosomething.trafficserver.com", false, &matching) == true);
  REQUIRE(strcmp("foo*.trafficserver.com", matching) == 0);
  ats_free(matching);

  REQUIRE(validate_hostname(x, "somethingbar.trafficserver.net", false, &matching) == true);
  REQUIRE(strcmp("*bar.trafficserver.net", matching) == 0);
  ats_free(matching);

  // A wildcard matches one label only, and never the requested name's own wildcard.
  REQUIRE(validate_hostname(x, "a.*.trafficserver.org", false, nullptr) == false);
  REQUIRE(validate_hostname(x, "a.bar.trafficserver.net", false, nullptr) == false);
  REQUIRE(validate_hostname(x, "foo.bar.trafficserver.net", false, nullptr) == false);
}

// Patterns with a bare or single-dot wildcard are not usable wildcards, so they only ever
// match literally.
TEST_CASE("degenerate_wildcard_SANs_do_not_match", "[libts][X509HostnameValidator]")
{
  X509          *x = load_cert_from_string(test_certificate_bad_sans);
  ts::PostScript x_defer([&]() -> void { X509_free(x); });

  REQUIRE(x != nullptr);
  REQUIRE(validate_hostname(x, "something.or.other", false, nullptr) == false);
  REQUIRE(validate_hostname(x, "a.b.c", false, nullptr) == false);
  REQUIRE(validate_hostname(x, "......", false, nullptr) == false);

  // The same fixture is the only one carrying iPAddress SANs alongside a CN (*.*.*.*), so it is
  // where the is_ip path meets the SAN-present rule: none of these reach the CN.
  REQUIRE(validate_hostname(x, "0.0.0.0", true, nullptr) == false);
  REQUIRE(validate_hostname(x, "......", true, nullptr) == false);
  REQUIRE(validate_hostname(x, "a.b", true, nullptr) == false);
}

// RFC 9525: once the certificate presents a dNSName SAN, that SAN set is the
// only identity binding -- a non-matching SAN must not be treated as permission to fall
// back to the Common Name. This is the reported certificate shape.
TEST_CASE("non_matching_DNS_SAN_does_not_fall_back_to_CN", "[libts][X509HostnameValidator]")
{
  char          *matching = nullptr;
  X509          *x        = load_cert_from_string(test_certificate_victim_cn_other_SAN);
  ts::PostScript x_defer([&]() -> void { X509_free(x); });

  REQUIRE(x != nullptr);
  REQUIRE(validate_hostname(x, test_certificate_victim_cn_name, false, &matching) == false);
  REQUIRE(matching == nullptr);
  // A dNSName SAN suppresses the CN for an IP query too: the binding is the SAN set's presence,
  // not whether it holds an entry of the queried type.
  REQUIRE(validate_hostname(x, test_certificate_victim_cn_name, true, &matching) == false);
  REQUIRE(matching == nullptr);
  // The SAN it does carry still matches, so the rejection above is not blanket failure.
  REQUIRE(validate_hostname(x, "other.example", false, &matching) == true);
  REQUIRE(strcmp("other.example", matching) == 0);
  ats_free(matching);
}

TEST_CASE("non_matching_IP_SAN_does_not_fall_back_to_CN", "[libts][X509HostnameValidator]")
{
  char          *matching = nullptr;
  X509          *x        = load_cert_from_string(test_certificate_cn_ip_and_other_ip_SAN);
  ts::PostScript x_defer([&]() -> void { X509_free(x); });

  REQUIRE(x != nullptr);
  // CN is 192.168.1.1, but the only iPAddress SAN is 10.0.0.1.
  REQUIRE(validate_hostname(x, "192.168.1.1", true, &matching) == false);
  REQUIRE(matching == nullptr);
  // And the CN stays suppressed for a name query, which no iPAddress SAN can ever satisfy.
  REQUIRE(validate_hostname(x, "192.168.1.1", false, &matching) == false);
  REQUIRE(matching == nullptr);
}

// The CN fallback stays available for certificates that present no dNSName or iPAddress SAN.
TEST_CASE("CN_match_without_SAN", "[libts][X509HostnameValidator]")
{
  char          *matching = nullptr;
  X509          *x        = load_cert_from_string(test_certificate_cn_no_SAN);
  ts::PostScript x_defer([&]() -> void { X509_free(x); });

  REQUIRE(x != nullptr);
  REQUIRE(validate_hostname(x, test_certificate_cn_name, false, &matching) == true);
  REQUIRE(strcmp(test_certificate_cn_name, matching) == 0);
  ats_free(matching);

  REQUIRE(validate_hostname(x, "other.trafficserver.apache.org", false, nullptr) == false);
}

// A wildcard cannot stand in for part of an IDNA label, only for a whole one.
TEST_CASE("IDNA_wildcard_requires_full_label", "[libts][X509HostnameValidator]")
{
  char          *matching = nullptr;
  X509          *x        = load_cert_from_string(test_certificate_cn_and_SANs);
  ts::PostScript x_defer([&]() -> void { X509_free(x); });

  REQUIRE(x != nullptr);
  REQUIRE(validate_hostname(x, "xn--foobar.trafficserver.org", false, &matching) == true);
  REQUIRE(strcmp("*.trafficserver.org", matching) == 0);
  ats_free(matching);

  // *bar.trafficserver.net would match a non-IDNA subject, but not this one.
  REQUIRE(validate_hostname(x, "xn--foobar.trafficserver.net", false, nullptr) == false);
}

// A Common Name that cannot be decoded proves nothing about the requested name, so it must
// not be accepted.
TEST_CASE("undecodable_CN_is_rejected", "[libts][X509HostnameValidator]")
{
  char          *matching = nullptr;
  X509          *x        = load_cert_from_string(test_certificate_undecodable_cn);
  ts::PostScript x_defer([&]() -> void { X509_free(x); });

  REQUIRE(x != nullptr);
  REQUIRE(validate_hostname(x, test_certificate_undecodable_cn_name, false, &matching) == false);
  REQUIRE(matching == nullptr);
}

// An empty requested name must never match anything. The guard in validate_hostname() is what
// enforces this: do_check_string() already rejects zero-length SANs, but the Common Name path
// has no length check, so a zero-length CN would otherwise compare equal to it.
TEST_CASE("empty_hostname_never_matches", "[libts][X509HostnameValidator]")
{
  char          *matching = nullptr;
  X509          *x        = load_cert_from_string(test_certificate_empty_cn);
  ts::PostScript x_defer([&]() -> void { X509_free(x); });

  REQUIRE(x != nullptr);
  REQUIRE(validate_hostname(x, "", false, &matching) == false);
  REQUIRE(validate_hostname(x, "", true, &matching) == false);
  REQUIRE(matching == nullptr);
}

int
main(int argc, const char **argv)
{
  BaseLogFile *blf = new BaseLogFile("stdout");
  DiagsPtr::set(new Diags("test_x509", nullptr, nullptr, blf));
  res_track_memory = 1;

  SSL_library_init();
  ink_freelists_snap_baseline();

  int status = Catch::Session().run(argc, argv);
  ink_freelists_dump(stdout);

  return status;
}
