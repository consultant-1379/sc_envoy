#include "source/extensions/transport_sockets/tls/cert_validator/eric_sepp/eric_sepp_validator.h"

#include "test/extensions/transport_sockets/tls/cert_validator/test_common.h"
#include "test/extensions/transport_sockets/tls/ssl_test_utility.h"
#include "test/test_common/environment.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/test_runtime.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"
#include "openssl/ssl.h"
#include "openssl/x509v3.h"

#include <iostream>
#include <vector>

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

using TestCertificateValidationContextConfigPtr =
    std::unique_ptr<TestCertificateValidationContextConfig>;
using SEPPValidatorPtr = std::unique_ptr<SEPPValidator>;
using ASN1IA5StringPtr = CSmartPtr<ASN1_IA5STRING, ASN1_IA5STRING_free>;
using GeneralNamesPtr = CSmartPtr<GENERAL_NAMES, GENERAL_NAMES_free>;
using X509StoreContextPtr = CSmartPtr<X509_STORE_CTX, X509_STORE_CTX_free>;
using X509Ptr = CSmartPtr<X509, X509_free>;
using SSLContextPtr = CSmartPtr<SSL_CTX, SSL_CTX_free>;

class TestSEPPValidator : public testing::Test {
public:
  TestSEPPValidator() : stats_(generateSslStats(*store_.rootScope())) {}
  void initialize(std::string yaml, TimeSource& time_source) {
    envoy::config::core::v3::TypedExtensionConfig typed_conf;
    TestUtility::loadFromYaml(yaml, typed_conf);
    config_ = std::make_unique<TestCertificateValidationContextConfig>(
        typed_conf, allow_expired_certificate_, san_matchers_);
    validator_ = std::make_unique<SEPPValidator>(config_.get(), stats_, time_source);
  }
  void initialize(std::string yaml) {
    envoy::config::core::v3::TypedExtensionConfig typed_conf;
    TestUtility::loadFromYaml(yaml, typed_conf);
    config_ = std::make_unique<TestCertificateValidationContextConfig>(
        typed_conf, allow_expired_certificate_, san_matchers_);
    validator_ =
        std::make_unique<SEPPValidator>(config_.get(), stats_, config_->api().timeSource());
  };
  void initialize() { validator_ = std::make_unique<SEPPValidator>(stats_, time_system_); }

  SEPPValidator& validator() { return *validator_; }
  SslStats& stats() { return stats_; }

  void setSanMatchers(std::vector<envoy::type::matcher::v3::StringMatcher> san_matchers) {
    san_matchers_.clear();
    for (auto& matcher : san_matchers) {
      san_matchers_.emplace_back();
      san_matchers_.back().set_san_type(
          envoy::extensions::transport_sockets::tls::v3::SubjectAltNameMatcher::DNS);
      *san_matchers_.back().mutable_matcher() = matcher;
    }
  };

#pragma region config
  const std::string basic_config{R"EOF(
name: envoy.tls.cert_validator.sepp
typed_config:
  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.SEPPCertValidatorConfig
  trust_stores:
  - name: RP_A
    matchers:
    - san_type: DNS
      matcher:
        exact: "server1.example.com"
    trusted_ca:
      filename: "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/ca1_cert.pem"
)EOF"};
#pragma endregion config

#pragma region config2
  const std::string config_double{R"EOF(
name: envoy.tls.cert_validator.sepp
typed_config:
  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.SEPPCertValidatorConfig
  trust_stores:
  - name: RP_A
    matchers:
    - san_type: DNS
      matcher:
        exact: "server1.example.com"
    trusted_ca:
      filename: "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/ca1_cert.pem"
  - name: RP_B
    matchers:
    - san_type: DNS
      matcher:
        exact: "server2.example.de"
    trusted_ca:
      filename: "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/ca2_cert.pem"
    )EOF"};
#pragma endregion config2

private:
  bool allow_expired_certificate_{false};
  TestCertificateValidationContextConfigPtr config_;
  std::vector<envoy::extensions::transport_sockets::tls::v3::SubjectAltNameMatcher> san_matchers_{};
  Stats::TestUtil::TestStore store_;
  SslStats stats_;
  Event::TestRealTimeSystem time_system_;
  SEPPValidatorPtr validator_;
};

// test config
TEST_F(TestSEPPValidator, TestInizialization) {
  VERBOSE_EXPECT_NO_THROW(initialize(TestEnvironment::substitute(basic_config)));
}

// Testing multiple trust store
// should get trust store for cert
TEST_F(TestSEPPValidator, TestTrustStore) {
  initialize();

  bssl::UniquePtr<X509> cert = readCertFromFile(TestEnvironment::substitute(
      "{{ test_rundir "
      "}}/test/extensions/transport_sockets/tls/test_data/san_multiple_dns_cert.pem"));
  envoy::type::matcher::v3::StringMatcher matcher;
  matcher.set_exact("api.example.com");
  std::vector<SanMatcherPtr> subject_alt_name_matchers;
  subject_alt_name_matchers.push_back(
      SanMatcherPtr{std::make_unique<StringSanMatcher>(GEN_DNS, matcher)});

  // Trust bundle not provided.
  EXPECT_FALSE(validator().getTrustStore(cert.get()));

  // Trust bundle provided.
  validator().trustStores().clear();
  validator().trustStores().push_back(
      std::make_pair(X509StorePtr(X509_STORE_new()), std::move(subject_alt_name_matchers)));
  EXPECT_EQ(1, validator().trustStores().size());
  EXPECT_TRUE(validator().getTrustStore(cert.get()));
}

// test certificate check for wrong certificate
// should not pass the validation
TEST_F(TestSEPPValidator, TestDoVerifyCertChainPrecheckFailure) {
  initialize();
  X509StoreContextPtr store_ctx = X509_STORE_CTX_new();
  bssl::UniquePtr<X509> cert = readCertFromFile(TestEnvironment::substitute(
      // basicConstraints: CA:True
      "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/ca_cert.pem"));

  TestSslExtendedSocketInfo info;
  EXPECT_FALSE(validator().doSynchronousVerifyCertChain(store_ctx.get(), &info, *cert, nullptr));
  EXPECT_EQ(1, stats().fail_verify_error_.value());
  EXPECT_EQ(info.certificateValidationStatus(), Envoy::Ssl::ClientValidationStatus::Failed);
}

// test single trust domain
TEST_F(TestSEPPValidator, TestDoVerifyCertChainSingleTrustDomain) {
  initialize(TestEnvironment::substitute(basic_config));
  EXPECT_EQ(1, validator().trustStores().size());

  X509StorePtr ssl_ctx = X509_STORE_new();

  // Trust domain matches so should be accepted.
  auto cert = readCertFromFile(TestEnvironment::substitute(
      "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/rp_1_cert.pem"));

  X509StoreContextPtr store_ctx = X509_STORE_CTX_new();
  EXPECT_TRUE(X509_STORE_CTX_init(store_ctx.get(), ssl_ctx.get(), cert.get(), nullptr));
  EXPECT_TRUE(validator().doSynchronousVerifyCertChain(store_ctx.get(), nullptr, *cert, nullptr));

  // Does not have san.
  cert = readCertFromFile(TestEnvironment::substitute(
      "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/extensions_cert.pem"));

  store_ctx = X509_STORE_CTX_new();
  EXPECT_TRUE(X509_STORE_CTX_init(store_ctx.get(), ssl_ctx.get(), cert.get(), nullptr));
  EXPECT_FALSE(validator().doSynchronousVerifyCertChain(store_ctx.get(), nullptr, *cert, nullptr));

  EXPECT_EQ(1, stats().fail_verify_error_.value());
}

// test multiple domains
TEST_F(TestSEPPValidator, TestDoVerifyCertChainMultipleTrustDomain) {
  initialize(TestEnvironment::substitute(config_double));
  X509StorePtr ssl_ctx = X509_STORE_new();

  // Trust domain matches so should be accepted.
  auto cert = readCertFromFile(TestEnvironment::substitute(
      "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/rp_1_cert.pem"));
  X509StoreContextPtr store_ctx = X509_STORE_CTX_new();
  EXPECT_TRUE(X509_STORE_CTX_init(store_ctx.get(), ssl_ctx.get(), cert.get(), nullptr));
  EXPECT_TRUE(validator().doSynchronousVerifyCertChain(store_ctx.get(), nullptr, *cert, nullptr));

  cert = readCertFromFile(TestEnvironment::substitute(
      "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/rp_2_cert.pem"));
  store_ctx = X509_STORE_CTX_new();
  EXPECT_TRUE(X509_STORE_CTX_init(store_ctx.get(), ssl_ctx.get(), cert.get(), nullptr));
  EXPECT_TRUE(validator().doSynchronousVerifyCertChain(store_ctx.get(), nullptr, *cert, nullptr));

  // Trust domain matches but it has expired.
  cert = readCertFromFile(TestEnvironment::substitute(
      "{{ test_rundir "
      "}}/test/extensions/transport_sockets/tls/test_data/name_imp/expired_cert.pem"));
  store_ctx = X509_STORE_CTX_new();
  EXPECT_TRUE(X509_STORE_CTX_init(store_ctx.get(), ssl_ctx.get(), cert.get(), nullptr));
  EXPECT_FALSE(validator().doSynchronousVerifyCertChain(store_ctx.get(), nullptr, *cert, nullptr));

  // // Does not have san.
  // cert = readCertFromFile(TestEnvironment::substitute(
  //     "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/extensions_cert.pem"));

  // store_ctx = X509_STORE_CTX_new();
  // EXPECT_TRUE(X509_STORE_CTX_init(store_ctx.get(), ssl_ctx.get(), cert.get(), nullptr));
  // EXPECT_FALSE(validator().doSynchronousVerifyCertChain(store_ctx.get(), nullptr, *cert,
  // nullptr));

  EXPECT_EQ(1, stats().fail_verify_error_.value());
}

TEST_F(TestSEPPValidator, TestUpdateDigestForSessionId) {
  Event::TestRealTimeSystem time_system;
  initialize(TestEnvironment::substitute(config_double), time_system);
  uint8_t hash_buffer[EVP_MAX_MD_SIZE];
  bssl::ScopedEVP_MD_CTX md;
  EVP_DigestInit(md.get(), EVP_sha256());
  validator().updateDigestForSessionId(md, hash_buffer, SHA256_DIGEST_LENGTH);
}

TEST_F(TestSEPPValidator, TestAddClientValidationContext) {
  Event::TestRealTimeSystem time_system;
  initialize(TestEnvironment::substitute(config_double), time_system);
  bool foundFirstCA = false;
  bool foundSecondCA = false;
  SSLContextPtr ctx = SSL_CTX_new(TLS_method());
  validator().addClientValidationContext(ctx.get(), false);

  for (X509_NAME* name : SSL_CTX_get_client_CA_list(ctx.get())) {
    const int cn_index = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    EXPECT_TRUE(cn_index >= 0);
    X509_NAME_ENTRY* cn_entry = X509_NAME_get_entry(name, cn_index);
    EXPECT_TRUE(cn_entry);
    ASN1_STRING* cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
    EXPECT_TRUE(cn_asn1);

    auto cn_str = std::string(reinterpret_cast<char const*>(ASN1_STRING_data(cn_asn1)));
    if (cn_str == "Test CA1") {
      foundFirstCA = true;
    } else if (cn_str == "Test CA2") {
      foundSecondCA = true;
    }
  }

  EXPECT_TRUE(foundFirstCA);
  EXPECT_TRUE(foundSecondCA);
}

TEST_F(TestSEPPValidator, TestDaysUntilFirstCertExpiresExpired) {
  Event::SimulatedTimeSystem time_system;
  // 2033-05-18 03:33:20 UTC
  const time_t known_date_time = 2000000000;
  time_system.setSystemTime(std::chrono::system_clock::from_time_t(known_date_time));
  initialize(TestEnvironment::substitute(basic_config), time_system);
  EXPECT_EQ(absl::nullopt, validator().daysUntilFirstCertExpires());
}

TEST_F(TestSEPPValidator, TestDaysUntilFirstCertExpires) {
  initialize();
  EXPECT_EQ(std::numeric_limits<uint32_t>::max(), validator().daysUntilFirstCertExpires().value());

  Event::SimulatedTimeSystem time_system;
  time_system.setSystemTime(std::chrono::milliseconds(0));
  initialize(TestEnvironment::substitute(basic_config), time_system);
  EXPECT_EQ(20610, validator().daysUntilFirstCertExpires().value());
  time_system.setSystemTime(std::chrono::milliseconds(864000000));
  EXPECT_EQ(20600, validator().daysUntilFirstCertExpires().value());
}

TEST_F(TestSEPPValidator, TestGetCaCertInformation) {
  initialize();

  // No cert is set so this should be nullptr.
  EXPECT_FALSE(validator().getCaCertInformation());
  initialize(TestEnvironment::substitute(basic_config));
  auto actual = validator().getCaCertInformation();
  EXPECT_TRUE(actual);
}

TEST_F(TestSEPPValidator, TestDoVerifyCertChainIntermediateCerts) {
  initialize(TestEnvironment::substitute(config_double));

  X509StorePtr ssl_ctx = X509_STORE_new();

  // Chain contains workload, intermediate, and ca cert, so it should be accepted.
  auto cert = readCertFromFile(TestEnvironment::substitute(
      "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/"
      "rp_2_signed_by_intermediate_cert.pem"));
  auto intermediate_ca_cert = readCertFromFile(TestEnvironment::substitute(
      "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/"
      "intermediate_ca_cert.pem"));

  STACK_OF(X509)* intermediates = sk_X509_new_null();
  sk_X509_push(intermediates, intermediate_ca_cert.release());

  X509StoreContextPtr store_ctx = X509_STORE_CTX_new();
  EXPECT_TRUE(X509_STORE_CTX_init(store_ctx.get(), ssl_ctx.get(), cert.get(), intermediates));
  EXPECT_TRUE(validator().doSynchronousVerifyCertChain(store_ctx.get(), nullptr, *cert, nullptr));

  sk_X509_pop_free(intermediates, X509_free);
}

TEST_F(TestSEPPValidator, TestDoVerifyCertChainSANMatching) {
  X509StorePtr ssl_ctx = X509_STORE_new();
  auto cert = readCertFromFile(TestEnvironment::substitute(
      "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/rp_1_cert.pem"));
  X509StoreContextPtr store_ctx = X509_STORE_CTX_new();
  EXPECT_TRUE(X509_STORE_CTX_init(store_ctx.get(), ssl_ctx.get(), cert.get(), nullptr));
  TestSslExtendedSocketInfo info;
  info.setCertificateValidationStatus(Envoy::Ssl::ClientValidationStatus::NotValidated);

  {
    envoy::type::matcher::v3::StringMatcher matcher;
    matcher.set_exact("server1.example.com");
    setSanMatchers({matcher});
    initialize(TestEnvironment::substitute(basic_config));
    EXPECT_TRUE(validator().doSynchronousVerifyCertChain(store_ctx.get(), &info, *cert, nullptr));
    EXPECT_EQ(info.certificateValidationStatus(), Envoy::Ssl::ClientValidationStatus::Validated);
  }
  {
    envoy::type::matcher::v3::StringMatcher matcher;
    matcher.set_prefix("server2.example.com");
    setSanMatchers({matcher});
    initialize(TestEnvironment::substitute(basic_config));
    EXPECT_FALSE(validator().doSynchronousVerifyCertChain(store_ctx.get(), &info, *cert, nullptr));
    EXPECT_EQ(1, stats().fail_verify_error_.value());
    EXPECT_EQ(info.certificateValidationStatus(), Envoy::Ssl::ClientValidationStatus::Failed);
    stats().fail_verify_error_.reset();
  }
}

// Here I use one trust store with combined certificated for rp1 and rp2
// Expected behaviour: name impersenalisation successfully accept traffic
// Should ceparate trust stores for roaming partners to avoid
TEST_F(TestSEPPValidator, TestNameImpOneStore) {
  const auto config = TestEnvironment::substitute(R"EOF(
name: envoy.tls.cert_validator.sepp
typed_config:
  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.SEPPCertValidatorConfig
  trust_stores:
  - name: RP_A_B
    matchers:
    - san_type: DNS
      matcher:
        exact: "server1.example.com"
    trusted_ca:
      filename: "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/ca_comb.pem"
)EOF");

  initialize(config);

  X509StorePtr ssl_ctx = X509_STORE_new();

  auto cert = readCertFromFile(TestEnvironment::substitute(
      "{{ test_rundir "
      "}}/test/extensions/transport_sockets/tls/test_data/name_imp/rp_2_imp_1_cert.pem"));

  X509StoreContextPtr store_ctx = X509_STORE_CTX_new();
  EXPECT_TRUE(X509_STORE_CTX_init(store_ctx.get(), ssl_ctx.get(), cert.get(), nullptr));
  EXPECT_TRUE(validator().doSynchronousVerifyCertChain(store_ctx.get(), nullptr, *cert, nullptr));
}

// test cert removal
// first config - one trust store with rp1 and rp2 cas, cert for rp2 is accepted
// second config with rp1 ca only, should not accept rp2 traffic
TEST_F(TestSEPPValidator, TestCertRemoval) {
  auto config = TestEnvironment::substitute(R"EOF(
name: envoy.tls.cert_validator.sepp
typed_config:
  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.SEPPCertValidatorConfig
  trust_stores:
  - name: RP_A_B
    matchers:
    - san_type: DNS
      matcher:
        exact: "server1.example.com"
    trusted_ca:
      filename: "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/ca_comb.pem"
)EOF");

  initialize(config);

  X509StorePtr ssl_ctx = X509_STORE_new();

  auto cert = readCertFromFile(TestEnvironment::substitute(
      "{{ test_rundir "
      "}}/test/extensions/transport_sockets/tls/test_data/name_imp/rp_2_imp_1_cert.pem"));

  X509StoreContextPtr store_ctx = X509_STORE_CTX_new();
  EXPECT_TRUE(X509_STORE_CTX_init(store_ctx.get(), ssl_ctx.get(), cert.get(), nullptr));
  EXPECT_TRUE(validator().doSynchronousVerifyCertChain(store_ctx.get(), nullptr, *cert, nullptr));

  config = TestEnvironment::substitute(R"EOF(
name: envoy.tls.cert_validator.sepp
typed_config:
  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.SEPPCertValidatorConfig
  trust_stores:
  - name: RP_A
    matchers:
    - san_type: DNS
      matcher:
        exact: "server1.example.com"
    trusted_ca:
      filename: "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/ca1_cert.pem"
)EOF");
  initialize(config);
  store_ctx = X509_STORE_CTX_new();
  EXPECT_TRUE(X509_STORE_CTX_init(store_ctx.get(), ssl_ctx.get(), cert.get(), nullptr));
  EXPECT_FALSE(validator().doSynchronousVerifyCertChain(store_ctx.get(), nullptr, *cert, nullptr));
}

// Test name impersonalisation
// rps are splitted should not accept imp certificate
TEST_F(TestSEPPValidator, TestNameImp) {
  const auto config = TestEnvironment::substitute(R"EOF(
name: envoy.tls.cert_validator.sepp
typed_config:
  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.SEPPCertValidatorConfig
  trust_stores:
  - name: RP_A
    matchers:
    - san_type: DNS
      matcher:
        exact: "server1.example.com"
    trusted_ca:
      filename: "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/ca1_cert.pem"
  - name: RP_B
    matchers:
    - san_type: DNS
      matcher:
        exact: "server2.example.de"
    trusted_ca:
      filename: "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/ca2_cert.pem"
    )EOF");

  initialize(config);

  X509StorePtr ssl_ctx = X509_STORE_new();

  auto cert = readCertFromFile(TestEnvironment::substitute(
      "{{ test_rundir "
      "}}/test/extensions/transport_sockets/tls/test_data/name_imp/rp_2_imp_1_cert.pem"));

  X509StoreContextPtr store_ctx = X509_STORE_CTX_new();
  EXPECT_TRUE(X509_STORE_CTX_init(store_ctx.get(), ssl_ctx.get(), cert.get(), nullptr));
  EXPECT_FALSE(validator().doSynchronousVerifyCertChain(store_ctx.get(), nullptr, *cert, nullptr));

  cert = readCertFromFile(TestEnvironment::substitute(
      "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/rp_1_cert.pem"));

  store_ctx = X509_STORE_CTX_new();
  EXPECT_TRUE(X509_STORE_CTX_init(store_ctx.get(), ssl_ctx.get(), cert.get(), nullptr));
  EXPECT_TRUE(validator().doSynchronousVerifyCertChain(store_ctx.get(), nullptr, *cert, nullptr));

  cert = readCertFromFile(TestEnvironment::substitute(
      "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/rp_2_cert.pem"));

  store_ctx = X509_STORE_CTX_new();
  EXPECT_TRUE(X509_STORE_CTX_init(store_ctx.get(), ssl_ctx.get(), cert.get(), nullptr));
  EXPECT_TRUE(validator().doSynchronousVerifyCertChain(store_ctx.get(), nullptr, *cert, nullptr));
}

// test error cert from
TEST_F(TestSEPPValidator, TestError) {
  GTEST_SKIP();
  const auto config = TestEnvironment::substitute(R"EOF(
name: envoy.tls.cert_validator.sepp
typed_config:
  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.SEPPCertValidatorConfig
  trust_stores:
  - name: RP_A
    matchers:
    - san_type: DNS
      matcher:
        exact: "pSepp11.mnc.012.mcc.210.ericsson.se"
    trusted_ca:
      filename: "{{ test_rundir }}/test/extensions/transport_sockets/tls/test_data/name_imp/ca.pem"
  )EOF");

  initialize(config);

  X509StorePtr ssl_ctx = X509_STORE_new();

  auto cert = readCertFromFile(TestEnvironment::substitute(
      "{{ test_rundir "
      "}}/test/extensions/transport_sockets/tls/test_data/name_imp/sepp1.pem"));

  X509StoreContextPtr store_ctx = X509_STORE_CTX_new();
  EXPECT_TRUE(X509_STORE_CTX_init(store_ctx.get(), ssl_ctx.get(), cert.get(), nullptr));
  EXPECT_TRUE(validator().doSynchronousVerifyCertChain(store_ctx.get(), nullptr, *cert, nullptr));
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
