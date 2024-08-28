#include "sepp_validator_integration_test.h"

#include <memory>

#include "source/extensions/transport_sockets/tls/context_manager_impl.h"

#include "test/integration/integration.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Ssl {

void SslSEPPValidatorIntegrationTest::initialize() {
  config_helper_.addSslConfig(ConfigHelper::ServerSslOptions()
                                  .setRsaCert(true)
                                  .setTlsV13(true)
                                  .setRsaCertOcspStaple(false)
                                  .setCustomValidatorConfig(custom_validator_config_)
                                  .setSanMatchers(san_matchers_)
                                  .setAllowExpiredCertificate(allow_expired_cert_));
  HttpIntegrationTest::initialize();

  context_manager_ = std::make_unique<Extensions::TransportSockets::Tls::ContextManagerImpl>(
      timeSystem(), access_log_manager_);
  registerTestServerPorts({"http"});
}

void SslSEPPValidatorIntegrationTest::TearDown() {
  HttpIntegrationTest::cleanupUpstreamAndDownstream();
  codec_client_.reset();
  context_manager_.reset();
}

Network::ClientConnectionPtr
SslSEPPValidatorIntegrationTest::makeSslClientConnection(const ClientSslTransportOptions& options,
                                                         bool use_expired = false) {
  ClientSslTransportOptions modified_options{options};
  modified_options.setTlsVersion(tls_version_);
  modified_options.use_expired_spiffe_cert_ = use_expired;

  Network::Address::InstanceConstSharedPtr address = getSslAddress(version_, lookupPort("http"));
  auto client_transport_socket_factory_ptr =
      createClientSslTransportSocketFactory(modified_options, *context_manager_, *api_);
  return dispatcher_->createClientConnection(
      address, Network::Address::InstanceConstSharedPtr(),
      client_transport_socket_factory_ptr->createTransportSocket({}, nullptr), nullptr, nullptr);
}

void SslSEPPValidatorIntegrationTest::checkVerifyErrorCouter(uint64_t value) {
  Stats::CounterSharedPtr counter =
      test_server_->counter(listenerStatPrefix("ssl.fail_verify_error"));
  EXPECT_EQ(value, counter->value());
  counter->reset();
}

void SslSEPPValidatorIntegrationTest::addStringMatcher(
    const envoy::type::matcher::v3::StringMatcher& matcher) {
  san_matchers_.emplace_back();
  *san_matchers_.back().mutable_matcher() = matcher;
  san_matchers_.back().set_san_type(
      envoy::extensions::transport_sockets::tls::v3::SubjectAltNameMatcher::DNS);
  san_matchers_.emplace_back();
  *san_matchers_.back().mutable_matcher() = matcher;
  san_matchers_.back().set_san_type(
      envoy::extensions::transport_sockets::tls::v3::SubjectAltNameMatcher::URI);
  san_matchers_.emplace_back();
  *san_matchers_.back().mutable_matcher() = matcher;
  san_matchers_.back().set_san_type(
      envoy::extensions::transport_sockets::tls::v3::SubjectAltNameMatcher::EMAIL);
  san_matchers_.emplace_back();
  *san_matchers_.back().mutable_matcher() = matcher;
  san_matchers_.back().set_san_type(
      envoy::extensions::transport_sockets::tls::v3::SubjectAltNameMatcher::IP_ADDRESS);
}

INSTANTIATE_TEST_SUITE_P(
    IpVersionsClientVersions, SslSEPPValidatorIntegrationTest,
    testing::Combine(
        testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
        testing::Values(envoy::extensions::transport_sockets::tls::v3::TlsParameters::TLSv1_2,
                        envoy::extensions::transport_sockets::tls::v3::TlsParameters::TLSv1_3)),
    SslSEPPValidatorIntegrationTest::ipClientVersionTestParamsToString);

TEST_P(SslSEPPValidatorIntegrationTest, ServerValidatorAccepted) {
  auto typed_conf = new envoy::config::core::v3::TypedExtensionConfig();
  TestUtility::loadFromYaml(TestEnvironment::substitute(R"EOF(
name: envoy.tls.cert_validator.sepp
typed_config:
  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.SEPPCertValidatorConfig
  trust_stores:
  - name: RP_A
    matchers:
    - san_type: DNS
      matcher:
        exact: "lyft.com"
    trusted_ca:
      filename: "{{ test_rundir }}/test/config/integration/certs/cacert.pem"
  )EOF"),
                            *typed_conf);

  custom_validator_config_ = typed_conf;
  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection({});
  };
  testRouterRequestAndResponseWithBody(1024, 512, false, false, &creator);
  checkVerifyErrorCouter(0);
}

TEST_P(SslSEPPValidatorIntegrationTest, ServerRsaSEPPValidatorSANMatch) {
  auto typed_conf = new envoy::config::core::v3::TypedExtensionConfig();
  TestUtility::loadFromYaml(TestEnvironment::substitute(R"EOF(
name: envoy.tls.cert_validator.sepp
typed_config:
  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.SEPPCertValidatorConfig
  trust_stores:
  - name: RP_A
    matchers:
    - san_type: DNS
      matcher:
        exact: "lyft.com"
    trusted_ca:
      filename: "{{ test_rundir }}/test/config/integration/certs/cacert.pem"
  )EOF"),
                            *typed_conf);
  custom_validator_config_ = typed_conf;

  envoy::type::matcher::v3::StringMatcher matcher;
  matcher.set_exact("smf1.external_plmn.com");
  addStringMatcher(matcher);

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection({});
  };
  testRouterRequestAndResponseWithBody(1024, 512, false, false, &creator);
  checkVerifyErrorCouter(0);
}

// wrong server key par should be rejected
TEST_P(SslSEPPValidatorIntegrationTest, ServerRsaSPIFFEValidatorRejected1) {
  auto typed_conf = new envoy::config::core::v3::TypedExtensionConfig();
  TestUtility::loadFromYaml(TestEnvironment::substitute(R"EOF(
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
  )EOF"),
                            *typed_conf);
  custom_validator_config_ = typed_conf;
  initialize();
  auto conn = makeSslClientConnection({});
  if (tls_version_ == envoy::extensions::transport_sockets::tls::v3::TlsParameters::TLSv1_2) {
    auto codec = makeRawHttpConnection(std::move(conn), absl::nullopt);
    EXPECT_FALSE(codec->connected());
  } else {
    auto codec = makeHttpConnection(std::move(conn));
    ASSERT_TRUE(codec->waitForDisconnect());
    codec->close();
  }
  checkVerifyErrorCouter(1);
}

} // namespace Ssl
} // namespace Envoy