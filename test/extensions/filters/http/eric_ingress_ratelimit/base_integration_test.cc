#include "base_integration_test.h"

#include <memory>
#include <string>

#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "envoy/config/core/v3/address.pb.h"
#include "envoy/config/core/v3/base.pb.h"
#include "envoy/config/tap/v3/common.pb.h"
#include "envoy/data/tap/v3/wrapper.pb.h"
#include "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.pb.h"
#include "envoy/extensions/transport_sockets/tap/v3/tap.pb.h"
#include "envoy/extensions/transport_sockets/tls/v3/cert.pb.h"

#include "source/common/event/dispatcher_impl.h"
#include "source/common/network/connection_impl.h"
#include "source/common/network/utility.h"

#include "source/extensions/transport_sockets/tls/context_config_impl.h"
#include "source/extensions/transport_sockets/tls/context_manager_impl.h"
#include "source/extensions/transport_sockets/tls/ssl_handshaker.h"

#include "test/extensions/common/tap/common.h"
#include "test/integration/autonomous_upstream.h"
#include "test/integration/integration.h"
#include "test/integration/utility.h"
#include "test/test_common/network_utility.h"
#include "test/test_common/utility.h"

#include "absl/strings/match.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {

void RatelimitIntegrationTestSsl::initialize() {
  config_helper_.addSslConfig(ConfigHelper::ServerSslOptions()
                                  .setRsaCert(server_rsa_cert_)
                                  .setRsaCertOcspStaple(server_rsa_cert_ocsp_staple_)
                                  .setEcdsaCert(server_ecdsa_cert_)
                                  .setEcdsaCertOcspStaple(server_ecdsa_cert_ocsp_staple_)
                                  .setOcspStapleRequired(ocsp_staple_required_)
                                  .setTlsV13(server_tlsv1_3_)
                                  .setExpectClientEcdsaCert(client_ecdsa_cert_));


  
  HttpIntegrationTest::initialize();

  context_manager_ = std::make_unique<Extensions::TransportSockets::Tls::ContextManagerImpl>(
      timeSystem(), access_log_manager_);

  registerTestServerPorts({"http"});
}

void RatelimitIntegrationTestSsl::TearDown() {
  HttpIntegrationTest::cleanupUpstreamAndDownstream();
  codec_client_.reset();
  context_manager_.reset();
}

Network::ClientConnectionPtr RatelimitIntegrationTestSsl::makeSslClientConnection(
    const Ssl::ClientSslTransportOptions& options) {
  Network::Address::InstanceConstSharedPtr address =
      Ssl::getSslAddress(version_, lookupPort("http"));
  if (debug_with_s_client_) {
    const std::string s_client_cmd = TestEnvironment::substitute(
        "openssl s_client -connect " + address->asString() +
            " -showcerts -debug -msg -CAfile "
            "{{ test_rundir }}/test/config/integration/certs/cacert.pem "
            "-servername lyft.com -cert "
            "{{ test_rundir }}/test/config/integration/certs/clientcert.pem "
            "-key "
            "{{ test_rundir }}/test/config/integration/certs/clientkey.pem ",
        version_);
    ENVOY_LOG_MISC(debug, "Executing {}", s_client_cmd);
    RELEASE_ASSERT(::system(s_client_cmd.c_str()) == 0, "");
  }
  auto client_transport_socket_factory_ptr =
      createClientSslTransportSocketFactory(options, *context_manager_, *api_);
  return dispatcher_->createClientConnection(
      address, Network::Address::InstanceConstSharedPtr(),
      client_transport_socket_factory_ptr->createTransportSocket({}, nullptr), nullptr, nullptr);
}

void RatelimitIntegrationTestSsl::checkStats() {
  const uint32_t expected_handshakes = debug_with_s_client_ ? 2 : 1;
  Stats::CounterSharedPtr counter = test_server_->counter(listenerStatPrefix("ssl.handshake"));
  EXPECT_EQ(expected_handshakes, counter->value());
  counter->reset();
}

// function accepts two json arrays and compares them
// for float comparison an approximation is considered
void RatelimitIntegrationTestBase::compareJsonBodies(json rec_list, json expected_list) {
  ASSERT(rec_list.is_array());
  ASSERT(expected_list.is_array());

  EXPECT_EQ(rec_list.size(), expected_list.size());
  size_t index = 0;
  while (index < rec_list.size()) {
    json rec = rec_list[index];
    json expected = expected_list[index];
    EXPECT_EQ(rec.size(), expected.size());

    for (json::iterator it = rec.begin(); it != rec.end(); ++it) {
      EXPECT_TRUE(expected.contains(it.key()));
      // comparing float values is done by approximation
      if (it.key() == "watermark") {
        float diff = static_cast<float>(it.value()) - static_cast<float>(expected[it.key()]);
        EXPECT_LE(std::fabs(diff), 0.1f);
      } else {
        EXPECT_EQ(expected[it.key()], it.value());
      }
    }
    index++;
  }
}

} // namespace Envoy
