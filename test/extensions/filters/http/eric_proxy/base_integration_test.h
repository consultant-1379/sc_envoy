#include "test/integration/http_integration.h"
#include "test/integration/ssl_utility.h"
//#include "test/extensions/transport_sockets/tls/integration/ssl_integration_test.h"

namespace Envoy {


class EricProxyIntegrationTestBase : public HttpIntegrationTest {
public:
  EricProxyIntegrationTestBase(Http::CodecClient::Type downstream_protocol,
                      Network::Address::IpVersion ip_version,
                      const std::string& config)
        : HttpIntegrationTest(downstream_protocol, ip_version, config) {}

  EricProxyIntegrationTestBase(Http::CodecClient::Type downstream_protocol,
                      Network::Address::IpVersion ip_version)
        : HttpIntegrationTest(downstream_protocol, ip_version) {}

  void TearDown();
  void initializeWithRouteConfigFromYaml(const std::string& route_config) {

  config_helper_.addConfigModifier(
      [route_config](
          envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager&
              hcm) {
          TestUtility::loadFromYaml(route_config, *hcm.mutable_route_config());
//        TestUtility::loadFromYaml(route_config, *hcm.mutable_route_config(), true);
      });
    initialize();
  }

protected:
 
};

class EricProxyIntegrationTestSsl : public EricProxyIntegrationTestBase {
public:
  EricProxyIntegrationTestSsl(Network::Address::IpVersion ip_version)
      : EricProxyIntegrationTestBase(Http::CodecClient::Type::HTTP1, ip_version) {}

  void initialize() override;

  void TearDown();

  Network::ClientConnectionPtr makeSslConn() { return makeSslClientConnection({}); }
  virtual Network::ClientConnectionPtr
  makeSslClientConnection(const Ssl::ClientSslTransportOptions& options);
  void checkStats();

protected:
  bool server_tlsv1_3_{false};
  bool server_rsa_cert_{true};
  bool server_rsa_cert_ocsp_staple_{false};
  bool server_ecdsa_cert_{false};
  bool server_ecdsa_cert_ocsp_staple_{false};
  bool ocsp_staple_required_{false};
  bool client_ecdsa_cert_{false};
  // Set this true to debug SSL handshake issues with openssl s_client. The
  // verbose trace will be in the logs, openssl must be installed separately.
  bool debug_with_s_client_{false};
  std::unique_ptr<Ssl::ContextManager> context_manager_;
};



} // namespace Envoy
