#pragma once
#include "test/integration/http_integration.h"
#include "envoy/http/filter.h"
#include "envoy/http/codes.h"
#include "cluster_configurator.h"
using namespace fmt::literals;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

//-----------------------------------------------------------------------------------
// Generic version of the pluggable configurator. See the "using" statements below
// for specialized versions

enum BodyContentType {APPLICATION_JSON, MULTIPART_RELATED};

template<typename Variant1, typename... Variants>
class PluggableConfiguratorBase
    : public HttpIntegrationTest,
      public testing::TestWithParam<std::tuple<Variant1, Variants...>> {
public:
  // uses the listener + route config present in the class
  PluggableConfiguratorBase()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, std::get<0>(this->GetParam()), baseConfig()) {
    downstream_http_protocol_ = Http::CodecClient::Type::HTTP1;
  }
  // Supply a custom route and listener config
  PluggableConfiguratorBase(std::string base_config)
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, std::get<0>(this->GetParam()), base_config) {
    downstream_http_protocol_ = Http::CodecClient::Type::HTTP1;
  }
  // Supply the Http Codec type for the integration test and an optional listener config
  PluggableConfiguratorBase(Http::CodecClient::Type codec_type, absl::optional<std::string> base_config)
      : HttpIntegrationTest(codec_type, std::get<0>(this->GetParam()),
                            base_config.has_value() ? base_config.value() : baseConfig()) {
    downstream_http_protocol_ = codec_type;
  }

  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // If you specialize the PluggableConfiguratorBase class for something else, then
  // add an access function here (or use std::get<X>(this->GetParam())) in your code)
  BodyContentType getBodyContentType() const { return std::get<1>(this->GetParam()); }

  // To Set the protocol type for downstream and upstream
  // Typically no use-cases for mixed protocol routing so we dont care
  // to provide granular control
  Http::CodecClient::Type downstream_http_protocol_;

  /**
   * Initializes configuration with one HTTP filter
   *
   * @param filter_configs string containing the filter configuration
   * @param cluster_configurator Cluster configurator implementing the desired cluster and endpoint
            config
   */
  void initConfig(const std::string& filter_config, ClusterConfigurator& cluster_configurator) {
    initConfig(std::vector<std::string>{filter_config}, cluster_configurator);
  }

  /**
   * Initializes configuration with many HTTP filters
   *
   * @param filter_configs vector containing HTTP filter chain configuration
            in the desirabled order
   * @param cluster_configurator Cluster configurator implementing the desired cluster and endpoint
            config
   */
  void initConfig(const std::vector<std::string>& filter_configs,
                  ClusterConfigurator& cluster_configurator) {
    addClusterConfigsFromYaml(cluster_configurator.getConfigForClusters(
        Network::Test::getLoopbackAddressString(version_)));

    setUpstreamCount(cluster_configurator.upstreamCount());
    setUpstreamProtocol(downstream_http_protocol_);

    for (auto filter_config = filter_configs.rbegin(); filter_config != filter_configs.rend();
         ++filter_config) {
      config_helper_.addFilter(*filter_config);
    }
    HttpIntegrationTest::initialize();
  }

  void initConfig(const std::vector<std::string>& filter_configs,
                  ClusterConfigurator& cluster_configurator, const std::string& route_config) {
    addClusterConfigsFromYaml(cluster_configurator.getConfigForClusters(
        Network::Test::getLoopbackAddressString(version_)));
    addRouteConfigFromYaml(route_config);

    setUpstreamCount(cluster_configurator.upstreamCount());
    setUpstreamProtocol(downstream_http_protocol_);

    for (auto filter_config = filter_configs.rbegin(); filter_config != filter_configs.rend();
         ++filter_config) {
      config_helper_.addFilter(*filter_config);
    }
    HttpIntegrationTest::initialize();
  }

  void addClusterConfigsFromYaml(const std::vector<std::string>& config_clusters) {
    config_helper_.addConfigModifier([config_clusters](
                                         envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      for (const auto& cluster : config_clusters) {
        ENVOY_LOG_MISC(debug, "cluster config: {}", cluster);
        TestUtility::loadFromYaml(cluster, *bootstrap.mutable_static_resources()->add_clusters());
      }
    });
  }

  // Add a new route
  void addRouteConfigFromYaml(const std::string& config_route) {
    config_helper_.addConfigModifier(
        [config_route](
            envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager&
                hcm) { TestUtility::loadFromYaml(config_route, *hcm.mutable_route_config()); });
  }

private:
  // Base configuration for the testcase
  static std::string baseConfig() {
    return fmt::format(R"EOF(
admin:
  access_log_path: {dev_null_path}
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 0
dynamic_resources:
  lds_config:
    resource_api_version: V3
    path: {dev_null_path}
static_resources:
  secrets:
  - name: "secret_static_0"
    tls_certificate:
      certificate_chain:
        inline_string: "DUMMY_INLINE_BYTES"
      private_key:
        inline_string: "DUMMY_INLINE_BYTES"
      password:
        inline_string: "DUMMY_INLINE_BYTES"
  listeners:
    name: listener_0
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 0
    filter_chains:
      filters:
        name: http
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: config_test
          delayed_close_timeout:
            nanos: 100
          http_filters:
            name: envoy.filters.http.router
          codec_type: HTTP1
          access_log:
            name: accesslog
            filter:
              not_health_check_filter:  {{}}
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
              path: {dev_null_path}
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - name: catch_all
                match:
                  prefix: "/"
                  headers:
                    - name: x-eric-proxy
                      present_match: true
                      invert_match: true
                route:
                  cluster_header: not_used
              - name: matches_on_x_cluster
                match:
                  prefix: "/"
                route:
                  cluster_header: x-cluster
)EOF",
                       "dev_null_path"_a = Platform::null_device_path);
  }
};

// Specialized and ready-to-use versions

// Run the test with IPv4 and IPv6
using PluggableConfigurator = PluggableConfiguratorBase<Network::Address::IpVersion>;

// Run the test with IPv4, IPv6, and with multipart/non-multipart, all 4 combinations
using PluggableConfiguratorMultipart = PluggableConfiguratorBase<Network::Address::IpVersion, BodyContentType>;


} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
