#pragma once
#include "test/integration/http_integration.h"
#include "envoy/http/filter.h"
#include "envoy/http/codes.h"

using namespace fmt::literals;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

class PluggableConfigurator : public HttpIntegrationTest,
                              public testing::TestWithParam<Network::Address::IpVersion> {
public:
  // uses the listener + route config present in the class
  PluggableConfigurator()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(), baseConfig()) {}
  // Supply a custom route and listener config
  PluggableConfigurator(std::string base_config)
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(), base_config) {}

  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // One filter, Clusters without endpoints
  // The filter_configs list must be in reverse order: the last filter in the
  // vector is the first in the filter chain.
  void initConfig(const std::string filter_config) {
    initConfig(std::vector<std::string>{filter_config});
  }

  // Several filters, Clusters without endpoints
  // The filter_configs list must be in reverse order: the last filter in the
  // vector is the first in the filter chain.
  void initConfig(const std::vector<std::string> filter_configs) {
    std::vector<std::map<std::string, std::vector<std::string>>> empty;
    initConfig(filter_configs, empty);
  }

  // One filter, Clusters with one endpoint each
  // The filter_configs list must be in reverse order: the last filter in the
  // vector is the first in the filter chain.
  // Cluster-dict is a list of (cluster-name, single endpoint)
  void initConfig(const std::string filter_config,
                  std::vector<std::map<std::string, std::string>>& cluster_dict,
                  std::string ep_support="") {
    initConfig(std::vector<std::string>{filter_config}, cluster_dict, ep_support);
  }

  // Several filters, Clusters with one endpoint each
  // The filter_configs list must be in reverse order: the last filter in the
  // vector is the first in the filter chain.
  // Cluster-dict is a list of (cluster-name, single endpoint)
  void initConfig(const std::vector<std::string> filter_configs,
                  std::vector<std::map<std::string, std::string>>& cluster_dict,
                  std::string ep_support="") {
    // Convert the single endpoints to a list with one endpoint for each cluster
    // so that the other constructor can be called.
    std::vector<std::map<std::string, std::vector<std::string>>> cluster_dict_vect;
    for (auto& vect_entry : cluster_dict) {
      for (auto& map_entry : vect_entry) {
        cluster_dict_vect.push_back({{map_entry.first, {map_entry.second}}});
        break;
      }
    }

    initConfig(filter_configs, cluster_dict_vect, ep_support);
  }

  // One filter, Clusters with a list of endpoints each
  // The filter_configs list must be in reverse order: the last filter in the
  // vector is the first in the filter chain.
  // Cluster-dict is a list of cluster-name and a list of endpoints
  // TODO(eedala): improve supports_tfqdn to use flags instead TFQDN | Indirect | NF  and so on
  void initConfig(const std::string filter_config,
                  std::vector<std::map<std::string, std::vector<std::string>>>& cluster_dict,
                  std::string ep_support="") {
    initConfig(std::vector<std::string>{filter_config}, cluster_dict, ep_support);
  }

  // Several filters, Clusters with a list of endpoints each
  // The filter_configs list must be in reverse order: the last filter in the
  // vector is the first in the filter chain.
  // Cluster-dict is a list of cluster-name and a list of endpoints
  // TODO(eedala): improve supports_tfqdn to use flags instead TFQDN | Indirect | NF  and so on
  void initConfig(const std::vector<std::string> filter_configs,
                  std::vector<std::map<std::string, std::vector<std::string>>>& cluster_dict,
                  std::string ep_support="",
                  std::vector<std::string> aggregate_cluster = {}) {
    std::vector<std::string> cluster_configs;
    cluster_configs.reserve(cluster_dict.size());
      ENVOY_LOG_MISC(debug, "Cluster dict size: {}", cluster_dict.size());
    uint32_t host_count{0};

    for (auto& vect_entry : cluster_dict) {
      for (auto& map_entry : vect_entry) {
        ENVOY_LOG_MISC(debug, "Adding cluster:\n{}", getConfigForCluster(map_entry, ep_support));
        cluster_configs.push_back(getConfigForCluster(map_entry, ep_support));
        host_count += map_entry.second.size();
        break;
      }
    }

    if (!aggregate_cluster.empty()) {
      cluster_configs.push_back(
        aggregateClusterConfig(
          aggregate_cluster.at(0),
          aggregate_cluster.at(1),
          aggregate_cluster.at(2)
        )
      );
    }

    ENVOY_LOG_MISC(debug, "host count: {}", host_count);
    addClusterConfigsFromYaml(cluster_configs);
    setUpstreamCount(host_count);
    for (const auto& filter_config : filter_configs) {
      config_helper_.addFilter(filter_config);
    }
    HttpIntegrationTest::initialize();
  }

  // Create and return the configuration for one cluster including all endpoints
  // and metadata.
  // First element of the pair is the cluster name, second element a list of endpoints
  static std::string
  getConfigForCluster(std::pair<const std::string, std::vector<std::string>>& cluster_entry,
      std::string ep_support="") {
    auto cluster = clusterConfig(cluster_entry.first);

    for (auto& host : cluster_entry.second) {
      auto endpoint = endpointConfig(host, Network::Test::getLoopbackAddressString(GetParam()),
          ep_support.empty() ? "" : mdEpSupport(ep_support));
      absl::StrAppend(&cluster, endpoint);
    }
    return cluster;
  }

  void addClusterConfigsFromYaml(std::vector<std::string>& config_clusters) {
    config_helper_.addConfigModifier([config_clusters](
          envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      for (const auto& cluster : config_clusters) {
        ENVOY_LOG_MISC(debug, "cluster config: {}", cluster);
        TestUtility::loadFromYaml(cluster, *bootstrap.mutable_static_resources()->add_clusters());
      }
    });
  }

public:
  // Beginning of a cluster configuration
  static std::string clusterConfig(const std::string& name) {
    return fmt::format(R"EOF(
name: '{name}'
connect_timeout: 15s
load_assignment:
  cluster_name: '{name}'
  endpoints:)EOF",
          "name"_a=name);
        }

  // Common cluster endpoint configuration
  static std::string endpointConfig(const std::string& hostname, const std::string& ip_address,
      const std::string& metadata) {
    return fmt::format(R"EOF(
  - priority: 0
    lb_endpoints:
    - endpoint:
        address:
          socket_address:
            address: {ip_address}
            port_value: 0
        hostname: {hostname}
      {metadata})EOF",
        "hostname"_a=hostname, "ip_address"_a=ip_address, "metadata"_a=metadata);
  }

  // Optional endpoint metadata for "support"
  static std::string mdEpSupport(std::string support) {
    return fmt::format(R"EOF(
      metadata:
        filter_metadata:
          envoy.eric_proxy:
            support:
            - {support})EOF",
        "support"_a=support);
  }

  // Common aggregate cluster configuration
  static std::string aggregateClusterConfig(
    const std::string& aggregate_cluster,
    const std::string& primary_cluster,
    const std::string& last_resort_cluster
  ) {
    return fmt::format(R"EOF(
name: '{aggregate_cluster}'
connect_timeout: 15s
lb_policy: CLUSTER_PROVIDED
cluster_type:
  name: envoy.clusters.aggregate
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
    clusters:
    - '{primary_cluster}'
    - '{last_resort_cluster}'
)EOF",
    "aggregate_cluster"_a=aggregate_cluster,
    "primary_cluster"_a=primary_cluster,
    "last_resort_cluster"_a=last_resort_cluster
    );
  }

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
                  headers:
                    - name: x-cluster
                      present_match: true
                route:
                  cluster_header: x-cluster)EOF",
    "dev_null_path"_a=Platform::null_device_path);
  }

  // Base configuration with the catch-all route going to a named cluster.
  // This is needed when there is no eric-proxy filter in the testcase
  // (as it is in sepp_tfqdn_router_integration_test)
  static std::string baseConfigWithCatchAllCluster() {
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
                  cluster: catch_all
              - name: matches_on_x_cluster
                match:
                  prefix: "/"
                  headers:
                    - name: x-cluster
                      present_match: true
                route:
                  cluster_header: x-cluster)EOF",
    "dev_null_path"_a=Platform::null_device_path);
  }
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
