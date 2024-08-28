#include "test/integration/http_integration.h"
#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include <algorithm>
#include <iterator>
#include <ostream>
#include <string>
#include "fmt/core.h"
#include "fmt/format.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using namespace fmt::literals;

class EricProxyFailoverTestBase : public HttpIntegrationTest,
                                  public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFailoverTestBase(bool temp_blocking, bool loop_prevention)
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(),
                            EricProxyFailoverTestBase::ericProxyHttpBaseConfig()),
        support_temporary_blocking_(temp_blocking), support_loop_prevention_(loop_prevention) {}
  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config, const int& upstream_count) {
    config_helper_.addFilter(config);
    config_helper_.addFilter(config_cdn_loop_filter);
    setUpstreamCount(upstream_count);
    HttpIntegrationTest::initialize();
  }

  // Common base configuration
  std::string ericProxyHttpBaseConfig() {
    return fmt::format(R"EOF(
admin:
  access_log_path: {}
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 0
dynamic_resources:
  lds_config:
    resource_api_version: V3
    path: {}
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
              path: {}
)EOF",
                       Platform::null_device_path, Platform::null_device_path,
                       Platform::null_device_path);
  }

  // Common configuration for eric proxy filter
  const std::string config_common_eric_proxy = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: default_route
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: '{all_cluster}'
            routing_behaviour: {routing_behaviour}
)EOF";

  const std::string config_cdn_loop_filter = R"EOF(
name: envoy.filters.http.cdn_loop
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.cdn_loop.v3.CdnLoopConfig
  cdn_id: "2.0 scp.ericsson.se"
)EOF";

  class RoutingBehaviourWrapper {
  public:
    RoutingBehaviourWrapper() : rb_(RoutingBehaviour::ROUND_ROBIN) {}
    RoutingBehaviourWrapper(RoutingBehaviour rb, std::string preferred_host)
        : rb_(rb), preferred_host_(preferred_host) {
      ASSERT(rb_ != RoutingBehaviour::ROUND_ROBIN);
    }

    const absl::optional<std::string> preferredHost() { return preferred_host_; }
    const std::string getConfig() {
      switch (rb_) {
      case RoutingBehaviour::PREFERRED:
        return routing_behaviour_pref_;
      case RoutingBehaviour::ROUND_ROBIN:
        return routing_behaviour_rr_;
      case RoutingBehaviour::STRICT:
        return routing_behaviour_strict_;
      default:
        return "";
      }
    }

    bool isRoundRobin() { return rb_ == RoutingBehaviour::ROUND_ROBIN; }

  private:
    RoutingBehaviour rb_;
    absl::optional<std::string> preferred_host_;
    // routing behaviour, i.e. ROUND_ROBIN/PREFERRED/STRICT
    const std::string routing_behaviour_rr_ = R"EOF(ROUND_ROBIN)EOF";
    const std::string routing_behaviour_strict_ = R"EOF(STRICT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
  )EOF";
    const std::string routing_behaviour_pref_ = R"EOF(PREFERRED
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
  )EOF";
  };

  // Common subset cluster configuration
  std::string config_common_subset_cluster = R"EOF(
name: {subset_cluster}
connect_timeout: 15s
lb_subset_config:
  fallback_policy: ANY_ENDPOINT
  subset_selectors:
  - keys:
    - host
  list_as_any: true
load_assignment:
  cluster_name: {subset_cluster}
  endpoints:
)EOF";

  // Common all cluster configuration
  std::string config_common_cluster = R"EOF(
name: {all_cluster}
connect_timeout: 15s
load_assignment:
  cluster_name: {all_cluster}
  policy:
    overprovisioning_factor: 140
  endpoints:
)EOF";

  const std::string outlier_detection = R"EOF(
outlier_detection:
  consecutive_5xx: 2
  interval: "0.1s"
  base_ejection_time: "10s"
  max_ejection_percent: 100
  enforcing_consecutive_5xx: 100
  enforcing_success_rate: 0
  success_rate_minimum_hosts: 5
  success_rate_request_volume: 100000
  success_rate_stdev_factor: 1900
  consecutive_gateway_failure: 2
  enforcing_consecutive_gateway_failure: 100
  consecutive_local_origin_failure: 2
  enforcing_consecutive_local_origin_failure: 100
  enforcing_local_origin_success_rate: 100
  max_ejection_time: "10s"
common_lb_config:
  healthy_panic_threshold: {}
)EOF";

  // Common all cluster endpoints configuration
  std::string config_common_cluster_endpoints = R"EOF(
  - priority: {priority}
    lb_endpoints:
    - endpoint:
        address:
          socket_address:
            address: {ip_address}
            port_value: 0
        hostname: {hostname}
      metadata:
        filter_metadata:
          envoy.lb:
            host: {hostname}
          envoy.transport_socket_match:
            matchTLS:
            - false
          envoy.eric_proxy:
            nfInstanceId:
                - {nf_instance_id}
            pernfcounter: true
            support: ["NF"]            
)EOF";

  // Common aggregate cluster configuration
  std::string config_common_aggregate_cluster = R"EOF(
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
)EOF";

  // Common route configuration
  std::string config_common_route = R"EOF(
name: local_route
virtual_hosts:
- name: local_service
  domains: ["*"]
  routes:
  - name: route0
    match:
      prefix: "/"
      headers:
        - name: x-cluster
          string_match:
            exact: '{all_cluster}'
    route:
      cluster: '{all_cluster}'
      retry_policy:
        retry_on: 5xx
        retry_host_predicate:
        - name: envoy.retry_host_predicates.eric_loop_prevention
        - name: envoy.retry_host_predicates.previous_hosts
        host_selection_retry_max_attempts: 3
        num_retries: {num_retries}
        retry_priority:
          name: envoy.retry_priorities.eric_reselect_priorities
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.retry.priority.eric_reselect_priorities.v3.EricReselectPrioritiesConfig
            preferred_host_retries: {num_preferred_host_retries}
            failover_reselects: {num_reselects}
            last_resort_reselects: {num_lr_reselects}
            support_temporary_blocking: {support_temp_blocking}
            support_loop_prevention: {support_loop_prevention}
)EOF";

  // Get specific all cluster configuration from common
  virtual std::string
  getConfigForCluster(const std::string all_cluster,
                      std::vector<std::map<std::string, std::string>> all_hosts,
                      const std::string& cluster_metadata="") {
    auto config_all_cluster = fmt::format(config_common_cluster,"all_cluster"_a = all_cluster) ;
    for (auto& all_host : all_hosts) {
      auto config_cluster_endpoint =
      fmt::format(config_common_cluster_endpoints,"priority"_a = all_host["priority"],
                                                  "ip_address"_a = Network::Test::getLoopbackAddressString(GetParam()),
                                                  "hostname"_a = all_host["hostname"],
                                                  "nf_instance_id"_a = all_host["nf_instance_id"]);
      absl::StrAppend(&config_all_cluster, config_cluster_endpoint);
    }
    // absl::StrAppend(&config_all_cluster, outlier_detection);
    if (!cluster_metadata.empty()) {
      absl::StrAppend(&config_all_cluster, cluster_metadata);
    }
    return config_all_cluster;
  }

  // Get specific aggregate cluster configuration from common
  std::string getConfigAggregateCluster(const absl::string_view aggregate_cluster,
                                        const absl::string_view primary_cluster,
                                        const absl::string_view last_resort_cluster) {
    auto config_aggregate_cluster = fmt::format(config_common_aggregate_cluster,
                                                "aggregate_cluster"_a = aggregate_cluster,
                                                "primary_cluster"_a = primary_cluster,
                                                "last_resort_cluster"_a = last_resort_cluster);
    return config_aggregate_cluster;
  }

  // Get specific route configuration from common
  std::string getConfigRoute(const std::string all_cluster,
                             const std::vector<uint64_t> retry_params) {
    auto config_route = fmt::format(config_common_route,
                                      "all_cluster"_a = all_cluster,
                                      "num_retries"_a = std::to_string(retry_params[0]),
                                      "num_preferred_host_retries"_a = std::to_string(retry_params[1]),
                                      "num_reselects"_a = std::to_string(retry_params[2]),
                                      "num_lr_reselects"_a = std::to_string(retry_params[3]),
                                      "support_temp_blocking"_a = fmt::format("{}",support_temporary_blocking_),
                                      "support_loop_prevention"_a = fmt::format("{}",support_loop_prevention_));
    return config_route;
  }

  // Get specific eric proxy configuration from common
  std::string getConfigEricProxy(const std::string target_cluster, RoutingBehaviourWrapper rb) {
    auto config_eric_proxy = fmt::format(config_common_eric_proxy,
                                            "all_cluster"_a = target_cluster,
                                            "routing_behaviour"_a = fmt::format("{}",rb.getConfig()));
    return  config_eric_proxy;
  }

  // Add new cluster configurations from yaml and replacing them with the existing configurations
  void addClusterConfigsFromYaml(std::vector<std::string>& config_clusters) {

    config_helper_.addConfigModifier([config_clusters](
                                         envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      for (const auto& cluster : config_clusters) {

        TestUtility::loadFromYaml(cluster, *bootstrap.mutable_static_resources()->add_clusters());
      }
    });
  }

  // Add new route configuration from yaml and replacing it with the existing configuration
  void addRouteConfigFromYaml(const std::string& config_route) {
    config_helper_.addConfigModifier(
        [config_route](
            envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager&
                hcm) { TestUtility::loadFromYaml(config_route, *hcm.mutable_route_config()); });
  }

  std::string getCounters(const std::vector<Stats::CounterSharedPtr>& counters,
                          const std::vector<absl::string_view> greps) {
    // returns true if name contains all greps
    const auto contains = [&greps](const std::string& name) -> bool {
      for (const auto g : greps) {
        if (!g.empty() && name.find(g) == std::string::npos) {
          return false;
        } else {
          continue;
        }
      }
      return true;
    };
    std::vector<Stats::CounterSharedPtr> sorted_counters;
    for (const auto& counter : counters) {
      if (!contains(counter->name())) {
        continue;
      } else {
        sorted_counters.push_back(counter);
      }
    }
    std::sort(sorted_counters.begin(), sorted_counters.end(),
              [](const Stats::CounterSharedPtr a, const Stats::CounterSharedPtr b) -> bool {
                return a->name() > b->name();
              });
    std::string res = "";
    res += "counter_map = {";
    for (const auto& counter : sorted_counters) {
      absl::StrAppend(&res, "\n", "{\"", counter->name(), "\", \"", counter->value(), "\"},");
    }
    absl::StrAppend(&res, "\n}");
    return res;
  }

  // initialize TC related config

  void initConfig(const std::string& primary_cluster,
                  std::vector<std::map<std::string, std::string>>& primary_hosts,
                  RoutingBehaviourWrapper rb, const std::vector<uint64_t> retry_params,
                  const std::string& cluster_metadata="") {
    initConfig("", primary_cluster, primary_hosts, "", {}, rb, retry_params, cluster_metadata);
  }

  void initConfig(const std::string& aggr_cluster, const std::string& primary_cluster,
                  std::vector<std::map<std::string, std::string>>& primary_hosts,
                  const std::string& last_resort_cluster,
                  std::vector<std::map<std::string, std::string>> last_resort_hosts,
                  RoutingBehaviourWrapper rb, const std::vector<uint64_t> retry_params,
                  const std::string& cluster_metadata="") {

    std::vector<std::string> cluster_configs;
    std::string target_cluster;
    cluster_configs.push_back(getConfigForCluster(primary_cluster, primary_hosts, cluster_metadata));
    int host_count = primary_hosts.size();
    if (!aggr_cluster.empty() && !last_resort_cluster.empty() && !last_resort_hosts.empty()) {
      cluster_configs.push_back(getConfigForCluster(last_resort_cluster, last_resort_hosts));
      cluster_configs.push_back(
          getConfigAggregateCluster(aggr_cluster, primary_cluster, last_resort_cluster));
      target_cluster = aggr_cluster;
      host_count += last_resort_hosts.size();
    } else {
      target_cluster = primary_cluster;
    }

    addClusterConfigsFromYaml(cluster_configs);
    addRouteConfigFromYaml(getConfigRoute(target_cluster, retry_params));
    initializeFilter(getConfigEricProxy(target_cluster, rb), host_count);
  }

private:
  bool support_temporary_blocking_;
  bool support_loop_prevention_;
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy