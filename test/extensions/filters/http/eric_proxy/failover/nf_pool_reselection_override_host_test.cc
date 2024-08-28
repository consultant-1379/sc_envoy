#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "test/integration/http_integration.h"
#include <ostream>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterNfPoolReselectionOverrideHostTest
    : public HttpIntegrationTest,
      public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterNfPoolReselectionOverrideHostTest()
      : HttpIntegrationTest(
            Http::CodecClient::Type::HTTP1, GetParam(),
            EricProxyFilterNfPoolReselectionOverrideHostTest::ericProxyHttpBaseConfig()) {}
  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config, const int& upstream_count) {
    config_helper_.addFilter(config);
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
              term_string: <all-cluster>
            routing_behaviour: <routing-behaviour>
)EOF";

  class RoutingBehaviourWrapper {
  public:
    RoutingBehaviourWrapper() : rb_(RoutingBehaviour::ROUND_ROBIN) {}
    RoutingBehaviourWrapper(std::string preferred_host)
        : rb_(RoutingBehaviour::PREFERRED), preferred_host_(preferred_host) {}

    const absl::optional<std::string> preferredHost() { return preferred_host_; }
    const std::string getConfig() {
      switch (rb_) {
      case RoutingBehaviour::PREFERRED:
        return routing_behaviour_pref_;
      case RoutingBehaviour::ROUND_ROBIN:
        return routing_behaviour_rr_;
      default:
        return "";
      }
    }

    bool isRoundRobin() { return rb_ == RoutingBehaviour::ROUND_ROBIN; }

  private:
    RoutingBehaviour rb_;
    absl::optional<std::string> preferred_host_;
    // routing behaviour, i.e. ROUND_ROBIN/PREFERRED
    const std::string routing_behaviour_rr_ = R"EOF(ROUND_ROBIN)EOF";

    const std::string routing_behaviour_pref_ = R"EOF(PREFERRED
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
  )EOF";
  };

  // Common subset cluster configuration
  std::string config_common_subset_cluster = R"EOF(
name: <subset-cluster>
connect_timeout: 15s
lb_subset_config:
  fallback_policy: ANY_ENDPOINT
  subset_selectors:
  - keys:
    - host
  list_as_any: true
load_assignment:
  cluster_name: <subset-cluster>
  endpoints:
)EOF";

  // Common all cluster configuration
  std::string config_common_cluster = R"EOF(
name: <all-cluster>
connect_timeout: 15s
load_assignment:
  cluster_name: <all-cluster>
  endpoints:
)EOF";

  std::string outlier_detection = R"EOF(
outlier_detection:
  consecutive_5xx: 2
  interval: "1s"
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
  - lb_endpoints:
    - endpoint:
        address:
          socket_address:
            address: <ip-address>
            port_value: 0
        hostname: <hostname>
      metadata:
        filter_metadata:
          envoy.lb:
            host: <hostname>
    priority: <priority>
)EOF";

  // Common aggregate cluster configuration
  std::string config_common_aggregate_cluster = R"EOF(
name: <aggregate-cluster>
connect_timeout: 15s
lb_policy: CLUSTER_PROVIDED
cluster_type:
  name: envoy.clusters.aggregate
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
    clusters:
    - <primary-cluster>
    - <last-resort-cluster>
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
            exact: <all-cluster>
    route:
      cluster: <all-cluster>
      retry_policy:
        retry_on: retriable-status-codes
        retriable_status_codes:
        - 500
        - 501
        - 502
        - 503
        retry_host_predicate:
        - name: envoy.retry_host_predicates.eric_omit_host_metadata_dynamic
        - name: envoy.retry_host_predicates.previous_hosts
        host_selection_retry_max_attempts: 3
        num_retries: <num-retries>
        retry_priority:
          name: envoy.retry_priorities.eric_reselect_priorities
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.retry.priority.eric_reselect_priorities.v3.EricReselectPrioritiesConfig
            preferred_host_retries: <num-preferred-host-retries>
            failover_reselects: <num-reselects>
            last_resort_reselects: <num-lr-reselects>


)EOF";

  // Get specific all cluster configuration from common
  std::string getConfigForCluster(const std::string all_cluster,
                                  std::vector<std::map<std::string, std::string>> all_hosts) {
    auto config_all_cluster = std::regex_replace(
        config_common_cluster, std::regex("<all-cluster>*"), fmt::format("'{}'", all_cluster));

    auto config_all_cluster_endpoints_ip =
        std::regex_replace(config_common_cluster_endpoints, std::regex("<ip-address>*"),
                           Network::Test::getLoopbackAddressString(GetParam()));
    for (auto& all_host : all_hosts) {
      auto config_all_cluster_host =
          std::regex_replace(config_all_cluster_endpoints_ip, std::regex("<hostname>*"),
                             fmt::format("'{}'", all_host["hostname"]));
      absl::StrAppend(&config_all_cluster,
                      std::regex_replace(config_all_cluster_host, std::regex("<priority>*"),
                                         all_host["priority"]));
    }
    absl::StrAppend(&config_all_cluster, outlier_detection);
    return config_all_cluster;
  }

  // Get specific aggregate cluster configuration from common
  std::string getConfigAggregateCluster(const absl::string_view aggregate_cluster,
                                        const absl::string_view primary_cluster,
                                        const absl::string_view last_resort_cluster) {
    auto config_aggregate_cluster =
        std::regex_replace(config_common_aggregate_cluster, std::regex("<aggregate-cluster>*"),
                           fmt::format("'{}'", aggregate_cluster));

    config_aggregate_cluster =
        std::regex_replace(config_aggregate_cluster, std::regex("<primary-cluster>"),
                           fmt::format("'{}'", primary_cluster));

    config_aggregate_cluster =
        std::regex_replace(config_aggregate_cluster, std::regex("<last-resort-cluster>"),
                           fmt::format("'{}'", last_resort_cluster));

    return config_aggregate_cluster;
  }

  // Get specific route configuration from common
  std::string getConfigRoute(const std::string all_cluster,
                             const std::vector<uint64_t> retry_params) {
    auto config_route = std::regex_replace(config_common_route, std::regex("<all-cluster>"),
                                           fmt::format("'{}'", all_cluster));
    config_route = std::regex_replace(config_route, std::regex("<num-retries>"),
                                      std::to_string(retry_params[0]));
    config_route = std::regex_replace(config_route, std::regex("<num-preferred-host-retries>"),
                                      std::to_string(retry_params[1]));
    config_route = std::regex_replace(config_route, std::regex("<num-reselects>"),
                                      std::to_string(retry_params[2]));
    config_route = std::regex_replace(config_route, std::regex("<num-lr-reselects>"),
                                      std::to_string(retry_params[3]));
    return config_route;
  }

  // Get specific eric proxy configuration from common
  std::string getConfigEricProxy(const std::string target_cluster, RoutingBehaviourWrapper rb) {
    auto config_eric_proxy = std::regex_replace(
        config_common_eric_proxy, std::regex("<all-cluster>"), fmt::format("'{}'", target_cluster));

    return std::regex_replace(config_eric_proxy, std::regex("<routing-behaviour>"),
                              fmt::format("{}", rb.getConfig()));
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

  // initialize TC related config

  void initConfig(const std::string& primary_cluster,
                  std::vector<std::map<std::string, std::string>>& primary_hosts,
                  RoutingBehaviourWrapper rb, const std::vector<uint64_t> retry_params) {
    initConfig("", primary_cluster, primary_hosts, "", {}, rb, retry_params);
  }

  void initConfig(const std::string& aggr_cluster, const std::string& primary_cluster,
                  std::vector<std::map<std::string, std::string>>& primary_hosts,
                  const std::string& last_resort_cluster,
                  std::vector<std::map<std::string, std::string>> last_resort_hosts,
                  RoutingBehaviourWrapper rb, const std::vector<uint64_t> retry_params) {

    std::vector<std::string> cluster_configs;
    std::string target_cluster;
    cluster_configs.push_back(getConfigForCluster(primary_cluster, primary_hosts));
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

    auto config_route = getConfigRoute(target_cluster, retry_params);
    addClusterConfigsFromYaml(cluster_configs);
    addRouteConfigFromYaml(getConfigRoute(target_cluster, retry_params));

    initializeFilter(getConfigEricProxy(target_cluster, rb), host_count);
  }

  // Common function for nf pool reselection tests with different scenarios
  void testNfPoolReselection(std::string target_cluster, RoutingBehaviourWrapper rb,
                             const std::vector<std::vector<uint64_t>> expected_hosts_list) {

    Http::TestRequestHeaderMapImpl headers{
        {":scheme","http"},
        {":method", "GET"}, 
        {":path", "/"}, 
        {":authority", "scp.ericsson.se"}
      };

    if (rb.preferredHost()) {
      headers.addCopy("3gpp-Sbi-target-apiRoot",
                      fmt::format("https://{}", rb.preferredHost().value()));
    }

    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(headers);

    // Extracting and testing the expected producers from the expected list in a sequence
    for (const auto& per_try_indx : expected_hosts_list) {

      waitForNextUpstreamRequest(per_try_indx);

      // Send fake 500 status upstream response
      upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "500"}}, true);

      ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
      ASSERT_TRUE(fake_upstream_connection_->close());
      ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
      fake_upstream_connection_.reset();

      // Verify upstream request
      EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
      EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", target_cluster));
      // todo: remove me later
      if (!rb.isRoundRobin() && rb.preferredHost()) {

        EXPECT_THAT(upstream_request_->headers(),
                    Http::HeaderValueOf("x-host", rb.preferredHost().value()));
      }
    }

    // ENVOY_LOG(debug, "{}", fmt::format("tried hosts?->{}\n", tried_hosts));
    // Verify downstream response

    // Wait for the response and close the fake upstream connection

    ASSERT_TRUE(response->waitForEndStream());
    // ASSERT_TRUE(fake_upstream_connection_->close());

    EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "500"));
    std::replace(target_cluster.begin(), target_cluster.end(), ':', '_');
    // EXPECT_EQ(
    //     1, test_server_->counter("cluster." + target_cluster +
    //     ".upstream_rq_retry_limit_exceeded")
    //            ->value());
    // EXPECT_EQ(expected_hosts_list.size() - 1,
    //           test_server_->counter("cluster." + target_cluster +
    //           ".upstream_rq_retry")->value());

    codec_client_->close();
  }
};

//------------------------------------------------------------------------
//-------------BEGIN TEST SUITES---------------------
//------------------------------------------------------------------------

//------------------------------------------------------------------------
//----------------------- Preferred Host ---------------------------------
//------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterNfPoolReselectionOverrideHostTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestNfPoolReselection1) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}};

  std::vector<uint64_t> retry_params{3, 2, 1, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {0}, {0}, {1}};
  auto rb = RoutingBehaviourWrapper("chf0.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
  ENVOY_LOG(trace, printCounters(test_server_, "cluster."));
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestNfPoolReselection2) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}};

  std::vector<uint64_t> retry_params{2, 1, 1, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{1}, {1}, {0}};
  auto rb = RoutingBehaviourWrapper("chf1.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestNfPoolReselection3) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "2"}}

  };

  std::vector<uint64_t> retry_params{6, 2, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0},    {0},    {0},   {1, 2},
                                                           {2, 1}, {3, 4}, {4, 3}};
  auto rb = RoutingBehaviourWrapper("chf0.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestNfPoolReselection4) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "2"}}

  };

  std::vector<uint64_t> retry_params{4, 0, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{1}, {0}, {2}, {4, 3}, {3, 4}};
  auto rb = RoutingBehaviourWrapper("chf1.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestNfPoolReselection4b) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "2"}}

  };

  std::vector<uint64_t> retry_params{4, 0, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{2}, {0, 1}, {0, 1}, {4, 3}, {3, 4}};
  auto rb = RoutingBehaviourWrapper("chf2.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestNfPoolReselection5) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "2"}}

  };

  std::vector<uint64_t> retry_params{6, 2, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{1}, {1}, {1}, {0}, {2}, {4, 3}, {3, 4}};
  auto rb = RoutingBehaviourWrapper("chf1.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestNfPoolReselection6) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "1"}},
  };

  std::vector<uint64_t> retry_params{4, 0, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {
      {4}, {0, 1, 2, 3}, {0, 1, 2, 3}, {0, 1, 2, 3}, {0, 1, 2, 3}};
  auto rb = RoutingBehaviourWrapper("chf4.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
  ;
}

// tests first_host interraction
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, SinglePrio) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "1"}},
  };

  std::vector<uint64_t> retry_params{3, 2, 1, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {0}, {0}, {1, 2}};
  auto rb = RoutingBehaviourWrapper("chf0.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
  ;
}

//------------------------------------------------------------------------
//---------------------------- Strict ------------------------------------
//------------------------------------------------------------------------
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, Strict01) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "1"}},
  };

  std::vector<uint64_t> retry_params{3, 3, 0, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{3}, {3}, {3}, {3}};
  auto rb = RoutingBehaviourWrapper("chf3.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
  ;
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, Strict02) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "1"}},
  };

  std::vector<uint64_t> retry_params{2, 2, 0, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{1}, {1}, {1}};
  auto rb = RoutingBehaviourWrapper("chf1.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
  ;
}

//------------------------------------------------------------------------
//-------------------------- Round Robin ---------------------------------
//------------------------------------------------------------------------
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestNfPoolReselection7) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "1"}},
  };

  std::vector<uint64_t> retry_params{4, 0, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {
      {0, 1, 2, 3}, {0, 1, 2, 3}, {0, 1, 2, 3}, {0, 1, 2, 3}, {4}};
  auto rb = RoutingBehaviourWrapper();
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
  ENVOY_LOG(trace, printCounters(test_server_, "cluster."));
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestNfPoolReselection8) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "3"}},
  };

  std::vector<uint64_t> retry_params{4, 0, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {1, 2}, {1, 2}, {3}, {4}};
  auto rb = RoutingBehaviourWrapper();
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestNfPoolReselection9) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "3"}},
  };

  std::vector<uint64_t> retry_params{7, 0, 7, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {1, 2}, {1, 2}, {3}, {4}};
  auto rb = RoutingBehaviourWrapper();
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
}

//------------------------------------------------------------------------
//----------------------- Aggregate Cluster (LRP) ------------------------
//------------------------------------------------------------------------

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, LastResortRR) {
  std::string aggregate_cluster = "chf_primary#!_#LRP:chf_lr_pool#!_#aggr:";
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
  };
  std::string last_resort_cluster = "chf_lr_pool";

  std::vector<std::map<std::string, std::string>> last_resort_hosts = {

      {{"hostname", "chf01.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf02.ericsson.se:443"}, {"priority", "1"}},
  };

  std::vector<uint64_t> retry_params{3, 0, 1, 2};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {1}, {2}, {3}};
  auto rb = RoutingBehaviourWrapper();
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params);
  testNfPoolReselection(aggregate_cluster, rb, expected_reselects);
  // ENVOY_LOG(trace,printCounters(test_server_, "cluster."));
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, LastResortRRJumpPrio) {
  std::string aggregate_cluster = "chf_primary#!_#LRP:chf_lr_pool#!_#aggr:";
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "3"}},
  };
  std::string last_resort_cluster = "chf_lr_pool";

  std::vector<std::map<std::string, std::string>> last_resort_hosts = {

      {{"hostname", "chf01.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf02.ericsson.se:443"}, {"priority", "0"}},
  };

  std::vector<uint64_t> retry_params{4, 0, 2, 2};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {1, 2}, {1, 2}, {5, 6}, {5, 6}};
  auto rb = RoutingBehaviourWrapper();
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params);
  testNfPoolReselection(aggregate_cluster, rb, expected_reselects);
  // ENVOY_LOG(trace,printCounters(test_server_, "cluster."));
}

// preferred host from primary cluster
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, LastResortPreferred) {
  std::string aggregate_cluster = "chf_primary#!_#LRP:chf_lr_pool#!_#aggr:";
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
  };
  std::string last_resort_cluster = "chf_lr_pool";

  std::vector<std::map<std::string, std::string>> last_resort_hosts = {

      {{"hostname", "chf01.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf02.ericsson.se:443"}, {"priority", "1"}},
  };

  std::vector<uint64_t> retry_params{4, 2, 2, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{1}, {1}, {1}, {0}, {2, 3}};
  auto rb = RoutingBehaviourWrapper("chf1.ericsson.se:443");
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params);
  testNfPoolReselection(aggregate_cluster, rb, expected_reselects);
  // ENVOY_LOG(trace,printCounters(test_server_, "cluster."));
}

// preferred host from primary cluster
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, LastResortPreferred1) {
  std::string aggregate_cluster = "chf_primary#!_#LRP:chf_lr_pool#!_#aggr:";
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}},

  };
  std::string last_resort_cluster = "chf_lr_pool";

  std::vector<std::map<std::string, std::string>> last_resort_hosts = {

      {{"hostname", "chf01.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf02.ericsson.se:443"}, {"priority", "0"}},
  };

  std::vector<uint64_t> retry_params{5, 2, 2, 1};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {0}, {0}, {1, 2}, {1, 2}, {3, 4}};
  auto rb = RoutingBehaviourWrapper("chf0.ericsson.se:443");
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params);
  testNfPoolReselection(aggregate_cluster, rb, expected_reselects);
  // ENVOY_LOG(trace,printCounters(test_server_, "cluster."));
}

//------------------------------------------------------------------------
//-------------END TEST SUITES---------------------
//------------------------------------------------------------------------

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
