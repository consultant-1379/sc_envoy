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

class EricProxyFilterNfPoolReselectionIntegrationTest : public HttpIntegrationTest,
                                        public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterNfPoolReselectionIntegrationTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(),
                            EricProxyFilterNfPoolReselectionIntegrationTest::ericProxyHttpBaseConfig()) {}
  void SetUp() override { }
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
)EOF", Platform::null_device_path,
       Platform::null_device_path, 
       Platform::null_device_path);
  }
  
  // Common configuration for eric proxy filter
  const std::string config_common_eric_proxy= R"EOF(
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
              term_string: <aggregate-cluster>
            routing_behaviour: PREFERRED
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
)EOF";

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

  // Common subset cluster endpoints configuration
  std::string config_common_subset_cluster_endpoints = R"EOF(
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
)EOF";

  // Common all cluster configuration
  std::string config_common_all_cluster = R"EOF(
name: <all-cluster>
connect_timeout: 15s
load_assignment:
  cluster_name: <all-cluster>
  endpoints:
)EOF";

  // Common all cluster endpoints configuration
  std::string config_common_all_cluster_endpoints = R"EOF(
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
    - <subset-cluster>
    - <all-cluster>
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
            exact: <aggregate-cluster>
        - name: x-host
          string_match:
            exact: <preferred-host>
    route:
      cluster: <aggregate-cluster>
      retry_policy:
        retry_on: retriable-status-codes
        retriable_status_codes:
        - 500
        - 501
        - 502
        - 503
        retry_host_predicate:
        - name: envoy.retry_host_predicates.omit_host_metadata
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.retry.host.omit_host_metadata.v3.OmitHostMetadataConfig
            metadata_match:
              filter_metadata:
                envoy.lb:
                  host: <preferred-host>
        num_retries: <num-retries>
        retry_priority:
          name: envoy.retry_priorities.previous_priorities
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.retry.priority.previous_priorities.v3.PreviousPrioritiesConfig
            update_frequency:
)EOF";

  // Common route update frequency configuration
  std::string config_common_route_update_frequency = R"EOF(
            - <update-frequency>
)EOF";

  // Get specific subset cluster configuration from common
  std::string getConfigSubsetCluster(
    const std::string subset_cluster,
    const std::vector<std::string> subset_hosts
  ) {
    auto config_subset_cluster = std::regex_replace(
      config_common_subset_cluster,
      std::regex("<subset-cluster>*"),
      fmt::format("'{}'", subset_cluster)
    );

    auto config_subset_cluster_endpoints_ip = std::regex_replace(
      config_common_subset_cluster_endpoints,
      std::regex("<ip-address>*"),
      Network::Test::getLoopbackAddressString(GetParam())
    );

    for (auto& subset_host:subset_hosts) {
      config_subset_cluster = absl::StrCat(
        config_subset_cluster,
        std::regex_replace(
          config_subset_cluster_endpoints_ip,
          std::regex("<hostname>*"),
          fmt::format("'{}'", subset_host)
        )
      );
    }

    return config_subset_cluster;
  }

  // Get specific all cluster configuration from common
  std::string getConfigAllCluster(
    const std::string all_cluster,
    std::vector<std::map<std::string, std::string>> all_hosts
  ) {
    auto config_all_cluster = std::regex_replace(
      config_common_all_cluster,
      std::regex("<all-cluster>*"),
      fmt::format("'{}'", all_cluster)
    );

    auto config_all_cluster_endpoints_ip = std::regex_replace(
      config_common_all_cluster_endpoints,
      std::regex("<ip-address>*"),
      Network::Test::getLoopbackAddressString(GetParam())
    );

    for (auto& all_host:all_hosts) {
      auto config_all_cluster_host = std::regex_replace(
        config_all_cluster_endpoints_ip,
        std::regex("<hostname>*"),
        fmt::format("'{}'", all_host["hostname"])
      );
      config_all_cluster = absl::StrCat(
        config_all_cluster,
        std::regex_replace(
          config_all_cluster_host,
          std::regex("<priority>*"),
          all_host["priority"]
        )
      );
    }

    return config_all_cluster;
  }

  // Get specific aggregate cluster configuration from common
  std::string getConfigAggregateCluster(
    const std::string aggregate_cluster,
    const std::string subset_cluster,
    const std::string all_cluster
  ) {
    auto config_aggregate_cluster_aggregate = std::regex_replace(
      config_common_aggregate_cluster,
      std::regex("<aggregate-cluster>*"),
      fmt::format("'{}'", aggregate_cluster)
    );

    auto config_aggregate_cluster_subset = std::regex_replace(
      config_aggregate_cluster_aggregate,
      std::regex("<subset-cluster>*"),
      fmt::format("'{}'", subset_cluster)
    );

    auto config_aggregate_cluster = std::regex_replace(
      config_aggregate_cluster_subset,
      std::regex("<all-cluster>*"),
      fmt::format("'{}'", all_cluster)
    );

    return config_aggregate_cluster;
  }

  // Get specific route configuration from common
  std::string getConfigRoute(
    const std::string aggregate_cluster,
    const std::string preferred_host,
    const std::string num_retries,
    const std::vector<std::string> update_frequency_list
  ) {
    auto config_common_route_aggregate = std::regex_replace(
      config_common_route,
      std::regex("<aggregate-cluster>*"),
      fmt::format("'{}'", aggregate_cluster)
    );

    auto config_route_preferred = std::regex_replace(
      config_common_route_aggregate,
      std::regex("<preferred-host>*"),
      fmt::format("'{}'", preferred_host)
    );

    auto config_route = std::regex_replace(
      config_route_preferred,
      std::regex("<num-retries>*"),
      num_retries
    );

    for (auto& update_frequency:update_frequency_list) {
      config_route = absl::StrCat(
        config_route,
        std::regex_replace(
          config_common_route_update_frequency,
          std::regex("<update-frequency>*"),
          update_frequency
        )
      );
    }

    return config_route;
  }

  // Get specific eric proxy configuration from common
  std::string getConfigEricProxy(const std::string aggregate_cluster) {
    auto config_eric_proxy = std::regex_replace(
      config_common_eric_proxy,
      std::regex("<aggregate-cluster>*"),
      fmt::format("'{}'", aggregate_cluster)
    );

    return config_eric_proxy;
  }

  // Add new cluster configurations from yaml and replacing them with the existing configurations
  void addClusterConfigsFromYaml(
    const std::string& config_subset_cluster,
    const std::string& config_all_cluster, 
    const std::string& config_aggregate_cluster
    ) {
    config_helper_.addConfigModifier(
      [config_subset_cluster](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
          TestUtility::loadFromYaml(config_subset_cluster, *bootstrap.mutable_static_resources()->add_clusters());
      });
    config_helper_.addConfigModifier(
      [config_all_cluster](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
          TestUtility::loadFromYaml(config_all_cluster, *bootstrap.mutable_static_resources()->add_clusters());
      });
    config_helper_.addConfigModifier(
      [config_aggregate_cluster](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
          TestUtility::loadFromYaml(config_aggregate_cluster, *bootstrap.mutable_static_resources()->add_clusters());
      });
  }

  // Add new route configuration from yaml and replacing it with the existing configuration
  void addRouteConfigFromYaml(const std::string& config_route) {
    config_helper_.addConfigModifier(
      [config_route](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager& hcm) {
          TestUtility::loadFromYaml(config_route, *hcm.mutable_route_config());
      });
  }

  // Common function for nf pool reselection tests with different scenarios
  void testNfPoolReselection(const std::string aggregate_cluster, const std::string subset_cluster,
    const std::vector<std::string> subset_hosts, const std::string all_cluster,
    std::vector<std::map<std::string, std::string>> all_hosts, const std::string preferred_host,
    const std::string num_retries, const std::vector<std::string> update_frequency_list,
    const std::vector<std::string> producer_list, const std::vector<std::string> expected_list
  ){
    auto config_subset_cluster = getConfigSubsetCluster(subset_cluster, subset_hosts);
    auto config_all_cluster = getConfigAllCluster(all_cluster, all_hosts);
    auto config_aggregate_cluster = getConfigAggregateCluster(aggregate_cluster, subset_cluster, all_cluster);
    auto config_route = getConfigRoute(aggregate_cluster, preferred_host, num_retries, update_frequency_list);
    auto config_eric_proxy = getConfigEricProxy(aggregate_cluster);

    addClusterConfigsFromYaml(
      config_subset_cluster,
      config_all_cluster,
      config_aggregate_cluster
    );
    addRouteConfigFromYaml(config_route);

    initializeFilter(config_eric_proxy, producer_list.size());

    Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", preferred_host},
      {"3gpp-Sbi-target-apiRoot", fmt::format("https://{}", preferred_host)}
    };

    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(headers);

    // Extracting and testing the expected producers from the expected list in a sequence
    for (size_t i = 0; i < expected_list.size(); i++) {
      std::string expected_producer = "";
      std::vector<std::string> expected_producer_list;
      std::vector<uint64_t> expected_producer_idx_list;
      char delimiter = '/';

      for (auto& char_elem:expected_list[i]) {
        if (char_elem == delimiter) {
          expected_producer_list.push_back(expected_producer);
          expected_producer = "";
        }
        else {
          expected_producer = expected_producer + char_elem;
        }
      }
      expected_producer_list.push_back(expected_producer);
      
      for (auto& expected_producer:expected_producer_list) {
        ptrdiff_t idx = std::distance(
          producer_list.begin(), std::find(producer_list.begin(), producer_list.end(), expected_producer)
        );
        expected_producer_idx_list.push_back(idx);
      }

      waitForNextUpstreamRequest(expected_producer_idx_list);

      // Retry until the last expected producer from the expected list is reached.
      // Therefore, sending the fake 500 status upstream response.
      if (i != expected_list.size() - 1) {
        // Send fake 500 status upstream response
        upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "500"}}, false);

        ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
        ASSERT_TRUE(fake_upstream_connection_->close());
        ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
        fake_upstream_connection_.reset();

        // Verify upstream request
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", aggregate_cluster));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", preferred_host));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", preferred_host));
      }
      // Last expected producer from the expected list is reached.
      // Therefore, sending the fake 200 status upstream response.
      else {
        // Send fake 200 status upstream response
        upstream_request_->encodeHeaders(default_response_headers_, true);

        // Wait for the response and close the fake upstream connection
        ASSERT_TRUE(response->waitForEndStream());
        ASSERT_TRUE(fake_upstream_connection_->close());

        // Verify upstream request
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", aggregate_cluster));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", preferred_host));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", preferred_host));

        // Verify downstream response
        EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));

        codec_client_->close();
      }
    }
  }

};

//------------------------------------------------------------------------
//-------------BEGIN TEST SUITES---------------------
//------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterNfPoolReselectionIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

// Testing with the following testcase scenario:
// - Subset cluster: h1, h2
// - All cluster: 0:h1, 1:h2
// - Aggregate cluster: h1, h2, 0:h1, 1:h2
// - Preferred host: h1
// - Disturbances: h1
// - Number of retries: 2
// - Update freuency list: 2, 0, 1
// - Expected sequence: h1, h1, h2
TEST_P(EricProxyFilterNfPoolReselectionIntegrationTest, TestNfPoolReselection1) {
  std::string aggregate_cluster = "chf_pool#!_#aggr:";

  std::string subset_cluster = "chf_pool#!_#subset:";
  std::vector<std::string> subset_hosts = {
    "chf1.ericsson.se:443",
    "chf2.ericsson.se:443"
  };

  std::string all_cluster = "chf_pool#!_#all:";
  std::vector<std::map<std::string, std::string>> all_hosts = {
    {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}}
  };

  std::string preferred_host = "chf1.ericsson.se:443";
  std::string num_retries = "2";
  std::vector<std::string> update_frequency_list = {"2", "0", "1"};

  std::vector<std::string> producer_list = {
    "h1_subset",
    "h2_subset",
    "h1_all",
    "h2_all"
  };

  std::vector<std::string> expected_list = {
    "h1_subset",
    "h1_subset",
    "h2_all"
  };

  testNfPoolReselection(aggregate_cluster, subset_cluster, subset_hosts, all_cluster, all_hosts,
    preferred_host, num_retries, update_frequency_list, producer_list, expected_list);
}

// Testing with the following testcase scenario:
// - Subset cluster: h1, h2
// - All cluster: 0:h1, 1:h2
// - Aggregate cluster: h1, h2, 0:h1, 1:h2
// - Preferred host: h2
// - Disturbances: h2
// - Number of retries: 2
// - Update freuency list: 2, 1, 0
// - Expected sequence: h2, h2, h1
TEST_P(EricProxyFilterNfPoolReselectionIntegrationTest, TestNfPoolReselection2) {
  std::string aggregate_cluster = "chf_pool#!_#aggr:";

  std::string subset_cluster = "chf_pool#!_#subset:";
  std::vector<std::string> subset_hosts = {
    "chf1.ericsson.se:443",
    "chf2.ericsson.se:443"
  };

  std::string all_cluster = "chf_pool#!_#all:";
  std::vector<std::map<std::string, std::string>> all_hosts = {
    {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}}
  };

  std::string preferred_host = "chf2.ericsson.se:443";
  std::string num_retries = "2";
  std::vector<std::string> update_frequency_list = {"2", "1", "0"};

  std::vector<std::string> producer_list = {
    "h1_subset",
    "h2_subset",
    "h1_all",
    "h2_all"
  };

  std::vector<std::string> expected_list = {
    "h2_subset",
    "h2_subset",
    "h1_all"
  };

  testNfPoolReselection(aggregate_cluster, subset_cluster, subset_hosts, all_cluster, all_hosts,
    preferred_host, num_retries, update_frequency_list, producer_list, expected_list);
}

// Testing with the following testcase scenario:
// - Subset cluster: h1, h2
// - All cluster: 0:h1, 1:h2
// - Aggregate cluster: h1, h2, 0:h1, 1:h2
// - Preferred host: h1
// - Disturbances: h1
// - Number of retries: 3
// - Update freuency list: 2, 0, 1
// - Expected sequence: h1, h1, h2
TEST_P(EricProxyFilterNfPoolReselectionIntegrationTest, TestNfPoolReselection3) {
  std::string aggregate_cluster = "chf_pool#!_#aggr:";

  std::string subset_cluster = "chf_pool#!_#subset:";
  std::vector<std::string> subset_hosts = {
    "chf1.ericsson.se:443",
    "chf2.ericsson.se:443"
  };

  std::string all_cluster = "chf_pool#!_#all:";
  std::vector<std::map<std::string, std::string>> all_hosts = {
    {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}}
  };

  std::string preferred_host = "chf1.ericsson.se:443";
  std::string num_retries = "3";
  std::vector<std::string> update_frequency_list = {"2", "0", "1"};

  std::vector<std::string> producer_list = {
    "h1_subset",
    "h2_subset",
    "h1_all",
    "h2_all"
  };

  std::vector<std::string> expected_list = {
    "h1_subset",
    "h1_subset",
    "h2_all"
  };

  testNfPoolReselection(aggregate_cluster, subset_cluster, subset_hosts, all_cluster, all_hosts,
    preferred_host, num_retries, update_frequency_list, producer_list, expected_list);
}

// Testing with the following testcase scenario:
// - Subset cluster: h1, h2
// - All cluster: 0:h1, 1:h2
// - Aggregate cluster: h1, h2, 0:h1, 1:h2
// - Preferred host: h2
// - Disturbances: h2
// - Number of retries: 3
// - Update freuency list: 2, 1, 0
// - Expected sequence: h1, h1, h2
TEST_P(EricProxyFilterNfPoolReselectionIntegrationTest, TestNfPoolReselection4) {
  std::string aggregate_cluster = "chf_pool#!_#aggr:";

  std::string subset_cluster = "chf_pool#!_#subset:";
  std::vector<std::string> subset_hosts = {
    "chf1.ericsson.se:443",
    "chf2.ericsson.se:443"
  };

  std::string all_cluster = "chf_pool#!_#all:";
  std::vector<std::map<std::string, std::string>> all_hosts = {
    {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}}
  };

  std::string preferred_host = "chf2.ericsson.se:443";
  std::string num_retries = "3";
  std::vector<std::string> update_frequency_list = {"2", "1", "0"};

  std::vector<std::string> producer_list = {
    "h1_subset",
    "h2_subset",
    "h1_all",
    "h2_all"
  };

  std::vector<std::string> expected_list = {
    "h2_subset",
    "h2_subset",
    "h1_all"
  };

  testNfPoolReselection(aggregate_cluster, subset_cluster, subset_hosts, all_cluster, all_hosts,
    preferred_host, num_retries, update_frequency_list, producer_list, expected_list);
}

// Testing with the following testcase scenario:
// - Subset cluster: h1, h2
// - All cluster: 0:h1, 1:h2, 2:h7 (Last Resort: h7)
// - Aggregate cluster: h1, h2, 0:h1, 1:h2, 2:h7
// - Preferred host: h1
// - Disturbances: h1, h2
// - Number of retries: 3
// - Update freuency list: 2, 0, 1, 1
// - Expected sequence: h1, h1, h2, h7
TEST_P(EricProxyFilterNfPoolReselectionIntegrationTest, TestNfPoolReselection5) {
  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::string subset_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#subset:";
  std::vector<std::string> subset_hosts = {
    "chf1.ericsson.se:443",
    "chf2.ericsson.se:443"
  };

  std::string all_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#all:";
  std::vector<std::map<std::string, std::string>> all_hosts = {
    {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
    {{"hostname", "chf7.ericsson.se:443"}, {"priority", "2"}}
  };

  std::string preferred_host = "chf1.ericsson.se:443";
  std::string num_retries = "3";
  std::vector<std::string> update_frequency_list = {"2", "0", "1", "1"};

  std::vector<std::string> producer_list = {
    "h1_subset",
    "h2_subset",
    "h1_all",
    "h2_all",
    "h7_all"
  };

  std::vector<std::string> expected_list = {
    "h1_subset",
    "h1_subset",
    "h2_all",
    "h7_all"
  };

  testNfPoolReselection(aggregate_cluster, subset_cluster, subset_hosts, all_cluster, all_hosts,
    preferred_host, num_retries, update_frequency_list, producer_list, expected_list);
}

// Testing with the following testcase scenario:
// - Subset cluster: h1, h2
// - All cluster: 0:h1, 1:h2, 2:h7 (Last Resort: h7)
// - Aggregate cluster: h1, h2, 0:h1, 1:h2, 2:h7
// - Preferred host: h2
// - Disturbances: h1, h2
// - Number of retries: 3
// - Update freuency list: 2, 1, 0, 1
// - Expected sequence: h2, h2, h1, h7
TEST_P(EricProxyFilterNfPoolReselectionIntegrationTest, TestNfPoolReselection6) {
  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::string subset_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#subset:";
  std::vector<std::string> subset_hosts = {
    "chf1.ericsson.se:443",
    "chf2.ericsson.se:443"
  };

  std::string all_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#all:";
  std::vector<std::map<std::string, std::string>> all_hosts = {
    {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
    {{"hostname", "chf7.ericsson.se:443"}, {"priority", "2"}}
  };

  std::string preferred_host = "chf2.ericsson.se:443";
  std::string num_retries = "3";
  std::vector<std::string> update_frequency_list = {"2", "1", "0", "1"};

  std::vector<std::string> producer_list = {
    "h1_subset",
    "h2_subset",
    "h1_all",
    "h2_all",
    "h7_all"
  };

  std::vector<std::string> expected_list = {
    "h2_subset",
    "h2_subset",
    "h1_all",
    "h7_all"
  };

  testNfPoolReselection(aggregate_cluster, subset_cluster, subset_hosts, all_cluster, all_hosts,
    preferred_host, num_retries, update_frequency_list, producer_list, expected_list);
}

// Testing with the following testcase scenario:
// - Subset cluster: h1, h2, h3
// - All cluster: 0:h1, 1:h2, 2:h3, 3:h7 (Last Resort: h7)
// - Aggregate cluster: h1, h2, h3, 0:h1, 1:h2, 2:h3, 3:h7
// - Preferred host: h1
// - Disturbances: h1, h2, h3
// - Number of retries: 3
// - Update freuency list: 2, 0, 1, 0, 1
// - Expected sequence: h1, h1, h2, h7
TEST_P(EricProxyFilterNfPoolReselectionIntegrationTest, TestNfPoolReselection7) {
  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::string subset_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#subset:";
  std::vector<std::string> subset_hosts = {
    "chf1.ericsson.se:443",
    "chf2.ericsson.se:443",
    "chf3.ericsson.se:443"
  };

  std::string all_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#all:";
  std::vector<std::map<std::string, std::string>> all_hosts = {
    {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
    {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}},
    {{"hostname", "chf7.ericsson.se:443"}, {"priority", "3"}}
  };

  std::string preferred_host = "chf1.ericsson.se:443";
  std::string num_retries = "3";
  std::vector<std::string> update_frequency_list = {"2", "0", "1", "0", "1"};

  std::vector<std::string> producer_list = {
    "h1_subset",
    "h2_subset",
    "h3_subset",
    "h1_all",
    "h2_all",
    "h3_all",
    "h7_all"
  };

  std::vector<std::string> expected_list = {
    "h1_subset",
    "h1_subset",
    "h2_all",
    "h7_all"
  };

  testNfPoolReselection(aggregate_cluster, subset_cluster, subset_hosts, all_cluster, all_hosts,
    preferred_host, num_retries, update_frequency_list, producer_list, expected_list);
}

// Testing with the following testcase scenario:
// - Subset cluster: h1, h2, h3
// - All cluster: 0:h1, 1:h2, 2:h3, 3:h7 (Last Resort: h7)
// - Aggregate cluster: h1, h2, h3, 0:h1, 1:h2, 2:h3, 3:h7
// - Preferred host: h2
// - Disturbances: h1, h2, h3
// - Number of retries: 3
// - Update freuency list: 2, 1, 0, 0, 1
// - Expected sequence: h2, h2, h1, h7
TEST_P(EricProxyFilterNfPoolReselectionIntegrationTest, TestNfPoolReselection8) {
  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::string subset_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#subset:";
  std::vector<std::string> subset_hosts = {
    "chf1.ericsson.se:443",
    "chf2.ericsson.se:443",
    "chf3.ericsson.se:443"
  };

  std::string all_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#all:";
  std::vector<std::map<std::string, std::string>> all_hosts = {
    {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
    {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}},
    {{"hostname", "chf7.ericsson.se:443"}, {"priority", "3"}}
  };

  std::string preferred_host = "chf2.ericsson.se:443";
  std::string num_retries = "3";
  std::vector<std::string> update_frequency_list = {"2", "1", "0", "0", "1"};

  std::vector<std::string> producer_list = {
    "h1_subset",
    "h2_subset",
    "h3_subset",
    "h1_all",
    "h2_all",
    "h3_all",
    "h7_all"
  };

  std::vector<std::string> expected_list = {
    "h2_subset",
    "h2_subset",
    "h1_all",
    "h7_all"
  };

  testNfPoolReselection(aggregate_cluster, subset_cluster, subset_hosts, all_cluster, all_hosts,
    preferred_host, num_retries, update_frequency_list, producer_list, expected_list);
}

// Testing with the following testcase scenario:
// - Subset cluster: h1, h2, h3
// - All cluster: 0:h1, 1:h2, 2:h3, 3:h7 (Last Resort: h7)
// - Aggregate cluster: h1, h2, h3, 0:h1, 1:h2, 2:h3, 3:h7
// - Preferred host: h3
// - Disturbances: h1, h2, h3
// - Number of retries: 3
// - Update freuency list: 2, 1, 0, 0, 1
// - Expected sequence: h3, h3, h1, h7
TEST_P(EricProxyFilterNfPoolReselectionIntegrationTest, TestNfPoolReselection9) {
  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::string subset_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#subset:";
  std::vector<std::string> subset_hosts = {
    "chf1.ericsson.se:443",
    "chf2.ericsson.se:443",
    "chf3.ericsson.se:443"
  };

  std::string all_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#all:";
  std::vector<std::map<std::string, std::string>> all_hosts = {
    {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
    {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}},
    {{"hostname", "chf7.ericsson.se:443"}, {"priority", "3"}}
  };

  std::string preferred_host = "chf3.ericsson.se:443";
  std::string num_retries = "3";
  std::vector<std::string> update_frequency_list = {"2", "1", "0", "0", "1"};

  std::vector<std::string> producer_list = {
    "h1_subset",
    "h2_subset",
    "h3_subset",
    "h1_all",
    "h2_all",
    "h3_all",
    "h7_all"
  };

  std::vector<std::string> expected_list = {
    "h3_subset",
    "h3_subset",
    "h1_all",
    "h7_all"
  };

  testNfPoolReselection(aggregate_cluster, subset_cluster, subset_hosts, all_cluster, all_hosts,
    preferred_host, num_retries, update_frequency_list, producer_list, expected_list);
}

// Testing with the following testcase scenario:
// - Subset cluster: h1, h2
// - All cluster: 0:h1, 1:h2, 2:h7, 3:h8 (Last Resort: 0:h7, 1:h8)
// - Aggregate cluster: h1, h2, 0:h1, 1:h2, 2:h7, 3:h8
// - Preferred host: h1
// - Disturbances: h1, h2, h7
// - Number of retries: 5
// - Update freuency list: 2, 0, 1, 1, 1
// - Expected sequence: h1, h1, h2, h7, h8
TEST_P(EricProxyFilterNfPoolReselectionIntegrationTest, TestNfPoolReselection10) {
  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::string subset_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#subset:";
  std::vector<std::string> subset_hosts = {
    "chf1.ericsson.se:443",
    "chf2.ericsson.se:443"
  };

  std::string all_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#all:";
  std::vector<std::map<std::string, std::string>> all_hosts = {
    {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
    {{"hostname", "chf7.ericsson.se:443"}, {"priority", "2"}},
    {{"hostname", "chf8.ericsson.se:443"}, {"priority", "3"}}
  };

  std::string preferred_host = "chf1.ericsson.se:443";
  std::string num_retries = "5";
  std::vector<std::string> update_frequency_list = {"2", "0", "1", "1", "1"};

  std::vector<std::string> producer_list = {
    "h1_subset",
    "h2_subset",
    "h1_all",
    "h2_all",
    "h7_all",
    "h8_all"
  };

  std::vector<std::string> expected_list = {
    "h1_subset",
    "h1_subset",
    "h2_all",
    "h7_all",
    "h8_all"
  };

  testNfPoolReselection(aggregate_cluster, subset_cluster, subset_hosts, all_cluster, all_hosts,
    preferred_host, num_retries, update_frequency_list, producer_list, expected_list);
}

// Testing with the following testcase scenario:
// - Subset cluster: h1, h2
// - All cluster: 0:h1, 1:h2, 2:h7, 3:h8 (Last Resort: 0:h7, 1:h8)
// - Aggregate cluster: h1, h2, 0:h1, 1:h2, 2:h7, 3:h8
// - Preferred host: h2
// - Disturbances: h1, h2, h7
// - Number of retries: 5
// - Update freuency list: 2, 1, 0, 1, 1
// - Expected sequence: h2, h2, h1, h7, h8
TEST_P(EricProxyFilterNfPoolReselectionIntegrationTest, TestNfPoolReselection11) {
  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::string subset_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#subset:";
  std::vector<std::string> subset_hosts = {
    "chf1.ericsson.se:443",
    "chf2.ericsson.se:443"
  };

  std::string all_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#all:";
  std::vector<std::map<std::string, std::string>> all_hosts = {
    {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
    {{"hostname", "chf7.ericsson.se:443"}, {"priority", "2"}},
    {{"hostname", "chf8.ericsson.se:443"}, {"priority", "3"}}
  };

  std::string preferred_host = "chf2.ericsson.se:443";
  std::string num_retries = "5";
  std::vector<std::string> update_frequency_list = {"2", "1", "0", "1", "1"};

  std::vector<std::string> producer_list = {
    "h1_subset",
    "h2_subset",
    "h1_all",
    "h2_all",
    "h7_all",
    "h8_all"
  };

  std::vector<std::string> expected_list = {
    "h2_subset",
    "h2_subset",
    "h1_all",
    "h7_all",
    "h8_all"
  };

  testNfPoolReselection(aggregate_cluster, subset_cluster, subset_hosts, all_cluster, all_hosts,
    preferred_host, num_retries, update_frequency_list, producer_list, expected_list);
}

// Testing with the following testcase scenario:
// - Subset cluster: h1, h2, h3
// - All cluster: 0:h1, 0:h3, 1:h2, 2:h7 (Last Resort: h7)
// - Aggregate cluster: h1, h2, h3, 0:h1, 0:h3, 1:h2, 2:h7
// - Preferred host: h1
// - Disturbances: h1, h2, h3
// - Number of retries: 4
// - Update freuency list: 2, 1, 1, 1
// - Expected sequence: h1, h1, h3, h2, h7
TEST_P(EricProxyFilterNfPoolReselectionIntegrationTest, TestNfPoolReselection12) {
  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::string subset_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#subset:";
  std::vector<std::string> subset_hosts = {
    "chf1.ericsson.se:443",
    "chf2.ericsson.se:443",
    "chf3.ericsson.se:443"
  };

  std::string all_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#all:";
  std::vector<std::map<std::string, std::string>> all_hosts = {
    {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf3.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
    {{"hostname", "chf7.ericsson.se:443"}, {"priority", "2"}}
  };

  std::string preferred_host = "chf1.ericsson.se:443";
  std::string num_retries = "4";
  std::vector<std::string> update_frequency_list = {"2", "1", "1", "1"};

  std::vector<std::string> producer_list = {
    "h1_subset",
    "h2_subset",
    "h3_subset",
    "h1_all",
    "h3_all",
    "h2_all",
    "h7_all"
  };

  std::vector<std::string> expected_list = {
    "h1_subset",
    "h1_subset",
    "h3_all",
    "h2_all",
    "h7_all"
  };

  testNfPoolReselection(aggregate_cluster, subset_cluster, subset_hosts, all_cluster, all_hosts,
    preferred_host, num_retries, update_frequency_list, producer_list, expected_list);
}

// Testing with the following testcase scenario:
// - Subset cluster: h1, h2, h3
// - All cluster: 0:h1, 0:h3, 1:h2, 2:h7 (Last Resort: h7)
// - Aggregate cluster: h1, h2, h3, 0:h1, 0:h3, 1:h2, 2:h7
// - Preferred host: h2
// - Disturbances: h1, h2, h3
// - Number of retries: 4
// - Update freuency list: 2, 2, 0, 1
// - Expected sequence: h2, h2, h1/h3, h3/h1, h7
TEST_P(EricProxyFilterNfPoolReselectionIntegrationTest, TestNfPoolReselection13) {
  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::string subset_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#subset:";
  std::vector<std::string> subset_hosts = {
    "chf1.ericsson.se:443",
    "chf2.ericsson.se:443",
    "chf3.ericsson.se:443"
  };

  std::string all_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#all:";
  std::vector<std::map<std::string, std::string>> all_hosts = {
    {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf3.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
    {{"hostname", "chf7.ericsson.se:443"}, {"priority", "2"}}
  };

  std::string preferred_host = "chf2.ericsson.se:443";
  std::string num_retries = "4";
  std::vector<std::string> update_frequency_list = {"2", "2", "0", "1"};

  std::vector<std::string> producer_list = {
    "h1_subset",
    "h2_subset",
    "h3_subset",
    "h1_all",
    "h3_all",
    "h2_all",
    "h7_all"
  };

  std::vector<std::string> expected_list = {
    "h2_subset",
    "h2_subset",
    "h1_all/h3_all",
    "h3_all/h1_all",
    "h7_all"
  };

  testNfPoolReselection(aggregate_cluster, subset_cluster, subset_hosts, all_cluster, all_hosts,
    preferred_host, num_retries, update_frequency_list, producer_list, expected_list);
}

// Testing with the following testcase scenario:
// - Subset cluster: h1, h2, h3
// - All cluster: 0:h1, 1:h2, 1:h3, 2:h7 (Last Resort: h7)
// - Aggregate cluster: h1, h2, h3, 0:h1, 1:h2, 1:h3, 2:h7
// - Preferred host: h1
// - Disturbances: h1, h2, h3
// - Number of retries: 4
// - Update freuency list: 2, 0, 2, 1
// - Expected sequence: h1, h1, h2/h3, h3/h2, h7
TEST_P(EricProxyFilterNfPoolReselectionIntegrationTest, TestNfPoolReselection14) {
  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::string subset_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#subset:";
  std::vector<std::string> subset_hosts = {
    "chf1.ericsson.se:443",
    "chf2.ericsson.se:443",
    "chf3.ericsson.se:443"
  };

  std::string all_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#all:";
  std::vector<std::map<std::string, std::string>> all_hosts = {
    {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
    {{"hostname", "chf3.ericsson.se:443"}, {"priority", "1"}},
    {{"hostname", "chf7.ericsson.se:443"}, {"priority", "2"}}
  };

  std::string preferred_host = "chf1.ericsson.se:443";
  std::string num_retries = "4";
  std::vector<std::string> update_frequency_list = {"2", "0", "2", "1"};

  std::vector<std::string> producer_list = {
    "h1_subset",
    "h2_subset",
    "h3_subset",
    "h1_all",
    "h2_all",
    "h3_all",
    "h7_all"
  };

  std::vector<std::string> expected_list = {
    "h1_subset",
    "h1_subset",
    "h2_all/h3_all",
    "h3_all/h2_all",
    "h7_all"
  };

  testNfPoolReselection(aggregate_cluster, subset_cluster, subset_hosts, all_cluster, all_hosts,
    preferred_host, num_retries, update_frequency_list, producer_list, expected_list);
}

// Testing with the following testcase scenario:
// - Subset cluster: h1, h2, h3
// - All cluster: 0:h1, 1:h2, 2:h3, 3:h7 (Last Resort: h7)
// - Aggregate cluster: h1, h2, h3, 0:h1, 1:h2, 2:h3, 3:h7
// - Preferred host: h2
// - Disturbances: h1, h2, h3
// - Number of retries: 4
// - Update freuency list: 2, 1, 0, 1, 1
// - Expected sequence: h2, h2, h1, h3, h7
TEST_P(EricProxyFilterNfPoolReselectionIntegrationTest, TestNfPoolReselection15) {
  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::string subset_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#subset:";
  std::vector<std::string> subset_hosts = {
    "chf1.ericsson.se:443",
    "chf2.ericsson.se:443",
    "chf3.ericsson.se:443"
  };

  std::string all_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#all:";
  std::vector<std::map<std::string, std::string>> all_hosts = {
    {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
    {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
    {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}},
    {{"hostname", "chf7.ericsson.se:443"}, {"priority", "3"}}
  };

  std::string preferred_host = "chf2.ericsson.se:443";
  std::string num_retries = "4";
  std::vector<std::string> update_frequency_list = {"2", "1", "0", "1", "1"};

  std::vector<std::string> producer_list = {
    "h1_subset",
    "h2_subset",
    "h3_subset",
    "h1_all",
    "h2_all",
    "h3_all",
    "h7_all"
  };

  std::vector<std::string> expected_list = {
    "h2_subset",
    "h2_subset",
    "h1_all",
    "h3_all",
    "h7_all"
  };

  testNfPoolReselection(aggregate_cluster, subset_cluster, subset_hosts, all_cluster, all_hosts,
    preferred_host, num_retries, update_frequency_list, producer_list, expected_list);
}

//------------------------------------------------------------------------
//-------------END TEST SUITES---------------------
//------------------------------------------------------------------------

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
