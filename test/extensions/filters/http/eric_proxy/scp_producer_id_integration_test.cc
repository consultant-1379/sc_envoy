#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "envoy/http/codes.h"
#include "envoy/http/filter.h"
#include "source/common/common/logger.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "test/integration/http_integration.h"
#include <cstdint>
#include <ostream>
#include <regex>
#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterProducerIdIntegrationTest : public HttpIntegrationTest,
                                          public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterProducerIdIntegrationTest() : HttpIntegrationTest(
    Http::CodecClient::Type::HTTP1,
    GetParam(),
    EricProxyFilterProducerIdIntegrationTest::ericProxyHttpBaseConfig()
  ) {}

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
  access_log_path: /dev/null
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 0
static_resources:
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
)EOF");
  }

  // Common configuration for eric proxy filter
  const std::string config_common_eric_proxy = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: <config-name>
  node_type: <node-type>
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
              term_string: <cluster-name>
            routing_behaviour: <routing-behaviour>
)EOF";

  // Common configuration for preferred target
  const std::string config_common_preferred_target = R"EOF(
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
)EOF";

  // Common cluster configuration
  std::string config_common_cluster = R"EOF(
name: <cluster>
connect_timeout: 15s
load_assignment:
  cluster_name: <cluster>
  endpoints:
)EOF";

  // Common cluster endpoints configuration
  // Multiple lb_endpoints required as they 
  // may have different priorities.
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
)EOF";

  // Common primary cluster endpoints eric proxy metadata configuration
  std::string config_common_eric_proxy_md = R"EOF(
          envoy.eric_proxy:
            support:
)EOF";

  // Common primary cluster endpoints eric proxy metadata support configuration
  std::string config_common_support = R"EOF(
            - <support>
)EOF";

  // Common primary cluster endpoints eric proxy metadata nf instance id configuration
  std::string config_common_nf_instance_id = R"EOF(
            nfInstanceId: 
            - <nf-instance-id>
            - <nf-serv-inst-id>
            - <nf-set-id>
            - <nf-serv-set-id>
)EOF";

  // Common primary cluster endpoints priority configuration
  std::string config_common_priority = R"EOF(
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
            exact: <cluster>
    route:
      cluster: <cluster>
      retry_policy:
        retry_on: retriable-status-codes
        retriable_status_codes:
        - 500
        - 501
        - 502
        - 503
        retry_host_predicate:
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

  // Endpoints Definition
  struct EpDefinition {
    std::string hostname;
    std::vector<std::string> nfInstId;
    std::string priority;
    std::vector<std::string> support;
  };

  // Routing Behaviours
  enum ROUTING {
    Preferred,
    RoundRobin,
    Strict
  };
 
  // Get specific cluster configuration from common
  std::string getConfigCluster(
    const std::string& cluster,
    const std::vector<EpDefinition*>& hosts
  ) {
    auto config_cluster = std::regex_replace(
      config_common_cluster,
      std::regex("<cluster>*"),
      fmt::format("'{}'", cluster)
    );

    auto config_cluster_endpoints_ip = std::regex_replace(
      config_common_cluster_endpoints,
      std::regex("<ip-address>*"),
      Network::Test::getLoopbackAddressString(GetParam())
    );

    for (const auto& host : hosts) {
      absl::StrAppend(
        &config_cluster,
        std::regex_replace(
          config_cluster_endpoints_ip,
          std::regex("<hostname>*"),
          fmt::format("'{}'", host->hostname)
        )
      );

      absl::StrAppend(
        &config_cluster,
        config_common_eric_proxy_md
      );

      for(const auto& support : host->support) {
        absl::StrAppend(
          &config_cluster,
          std::regex_replace(
            config_common_support,
            std::regex("<support>*"),
            support
          )
        );
      }

      if (!host->nfInstId[0].empty()) {
        absl::StrAppend(
          &config_cluster,
          std::regex_replace(
            config_common_nf_instance_id,
            std::regex("<nf-instance-id>*"),
            fmt::format("'{}'", host->nfInstId[0])
          )
        );
      }
      absl::StrAppend(
        &config_cluster,
        std::regex_replace(
          config_cluster,
          std::regex("<nf-serv-inst-id>*"),
          fmt::format("'{}'", host->nfInstId[1])
        )
      );
      absl::StrAppend(
        &config_cluster,
        std::regex_replace(
          config_cluster,
          std::regex("<nf-set-id>*"),
          fmt::format("'{}'", host->nfInstId[2])
        )
      );
      absl::StrAppend(
        &config_cluster,
        std::regex_replace(
          config_cluster,
          std::regex("<nf-serv-set-id>*"),
          fmt::format("'{}'", host->nfInstId[3])
        )
      );

      absl::StrAppend(
        &config_cluster,
        std::regex_replace(
          config_common_priority,
          std::regex("<priority>*"),
          host->priority
        )
      );
    }

    return config_cluster;
  }

  // Get specific aggregate cluster configuration from common
  std::string getConfigAggregateCluster(
    const std::string& aggregate_cluster,
    const std::string& primary_cluster,
    const std::string& last_resort_cluster
  ) {
    auto config_aggregate_cluster_aggregate = std::regex_replace(
      config_common_aggregate_cluster,
      std::regex("<aggregate-cluster>*"),
      fmt::format("'{}'", aggregate_cluster)
    );

    auto config_aggregate_cluster_subset = std::regex_replace(
      config_aggregate_cluster_aggregate,
      std::regex("<primary-cluster>*"),
      fmt::format("'{}'", primary_cluster)
    );

    auto config_aggregate_cluster = std::regex_replace(
      config_aggregate_cluster_subset,
      std::regex("<last-resort-cluster>*"),
      fmt::format("'{}'", last_resort_cluster)
    );

    return config_aggregate_cluster;
  }

  // Get specific route configuration from common
  std::string getConfigRoute(
    const std::string& cluster,
    const std::vector<uint64_t>& retry_params
  ) {
    auto config_route = std::regex_replace(config_common_route, std::regex("<cluster>"),
                                           fmt::format("'{}'", cluster));
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
  std::string getConfigEricProxy(
    const bool& is_sepp_node,
    const std::string& cluster_name,
    const ROUTING& routing_behaviour
  ) {
    std::string config_eric_proxy;
    std::string config_name;
    std::string node_type;

    if(is_sepp_node) {
      config_name = "sepp_router";
      node_type = "SEPP";
    }
    else {
      config_name = "scp_router";
      node_type = "SCP";
    }

    switch(routing_behaviour) {
      case ROUTING::Preferred : {
        auto config_eric_proxy_config_name = std::regex_replace(
          config_common_eric_proxy,
          std::regex("<config-name>*"),
          fmt::format("'{}'", config_name)
        );
        auto config_eric_proxy_node_type = std::regex_replace(
          config_eric_proxy_config_name,
          std::regex("<node-type>*"),
          fmt::format("'{}'", node_type)
        );
        auto config_eric_proxy_cluster_name = std::regex_replace(
          config_eric_proxy_node_type,
          std::regex("<cluster-name>*"),
          fmt::format("'{}'", cluster_name)
        );
        config_eric_proxy = std::regex_replace(
          config_eric_proxy_cluster_name,
          std::regex("<routing-behaviour>*"),
          "PREFERRED"
        );
        absl::StrAppend(
          &config_eric_proxy,
          config_common_preferred_target
        );
      }
      break;
      case ROUTING::RoundRobin : {
        auto config_eric_proxy_config_name = std::regex_replace(
          config_common_eric_proxy,
          std::regex("<config-name>*"),
          fmt::format("'{}'", config_name)
        );
        auto config_eric_proxy_node_type = std::regex_replace(
          config_eric_proxy_config_name,
          std::regex("<node-type>*"),
          fmt::format("'{}'", node_type)
        );
        auto config_eric_proxy_cluster_name = std::regex_replace(
          config_eric_proxy_node_type,
          std::regex("<cluster-name>*"),
          fmt::format("'{}'", cluster_name)
        );
        config_eric_proxy = std::regex_replace(
          config_eric_proxy_cluster_name,
          std::regex("<routing-behaviour>*"),
          "ROUND_ROBIN"
        );
      }
      break;
      case ROUTING::Strict : {
        auto config_eric_proxy_config_name = std::regex_replace(
          config_common_eric_proxy,
          std::regex("<config-name>*"),
          fmt::format("'{}'", config_name)
        );
        auto config_eric_proxy_node_type = std::regex_replace(
          config_eric_proxy_config_name,
          std::regex("<node-type>*"),
          fmt::format("'{}'", node_type)
        );
        auto config_eric_proxy_cluster_name = std::regex_replace(
          config_eric_proxy_node_type,
          std::regex("<cluster-name>*"),
          fmt::format("'{}'", cluster_name)
        );
        config_eric_proxy = std::regex_replace(
          config_eric_proxy_cluster_name,
          std::regex("<routing-behaviour>*"),
          "STRICT"
        );
        absl::StrAppend(
          &config_eric_proxy,
          config_common_preferred_target
        );
      }
      break;
    }

    return config_eric_proxy;
  }

  // Add new cluster configurations from yaml and replace
  // the existing cluster configurations with them
  void addClusterConfigsFromYaml(const std::vector<std::string>& config_clusters) {
    for (const auto& config_cluster : config_clusters) {
      config_helper_.addConfigModifier(
        [config_cluster](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
            TestUtility::loadFromYaml(config_cluster, *bootstrap.mutable_static_resources()->add_clusters());
        }
      );
    }
  }

  // Add new route configuration from yaml and replace 
  // the existing route configuration with it
  void addRouteConfigFromYaml(const std::string& config_route) {
    config_helper_.addConfigModifier(
      [config_route](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager& hcm) {
          TestUtility::loadFromYaml(config_route, *hcm.mutable_route_config());
      }
    );
  }

  // Common function for preferrred routing producer id tests with different scenarios
  void testProducerIdPreferred(
    const bool& is_sepp_node,
    const std::string& primary_cluster,
    const std::vector<EpDefinition*>& primary_hosts,
    const std::string& preferred_host,
    const std::vector<uint64_t>& retry_params,
    const std::vector<EpDefinition*> producer_list,
    const std::vector<std::vector<EpDefinition*>> expected_list,
    const bool expect_producer_id,
    const std::string& last_resort_cluster = "",
    const std::vector<EpDefinition*>& last_resort_hosts = {},
    const std::string& aggregate_cluster = ""
  ) {
    std::string cluster = primary_cluster;
    std::vector<std::string> config_clusters;
    config_clusters.push_back(getConfigCluster(primary_cluster, primary_hosts));
    if (!last_resort_cluster.empty()) {
      config_clusters.push_back(getConfigCluster(last_resort_cluster, last_resort_hosts));
    }
    if (!aggregate_cluster.empty()) {
      config_clusters.push_back(getConfigAggregateCluster(aggregate_cluster, primary_cluster, last_resort_cluster));
      cluster = aggregate_cluster;
    }
    auto config_route = getConfigRoute(cluster, retry_params);
    auto config_eric_proxy = getConfigEricProxy(is_sepp_node, cluster, ROUTING::Preferred);

    addClusterConfigsFromYaml(config_clusters);
    addRouteConfigFromYaml(config_route);

    initializeFilter(config_eric_proxy, producer_list.size());

    Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":scheme","http"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", fmt::format("http://{}", preferred_host)}
    };

    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(headers);

    for (size_t i = 0; i < expected_list.size(); i++) {
      std::vector<EpDefinition *> expected_producer_list = expected_list.at(i);
      std::vector<uint64_t> expected_producer_idx_list;

      for (auto& expected_producer:expected_producer_list) {
        ptrdiff_t idx = std::distance(
          producer_list.begin(), std::find(producer_list.begin(), producer_list.end(), expected_producer)
        );
        expected_producer_idx_list.push_back(idx);
      }

      auto upstream_index = waitForNextUpstreamRequest(expected_producer_idx_list);

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
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", cluster));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", preferred_host));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", expected_producer_list.at(upstream_index.value())->hostname));
      }
      // Last expected producer from the expected list is reached.
      // Therefore, sending the fake 200 status upstream response.
      else {
        // Send fake 200 status upstream response with fake body
        std::string body{R"({"message":"success"})"};
        Http::TestResponseHeaderMapImpl response_headers{
            {":status", "200"},
            {"content-length", std::to_string(body.length())},
            {"content-type", "application/json"}
        };
        upstream_request_->encodeHeaders(response_headers, false);
        Buffer::OwnedImpl response_data(body);
        upstream_request_->encodeData(response_data, true);

        // Wait for the response and close the fake upstream connection
        ASSERT_TRUE(response->waitForEndStream());
        ASSERT_TRUE(fake_upstream_connection_->close());

        // Verify upstream request
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", cluster));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", preferred_host));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", expected_producer_list.at(upstream_index.value())->hostname));
        // Verify downstream response
        EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));

        auto expected_producer_id = std::string("nfinst=").append(expected_producer_list.at(upstream_index.value())->nfInstId[0]);

        if(! expected_producer_list.at(upstream_index.value())->nfInstId[1].empty())
        {
          expected_producer_id.append("; nfservinst="+expected_producer_list.at(upstream_index.value())->nfInstId[1]);
        }
        if(! expected_producer_list.at(upstream_index.value())->nfInstId[2].empty())
        {
          expected_producer_id.append("; nfset="+expected_producer_list.at(upstream_index.value())->nfInstId[2]);
        }
        if(! expected_producer_list.at(upstream_index.value())->nfInstId[3].empty())
        {
          expected_producer_id.append("; nfserviceset="+expected_producer_list.at(upstream_index.value())->nfInstId[3]);
        }
        if(expect_producer_id) {
          EXPECT_THAT(response->headers(), Http::HeaderValueOf("3gpp-sbi-producer-id", expected_producer_id));
        }
        else {
          EXPECT_EQ(response->headers().get(Http::LowerCaseString("3gpp-sbi-producer-id")).size(), 0);
        }

        codec_client_->close();
      }
    }
  }

  // Common function for round-robin routing producer id tests with different scenarios
  void testProducerIdRoundRobin(
    const bool& is_sepp_node,
    const std::string& primary_cluster,
    const std::vector<EpDefinition*>& primary_hosts,
    const std::vector<uint64_t>& retry_params,
    const std::vector<EpDefinition*> producer_list,
    const std::vector<std::vector<EpDefinition*>> expected_list,
    const bool expect_producer_id,
    const std::string& last_resort_cluster = "",
    const std::vector<EpDefinition*>& last_resort_hosts = {},
    const std::string& aggregate_cluster = ""
    ) {
    std::string cluster = primary_cluster;
    std::vector<std::string> config_clusters;
    config_clusters.push_back(getConfigCluster(primary_cluster, primary_hosts));
    if (!last_resort_cluster.empty()) {
      config_clusters.push_back(getConfigCluster(last_resort_cluster, last_resort_hosts));
    }
    if (!aggregate_cluster.empty()) {
      config_clusters.push_back(getConfigAggregateCluster(aggregate_cluster, primary_cluster, last_resort_cluster));
      cluster = aggregate_cluster;
    }
    auto config_route = getConfigRoute(cluster, retry_params);
    auto config_eric_proxy = getConfigEricProxy(is_sepp_node, cluster, ROUTING::RoundRobin);

    addClusterConfigsFromYaml(config_clusters);
    addRouteConfigFromYaml(config_route);

    initializeFilter(config_eric_proxy, producer_list.size());

    Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
    };
    
    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(headers);

    for (size_t i = 0; i < expected_list.size(); i++) {
      std::vector<EpDefinition *> expected_producer_list = expected_list.at(i);
      std::vector<uint64_t> expected_producer_idx_list;

      for (auto& expected_producer:expected_producer_list) {
        ptrdiff_t idx = std::distance(
          producer_list.begin(), std::find(producer_list.begin(), producer_list.end(), expected_producer)
        );
        expected_producer_idx_list.push_back(idx);
      }

      auto upstream_index = waitForNextUpstreamRequest(expected_producer_idx_list);

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
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", cluster));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", expected_producer_list.at(upstream_index.value())->hostname));
      }
      // Last expected producer from the expected list is reached.
      // Therefore, sending the fake 200 status upstream response.
      else {
        // Send fake 200 status upstream response with fake body
        std::string body{R"({"message":"success"})"};
        Http::TestResponseHeaderMapImpl response_headers{
            {":status", "200"},
            {"content-length", std::to_string(body.length())},
            {"content-type", "application/json"}
        };
        upstream_request_->encodeHeaders(response_headers, false);
        Buffer::OwnedImpl response_data(body);
        upstream_request_->encodeData(response_data, true);

        // Wait for the response and close the fake upstream connection
        ASSERT_TRUE(response->waitForEndStream());
        ASSERT_TRUE(fake_upstream_connection_->close());

        // Verify upstream request
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", cluster));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", expected_producer_list.at(upstream_index.value())->hostname));

        // Verify downstream response
        EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));

        auto expected_producer_id = std::string("nfinst=").append(expected_producer_list.at(upstream_index.value())->nfInstId[0]);
        if(! expected_producer_list.at(upstream_index.value())->nfInstId[1].empty())
        {
          expected_producer_id.append("; nfservinst="+expected_producer_list.at(upstream_index.value())->nfInstId[1]);
        }
        if(! expected_producer_list.at(upstream_index.value())->nfInstId[2].empty())
        {
          expected_producer_id.append("; nfset="+expected_producer_list.at(upstream_index.value())->nfInstId[2]);
        }
        if(! expected_producer_list.at(upstream_index.value())->nfInstId[3].empty())
        {
          expected_producer_id.append("; nfserviceset="+expected_producer_list.at(upstream_index.value())->nfInstId[3]);
        }
        if(expect_producer_id) {
          EXPECT_THAT(response->headers(), Http::HeaderValueOf("3gpp-sbi-producer-id", expected_producer_id));
        }
        else {
          EXPECT_EQ(response->headers().get(Http::LowerCaseString("3gpp-sbi-producer-id")).size(), 0);
        }

        codec_client_->close();
      }
    }
  }

  // Common function for strict routing producer id tests with different scenarios
  void testProducerIdStrict(
    const bool& is_sepp_node,
    const std::string& primary_cluster,
    const std::vector<EpDefinition*>& primary_hosts,
    const std::string& preferred_host,
    const std::vector<uint64_t>& retry_params,
    const std::vector<EpDefinition*> producer_list,
    const std::vector<std::vector<EpDefinition*>> expected_list,
    const bool expect_producer_id
    ) {
    std::vector<std::string> config_clusters;
    config_clusters.push_back(getConfigCluster(primary_cluster, primary_hosts));
    auto config_route = getConfigRoute(primary_cluster, retry_params);
    auto config_eric_proxy = getConfigEricProxy(is_sepp_node, primary_cluster, ROUTING::Strict);

    addClusterConfigsFromYaml(config_clusters);
    addRouteConfigFromYaml(config_route);

    initializeFilter(config_eric_proxy, producer_list.size());

    Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", fmt::format("http://{}", preferred_host)}
    };

    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(headers);

    for (size_t i = 0; i < expected_list.size(); i++) {
      std::vector<EpDefinition *> expected_producer_list = expected_list.at(i);
      std::vector<uint64_t> expected_producer_idx_list;

      for (auto& expected_producer:expected_producer_list) {
        ptrdiff_t idx = std::distance(
          producer_list.begin(), std::find(producer_list.begin(), producer_list.end(), expected_producer)
        );
        expected_producer_idx_list.push_back(idx);
      }

      auto upstream_index = waitForNextUpstreamRequest(expected_producer_idx_list);

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
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", primary_cluster));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", preferred_host));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", expected_producer_list.at(upstream_index.value())->hostname));
      }
      // Last expected producer from the expected list is reached.
      // Therefore, sending the fake 200 status upstream response.
      else {
        // Send fake 200 status upstream response with fake body
        std::string body{R"({"message":"success"})"};
        Http::TestResponseHeaderMapImpl response_headers{
            {":status", "200"},
            {"content-length", std::to_string(body.length())},
            {"content-type", "application/json"}
        };
        upstream_request_->encodeHeaders(response_headers, false);
        Buffer::OwnedImpl response_data(body);
        upstream_request_->encodeData(response_data, true);

        // Wait for the response and close the fake upstream connection
        ASSERT_TRUE(response->waitForEndStream());
        ASSERT_TRUE(fake_upstream_connection_->close());

        // Verify upstream request
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", primary_cluster));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", preferred_host));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", expected_producer_list.at(upstream_index.value())->hostname));

        // Verify downstream response
        EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));

        const auto expected_producer_id = std::string("nfinst=").append(expected_producer_list.at(upstream_index.value())->nfInstId[0]);

        if(expect_producer_id) {
          EXPECT_THAT(response->headers(), Http::HeaderValueOf("3gpp-sbi-producer-id", expected_producer_id));
        }
        else {
          EXPECT_EQ(response->headers().get(Http::LowerCaseString("3gpp-sbi-producer-id")).size(), 0);
        }

        codec_client_->close();
      }
    }
  }

};

/************************************************************************************** 

------------------------------ BEGIN TEST SUITES --------------------------------------

*************************************************************************************** */

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterProducerIdIntegrationTest, 
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

//----------------------- BEGIN TEST PREFERRED ROUTING --------------------------------

// Testing with the following testcase scenario:
// - Primary cluster: 0:h1, 1:h2
// - Support: NF, TFQDN
// - Preferred host: h1
// - Disturbances: None
// - Number of retries: 2
// - Number of preferred host retries: 2
// - Number of reselections: 0
// - Number of last resort reselections: 0
// - Expected sequence: h1
// - Expect Producer Id: False
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdPreferred1) {
  bool is_sepp_node = false;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"chf1","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"chf2","","",""}, "1", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary};

  std::string preferred_host = "chf1.ericsson.se:443";
  std::vector<uint64_t> retry_params{2, 2, 0, 0};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary}};
  bool expect_producer_id = false;

  testProducerIdPreferred(is_sepp_node, primary_cluster, primary_hosts, preferred_host,
  retry_params, producer_list, expected_list, expect_producer_id);
}

// Testing with the following testcase scenario:
// - Primary cluster: 0:h1, 1:h2
// - Support: NF, TFQDN
// - Preferred host: h1
// - Disturbances: h1
// - Number of retries: 2
// - Number of preferred host retries: 1
// - Number of reselections: 1
// - Number of last resort reselections: 0
// - Expected sequence: h1, h1, h2
// - Expect Producer Id: True
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdPreferred2) {
  bool is_sepp_node = false;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"chf1","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"chf2","","",""}, "1", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary};

  std::string preferred_host = "chf1.ericsson.se:443";
  std::vector<uint64_t> retry_params{2, 1, 1, 0};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary}, {&h1_primary}, {&h2_primary}};
  bool expect_producer_id = true;

  testProducerIdPreferred(is_sepp_node, primary_cluster, primary_hosts, preferred_host,
  retry_params, producer_list, expected_list, expect_producer_id);
}

// Testing with the following testcase scenario:
// - Primary cluster: 0:h1, 1:h2
// - Support: NF, TFQDN
// - Preferred host: h2
// - Disturbances: h2
// - Number of retries: 2
// - Number of preferred host retries: 1
// - Number of reselections: 1
// - Number of last resort reselections: 0
// - Expected sequence: h2, h2, h1
// - Expect Producer Id: True
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdPreferred3) {
  bool is_sepp_node = false;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"chf1","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"chf2","","",""}, "1", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary};

  std::string preferred_host = "chf2.ericsson.se:443";
  std::vector<uint64_t> retry_params{2, 1, 1, 0};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h2_primary}, {&h2_primary}, {&h1_primary}};
  bool expect_producer_id = true;

  testProducerIdPreferred(is_sepp_node, primary_cluster, primary_hosts, preferred_host,
  retry_params, producer_list, expected_list, expect_producer_id);
}

// Testing with the following testcase scenario:
// - Primary cluster: 0:h1, 1:h2
// - Last Resort cluster: 0:h7
// - Aggregate cluster: 0:h1, 1:h2, 2:h7
// - Support: NF, TFQDN
// - Preferred host: h1
// - Disturbances: h1, h2
// - Number of retries: 3
// - Number of preferred host retries: 1
// - Number of reselections: 1
// - Number of last resort reselections: 1
// - Expected sequence: h1, h1, h2, h7
// - Expect Producer Id: True
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdPreferred4) {
  bool is_sepp_node = false;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"chf1","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"chf2","","",""}, "1", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary};

  std::string last_resort_cluster = "chf_lr_pool";
  struct EpDefinition h7_last_resort = {"chf7.ericsson.se:443", {"chf7","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> last_resort_hosts = {&h7_last_resort};

  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::string preferred_host = "chf1.ericsson.se:443";
  std::vector<uint64_t> retry_params{3, 1, 1, 1};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary, &h7_last_resort};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary}, {&h1_primary}, {&h2_primary}, {&h7_last_resort}};
  bool expect_producer_id = true;

  testProducerIdPreferred(is_sepp_node, primary_cluster, primary_hosts, preferred_host, retry_params, producer_list,
  expected_list, expect_producer_id, last_resort_cluster, last_resort_hosts, aggregate_cluster);
}

// Testing with the following testcase scenario:
// - Primary cluster: 0:h1, 1:(h2, h3)
// - Last Resort cluster: 0:h7
// - Aggregate cluster: 0:h1, 1:(h2, h3), 2:h7
// - Support: NF, TFQDN
// - Preferred host: h1
// - Disturbances: h1, h2, h3
// - Number of retries: 4
// - Number of preferred host retries: 1
// - Number of reselections: 2
// - Number of last resort reselections: 1
// - Expected sequence: h1, h1, h2/h3, h3/h2, h7
// - Expect Producer Id: True
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdPreferred5) {
  bool is_sepp_node = false;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"chf1","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"chf2","","",""}, "1", {"NF", "TFQDN"}};
  struct EpDefinition h3_primary = {"chf3.ericsson.se:443", {"chf3","","",""}, "1", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary, &h3_primary};

  std::string last_resort_cluster = "chf_lr_pool";
  struct EpDefinition h7_last_resort = {"chf7.ericsson.se:443", {"chf7","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> last_resort_hosts = {&h7_last_resort};

  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::string preferred_host = "chf1.ericsson.se:443";
  std::vector<uint64_t> retry_params{4, 1, 2, 1};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary, &h3_primary, &h7_last_resort};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary}, {&h1_primary}, {&h2_primary, &h3_primary},
                                                           {&h3_primary, &h2_primary}, {&h7_last_resort}};
  bool expect_producer_id = true;

  testProducerIdPreferred(is_sepp_node, primary_cluster, primary_hosts, preferred_host, retry_params, producer_list,
  expected_list, expect_producer_id, last_resort_cluster, last_resort_hosts, aggregate_cluster);
}

// Testing with the following testcase scenario:
// - SCP Node in Last Resort Pool
// - Primary cluster: 0:h1, 1:(h2, h3)
// - Last Resort cluster: 0:h7
// - Aggregate cluster: 0:h1, 1:(h2, h3), 2:h7
// - Support: NF, TFQDN (Last Resort SCP Support: Indirect)
// - Preferred host: h1
// - Disturbances: h1, h2, h3
// - Number of retries: 4
// - Number of preferred host retries: 1
// - Number of reselections: 2
// - Number of last resort reselections: 1
// - Expected sequence: h1, h1, h2/h3, h3/h2, h7
// - Expect Producer Id: False
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdPreferred6) {
  bool is_sepp_node = false;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"chf1","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"chf2","","",""}, "1", {"NF", "TFQDN"}};
  struct EpDefinition h3_primary = {"chf3.ericsson.se:443", {"chf3","","",""}, "1", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary, &h3_primary};

  std::string last_resort_cluster = "scp_lr_pool";
  struct EpDefinition h7_last_resort = {"scp.ericsson.se:443", {"scp7","","",""}, "0", {"Indirect"}};
  std::vector<EpDefinition*> last_resort_hosts = {&h7_last_resort};

  std::string aggregate_cluster = "chf_pool#!_#LRP:scp_lr_pool#!_#aggr:";

  std::string preferred_host = "chf1.ericsson.se:443";
  std::vector<uint64_t> retry_params{4, 1, 2, 1};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary, &h3_primary, &h7_last_resort};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary}, {&h1_primary}, {&h2_primary, &h3_primary},
                                                           {&h3_primary, &h2_primary}, {&h7_last_resort}};
  bool expect_producer_id = false;

  testProducerIdPreferred(is_sepp_node, primary_cluster, primary_hosts, preferred_host, retry_params, producer_list,
  expected_list, expect_producer_id, last_resort_cluster, last_resort_hosts, aggregate_cluster);
}

// Testing with the following testcase scenario:
// - No NF instance id metadata provided
// - Primary cluster: 0:h1, 1:(h2, h3)
// - Last Resort cluster: 0:h7
// - Aggregate cluster: 0:h1, 1:(h2, h3), 2:h7
// - Support: NF, TFQDN
// - Preferred host: h1
// - Disturbances: h1, h2, h3
// - Number of retries: 4
// - Number of preferred host retries: 1
// - Number of reselections: 2
// - Number of last resort reselections: 1
// - Expected sequence: h1, h1, h2/h3, h3/h2, h7
// - Expect Producer Id: False
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdPreferred7) {
  bool is_sepp_node = false;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"","","",""}, "1", {"NF", "TFQDN"}};
  struct EpDefinition h3_primary = {"chf3.ericsson.se:443", {"","","",""}, "1", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary, &h3_primary};

  std::string last_resort_cluster = "chf_lr_pool";
  struct EpDefinition h7_last_resort = {"chf7.ericsson.se:443", {"","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> last_resort_hosts = {&h7_last_resort};

  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::string preferred_host = "chf1.ericsson.se:443";
  std::vector<uint64_t> retry_params{4, 1, 2, 1};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary, &h3_primary, &h7_last_resort};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary}, {&h1_primary}, {&h2_primary, &h3_primary},
                                                           {&h3_primary, &h2_primary}, {&h7_last_resort}};
  bool expect_producer_id = false;

  testProducerIdPreferred(is_sepp_node, primary_cluster, primary_hosts, preferred_host, retry_params, producer_list,
  expected_list, expect_producer_id, last_resort_cluster, last_resort_hosts, aggregate_cluster);
}

// Testing with the following testcase scenario:
// - SEPP Node
// - Primary cluster: 0:h1, 1:(h2, h3)
// - Last Resort cluster: 0:h7
// - Aggregate cluster: 0:h1, 1:(h2, h3), 2:h7
// - Support: NF, TFQDN
// - Preferred host: h1
// - Disturbances: h1, h2, h3
// - Number of retries: 4
// - Number of preferred host retries: 1
// - Number of reselections: 2
// - Number of last resort reselections: 1
// - Expected sequence: h1, h1, h2/h3, h3/h2, h7
// - Expect Producer Id: False
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdPreferred8) {
  bool is_sepp_node = true;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"chf1","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"chf2","","",""}, "1", {"NF", "TFQDN"}};
  struct EpDefinition h3_primary = {"chf3.ericsson.se:443", {"chf3","","",""}, "1", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary, &h3_primary};

  std::string last_resort_cluster = "chf_lr_pool";
  struct EpDefinition h7_last_resort = {"chf7.ericsson.se:443", {"chf7","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> last_resort_hosts = {&h7_last_resort};

  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::string preferred_host = "chf1.ericsson.se:443";
  std::vector<uint64_t> retry_params{4, 1, 2, 1};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary, &h3_primary, &h7_last_resort};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary}, {&h1_primary}, {&h2_primary, &h3_primary},
                                                           {&h3_primary, &h2_primary}, {&h7_last_resort}};
  bool expect_producer_id = false;

  testProducerIdPreferred(is_sepp_node, primary_cluster, primary_hosts, preferred_host, retry_params, producer_list,
  expected_list, expect_producer_id, last_resort_cluster, last_resort_hosts, aggregate_cluster);
}

//------------------------ END TEST PREFERRED ROUTING ---------------------------------

//---------------------- BEGIN TEST ROUND-ROBIN ROUTING -------------------------------

// Testing with the following testcase scenario:
// - Primary cluster: 0:(h1, h2)
// - Support: NF, TFQDN
// - Disturbances: None
// - Number of retries: 1
// - Number of preferred host retries: 0
// - Number of reselections: 1
// - Number of last resort reselections: 0
// - Expected sequence: h1/h2
// - Expect Producer Id: True
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdRoundRobin1) {
  bool is_sepp_node = false;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"chf1","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"chf2","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary};

  std::vector<uint64_t> retry_params{1, 0, 1, 0};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary, &h2_primary}};
  bool expect_producer_id = true;

  testProducerIdRoundRobin(is_sepp_node, primary_cluster, primary_hosts,
  retry_params, producer_list, expected_list, expect_producer_id);
}

// Testing with the following testcase scenario:
// - Primary cluster: 0:(h1, h2)
// - Last Resort cluster: 0:h7
// - Aggregate cluster: 0:(h1, h2), 1:h7
// - Support: NF, TFQDN
// - Disturbances: h1, h2
// - Number of retries: 2
// - Number of preferred host retries: 0
// - Number of reselections: 1
// - Number of last resort reselections: 1
// - Expected sequence: h1/h2, h2/h1, h7
// - Expect Producer Id: True
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdRoundRobin2) {
  bool is_sepp_node = false;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"chf1","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"chf2","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary};

  std::string last_resort_cluster = "chf_lr_pool";
  struct EpDefinition h7_last_resort = {"chf7.ericsson.se:443", {"chf7","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> last_resort_hosts = {&h7_last_resort};

  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::vector<uint64_t> retry_params{2, 0, 1, 1};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary, &h7_last_resort};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary, &h2_primary}, {&h2_primary, &h1_primary}, {&h7_last_resort}};
  bool expect_producer_id = true;

  testProducerIdRoundRobin(is_sepp_node, primary_cluster, primary_hosts, retry_params, producer_list,
  expected_list, expect_producer_id, last_resort_cluster, last_resort_hosts, aggregate_cluster);
}

// Testing with the following testcase scenario:
// - SCP Node in Last Resort Pool
// - Primary cluster: 0:(h1, h2)
// - Last Resort cluster: 0:h7
// - Aggregate cluster: 0:(h1, h2), 1:h7
// - Support: NF, TFQDN (Last Resort SCP Support: Indirect)
// - Disturbances: h1, h2
// - Number of retries: 2
// - Number of preferred host retries: 0
// - Number of reselections: 1
// - Number of last resort reselections: 1
// - Expected sequence: h1/h2, h2/h1, h7
// - Expect Producer Id: False
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdRoundRobin3) {
  bool is_sepp_node = false;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"chf1","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"chf2","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary};

  std::string last_resort_cluster = "scp_lr_pool";
  struct EpDefinition h7_last_resort = {"scp.ericsson.se:443", {"scp7","","",""}, "0", {"Indirect"}};
  std::vector<EpDefinition*> last_resort_hosts = {&h7_last_resort};

  std::string aggregate_cluster = "chf_pool#!_#LRP:scp_lr_pool#!_#aggr:";

  std::vector<uint64_t> retry_params{2, 0, 1, 1};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary, &h7_last_resort};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary, &h2_primary}, {&h2_primary, &h1_primary}, {&h7_last_resort}};
  bool expect_producer_id = false;

  testProducerIdRoundRobin(is_sepp_node, primary_cluster, primary_hosts, retry_params, producer_list,
  expected_list, expect_producer_id, last_resort_cluster, last_resort_hosts, aggregate_cluster);
}

// Testing with the following testcase scenario:
// - No NF instance id metadata provided
// - Primary cluster: 0:(h1, h2)
// - Last Resort cluster: 0:h7
// - Aggregate cluster: 0:(h1, h2), 1:h7
// - Support: NF, TFQDN
// - Disturbances: h1, h2
// - Number of retries: 2
// - Number of preferred host retries: 0
// - Number of reselections: 1
// - Number of last resort reselections: 1
// - Expected sequence: h1/h2, h2/h1, h7
// - Expect Producer Id: False
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdRoundRobin4) {
  bool is_sepp_node = false;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary};

  std::string last_resort_cluster = "chf_lr_pool";
  struct EpDefinition h7_last_resort = {"chf7.ericsson.se:443", {"","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> last_resort_hosts = {&h7_last_resort};

  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::vector<uint64_t> retry_params{2, 0, 1, 1};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary, &h7_last_resort};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary, &h2_primary}, {&h2_primary, &h1_primary}, {&h7_last_resort}};
  bool expect_producer_id = false;

  testProducerIdRoundRobin(is_sepp_node, primary_cluster, primary_hosts, retry_params, producer_list,
  expected_list, expect_producer_id, last_resort_cluster, last_resort_hosts, aggregate_cluster);
}

// Testing with the following testcase scenario:
// - SEPP Node
// - Primary cluster: 0:(h1, h2)
// - Last Resort cluster: 0:h7
// - Aggregate cluster: 0:(h1, h2), 1:h7
// - Support: NF, TFQDN
// - Disturbances: h1, h2
// - Number of retries: 2
// - Number of preferred host retries: 0
// - Number of reselections: 1
// - Number of last resort reselections: 1
// - Expected sequence: h1/h2, h2/h1, h7
// - Expect Producer Id: False
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdRoundRobin5) {
  bool is_sepp_node = true;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"chf1","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"chf2","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary};

  std::string last_resort_cluster = "chf_lr_pool";
  struct EpDefinition h7_last_resort = {"chf7.ericsson.se:443", {"chf7","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> last_resort_hosts = {&h7_last_resort};

  std::string aggregate_cluster = "chf_pool#!_#LRP:chf_lr_pool#!_#aggr:";

  std::vector<uint64_t> retry_params{2, 0, 1, 1};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary, &h7_last_resort};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary, &h2_primary}, {&h2_primary, &h1_primary}, {&h7_last_resort}};
  bool expect_producer_id = false;

  testProducerIdRoundRobin(is_sepp_node, primary_cluster, primary_hosts, retry_params, producer_list,
  expected_list, expect_producer_id, last_resort_cluster, last_resort_hosts, aggregate_cluster);
}

//----------------------- END TEST ROUND-ROBIN ROUTING --------------------------------

//------------------------- BEGIN TEST STRICT ROUTING ---------------------------------

// Testing with the following testcase scenario:
// - Primary cluster: 0:(h1, h2)
// - Support: NF, TFQDN
// - Preferred host: h1
// - Disturbances: None
// - Number of retries: 1
// - Number of preferred host retries: 1
// - Number of reselections: 0
// - Number of last resort reselections: 0
// - Expected sequence: h1
// - Expect Producer Id: False
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdStrict1) {
  bool is_sepp_node = false;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"chf1","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"chf2","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary};

  std::string preferred_host = "chf1.ericsson.se:443";
  std::vector<uint64_t> retry_params{1, 1, 0, 0};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary}};
  bool expect_producer_id = false;

  testProducerIdStrict(is_sepp_node, primary_cluster, primary_hosts, preferred_host,
  retry_params, producer_list, expected_list, expect_producer_id);
}

// Testing with the following testcase scenario:
// - Primary cluster: 0:(h1, h2)
// - Support: NF, TFQDN
// - Preferred host: h1
// - Disturbances: h1 (only first time)
// - Number of retries: 1
// - Number of preferred host retries: 1
// - Number of reselections: 0
// - Number of last resort reselections: 0
// - Expected sequence: h1, h1
// - Expect Producer Id: False
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdStrict2) {
  bool is_sepp_node = false;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"chf1","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"chf2","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary};

  std::string preferred_host = "chf1.ericsson.se:443";
  std::vector<uint64_t> retry_params{1, 1, 0, 0};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary}, {&h1_primary}};
  bool expect_producer_id = false;

  testProducerIdStrict(is_sepp_node, primary_cluster, primary_hosts, preferred_host,
  retry_params, producer_list, expected_list, expect_producer_id);
}

// Testing with the following testcase scenario:
// - No NF instance id metadata provided
// - Primary cluster: 0:(h1, h2)
// - Support: NF, TFQDN
// - Preferred host: h1
// - Disturbances: h1 (only first time)
// - Number of retries: 1
// - Number of preferred host retries: 1
// - Number of reselections: 0
// - Number of last resort reselections: 0
// - Expected sequence: h1, h1
// - Expect Producer Id: False
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdStrict3) {
  bool is_sepp_node = false;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary};

  std::string preferred_host = "chf1.ericsson.se:443";
  std::vector<uint64_t> retry_params{1, 1, 0, 0};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary}, {&h1_primary}};
  bool expect_producer_id = false;

  testProducerIdStrict(is_sepp_node, primary_cluster, primary_hosts, preferred_host,
  retry_params, producer_list, expected_list, expect_producer_id);
}

// Testing with the following testcase scenario:
// - SEPP Node
// - Primary cluster: 0:(h1, h2)
// - Support: NF, TFQDN
// - Preferred host: h1
// - Disturbances: h1 (only first time)
// - Number of retries: 1
// - Number of preferred host retries: 1
// - Number of reselections: 0
// - Number of last resort reselections: 0
// - Expected sequence: h1, h1
// - Expect Producer Id: False
TEST_P(EricProxyFilterProducerIdIntegrationTest, TestProducerIdStrict4) {  
  bool is_sepp_node = true;

  std::string primary_cluster = "chf_pool";
  struct EpDefinition h1_primary = {"chf1.ericsson.se:443", {"chf1","","",""}, "0", {"NF", "TFQDN"}};
  struct EpDefinition h2_primary = {"chf2.ericsson.se:443", {"chf2","","",""}, "0", {"NF", "TFQDN"}};
  std::vector<EpDefinition*> primary_hosts = {&h1_primary, &h2_primary};

  std::string preferred_host = "chf1.ericsson.se:443";
  std::vector<uint64_t> retry_params{1, 1, 0, 0};

  std::vector<EpDefinition*> producer_list = {&h1_primary, &h2_primary};
  // The expected sequence list contains an inner list for the non-deterministic sequence
  std::vector<std::vector<EpDefinition*>> expected_list = {{&h1_primary}, {&h1_primary}};
  bool expect_producer_id = false;

  testProducerIdStrict(is_sepp_node, primary_cluster, primary_hosts, preferred_host,
  retry_params, producer_list, expected_list, expect_producer_id);
}

//-------------------------- END TEST STRICT ROUTING ----------------------------------

/************************************************************************************** 

--------------------------------- END TEST SUITES -------------------------------------

*************************************************************************************** */

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
