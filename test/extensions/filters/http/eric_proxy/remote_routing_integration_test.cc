#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"
#include <ostream>
#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterRemoteRoutingIntegrationTest : public HttpIntegrationTest,
                                          public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterRemoteRoutingIntegrationTest() : HttpIntegrationTest(
    Http::CodecClient::Type::HTTP1, GetParam(),
    EricProxyFilterRemoteRoutingIntegrationTest::ericProxyHttpBaseConfig()
  ) {}

  void SetUp() override {}

  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);
    setUpstreamCount(4);
    HttpIntegrationTest::initialize();
  }

  FakeHttpConnectionPtr fake_nlf_connection_;

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
          stat_prefix: ingress.n8e.West1.g3p.ingress
          delayed_close_timeout:
            nanos: 100
          http_filters:
            name: envoy.filters.http.router
          codec_type: HTTP1
)EOF");
  }

  // NLF cluster configuration
  std::string configNlfCluster() {
    return fmt::format(R"EOF(
name: nlf_pool
connect_timeout: 15s
load_assignment:
  cluster_name: nlf_pool
  endpoints:
  - lb_endpoints:
    - endpoint:
        address:
          socket_address:
            address: {}
            port_value: 0
        hostname: nlf1.ericsson.se:443
      metadata:
        filter_metadata:
          envoy.lb:
            host: nlf1.ericsson.se:443
          envoy.eric_proxy:
            support:
            - NF
)EOF", Network::Test::getLoopbackAddressString(GetParam()));
  }

  // Proxy cluster configuration
  std::string configProxyCluster(const std::string& proxy) {
    return fmt::format(R"EOF(
name: {0}_pool
connect_timeout: 15s
load_assignment:
  cluster_name: {0}_pool
  endpoints:
  - lb_endpoints:
    - endpoint:
        address:
          socket_address:
            address: {1}
            port_value: 0
        hostname: {0}1.ericsson.se:443
      metadata:
        filter_metadata:
          envoy.lb:
            host: {0}1.ericsson.se:443
          envoy.eric_proxy:
            support:
            - Indirect
    - endpoint:
        address:
          socket_address:
            address: {1}
            port_value: 0
        hostname: {0}2.ericsson.se:443
      metadata:
        filter_metadata:
          envoy.lb:
            host: {0}2.ericsson.se:443
          envoy.eric_proxy:
            support:
            - Indirect
  - lb_endpoints:
    - endpoint:
        address:
          socket_address:
            address: {1}
            port_value: 0
        hostname: {0}3.ericsson.se:443
      metadata:
        filter_metadata:
          envoy.lb:
            host: {0}3.ericsson.se:443
          envoy.eric_proxy:
            support:
            - Indirect
    priority: 1
)EOF", proxy, Network::Test::getLoopbackAddressString(GetParam()));
  }

  // Route configuration
  std::string configRoute(const std::string& proxy, const int& num_retries) {
    return fmt::format(R"EOF(
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
            exact: {0}_pool
    route:
      cluster: {0}_pool
      retry_policy:
        retry_on: retriable-status-codes
        retriable_status_codes:
        - 500
        - 501
        - 502
        - 503
        num_retries: {1}
)EOF", proxy, num_retries);
  }

  // Basic configuration for eric proxy filter
  const std::string config_basic = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp_router
  node_type: SCP
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
      - name: remote_preferred_route
        condition:
          op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
        actions:
        - action_nf_discovery:
            cluster_name: nlf_pool
            timeout: 1000
            nrf_group_name: nrf_group
            use_all_parameters: true
            ip_version: IPv4
        - action_route_to_pool:
            pool_name:
              term_string: sepp_pool
            routing_behaviour: REMOTE_PREFERRED
            remote_retries: 1
            remote_reselections: 2
            preserve_disc_params_if_indirect:
              preserve_all: true
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: remote_round_robin_route
        condition:
          term_boolean: true
        actions:
        - action_nf_discovery:
            cluster_name: nlf_pool
            timeout: 1000
            nrf_group_name: nrf_group
            use_all_parameters: true
            ip_version: IPv4
        - action_route_to_pool:
            pool_name:
              term_string: sepp_pool
            routing_behaviour: REMOTE_ROUND_ROBIN
            remote_reselections: 3
            preserve_disc_params_if_indirect:
              preserve_all: true
)EOF";

  // DND-47325: Configuration for eric proxy filter
  // where list of TaRs generated for remote routing
  // depends on the nf_selection_on_priority result. 
  const std::string config_DND47325 = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp_router
  node_type: SCP
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
      - name: nf_discovery
        condition:
          term_boolean: true
        actions:
        - action_nf_discovery:
            cluster_name: nlf_pool
            timeout: 1000
            nrf_group_name: nrf_group
            use_all_parameters: true
            nf_selection_on_priority:
              var_name_preferred_host: pref
              var_name_nf_set: nfset
            ip_version: IPv4
      - name: remote_preferred_route
        condition:
          op_and:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
            arg2:
              op_equals:
                typed_config1:
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_var: nfset
                typed_config2:
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_string: 'scp_set'
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: scp_pool
            routing_behaviour: REMOTE_PREFERRED
            remote_retries: 1
            remote_reselections: 2
            preserve_disc_params_if_indirect:
              preserve_all: true
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: remote_round_robin_route
        condition:
          op_equals:
            typed_config1:
              '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
              term_var: nfset
            typed_config2:
              '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
              term_string: 'scp_set'
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: scp_pool
            routing_behaviour: REMOTE_ROUND_ROBIN
            remote_reselections: 3
            preserve_disc_params_if_indirect:
              preserve_all: true
)EOF";

  // NLF lookup result
  std::string nlf_lookup_result {R"(
{
  "validityPeriod": 60,
  "nfInstances": [
    {
      "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
      "nfInstanceName": "nfInstanceName_1",
      "nfType": "AUSF",
      "fqdn": "fqdn1.example.com",
      "priority": 1,
      "capacity": 60000,
      "nfSetIdList": ["setA"],
      "nfServices": [
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce100",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "fqdn11.example.com",
          "apiPrefix":"/one/example/com",
          "priority": 1,
          "capacity": 60000,
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9091
            }
          ]
        },
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce101",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "fqdn12.example.com",
          "apiPrefix":"/two/example/com",
          "priority": 2,
          "capacity": 60000,
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9092
            }
          ]
        }
      ]
    },
    {
      "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce101",
      "nfInstanceName": "nfInstanceName_2",
      "nfType": "AUSF",
      "fqdn": "fqdn2.example.com",
      "priority": 1,
      "capacity": 60000,
      "nfSetIdList": ["setB"],
      "nfServices": [
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce102",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "apiPrefix":"/three/example/com",
          "fqdn": "fqdn21.example.com",
          "priority": 3,
          "capacity": 60000,
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9093
            }
          ]
        },
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce103",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "fqdn22.example.com",
          "apiPrefix":"/four/example/com",
          "priority": 4,
          "capacity": 60000,
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9094
            },
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9095
            }
          ]
        }
      ]
    }
  ],
  "searchId": null,
  "numNfInstComplete": null,
  "preferredSearch": null,
  "nrfSupportedFeatures": "nausf-auth"
}
)"};

  // NLF lookup result for DND-52529: only a single nfInstance found that is
  // the same as the received TaR header
  std::string nlf_lookup_result_dnd52529 {R"(
{
  "validityPeriod": 60,
  "nfInstances": [
    {
      "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
      "nfInstanceName": "nfInstanceName_1",
      "nfType": "AUSF",
      "fqdn": "fqdn1.example.com",
      "priority": 1,
      "capacity": 60000,
      "nfSetIdList": ["setA"],
      "nfServices": [
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce100",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "fqdn11.example.com",
          "priority": 1,
          "capacity": 60000,
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9091
            }
          ]
        }
      ]
    }
  ],
  "searchId": null,
  "numNfInstComplete": null,
  "preferredSearch": null,
  "nrfSupportedFeatures": "nausf-auth"
}
)"};

  // Add new cluster configurations from yaml and modify the existing configuration
  void addClusterConfigsFromYaml(const std::vector<std::string>& config_clusters) {
    for (const auto& config_cluster : config_clusters) {
      config_helper_.addConfigModifier(
        [config_cluster](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
            TestUtility::loadFromYaml(config_cluster, *bootstrap.mutable_static_resources()->add_clusters());
        }
      );
    }
  }

  // Add new route configuration from yaml and modify the existing configuration
  void addRouteConfigFromYaml(const std::string& config_route) {
    config_helper_.addConfigModifier(
      [config_route](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager& hcm) {
          TestUtility::loadFromYaml(config_route, *hcm.mutable_route_config());
      }
    );
  }

  // Fake NLF Functionality: Send a response from "NLF" to Envoy with the supplied
  // status code and body. Return the stream.
  FakeStreamPtr sendNlfResponse(const std::string& status, const std::string& body) {
    ENVOY_LOG(trace, "sendNlfResponse()");

    if (!fake_nlf_connection_) {
      AssertionResult result =
        fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_nlf_connection_);
      RELEASE_ASSERT(result, result.message());
    }

    FakeStreamPtr request_stream;
    AssertionResult result = fake_nlf_connection_->waitForNewStream(*dispatcher_, request_stream);
    RELEASE_ASSERT(result, result.message());
    result = request_stream->waitForEndStream(*dispatcher_);
    RELEASE_ASSERT(result, result.message());

    if (body.empty()) {
      request_stream->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", status}}, true);
    } else {
      request_stream->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", status}}, false);
      Buffer::OwnedImpl responseBuffer(body);
      request_stream->encodeData(responseBuffer, true);
    }

    return request_stream;
  }

  bool isExpectedTar(const absl::string_view& current_tar, const std::vector<std::string>& expected_tars) {
    for (const auto& tar : expected_tars) {
      if (current_tar == tar) {
        return true;
      }
    }
    return false;
  }

  void testRemoteRoundRobin(
    const std::string& proxy,
    const std::string& config,
    const uint32_t& num_reselections,
    const std::string& nlf_lookup_result,
    const std::vector<std::pair<uint32_t, std::vector<std::string>>>& expected_tar_levels
  ) {
    addClusterConfigsFromYaml(std::vector{configNlfCluster(), configProxyCluster(proxy)});
    addRouteConfigFromYaml(configRoute(proxy, num_reselections));
    initializeFilter(config);

    Http::TestRequestHeaderMapImpl request_headers{
        {":method", "GET"},
        {":path", "/"},
        {":authority", "host"},
        {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
        {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
        {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
        {"3gpp-sbi-discovery-target-plmn-list", R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
        {"3gpp-sbi-correlation-info", "imsi-345012123123123"}
    };

    // Expected path towards NLF
    std::string expected_nnlf_path = "/nnlf-disc/v0/nf-instances/scp?target-nf-type=AUSF&requester-nf-type=SMF&service-names=nausf-auth&target-plmn-list=%5B%7B%22mcc%22%3A%22123%22%2C%22mnc%22%3A%22456%22%7D%2C%7B%22mcc%22%3A%22234%22%2C%22mnc%22%3A%22567%22%7D%5D&";
    
    // Expected headers towards NLF
    std::map<std::string, std::string> expected_nlf_headers = {{":path", expected_nnlf_path},
                                                              {"nrf-group", "nrf_group"},
                                                              {"3gpp-sbi-correlation-info", "imsi-345012123123123"}};

    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(request_headers);

    FakeStreamPtr nlf_request_stream = sendNlfResponse("200", nlf_lookup_result);
    ASSERT_TRUE(nlf_request_stream->waitForEndStream(*dispatcher_));
    ASSERT_TRUE(fake_nlf_connection_->close());

    // Validate that all expected headers towards NLF are present and have the correct value:
    for (std::map<std::string, std::string>::const_iterator it = expected_nlf_headers.begin();
        it != expected_nlf_headers.end(); ++it) {
      std::string header_name = it->first;
      EXPECT_THAT(nlf_request_stream->headers(), Http::HeaderValueOf(it->first, it->second));
    }

    for (uint32_t level_idx = 0; level_idx < expected_tar_levels.size(); level_idx++) {
      uint32_t num_attempts = expected_tar_levels.at(level_idx).first;
      if (level_idx == expected_tar_levels.size() - 1) {
        num_attempts = expected_tar_levels.at(level_idx).first - 1;
      }
      for (uint32_t idx = 0; idx < num_attempts; idx++) {
        auto upstream_index = waitForNextUpstreamRequest({1, 2, 3});

        // Send fake 500 status upstream response
        upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "500"}}, false);

        ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
        ASSERT_TRUE(fake_upstream_connection_->close());
        ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
        fake_upstream_connection_.reset();

        // Verify upstream request
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", absl::StrCat(proxy, "_pool")));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-sbi-discovery-target-nf-type", "AUSF"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-sbi-discovery-target-plmn-list", R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-sbi-correlation-info", "imsi-345012123123123"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", absl::StrCat(proxy, std::to_string(upstream_index.value() + 1), ".ericsson.se:443")));
        auto tar_header = upstream_request_->headers().get(Http::LowerCaseString("3gpp-sbi-target-apiroot"));
        ASSERT_TRUE(!tar_header.empty());
        ASSERT_TRUE(isExpectedTar(tar_header[0]->value().getStringView(), expected_tar_levels.at(level_idx).second));
      }
    }

    auto upstream_index = waitForNextUpstreamRequest({1, 2, 3});

    // Send fake 500 status upstream response
    upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "500"}}, true);

    // Wait for the response and close the fake upstream connection
    ASSERT_TRUE(response->waitForEndStream());
    ASSERT_TRUE(fake_upstream_connection_->close());

    // Verify upstream request
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", absl::StrCat(proxy, "_pool")));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-sbi-discovery-target-nf-type", "AUSF"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-sbi-discovery-target-plmn-list", R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-sbi-correlation-info", "imsi-345012123123123"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", absl::StrCat(proxy, std::to_string(upstream_index.value() + 1), ".ericsson.se:443")));
    auto tar_header = upstream_request_->headers().get(Http::LowerCaseString("3gpp-sbi-target-apiroot"));
    ASSERT_TRUE(!tar_header.empty());
    ASSERT_TRUE(isExpectedTar(tar_header[0]->value().getStringView(), expected_tar_levels.back().second));

    // Verify downstream response
    EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "500"));

    codec_client_->close();
  }

  void testRemotePreferred(
    const std::string& proxy,
    const std::string& config,
    const uint32_t& num_retries,
    const uint32_t& num_reselections,
    const std::string& nlf_lookup_result,
    const std::vector<std::pair<uint32_t, std::vector<std::string>>>& expected_tar_levels
  ) {
    addClusterConfigsFromYaml(std::vector{configNlfCluster(), configProxyCluster(proxy)});
    addRouteConfigFromYaml(configRoute(proxy, num_retries + num_reselections));
    initializeFilter(config);

    Http::TestRequestHeaderMapImpl request_headers{
        {":method", "GET"},
        {":path", "/"},
        {":authority", "host"},
        {"3gpp-Sbi-target-apiRoot", expected_tar_levels.front().second.front()},
        {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
        {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
        {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
        {"3gpp-sbi-discovery-target-plmn-list", R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
        {"3gpp-sbi-correlation-info", "imsi-345012123123123"}
    };

    // Expected path towards NLF
    std::string expected_nnlf_path = "/nnlf-disc/v0/nf-instances/scp?target-nf-type=AUSF&requester-nf-type=SMF&service-names=nausf-auth&target-plmn-list=%5B%7B%22mcc%22%3A%22123%22%2C%22mnc%22%3A%22456%22%7D%2C%7B%22mcc%22%3A%22234%22%2C%22mnc%22%3A%22567%22%7D%5D&";
    
    // Expected headers towards NLF
    std::map<std::string, std::string> expected_nlf_headers = {{":path", expected_nnlf_path},
                                                              {"nrf-group", "nrf_group"},
                                                              {"3gpp-sbi-correlation-info", "imsi-345012123123123"}};

    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(request_headers);

    FakeStreamPtr nlf_request_stream = sendNlfResponse("200", nlf_lookup_result);
    ASSERT_TRUE(nlf_request_stream->waitForEndStream(*dispatcher_));
    ASSERT_TRUE(fake_nlf_connection_->close());

    // Validate that all expected headers towards NLF are present and have the correct value:
    for (std::map<std::string, std::string>::const_iterator it = expected_nlf_headers.begin();
        it != expected_nlf_headers.end(); ++it) {
      std::string header_name = it->first;
      EXPECT_THAT(nlf_request_stream->headers(), Http::HeaderValueOf(it->first, it->second));
    }

    for (uint32_t level_idx = 0; level_idx < expected_tar_levels.size(); level_idx++) {
      uint32_t num_attempts = expected_tar_levels.at(level_idx).first;
      if (level_idx == expected_tar_levels.size() - 1) {
        num_attempts = expected_tar_levels.at(level_idx).first - 1;
      }
      for (uint32_t idx = 0; idx < num_attempts; idx++) {
        auto upstream_index = waitForNextUpstreamRequest({1, 2, 3});

        // Send fake 500 status upstream response
        upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "500"}}, false);

        ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
        ASSERT_TRUE(fake_upstream_connection_->close());
        ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
        fake_upstream_connection_.reset();

        // Verify upstream request
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", absl::StrCat(proxy, "_pool")));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-sbi-discovery-target-nf-type", "AUSF"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-sbi-discovery-target-plmn-list", R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-sbi-correlation-info", "imsi-345012123123123"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", absl::StrCat(proxy, std::to_string(upstream_index.value() + 1), ".ericsson.se:443")));
        auto tar_header = upstream_request_->headers().get(Http::LowerCaseString("3gpp-sbi-target-apiroot"));
        ASSERT_TRUE(!tar_header.empty());
        ASSERT_TRUE(isExpectedTar(tar_header[0]->value().getStringView(), expected_tar_levels.at(level_idx).second));
      }
    }

    auto upstream_index = waitForNextUpstreamRequest({1, 2, 3});

    // Send fake 500 status upstream response
    upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "500"}}, true);

    // Wait for the response and close the fake upstream connection
    ASSERT_TRUE(response->waitForEndStream());
    ASSERT_TRUE(fake_upstream_connection_->close());

    // Verify upstream request
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", absl::StrCat(proxy, "_pool")));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-sbi-discovery-target-nf-type", "AUSF"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-sbi-discovery-target-plmn-list", R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-sbi-correlation-info", "imsi-345012123123123"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", absl::StrCat(proxy, std::to_string(upstream_index.value() + 1), ".ericsson.se:443")));
    auto tar_header = upstream_request_->headers().get(Http::LowerCaseString("3gpp-sbi-target-apiroot"));
    ASSERT_TRUE(!tar_header.empty());
    ASSERT_TRUE(isExpectedTar(tar_header[0]->value().getStringView(), expected_tar_levels.back().second));

    // Verify downstream response
    EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "500"));

    codec_client_->close();
  }

};

/************************************************************************************** 

------------------------------ BEGIN TEST SUITES --------------------------------------

*************************************************************************************** */

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterRemoteRoutingIntegrationTest, 
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

//-------------------- BEGIN TEST REMOTE ROUND-ROBIN ROUTING --------------------------

// Testing remote round robin routing where nlf result has 2 different priority levels.
TEST_P(EricProxyFilterRemoteRoutingIntegrationTest, TestRemoteRoundRobin1) {
  // Proxy for remote routing
  const std::string proxy = "sepp";

  // Number of reselections
  const uint32_t num_reselections = 3;

  // Fake NLF lookup result
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const std::string& nlf_lookup_result = json_body.dump();

  // Expected levels of TaRs
  // Each level contains number of attempts at that level and the
  // list of expected TaRs to be attempted
  const std::vector<std::pair<uint32_t, std::vector<std::string>>> expected_tar_levels {
    std::make_pair<uint32_t, std::vector<std::string>>(
      3,
      {
        "https://fqdn12.example.com:9092/two/example/com",
        "https://fqdn22.example.com:9094/four/example/com",
        "https://fqdn22.example.com:9095/four/example/com"
      }
    ),
    std::make_pair<uint32_t, std::vector<std::string>>(
      1,
      {
        "http://fqdn11.example.com:9091/one/example/com",
        "https://fqdn21.example.com:9093/three/example/com"
      }
    )
  };

  testRemoteRoundRobin(proxy, config_basic, num_reselections, nlf_lookup_result, expected_tar_levels);
}

// Testing remote round robin routing where nlf result has 3 different priority levels.
TEST_P(EricProxyFilterRemoteRoutingIntegrationTest, TestRemoteRoundRobin2) {
  // Proxy for remote routing
  const std::string proxy = "sepp";

  // Number of reselections
  const uint32_t num_reselections = 3;

  // Fake NLF lookup result
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 10;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const std::string& nlf_lookup_result = json_body.dump();

  // Expected levels of TaRs
  // Each level contains number of attempts at that level and the
  // list of expected TaRs to be attempted
  const std::vector<std::pair<uint32_t, std::vector<std::string>>> expected_tar_levels {
    std::make_pair<uint32_t, std::vector<std::string>>(
      1,
      {
        "https://fqdn12.example.com:9092/two/example/com"
      }
    ),
    std::make_pair<uint32_t, std::vector<std::string>>(
      2,
      {
        "http://fqdn11.example.com:9091/one/example/com",
        "https://fqdn21.example.com:9093/three/example/com"
      }
    ),
    std::make_pair<uint32_t, std::vector<std::string>>(
      1,
      {
        "https://fqdn22.example.com:9094/four/example/com",
        "https://fqdn22.example.com:9095/four/example/com"
      }
    )
  };

  testRemoteRoundRobin(proxy, config_basic, num_reselections, nlf_lookup_result, expected_tar_levels);
}

// Testing remote round robin routing where nlf result has only 1 priority level.
TEST_P(EricProxyFilterRemoteRoutingIntegrationTest, TestRemoteRoundRobin3) {
  // Proxy for remote routing
  const std::string proxy = "sepp";

  // Number of reselections
  const uint32_t num_reselections = 3;

  // Fake NLF lookup result
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").erase(1);
  const std::string& nlf_lookup_result = json_body.dump();

  // Expected levels of TaRs
  // Each level contains number of attempts at that level and the
  // list of expected TaRs to be attempted
  const std::vector<std::pair<uint32_t, std::vector<std::string>>> expected_tar_levels {
    std::make_pair<uint32_t, std::vector<std::string>>(
      2,
      {
        "http://fqdn11.example.com:9091/one/example/com",
        "https://fqdn12.example.com:9092/two/example/com"
      }
    )
  };

  testRemoteRoundRobin(proxy, config_basic, num_reselections, nlf_lookup_result, expected_tar_levels);
}

// Testing remote round robin routing where nlf result has 2 different priority levels
// and FQDNs are missing from highest priority NF, therefore IP address should be
// present instead of FQDN according to configured NF discovery IP version.
TEST_P(EricProxyFilterRemoteRoutingIntegrationTest, TestRemoteRoundRobin4) {
  // Proxy for remote routing
  const std::string proxy = "sepp";

  // Number of reselections
  const uint32_t num_reselections = 3;

  // Fake NLF lookup result
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const std::string& nlf_lookup_result = json_body.dump();

  // Expected levels of TaRs
  // Each level contains number of attempts at that level and the
  // list of expected TaRs to be attempted
  const std::vector<std::pair<uint32_t, std::vector<std::string>>> expected_tar_levels {
    std::make_pair<uint32_t, std::vector<std::string>>(
      3,
      {
        "https://10.11.12.253:9092/two/example/com",
        "https://fqdn22.example.com:9094/four/example/com",
        "https://fqdn22.example.com:9095/four/example/com"
      }
    ),
    std::make_pair<uint32_t, std::vector<std::string>>(
      1,
      {
        "http://fqdn11.example.com:9091/one/example/com",
        "https://fqdn21.example.com:9093/three/example/com"
      }
    )
  };

  testRemoteRoundRobin(proxy, config_basic, num_reselections, nlf_lookup_result, expected_tar_levels);
}

//-------------------- END TEST REMOTE ROUND-ROBIN ROUTING ----------------------------

//--------------------- BEGIN TEST REMOTE PREFERRED ROUTING ---------------------------

// Testing remote preferred routing where nlf result has 2 different priority levels.
TEST_P(EricProxyFilterRemoteRoutingIntegrationTest, TestRemotePreferred1) {
  // Proxy for remote routing
  const std::string proxy = "sepp";

  // Number of retries
  const uint32_t num_retries = 1;

  // Number of reselections
  const uint32_t num_reselections = 2;

  // Fake NLF lookup result
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const std::string& nlf_lookup_result = json_body.dump();

  // Expected levels of TaRs
  // Each level contains number of attempts at that level and the
  // list of expected TaRs to be attempted
  const std::vector<std::pair<uint32_t, std::vector<std::string>>> expected_tar_levels {
    std::make_pair<uint32_t, std::vector<std::string>>(
      2,
      {
        "https://fqdn22.example.com:9094/four/example/com"
      }
    ),
    std::make_pair<uint32_t, std::vector<std::string>>(
      2,
      {
        "https://fqdn12.example.com:9092/two/example/com",
        "https://fqdn22.example.com:9095/four/example/com"
      }
    )
  };

  testRemotePreferred(proxy, config_basic, num_retries, num_reselections, nlf_lookup_result, expected_tar_levels);
}

// Testing remote preferred routing where nlf result has 3 different priority levels.
TEST_P(EricProxyFilterRemoteRoutingIntegrationTest, TestRemotePreferred2) {
  // Proxy for remote routing
  const std::string proxy = "sepp";

  // Number of retries
  const uint32_t num_retries = 1;

  // Number of reselections
  const uint32_t num_reselections = 2;

  // Fake NLF lookup result
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 10;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const std::string& nlf_lookup_result = json_body.dump();

  // Expected levels of TaRs
  // Each level contains number of attempts at that level and the
  // list of expected TaRs to be attempted
  const std::vector<std::pair<uint32_t, std::vector<std::string>>> expected_tar_levels {
    std::make_pair<uint32_t, std::vector<std::string>>(
      2,
      {
        "https://fqdn22.example.com:9094/four/example/com"
      }
    ),
    std::make_pair<uint32_t, std::vector<std::string>>(
      1,
      {
        "https://fqdn12.example.com:9092/two/example/com"
      }
    ),
    std::make_pair<uint32_t, std::vector<std::string>>(
      1,
      {
        "http://fqdn11.example.com:9091/one/example/com",
        "https://fqdn21.example.com:9093/three/example/com"
      }
    )
  };

  testRemotePreferred(proxy, config_basic, num_retries, num_reselections, nlf_lookup_result, expected_tar_levels);
}

// Testing remote preferred routing where nlf result has only 1 priority level.
TEST_P(EricProxyFilterRemoteRoutingIntegrationTest, TestRemotePreferred3) {
  // Proxy for remote routing
  const std::string proxy = "sepp";

  // Number of retries
  const uint32_t num_retries = 1;

  // Number of reselections
  const uint32_t num_reselections = 2;

  // Fake NLF lookup result
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").erase(1);
  const std::string& nlf_lookup_result = json_body.dump();

  // Expected levels of TaRs
  // Each level contains number of attempts at that level and the
  // list of expected TaRs to be attempted
  const std::vector<std::pair<uint32_t, std::vector<std::string>>> expected_tar_levels {
    std::make_pair<uint32_t, std::vector<std::string>>(
      2,
      {
        "https://fqdn12.example.com:9092/two/example/com"
      }
    ),
    std::make_pair<uint32_t, std::vector<std::string>>(
      1,
      {
        "http://fqdn11.example.com:9091/one/example/com"
      }
    )
  };

  testRemotePreferred(proxy, config_basic, num_retries, num_reselections, nlf_lookup_result, expected_tar_levels);
}

//--------------------- END TEST REMOTE PREFERRED ROUTING -----------------------------

//------------------------------ BEGIN TEST DND-47325 ---------------------------------

// Bug DND-47325: The list of TaRs generated for remote round robin routing
// should depend on the nf_selection_on_priority result.
TEST_P(EricProxyFilterRemoteRoutingIntegrationTest, TestDND47325RemoteRoundRobin) {
  // Proxy for remote routing
  const std::string proxy = "scp";

  // Number of reselections
  const uint32_t num_reselections = 3;

  // Fake NLF lookup result
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfSetIdList").at(0) = "scp_set";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 20000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 20000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 20000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 20000;
  const std::string& nlf_lookup_result = json_body.dump();

  // Expected levels of TaRs
  // Each level contains number of attempts at that level and the
  // list of expected TaRs to be attempted
  const std::vector<std::pair<uint32_t, std::vector<std::string>>> expected_tar_levels {
    std::make_pair<uint32_t, std::vector<std::string>>(
      1,
      {
        "https://fqdn12.example.com:9092/two/example/com"
      }
    ),
    std::make_pair<uint32_t, std::vector<std::string>>(
      1,
      {
        "http://fqdn11.example.com:9091/one/example/com"
      }
    )
  };

  testRemoteRoundRobin(proxy, config_DND47325, num_reselections, nlf_lookup_result, expected_tar_levels);
}

// Bug DND-47325: The list of TaRs generated for remote preferred routing
// should depend on the nf_selection_on_priority result.
TEST_P(EricProxyFilterRemoteRoutingIntegrationTest, TestDND47325RemotePreferred) {
  // Proxy for remote routing
  const std::string proxy = "scp";

  // Number of retries
  const uint32_t num_retries = 1;

  // Number of reselections
  const uint32_t num_reselections = 2;

  // Fake NLF lookup result
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfSetIdList").at(0) = "scp_set";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 20000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 20000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 20000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 20000;
  const std::string& nlf_lookup_result = json_body.dump();

  // Expected levels of TaRs
  // Each level contains number of attempts at that level and the
  // list of expected TaRs to be attempted
  const std::vector<std::pair<uint32_t, std::vector<std::string>>> expected_tar_levels {
    std::make_pair<uint32_t, std::vector<std::string>>(
      2,
      {
        "https://fqdn12.example.com:9092/two/example/com"
      }
    ),
    std::make_pair<uint32_t, std::vector<std::string>>(
      1,
      {
        "http://fqdn11.example.com:9091/one/example/com"
      }
    )
  };

  testRemotePreferred(proxy, config_DND47325, num_retries, num_reselections, nlf_lookup_result, expected_tar_levels);
}

//------------------------------- END TEST DND-47325 ----------------------------------

//------------------- BEGIN TEST DND-52529 REMOTE PREFERRED ROUTING -------------------

// Bug DND-52529: NLF lookup fails if the NRF returns only one NF and
// that NF is the preferred host in a remote preferred-routing scenario.
TEST_P(EricProxyFilterRemoteRoutingIntegrationTest, TestDnd52529) {
  // Proxy for remote routing
  const std::string proxy = "sepp";

  // Number of retries
  const uint32_t num_retries = 1;

  // Number of reselections
  const uint32_t num_reselections = 2;

  // Expected levels of TaRs
  // Each level contains number of attempts at that level and the
  // list of expected TaRs to be attempted
  const std::vector<std::pair<uint32_t, std::vector<std::string>>> expected_tar_levels {
    std::make_pair<uint32_t, std::vector<std::string>>(
      2,
      {
        "https://fqdn11.example.com:9091"
      }
    )
  };

  testRemotePreferred(proxy, config_basic, num_retries, num_reselections,
      nlf_lookup_result_dnd52529, expected_tar_levels);
}

//------------------- END TEST DND-52529 REMOTE PREFERRED ROUTING ---------------------

/**************************************************************************************

--------------------------------- END TEST SUITES -------------------------------------

*************************************************************************************** */

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
