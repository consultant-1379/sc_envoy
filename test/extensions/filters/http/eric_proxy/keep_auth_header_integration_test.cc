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

class EricProxyFilterKeepAuthHeaderIntegrationTest : public HttpIntegrationTest,
                                          public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterKeepAuthHeaderIntegrationTest() : HttpIntegrationTest(
    Http::CodecClient::Type::HTTP1, GetParam(),
    EricProxyFilterKeepAuthHeaderIntegrationTest::ericProxyHttpBaseConfig()
  ) {}

  void SetUp() override {}

  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);
    setUpstreamCount(2);
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
          stat_prefix: ingress.n8e.West1.g3p.ingress
          delayed_close_timeout:
            nanos: 100
          http_filters:
            name: envoy.filters.http.router
          codec_type: HTTP1
)EOF");
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
)EOF", proxy, Network::Test::getLoopbackAddressString(GetParam()));
  }

  // Route configuration
  std::string configRoute(const std::string& proxy) {
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
        num_retries: 1
)EOF", proxy);
  }

  // Basic configuration for scp eric proxy filter
  const std::string config_basic_scp = R"EOF(
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
      filter_data:
      - name: apiRoot_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      filter_rules:
      - name: indirect_routing_using_tar
        condition:
          op_and:
            arg1:
              op_equals:
                typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mnc }
                typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '123' }
            arg2:
              op_equals:
                typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mcc }
                typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '123' }
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: scp_pool
            routing_behaviour: PREFERRED
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: indirect_routing_using_auth
        condition:
          op_and:
            arg1:
              op_equals:
                typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mnc }
                typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '456' }
            arg2:
              op_equals:
                typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mcc }
                typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '456' }
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: scp_pool
            routing_behaviour: PREFERRED
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
            keep_authority_header: true
)EOF";

  // Basic configuration for sepp eric proxy filter
  const std::string config_basic_sepp = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  filter_cases:
    - name: default_routing
      filter_data:
      - name: apiRoot_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      filter_rules:
      - name: rp1_routing_using_tar
        condition:
          op_and:
            arg1:
              op_equals:
                typed_config1:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                  term_var: mnc
                typed_config2:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                  term_string: '123'
            arg2:
              op_equals:
                typed_config1:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                  term_var: mcc
                typed_config2:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                  term_string: '123'
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_1
            routing_behaviour: PREFERRED
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: rp2_routing_using_auth
        condition:
          op_and:
            arg1:
              op_equals:
                typed_config1:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                  term_var: mnc
                typed_config2:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                  term_string: '456'
            arg2:
              op_equals:
                typed_config1:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                  term_var: mcc
                typed_config2:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                  term_string: '456'
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_2
            routing_behaviour: PREFERRED
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
            keep_authority_header: true
  roaming_partners:
    - name: rp_1
      pool_name: sepp_pool
    - name: rp_2
      pool_name: sepp_pool
)EOF";

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

};
/************************************************************************************** 

------------------------------ BEGIN TEST SUITES --------------------------------------

*************************************************************************************** */

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterKeepAuthHeaderIntegrationTest, 
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

// ---------------------------- BEGIN TEST SCP ----------------------------------------

TEST_P(EricProxyFilterKeepAuthHeaderIntegrationTest, TestScpIndirectRoutingWithTar) {
  std::string proxy = "scp";
  addClusterConfigsFromYaml(std::vector{configProxyCluster(proxy)});
  addRouteConfigFromYaml(configRoute(proxy));
  initializeFilter(config_basic_scp);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "eric-chfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"}
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);

  auto upstream_index = waitForNextUpstreamRequest({0, 1});

  // Send fake 500 status upstream response
  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "500"}}, false);

  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection_->close());
  ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
  fake_upstream_connection_.reset();

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", absl::StrCat(proxy, "_pool")));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "eric-chfsim-1-mnc-123-mcc-123:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", absl::StrCat(proxy, std::to_string(upstream_index.value() + 1), ".ericsson.se:443")));
  auto tar_header = upstream_request_->headers().get(Http::LowerCaseString("3gpp-sbi-target-apiroot"));
  ASSERT_TRUE(!tar_header.empty());
  EXPECT_THAT(tar_header[0]->value().getStringView(), "http://eric-chfsim-1-mnc-123-mcc-123:80");

  upstream_index = waitForNextUpstreamRequest({0, 1});

  // Send fake 200 status upstream response
  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "200"}}, true);

  // Wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", absl::StrCat(proxy, "_pool")));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "eric-chfsim-1-mnc-123-mcc-123:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", absl::StrCat(proxy, std::to_string(upstream_index.value() + 1), ".ericsson.se:443")));
  tar_header = upstream_request_->headers().get(Http::LowerCaseString("3gpp-sbi-target-apiroot"));
  ASSERT_TRUE(!tar_header.empty());
  EXPECT_THAT(tar_header[0]->value().getStringView(), "http://eric-chfsim-1-mnc-123-mcc-123:80");

  // Verify downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));

  codec_client_->close();
}

TEST_P(EricProxyFilterKeepAuthHeaderIntegrationTest, TestScpIndirectRoutingWithAuth) {
  std::string proxy = "scp";
  addClusterConfigsFromYaml(std::vector{configProxyCluster(proxy)});
  addRouteConfigFromYaml(configRoute(proxy));
  initializeFilter(config_basic_scp);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "eric-chfsim-1-mnc-456-mcc-456:80"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-456-mcc-456:80"}
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);

  auto upstream_index = waitForNextUpstreamRequest({0, 1});

  // Send fake 500 status upstream response
  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "500"}}, false);

  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection_->close());
  ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
  fake_upstream_connection_.reset();

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", absl::StrCat(proxy, "_pool")));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "eric-chfsim-1-mnc-456-mcc-456:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "eric-chfsim-1-mnc-456-mcc-456:80"));
  auto tar_header = upstream_request_->headers().get(Http::LowerCaseString("3gpp-sbi-target-apiroot"));
  ASSERT_TRUE(tar_header.empty());

  upstream_index = waitForNextUpstreamRequest({0, 1});

  // Send fake 200 status upstream response
  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "200"}}, true);

  // Wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", absl::StrCat(proxy, "_pool")));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "eric-chfsim-1-mnc-456-mcc-456:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "eric-chfsim-1-mnc-456-mcc-456:80"));
  tar_header = upstream_request_->headers().get(Http::LowerCaseString("3gpp-sbi-target-apiroot"));
  ASSERT_TRUE(tar_header.empty());

  // Verify downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));

  codec_client_->close();
}

// ----------------------------- END TEST SCP -----------------------------------------

// ---------------------------- BEGIN TEST SEPP ---------------------------------------

TEST_P(EricProxyFilterKeepAuthHeaderIntegrationTest, TestSeppIndirectRoutingWithTar) {
  std::string proxy = "sepp";
  addClusterConfigsFromYaml(std::vector{configProxyCluster(proxy)});
  addRouteConfigFromYaml(configRoute(proxy));
  initializeFilter(config_basic_sepp);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "eric-chfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"}
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);

  auto upstream_index = waitForNextUpstreamRequest({0, 1});

  // Send fake 500 status upstream response
  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "500"}}, false);

  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection_->close());
  ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
  fake_upstream_connection_.reset();

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", absl::StrCat(proxy, "_pool")));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "eric-chfsim-1-mnc-123-mcc-123:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", absl::StrCat(proxy, std::to_string(upstream_index.value() + 1), ".ericsson.se:443")));
  auto tar_header = upstream_request_->headers().get(Http::LowerCaseString("3gpp-sbi-target-apiroot"));
  ASSERT_TRUE(!tar_header.empty());
  EXPECT_THAT(tar_header[0]->value().getStringView(), "http://eric-chfsim-1-mnc-123-mcc-123:80");

  upstream_index = waitForNextUpstreamRequest({0, 1});

  // Send fake 200 status upstream response
  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "200"}}, true);

  // Wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", absl::StrCat(proxy, "_pool")));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "eric-chfsim-1-mnc-123-mcc-123:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", absl::StrCat(proxy, std::to_string(upstream_index.value() + 1), ".ericsson.se:443")));
  tar_header = upstream_request_->headers().get(Http::LowerCaseString("3gpp-sbi-target-apiroot"));
  ASSERT_TRUE(!tar_header.empty());
  EXPECT_THAT(tar_header[0]->value().getStringView(), "http://eric-chfsim-1-mnc-123-mcc-123:80");

  // Verify downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));

  codec_client_->close();
}

TEST_P(EricProxyFilterKeepAuthHeaderIntegrationTest, TestSeppIndirectRoutingWithAuth) {
  std::string proxy = "sepp";
  addClusterConfigsFromYaml(std::vector{configProxyCluster(proxy)});
  addRouteConfigFromYaml(configRoute(proxy));
  initializeFilter(config_basic_sepp);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "eric-chfsim-1-mnc-456-mcc-456:80"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-456-mcc-456:80"}
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);

  auto upstream_index = waitForNextUpstreamRequest({0, 1});

  // Send fake 500 status upstream response
  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "500"}}, false);

  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection_->close());
  ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
  fake_upstream_connection_.reset();

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", absl::StrCat(proxy, "_pool")));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "eric-chfsim-1-mnc-456-mcc-456:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "eric-chfsim-1-mnc-456-mcc-456:80"));
  auto tar_header = upstream_request_->headers().get(Http::LowerCaseString("3gpp-sbi-target-apiroot"));
  ASSERT_TRUE(tar_header.empty());

  upstream_index = waitForNextUpstreamRequest({0, 1});

  // Send fake 200 status upstream response
  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "200"}}, true);

  // Wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", absl::StrCat(proxy, "_pool")));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "eric-chfsim-1-mnc-456-mcc-456:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "eric-chfsim-1-mnc-456-mcc-456:80"));
  tar_header = upstream_request_->headers().get(Http::LowerCaseString("3gpp-sbi-target-apiroot"));
  ASSERT_TRUE(tar_header.empty());

  // Verify downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));

  codec_client_->close();
}

// ----------------------------- END TEST SEPP ----------------------------------------

/************************************************************************************** 

--------------------------------- END TEST SUITES -------------------------------------

*************************************************************************************** */

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
