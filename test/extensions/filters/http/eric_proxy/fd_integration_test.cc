#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "test/integration/http_integration.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterFilterDataIntegrationTest : public HttpIntegrationTest,
                                        public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterFilterDataIntegrationTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(), EricProxyFilterFilterDataIntegrationTest::ericProxyHttpProxyConfig()) {
      }
  /**
   * Initializer for an individual integration test.
   */
  void SetUp() override { }
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);

    HttpIntegrationTest::initialize();
  }

  // 1. Variable with non-existing header
  // 2. Regexp with existing header
  const std::string config_var_nok_re_ok = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
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
      - name: apiRoot_data2
        header: 3gpp-Sbi-target-apiRoot2
        variable_name: mcc
      - name: apiRoot_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: https://eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      filter_rules:
      - name: csepp_to_rp_A
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: psepp_to_dfw
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: STRICT
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  // 1. Regexp with existing header
  // 2. Variable with non-existing header
  const std::string config_re_ok_var_nok = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
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
        extractor_regex: https://eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      - name: apiRoot_data2
        header: 3gpp-Sbi-target-apiRoot2
        variable_name: mcc
      filter_rules:
      - name: csepp_to_rp_A
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: psepp_to_dfw
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: STRICT
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";



  // 1. Variable with existing header
  // 2. Regexp with non-existing header
  const std::string config_var_ok_re_nok = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
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
        variable_name: mcc
      - name: apiRoot_data2
        header: 3gpp-Sbi-target-apiRoot2
        extractor_regex: https://eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      filter_rules:
      - name: csepp_to_rp_A
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'https://123' }}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: psepp_to_dfw
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: STRICT
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  // 1. Regexp with non-existing header
  // 2. Variable with existing header
  const std::string config_re_nok_var_ok = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
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
      - name: apiRoot_data2
        header: 3gpp-Sbi-target-apiRoot2
        extractor_regex: https://eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      - name: apiRoot_data
        header: 3gpp-Sbi-target-apiRoot
        variable_name: mcc
      filter_rules:
      - name: csepp_to_rp_A
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'https://123' }}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: psepp_to_dfw
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: STRICT
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

std::string ericProxyHttpProxyConfig() {
  return absl::StrCat(ConfigHelper::baseConfig(), fmt::format(R"EOF(
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
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                route:
                  cluster: cluster_0
)EOF",Platform::null_device_path));
}


void test_dnd24931(const std::string& apiRoot) {
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", apiRoot}
      };

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));

  codec_client->close();
}

};

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterFilterDataIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

// DND-24931 Writing to the same variable from several different filter-data is not consistent
// All 4 tests must pass.
// The difference between the tests is the order of the filter-data rule and
// which of them has valid data (2 variables * (valid|empty) = 4 combinations).
TEST_P(EricProxyFilterFilterDataIntegrationTest, DND24931_a) {
  initializeFilter(config_var_nok_re_ok);
  test_dnd24931("https://eric-chfsim-1-mnc-123-mcc-123:80");
}
TEST_P(EricProxyFilterFilterDataIntegrationTest, DND24931_b) {
  initializeFilter(config_re_ok_var_nok);
  test_dnd24931("https://eric-chfsim-1-mnc-123-mcc-123:80");
}
TEST_P(EricProxyFilterFilterDataIntegrationTest, DND24931_c) {
  initializeFilter(config_var_ok_re_nok);
  test_dnd24931("https://123");
}
TEST_P(EricProxyFilterFilterDataIntegrationTest, DND24931_d) {
  initializeFilter(config_re_nok_var_ok);
  test_dnd24931("https://123");
}

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
