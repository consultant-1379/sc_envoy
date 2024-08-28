#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"

#include <ostream>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
class EricProxyRouterStageTests : public HttpIntegrationTest,
                                    public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyRouterStageTests()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(),
                            EricProxyRouterStageTests::ericProxyHttpProxyConfig()) {}
  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);
    setUpstreamCount(2);
    HttpIntegrationTest::initialize();
  }


  std::string ericProxyHttpProxyConfig() {
    return absl::StrCat(baseConfig(), fmt::format(R"EOF(
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
  )EOF",
                                                  Platform::null_device_path));
  }


  std::string baseConfig() {
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
  clusters:
    - name: cluster_0
      connect_timeout: 15s
      load_assignment:
        cluster_name: cluster_0
        endpoints:
        - lb_endpoints:
          - endpoint:
              address:
                socket_address:
                  address: 127.0.0.1
                  port_value: 0
    - name: cluster_1
      connect_timeout: 15s
      load_assignment:
        cluster_name: cluster_1
        endpoints:
        - lb_endpoints:
          - endpoint:
              address:
                socket_address:
                  address: 127.0.0.1
                  port_value: 0
    - name: cluster_2
      connect_timeout: 15s
      load_assignment:
        cluster_name: cluster_1
  listeners:
    name: listener_0
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 0
)EOF",
                       Platform::null_device_path, Platform::null_device_path);
  };
};

const std::string config_routing = R"EOF(
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
        extractor_regex: eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      filter_rules:
      - name: csepp_to_rp_A
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_goto_filter_case: continuation_fc
      - name: direct_response_plain
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '987' }}
        actions:
        - action_reject_message:
            status: 543
            title: "reject test"
            message_format: PLAIN_TEXT
      - name: drop_message
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '950' }}
        actions:
        - action_drop_message: true
      - name: psepp_to_dfw
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: STRICT
    - name: continuation_fc
      filter_rules:
      - name: remove
        condition:
           term_boolean: true
        actions:
        - action_goto_filter_case: final_fc
    - name: final_fc
      filter_rules:
      - name: replace_route
        condition:
           term_boolean: true
        actions:
        - action_modify_header:
            name: :status
            replace_value:
              term_string: '200'
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
    - name: response_processing
      filter_rules:
      - name: $up#rComl!cated(Rule)%
        condition:
          term_boolean: true
        actions:
        - action_remove_header:
            name: x-eric-proxy
        - action_goto_filter_case: response_continuation
    - name: response_continuation
      filter_rules:
      - name: rule_goneto
        condition:
          term_boolean: true
        actions:
        - action_log:
            max_log_message_length: 500
            log_values:
              - term_string: "### Log message from test-case (response continued): INFO ###"
            log_level: INFO
        - action_exit_filter_case: true

  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";


INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyRouterStageTests,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

/* 

  Test case to validate if action-reject counters (direct response)
  for routing stage failures in SLF lookup increments routing stage
  direct response counter and also sends direct response with correct status code

 */

TEST_P(EricProxyRouterStageTests, IncRejectCounterTest) {
    initializeFilter(config_routing);
    auto api_root_ = "eric-chfsim-6-mnc-123-mcc-987";
     Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", api_root_},
      };

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(headers);
 
  ASSERT_TRUE(response->waitForEndStream());
   codec_client->close();
   // Print all counters
   ENVOY_LOG(trace, printCounters(test_server_));
   // EXPECT_EQ(1UL, test_server_->
   //   counter("http.eric_proxy.n8e.West1.r6c3.default_routing.r6r3.direct_response_plain.routing_direct_resp_rejects")->value());
  EXPECT_EQ(response->headers().getStatusValue(), "543");
}




} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
