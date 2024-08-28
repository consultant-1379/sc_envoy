#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "test/integration/http_integration.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterCountersIntegrationTest
    : public HttpIntegrationTest,
      public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterCountersIntegrationTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(),
                            EricProxyFilterCountersIntegrationTest::ericProxyHttpProxyConfig()) {}
  /**
   * Initializer for an individual integration test.
   */
  void SetUp() override { }
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);

    HttpIntegrationTest::initialize();
  }

  const std::string config_16_instance = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  own_internal_port: 80
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - default_ingress_screening
  response_filter_cases:
    out_response_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - response_processing
  filter_cases:
    - name: default_ingress_screening
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
            log_level: INFO
            max_log_message_length: 500
            log_values:
            - term_string: "### Log message from test-case (response continued): INFO ###"
        - action_exit_filter_case: true

  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_34_instance = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - final_fc
    out_request_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          sepp_rp_A: second_ingress_screening
  response_filter_cases:
    in_response_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          sepp_rp_A: second_response_processing
  filter_cases:
    - name: second_ingress_screening
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
    - name: second_response_processing
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
// with the following we also test the fetched_config
std::string ericProxyHttpProxyConfig() {
  return absl::StrCat(ConfigHelper::baseConfig(), fmt::format(R"EOF(
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
)EOF",Platform::null_device_path));
}


void test_invocations_with_upstream_16(const std::string& apiRoot) {
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", apiRoot},
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

  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.s8c3.default_ingress_screening.s8r3.csepp_to_rp_A.ms_invocations_in_req_total")->value());
  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.s8c3.continuation_fc.s8r3.remove.ms_invocations_in_req_total")->value());
  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.s8c3.final_fc.s8r3.replace_route.ms_invocations_in_req_total")->value());
  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.s8c3.response_processing.s8r3.$up#rComl!cated(Rule)%.ms_invocations_out_resp_total")->value());
  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.s8c3.response_continuation.s8r3.rule_goneto.ms_invocations_out_resp_total")->value());

  codec_client->close();
}

void test_invocations_with_upstream_34(const std::string& apiRoot) {
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", apiRoot},
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

  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.p2l.sepp_rp_A.s8c3.second_ingress_screening.s8r3.csepp_to_rp_A.ms_invocations_out_req_total")->value());
  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.p2l.sepp_rp_A.s8c3.continuation_fc.s8r3.remove.ms_invocations_out_req_total")->value());
  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.p2l.sepp_rp_A.s8c3.final_fc.s8r3.replace_route.ms_invocations_out_req_total")->value());
  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.p2l.sepp_rp_A.s8c3.second_response_processing.s8r3.$up#rComl!cated(Rule)%.ms_invocations_in_resp_total")->value());
  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.p2l.sepp_rp_A.s8c3.response_continuation.s8r3.rule_goneto.ms_invocations_in_resp_total")->value());

  codec_client->close();
}

void test_action_reject(const std::string& api_root,IntegrationCodecClientPtr& codec_client, IntegrationStreamDecoderPtr& response) {
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", api_root},
      {"x-it-header-name-replaced", "x-it-header-value-orig"},
      {"x-it-header-name-replaced", "x-it-header-value-orig2"},
      {"x-it-header-name-removed", "x-it-header-value-removed"},
      {"x-it-header-name-removed", "x-it-header-value-removed2"},
      };

  codec_client = makeHttpConnection(lookupPort("http"));
  response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());
}
};

//--------------------------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterCountersIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(EricProxyFilterCountersIntegrationTest, multiple_invocations_with_response_16) {
  initializeFilter(config_16_instance);
  test_invocations_with_upstream_16("http://eric-chfsim-1-mnc-123-mcc-123:80");
}

TEST_P(EricProxyFilterCountersIntegrationTest, multiple_invocations_with_response_34) {
  initializeFilter(config_34_instance);
  test_invocations_with_upstream_34("http://eric-chfsim-1-mnc-123-mcc-123:80");
}

TEST_P(EricProxyFilterCountersIntegrationTest, reject_message_plain) {
  initializeFilter(config_16_instance);
  IntegrationCodecClientPtr codec_client;
  IntegrationStreamDecoderPtr response;
  test_action_reject("http://eric-chfsim-1-mnc-987-mcc-987:80", codec_client, response);

  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.s8c3.default_ingress_screening.s8r3.direct_response_plain.ms_reject_message_in_req_total")->value());
  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.s8c3.default_ingress_screening.s8r3.direct_response_plain.ms_invocations_in_req_total")->value());
  EXPECT_EQ("543", response->headers().getStatusValue());
  EXPECT_EQ("text/plain", response->headers().getContentTypeValue());
  EXPECT_EQ("reject test", response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()), response->headers().getContentLengthValue());
 codec_client->close();
}

TEST_P(EricProxyFilterCountersIntegrationTest, drop_message) {
  initializeFilter(config_16_instance);

  std::string api_root{"http://eric-chfsim-1-mnc-989-mcc-950:80"};
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", api_root},
      };

  auto codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForReset());

  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.s8c3.default_ingress_screening.s8r3.drop_message.ms_invocations_in_req_total")->value());
  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.s8c3.default_ingress_screening.s8r3.drop_message.ms_drop_message_in_req_total")->value());
  codec_client->close();
}


} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
