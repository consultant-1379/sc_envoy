#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "base_integration_test.h"
#include "test/integration/http_integration.h"
#include "test/integration/socket_interface_swap.h"
#include "test/integration/utility.h"
#include <iostream>
#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyLocalReplyIntegrationTest
    : public EricProxyIntegrationTestBase,
      public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyLocalReplyIntegrationTest()
      : EricProxyIntegrationTestBase(
            Http::CodecClient::Type::HTTP1, GetParam(),
            EricProxyLocalReplyIntegrationTest::ericProxyHttpProxyConfig()) {
    setUpstreamCount(1);
  }

  std::string path_ = TestEnvironment::substitute("{{ test_rundir }}/test/extensions/filters/http/eric_proxy/test_data/local_reply.yaml");
  std::unique_ptr<Envoy::Stats::IsolatedStoreImpl> stats_ = std::make_unique<Stats::IsolatedStoreImpl>();
  std::unique_ptr<Envoy::Api::Api> api_ = Api::createApiForTest(*stats_);

  /**
   * Initializer for an individual integration test.
   */
  void SetUp() override { useAccessLog("%RESPONSE_FLAGS% %RESPONSE_CODE_DETAILS%"); }
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);
    HttpIntegrationTest::initialize();
  }

  void setLocalReplyConfig(const std::string& yaml) {
    envoy::extensions::filters::network::http_connection_manager::v3::LocalReplyConfig
        local_reply_config;
    TestUtility::loadFromYaml(yaml, local_reply_config);
    config_helper_.setLocalReply(local_reply_config);
  }

  void setLocalReplyConfigFromFile(const std::string& path) {
    envoy::extensions::filters::network::http_connection_manager::v3::LocalReplyConfig
        local_reply_config;
    TestUtility::loadFromFile(path, local_reply_config, *api_);
    config_helper_.setLocalReply(local_reply_config);
  }

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

  // (eraprpa): All the test cases are passing irrespective of the presence or the absence of
  // "routing" phase in the configuration below. So, should we remove it or keep it?

  // Configuration for basic positive tests
#pragma region BaseConfig
  std::string config_basic{R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  callback_uri_klv_table: callback_uris
  key_list_value_tables:
    - name: callback_uris
      entries:
        - key: test_api_name_1/v1
          value:
            - /nfInstances/*/nfServices/*/test_api_1_cb_uri_1
            - /nfInstances/*/nfServices/*/test_api_1_cb_uri_2
        - key: test_api_name_2/v1
          value:
            - /nfInstances/*/nfServices/*/test_api_2_cb_uri_1
            - /nfInstances/*/nfServices/*/test_api_2_cb_uri_2
        - key: nchf-convergedcharging/v2
          value:
            - /notifyUri
  nf_types_requiring_t_fqdn:
    - SMF
    - PCF
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 80
  filter_cases:
    - name: default_routing
      filter_data:
      - name: apiRoot_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      - name: apiRoot_header
        header: 3gpp-Sbi-target-apiRoot
        variable_name:  apiRoot_hdr
      - name: chfsim_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: eric-(?P<chfsim>chfsim-\d+?)-.+
      filter_rules:
      - name: c_no_tar_pool
        condition:
          op_not:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: c_no_tar_pool
            routing_behaviour: ROUND_ROBIN
      - name: c_wrong_tar
        condition:
          op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':authority'},
                      typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'sepp.own_plmn_test.com:80'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: c_no_tar_pool
            routing_behaviour: STRICT
      - name: c_tar_nf1_other_plmn
        condition:
          op_and:
            arg1:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nf1.other-plmn.com:5678'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':authority'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'sepp.own_plmn.com:80'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: c_tar_nf1_other_plmn
            routing_behaviour: STRICT
      - name: csepp_to_rp_A
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: psepp_to_dfw
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456'}}
            arg2:
              op_and:
                arg1:
                  op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
                arg2:
                  op_or:
                    arg1:
                      op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-6'}}
                    arg2:
                      op_or:
                        arg1:
                          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-7'}}
                        arg2:
                          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-8'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: universal_pool
            routing_behaviour: ROUND_ROBIN
      - name: psepp_to_pref
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: occ
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF"};
#pragma endregion BaseConfig


};
const std::string config_header_to_metadata_nf = R"EOF(
name: envoy.filters.http.header_to_metadata
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.header_to_metadata.v3.Config
  request_rules:
    - header: x-absolute-path-processing
      on_header_present:
        metadata_namespace: eric_proxy
        key: absolute-path-processing
        type: STRING
    - header: x-tfqdn-cluster-relative
      on_header_present:
        metadata_namespace: eric_proxy
        key: relative-path-value
        type: STRING
    - header: x-sepp-tfqdn-original-body-replaced
      on_header_present:
        metadata_namespace: eric_proxy.sepp.routing
        key: sepp-tfqdn-original-body-was-replaced
        type: STRING
    - header: x-sepp-tfqdn-original-body
      on_header_present:
        metadata_namespace: eric_proxy.sepp.routing
        key: sepp-tfqdn-original-body
        type: STRING
    - header: x-sepp-tfqdn-original-body-len
      on_header_present:
        metadata_namespace: eric_proxy.sepp.routing
        key: sepp-tfqdn-original-body-len
        type: STRING
    - header: x-routing
      on_header_present:
        metadata_namespace: eric_proxy
        key: routing-behaviour
        type: STRING
)EOF";

const std::string config_cdn_loop_filter = R"EOF(
name: envoy.filters.http.cdn_loop
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.cdn_loop.v3.CdnLoopConfig
  cdn_id: "2.0 sepp.mnc.567.mcc.765.ericsson.de"
)EOF";

const std::string config_body_mod_add_to_json = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - default_ingress_screening
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  response_filter_cases:
    out_response_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - default_egress_screening
  own_internal_port: 80
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: json_object_from_body
        body_json_pointer: "/nfConsumerIdentification"
        variable_name: json_object_from_body
      filter_rules:
      - name: modify_req_body_add_to_json
        condition:
          op_exists: {arg1:  {term_var: 'json_object_from_body'}}
        actions:
        - action_modify_json_body:
            name: "test modify request body"
            json_operation:
              add_to_json:
                value:
                  term_string: '"supi-added"'
                json_pointer:
                  term_string: "/subscriberIdentifier1"
                if_path_not_exists:  DO_NOTHING
                if_element_exists:  NO_ACTION
    - name: default_routing
      filter_rules:
      - name: route_to_correct_pool
        condition:
          op_exists: {arg1:  {term_var: 'json_object_from_body'}}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_pool_strict
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: cluster_0
            routing_behaviour: STRICT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
    - name: default_egress_screening
      filter_rules:
      - name: modify_resp_body_add_to_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test modify response body"
            json_operation:
              add_to_json:
                value:
                  term_string: '"supi-added"'
                json_pointer:
                  term_string: "/subscriberIdentifier1"
                if_path_not_exists:  DO_NOTHING
                if_element_exists:  NO_ACTION
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

//--------------------------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyLocalReplyIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

#pragma region Missing_Host_Header
TEST_P(EricProxyLocalReplyIntegrationTest, Missing_Host_Header) {
  // GTEST_SKIP();

  const std::string yaml{R"EOF(
mappers:
- filter:
    and_filter:
      filters:
        - response_flag_filter:
            flags:
              - E_IVH
        - status_code_filter:
            comparison:
              op: EQ
              value:
                default_value: 400
                runtime_key: key_b
  status_code: 400
  body:
    inline_string: "MANDATORY_IE_INCORRECT"
- filter:
    status_code_filter:
      comparison:
        op: EQ
        value:
          default_value: 400
          runtime_key: key_b
  status_code: 400
  body:
    inline_string: "MANDATORY_IE_MISSING"
)EOF"};
  setLocalReplyConfig(yaml);
  initializeFilter(config_basic);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "MVZGS----NUGM43JNUWTMLLNNZRS2NBVGYWW2Y3DFU2DKNR2GM3TONY.sepp.own_plmn.com"},
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("text/plain", response->headers().ContentType()->value().getStringView());
  EXPECT_EQ(response->body(), "MANDATORY_IE_MISSING");

  codec_client_->close();
}
#pragma endregion Missing_Host_Header

// STRICT routing with wrong tar
TEST_P(EricProxyLocalReplyIntegrationTest, TestWrongTar) {
  setLocalReplyConfigFromFile(path_);
  initializeFilter(config_basic);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "sepp.own_plmn_test.com:80"},
      {"3gpp-Sbi-target-apiRoot", "edr_poe"},
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream()); 

  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ(
      R"({"status": 400, "title": "Bad Request", "cause": "MANDATORY_IE_INCORRECT", "detail": "3gpp-sbi-target-apiroot_header_malformed"})",
      response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());
}

TEST_P(EricProxyLocalReplyIntegrationTest, TestCAuthFaultyTFqdn) {
  // GTEST_SKIP();
  setLocalReplyConfigFromFile(path_);
  initializeFilter(config_basic);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "abcq.sepp.own_plmn.com"},
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ(
      R"({"status": 400, "title": "Bad Request", "cause": "MANDATORY_IE_INCORRECT", "detail": "decoding_error_tfqdn_invalid"})",
      response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());

  codec_client_->close();
}

TEST_P(EricProxyLocalReplyIntegrationTest, TestJsonBodyMod_add_to_json_malformed) {
  // GTEST_SKIP();
  setLocalReplyConfigFromFile(path_);
  initializeFilter(config_body_mod_add_to_json);
  // Malformed body: last closing } is missing
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
            "nFName": "123e-e8b-1d3-a46-421",
            "nFIPv4Address": "192.168.0.1",
            "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
            "nFPLMNID": {
                "mcc": "311",
                "mnc": "280"
            },
            "nodeFunctionality": "SMF"
        }
      )"};

  std::string ip_port;
  if (fake_upstreams_[0]->localAddress()->ip()->ipv6()) {
    absl::StrAppend(&ip_port, "http://", "[",
                    fake_upstreams_[0]->localAddress()->ip()->addressAsString(), "]");
  } else {
    absl::StrAppend(&ip_port, "http://",
                    fake_upstreams_[0]->localAddress()->ip()->addressAsString());
  }
  absl::StrAppend(&ip_port, ":", fake_upstreams_[0]->localAddress()->ip()->port());

  Http::TestRequestHeaderMapImpl headers{{":method", "POST"},
                                         {":path", "/"},
                                         {":authority", "host"},
                                         {"3gpp-Sbi-target-apiRoot", ip_port},
                                         {"content-length", std::to_string(body.length())}};
  const Json expected_body{
      R"({"cause":"SYSTEM_FAILURE","detail":"response_json_operation_failed","status":500,"title":"Internal Server Error"})"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));

  // Send fake upstream response, using same body as in request:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}};
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  EXPECT_EQ("500", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client_->close();
}

TEST_P(EricProxyLocalReplyIntegrationTest, MissingHostHeaderManager) {
  // GTEST_SKIP();
  setLocalReplyConfigFromFile(path_);
  initializeFilter(config_basic);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
  };

  IntegrationCodecClientPtr codec_client = makeHttpConnection(lookupPort("http"));
  IntegrationStreamDecoderPtr response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  const Json expected_body{
      R"({"status":400,"title":"Bad Request","cause":"MANDATORY_IE_MISSING","detail":"missing_host_header"})"_json};

  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ("400", response->headers().getStatusValue());

  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client->close();
}

TEST_P(EricProxyLocalReplyIntegrationTest, InvalidViaHeader) {
  // GTEST_SKIP();
  config_helper_.addFilter(config_cdn_loop_filter);
  setLocalReplyConfigFromFile(path_);
  initializeFilter(config_basic);

  std::string body{R"(
    {
      "subscriberIdentifier": "imsi-460001357924610",
      "nfConsumerIdentification": {
          "nFName": "123e-e8b-1d3-a46-421",
          "nFIPv4Address": "192.168.0.1",
          "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nFPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
      }
    }
  )"};
  Http::TestRequestHeaderMapImpl headers{{":method", "POST"},
                                         {":path", "/"},
                                         {":authority", "host"},
                                         {"x-test-supi", "12345"},
                                         {"via", "http/2.7 2.0 sepp.mnc.567.mcc.765.ericsson.de"},
                                         {"content-length", std::to_string(body.length())}};

  IntegrationCodecClientPtr codec_client = makeHttpConnection(lookupPort("http"));
  IntegrationStreamDecoderPtr response = codec_client->makeRequestWithBody(headers, body);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ("400", response->headers().getStatusValue());

  const Json expected_body{
      R"({"detail":"invalid_via_header","status":400,"cause":"MANDATORY_IE_INCORRECT","title":"Bad Request"})"_json};
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  EXPECT_THAT(waitForAccessLog(access_log_name_), testing::HasSubstr("E_IVH"));

  codec_client->close();
}

// DND 56014 In SCP/SEPP loop detection the status code should be 400 
// with message MSG_LOOP_DETECTED
TEST_P(EricProxyLocalReplyIntegrationTest, LoopDetected) {
  // GTEST_SKIP();
  config_helper_.addFilter(config_cdn_loop_filter);
  setLocalReplyConfigFromFile(path_);
  initializeFilter(config_basic);

  std::string body{R"(
    {
      "subscriberIdentifier": "imsi-460001357924610",
      "nfConsumerIdentification": {
          "nFName": "123e-e8b-1d3-a46-421",
          "nFIPv4Address": "192.168.0.1",
          "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nFPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
      }
    }
  )"};
  Http::TestRequestHeaderMapImpl headers{{":method", "POST"},
                                         {":path", "/"},
                                         {":authority", "host"},
                                         {"x-test-supi", "12345"},
                                         {"via", "2.0 sepp.mnc.567.mcc.765.ericsson.de"},
                                         {"content-length", std::to_string(body.length())}};

  IntegrationCodecClientPtr codec_client = makeHttpConnection(lookupPort("http"));
  IntegrationStreamDecoderPtr response = codec_client->makeRequestWithBody(headers, body);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ("400", response->headers().getStatusValue());

  const Json expected_body{R"({"status":400,"title":"Bad Request","cause":"MSG_LOOP_DETECTED","detail":"loop_detected"})"_json};
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client->close();
}
// DPE flag???
TEST_P(EricProxyLocalReplyIntegrationTest, CodecError) {
  // GTEST_SKIP();
  setLocalReplyConfigFromFile(path_);
  initializeFilter(config_basic);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", ""},
      {":authority", "host"},
  };

  IntegrationCodecClientPtr codec_client = makeHttpConnection(lookupPort("http"));
  IntegrationStreamDecoderPtr response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ("400", response->headers().getStatusValue());
  const Json expected_body{
      R"({"cause":"MANDATORY_IE_MISSING","detail":"http1.codec_error","status":400,"title":"Bad Request"})"_json};
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  EXPECT_THAT(waitForAccessLog(access_log_name_), testing::HasSubstr("DPE"));
  codec_client->close();
}

TEST_P(EricProxyLocalReplyIntegrationTest, Target_NF_NotReachable) {
  setLocalReplyConfigFromFile(path_);
  initializeFilter(config_basic);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1"},
      {":authority", "eric-chfsim-6-mnc-456-mcc-456:3777"},
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));

  auto response = codec_client_->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));

  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());
  ASSERT_TRUE(fake_upstream_connection_->close());
  ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ("504", response->headers().getStatusValue());
  const auto r = Json::parse(response->body());
  EXPECT_EQ(r.at("cause"), "TARGET_NF_NOT_REACHABLE");
  EXPECT_EQ(r.at("title"), "Gateway Timeout");

  EXPECT_THAT(waitForAccessLog(access_log_name_), testing::HasSubstr("UC"));

  codec_client_->close();
}

TEST_P(EricProxyLocalReplyIntegrationTest, RouteNotFound) {
  // GTEST_SKIP();
  config_helper_.prependFilter("{ name: invalid-header-filter, typed_config: { \"@type\": "
                               "type.googleapis.com/google.protobuf.Empty } }");
  setLocalReplyConfigFromFile(path_);
  initializeFilter(config_basic);

  codec_client_ = makeHttpConnection(lookupPort("http"));

  // Missing path for non-CONNECT
  auto response = codec_client_->makeHeaderOnlyRequest(
      Http::TestRequestHeaderMapImpl{{":method", "GET"},
                                     {":path", "/test/long/url"},
                                     {":scheme", "http"},
                                     {":authority", "host"},
                                     {"remove-path", "yes"}});

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(response->complete());
  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_THAT(waitForAccessLog(access_log_name_), testing::HasSubstr("NR"));

  const auto r = Json::parse(response->body());
  EXPECT_EQ(r.at("cause"), "UNSPECIFIED_MSG_FAILURE");
  EXPECT_EQ(r.at("detail"), "route_not_found");
  codec_client_->close();
}

TEST_P(EricProxyLocalReplyIntegrationTest, ClusterNotFound) {
  // GTEST_SKIP();
  config_helper_.addConfigModifier(
      [&](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager&
              hcm) -> void {
        auto* route_config = hcm.mutable_route_config();
        route_config->mutable_validate_clusters()->set_value(false);
      });

  setLocalReplyConfigFromFile(path_);
  auto host = config_helper_.createVirtualHost("foo.com", "/unknown", "unknown_cluster");
  host.mutable_routes(0)->mutable_route()->set_cluster_not_found_response_code(
      envoy::config::route::v3::RouteAction::NOT_FOUND);
  config_helper_.addVirtualHost(host);
  initialize();

  BufferingStreamDecoderPtr response = IntegrationUtil::makeSingleRequest(
      lookupPort("http"), "GET", "/unknown", "", downstream_protocol_, version_, "foo.com");
  ASSERT_TRUE(response->complete());
  EXPECT_EQ("500", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_THAT(waitForAccessLog(access_log_name_), testing::HasSubstr("NC"));

  std::cerr << "BODY: " << response->body() << std::endl;
  const auto r = Json::parse(response->body());
  EXPECT_EQ(r.at("cause"), "SYSTEM_FAILURE");
  EXPECT_EQ(r.at("detail"), "cluster_not_found");
}

TEST_P(EricProxyLocalReplyIntegrationTest, RequestPayloadTooLarge) {
  // GTEST_SKIP();
  config_helper_.prependFilter("{ name: encoder-decoder-buffer-filter, typed_config: { \"@type\": "
                               "type.googleapis.com/google.protobuf.Empty } }");
  config_helper_.setBufferLimits(1024, 1024);
  setLocalReplyConfigFromFile(path_);
  initialize();

  codec_client_ = makeHttpConnection(lookupPort("http"));

  auto response = codec_client_->makeRequestWithBody(
      Http::TestRequestHeaderMapImpl{{":method", "POST"},
                                     {":path", "/dynamo/url"},
                                     {":scheme", "http"},
                                     {":authority", "host"},
                                     {"x-forwarded-for", "10.0.0.1"},
                                     {"x-envoy-retry-on", "5xx"}},
      1024 * 65);

  ASSERT_TRUE(response->waitForEndStream());
  // With HTTP/1 there's a possible race where if the connection backs up early,
  // the 413-and-connection-close may be sent while the body is still being
  // sent, resulting in a write error and the connection being closed before the
  // response is read.
  if (downstream_protocol_ >= Http::CodecType::HTTP2) {
    ASSERT_TRUE(response->complete());
  }
  if (response->complete()) {
    EXPECT_EQ("413", response->headers().getStatusValue());
    EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  }

  EXPECT_THAT(waitForAccessLog(access_log_name_), testing::HasSubstr("E_PTL"));
  codec_client_->close();
}

TEST_P(EricProxyLocalReplyIntegrationTest, ResponsePayloadTooLarge) {
  // GTEST_SKIP();
  config_helper_.addConfigModifier(
      [&](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager&
              hcm) -> void {
        auto* route_config = hcm.mutable_route_config();
        auto* virtual_host = route_config->mutable_virtual_hosts(0);
        auto* header = virtual_host->mutable_response_headers_to_add()->Add()->mutable_header();
        header->set_key("foo");
        header->set_value("bar");
      });

  config_helper_.prependFilter("{ name: encoder-decoder-buffer-filter, typed_config: { \"@type\": "
                               "type.googleapis.com/google.protobuf.Empty } }");
  config_helper_.setBufferLimits(1024, 1024);
  setLocalReplyConfigFromFile(path_);
  initialize();

  // Send the request.
  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto encoder_decoder = codec_client_->startRequest(default_request_headers_);
  auto downstream_request = &encoder_decoder.first;
  auto response = std::move(encoder_decoder.second);
  Buffer::OwnedImpl data("HTTP body content goes here");
  codec_client_->sendData(*downstream_request, data, true);
  waitForNextUpstreamRequest();

  // Send the response headers.
  upstream_request_->encodeHeaders(default_response_headers_, false);

  // Now send an overly large response body. At some point, too much data will
  // be buffered, the stream will be reset, and the connection will disconnect.
  upstream_request_->encodeData(1024 * 65, false);
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
  } else {
    ASSERT_TRUE(upstream_request_->waitForReset());
    ASSERT_TRUE(fake_upstream_connection_->close());
    ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
  }

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(response->complete());
  EXPECT_EQ("500", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());

  EXPECT_THAT(waitForAccessLog(access_log_name_), testing::HasSubstr("E_PTL"));
  codec_client_->close();
}

// ROUND_ROBIN
TEST_P(EricProxyLocalReplyIntegrationTest, UpstreamResetBeforeResponseStartedRR) {
  SocketInterfaceSwap socket_swap(Network::Socket::Type::Stream);

  setLocalReplyConfigFromFile(path_);
  config_helper_.addFilter(config_header_to_metadata_nf);
  initialize();

  codec_client_ = makeHttpConnection(lookupPort("http"));
  Http::TestRequestHeaderMapImpl default_request_headers_ {
    {":method", "GET"}, 
    {":path", "/test/long/url"}, 
    {":scheme", "http"}, 
    {":authority", "sni.lyft.com"},
    {"x-routing", "ROUND_ROBIN"},
  };
  auto encoder_decoder = codec_client_->startRequest(default_request_headers_);
  auto downstream_request = &encoder_decoder.first;
  auto response = std::move(encoder_decoder.second);

  // Make sure the headers made it through.
  waitForNextUpstreamConnection(std::vector<uint64_t>{0}, TestUtility::DefaultTimeout,
                                fake_upstream_connection_);
  AssertionResult result =
      fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_);
  RELEASE_ASSERT(result, result.message());

  // Makes us have Envoy's writes to upstream return EBADF
  Api::IoErrorPtr ebadf = Network::IoSocketError::getIoSocketEbadfError();
  socket_swap.write_matcher_->setDestinationPort(fake_upstreams_[0]->localAddress()->ip()->port());
  socket_swap.write_matcher_->setWriteOverride(std::move(ebadf));

  Buffer::OwnedImpl data("HTTP body content goes here");
  codec_client_->sendData(*downstream_request, data, true);

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_THAT(waitForAccessLog(access_log_name_),
              testing::HasSubstr("upstream_reset_before_response_started{connection_termination}"));
  EXPECT_TRUE(response->complete());
  EXPECT_EQ("504", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());

  const auto r = Json::parse(response->body());
  EXPECT_EQ(r.at("cause"), "TARGET_NF_NOT_REACHABLE");
  EXPECT_EQ(r.at("title"), "Gateway Timeout");

  EXPECT_THAT(waitForAccessLog(access_log_name_), testing::HasSubstr("UC"));
  ebadf = nullptr;
  socket_swap.write_matcher_->setWriteOverride(std::move(ebadf));
  // Shut down the server before os_calls goes out of scope to avoid syscalls
  // during its removal.
  test_server_.reset();
}

// STRICT
// md routing-behavior==STRICT has a special meaning after the changes for custom reselection logic.
// If the target host is not supplied via the override host and eric-proxy, no host will be selected
// and a no healthy upstream is
TEST_P(EricProxyLocalReplyIntegrationTest, UpstreamResetBeforeResponseStartedStrict) {
  SocketInterfaceSwap socket_swap(Network::Socket::Type::Stream);
  // Common configuration for eric proxy filter
  const std::string minimal_eric_proxy_confg = R"EOF(
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
              term_string: cluster_0
            routing_behaviour: STRICT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
)EOF";
  setLocalReplyConfigFromFile(path_);
  config_helper_.addFilter(config_header_to_metadata_nf);
  config_helper_.addFilter(minimal_eric_proxy_confg);
  initialize();

  std::string ip_port;
  if (fake_upstreams_[0]->localAddress()->ip()->ipv6()) {
    absl::StrAppend(&ip_port, "http://", "[",
                    fake_upstreams_[0]->localAddress()->ip()->addressAsString(), "]");
  } else {
    absl::StrAppend(&ip_port, "http://",
                    fake_upstreams_[0]->localAddress()->ip()->addressAsString());
  }
  absl::StrAppend(&ip_port, ":", fake_upstreams_[0]->localAddress()->ip()->port());

  codec_client_ = makeHttpConnection(lookupPort("http"));
  Http::TestRequestHeaderMapImpl default_request_headers_{{":method", "GET"},
                                                          {":path", "/test/long/url"},
                                                          {":scheme", "http"},
                                                          {":authority", "sni.lyft.com"},
                                                          {"3gpp-Sbi-target-apiRoot", ip_port}};
  auto encoder_decoder = codec_client_->startRequest(default_request_headers_);
  auto downstream_request = &encoder_decoder.first;
  auto response = std::move(encoder_decoder.second);

  // Make sure the headers made it through.
  // waitForNextUpstreamConnection(std::vector<uint64_t>{0}, TestUtility::DefaultTimeout,
  //                             fake_upstream_connection_);
  // AssertionResult result =
  //     fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_);
  // RELEASE_ASSERT(result, result.message());

  // Makes us have Envoy's writes to upstream return EBADF
  Api::IoErrorPtr ebadf = Network::IoSocketError::getIoSocketEbadfError();
  socket_swap.write_matcher_->setDestinationPort(fake_upstreams_[0]->localAddress()->ip()->port());
  socket_swap.write_matcher_->setWriteOverride(std::move(ebadf));

  Buffer::OwnedImpl data("HTTP body content goes here");
  codec_client_->sendData(*downstream_request, data, true);

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_THAT(waitForAccessLog(access_log_name_),
              testing::HasSubstr("upstream_reset_before_response_started{connection_termination}"));
  EXPECT_TRUE(response->complete());
  EXPECT_EQ("500", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());

  const auto r = Json::parse(response->body());
  EXPECT_EQ(r.at("cause"), "NF_FAILOVER");
  EXPECT_EQ(r.at("title"), "Internal Server Error");

  EXPECT_THAT(waitForAccessLog(access_log_name_), testing::HasSubstr("UC"));
  ebadf = nullptr;
  socket_swap.write_matcher_->setWriteOverride(std::move(ebadf));
  // Shut down the server before os_calls goes out of scope to avoid syscalls
  // during its removal.
  test_server_.reset();
  test_server_.reset();
}

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
