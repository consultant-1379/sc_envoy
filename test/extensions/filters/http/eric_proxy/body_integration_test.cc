#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterBodyIntegrationTest
    : public HttpIntegrationTest,
      public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterBodyIntegrationTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(),
                            EricProxyFilterBodyIntegrationTest::ericProxyHttpProxyConfig()) {}
  /**
   * Initializer for an individual integration test.
   */
  void SetUp() override { }
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);
    HttpIntegrationTest::initialize();
  }

  const std::string config_one_fc = R"EOF(
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
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      - name: path_not_exist
        body_json_pointer: "/path/does/not/exist"
        variable_name: nopath
      filter_rules:
      - name: csepp_to_rp_A
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: supi }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'imsi-460001357924610' }}
        actions:
        - action_add_header:
            name: x-it-header-name-added
            value:
              term_string: x-it-header-value-added
        - action_add_header:
            name: x-it-null
            value:
              term_var: nopath
    - name: default_routing
      filter_rules:
      - name: xit_set
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: x-it-header-name-added }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'x-it-header-value-added' }}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: wrong_pool
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

  const std::string config_extract_whole_body = R"EOF(
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
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: whole_body
        body_json_pointer: ""
        variable_name: whole_body
      filter_rules:
      - name: csepp_to_rp_A
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: x-it-whole-body-read
            value:
              term_var: whole_body
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
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

};

//--------------------------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterBodyIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

// Test that a SUPI is extracted correctly from a JSON-body.
// The Envoy test configuration is so that the extracted supi is checked in
// a condition and if it is correct, a header is set, which is then checked
// here.
TEST_P(EricProxyFilterBodyIntegrationTest, TestSupiExtraction) {
  initializeFilter(config_one_fc);
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
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", std::to_string(body.length())}
  };

 // IntegrationCodecClientPtr codec_client;
 // FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, request_stream));
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection_->close());
  ASSERT_TRUE(response->waitForEndStream());

  // Request headers on upstream:
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-it-header-name-added", "x-it-header-value-added"));

  codec_client_->close();
}

// Same as above, but with a multipart/related body
// Test that a SUPI is extracted correctly from a JSON-body.
// The Envoy test configuration is so that the extracted supi is checked in
// a condition and if it is correct, a header is set, which is then checked
// here.
// Note: as in all multipart tests, many/most lines must end in CRLF, only the
//       data-parts of a body-part (e.g. the JSON itself) can be with \n only
TEST_P(EricProxyFilterBodyIntegrationTest, TestSupiExtractionMP) {
  initializeFilter(config_one_fc);
  std::string body{"--asdfasdf\r\nContent-Type: application/json\r\n\r\n"
R"({
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
})"
"\r\n--asdfasdf\r\nContent-type: text/plain\r\n\r\n"
"attachment1"
"\r\n--asdfasdf--\r\n"
R"(Epilogue1
Epilogue2
  )"};
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-type", "multipart/related; boundary=asdfasdf"},
      {"content-length", std::to_string(body.length())}
  };

 // IntegrationCodecClientPtr codec_client;
 // FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, request_stream));
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection_->close());
  ASSERT_TRUE(response->waitForEndStream());

  // Request headers on upstream:
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-it-header-name-added", "x-it-header-value-added"));

  codec_client_->close();
}


// Test that the whole body is extracted correctly from a JSON-body.
// The Envoy test configuration is so that the extracted body is added
// as a header and checked
TEST_P(EricProxyFilterBodyIntegrationTest, TestWholeBodyExtraction) {
  initializeFilter(config_extract_whole_body);
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
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", std::to_string(body.length())}
  };

 // IntegrationCodecClientPtr codec_client;
 // FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, request_stream));
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection_->close());
  ASSERT_TRUE(response->waitForEndStream());

  // Request headers on upstream:
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  auto req_whole_body_var = request_stream->headers().get(Http::LowerCaseString("x-it-whole-body-read"))[0]->value().getStringView();
  EXPECT_EQ(Json::parse(req_whole_body_var), Json::parse(body));

  codec_client_->close();
}

// Test too large body for the default max_message_bytes of 16000000
TEST_P(EricProxyFilterBodyIntegrationTest, TestTooLargeRequestBody) {
  initializeFilter(config_extract_whole_body);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", "16000001"}
  };

  FakeStreamPtr request_stream;

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, 16000001);
  ASSERT_TRUE(response->waitForEndStream());
  // With HTTP/1 there's a possible race where if the connection backs up early,
  // the 413-and-connection-close may be sent while the body is still being
  // sent, resulting in a write error and the connection being closed before the
  // response is read.
  if (downstream_protocol_ >= Http::CodecType::HTTP2) {
    ASSERT_TRUE(response->complete());
  }
  if (response->complete()) {
    EXPECT_EQ(response->headers().getStatusValue(), "413");
  }

  codec_client_->close();
}




} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
