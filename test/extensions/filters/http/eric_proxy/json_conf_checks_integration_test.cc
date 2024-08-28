#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "envoy/extensions/filters/http/cdn_loop/v3/cdn_loop.pb.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"
#include <iostream>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterJsonConfChecksTest
    : public HttpIntegrationTest,
      public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterJsonConfChecksTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(),
                                     EricProxyFilterJsonConfChecksTest::ericProxyHttpBaseConfig()) {
    setUpstreamCount(1);
  }
  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);

    HttpIntegrationTest::initialize();
  }

  // Common base configuration
  std::string ericProxyHttpBaseConfig() {
    return fmt::format(R"EOF(
admin:
  access_log:
  - name: envoy.access_loggers.file
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
      path: "{}"
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
    name: cluster_0
    load_assignment:
      cluster_name: cluster_0
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 0
          metadata:
            filter_metadata:
              envoy.eric_proxy:
                support:
                - TFQDN
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
          server_header_transformation: APPEND_IF_ABSENT
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - name: route2
                match:
                  prefix: "/"
                  headers:
                    - name: x-eric-proxy
                route:
                  cluster: cluster_0
              - name: route1
                match:
                  prefix: "/"
                route:
                  cluster: cluster_0
  )EOF",
      Platform::null_device_path, Platform::null_device_path,
      Platform::null_device_path);
  };

  // Common configuration to test configurable checks on JSON body
  const std::string config_common_json_conf_checks{R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp_router
  node_type: SCP
  own_internal_port: 80
  request_validation:
    check_message_bytes:
      <max_message_bytes>
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 413
          title: "Payload Too Large"
          detail: "request_payload_too_large"
          message_format: JSON
    check_json_leaves:
      <max_message_leaves>
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 413
          title: "Payload Too Large"
          detail: "request_json_leaves_limits_exceeded"
    check_json_depth:
      <max_message_nesting_depth>
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 413
          title: "Payload Too Large"
          detail: "request_json_depth_limits_exceeded"
          message_format: JSON
  response_validation:
    check_message_bytes:
      <max_message_bytes>
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 500
          title: "Internal Server Error"
          cause: "INSUFFICIENT_RESOURCES"
          detail: "response_payload_too_large"
          message_format: JSON
    check_json_leaves:
      <max_message_leaves>
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 500
          title: "Internal Server Error"
          cause: "INSUFFICIENT_RESOURCES"
          detail: "response_json_leaves_limits_exceeded"
          message_format: JSON
    check_json_depth:
      <max_message_nesting_depth>
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 500
          title: "Internal Server Error"
          cause: "INSUFFICIENT_RESOURCES"
          detail: "response_json_depth_limits_exceeded"
          message_format: JSON
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
              term_string: chf_pool
            routing_behaviour: ROUND_ROBIN
)EOF"};

  // Common function for request JSON body configurable checks tests with different scenarios
  void testReqJsonBodyConfChecks(
    const int& max_message_bytes,
    const int& max_message_leaves,
    const int& max_message_nesting_depth,
    const std::string& request_body,
    const Json& expected_body,
    const std::string& status_code
  ) {
    std::string config_json_conf_checks = std::regex_replace(
      config_common_json_conf_checks,
      std::regex("<max_message_bytes>*"),
      fmt::format("max_message_bytes: {}", max_message_bytes)
    );

    config_json_conf_checks = std::regex_replace(
      config_json_conf_checks,
      std::regex("<max_message_leaves>*"),
      fmt::format("max_message_leaves: {}", max_message_leaves)
    );

    config_json_conf_checks = std::regex_replace(
      config_json_conf_checks,
      std::regex("<max_message_nesting_depth>*"),
      fmt::format("max_message_nesting_depth: {}", max_message_nesting_depth)
    );

    initializeFilter(config_json_conf_checks);

    Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://chf1.ericsson.se:443"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}
    };
    
    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, request_body);

    // Wait for the response and close the fake upstream connection
    ASSERT_TRUE(response->waitForEndStream());

    // Verify downstream response
    EXPECT_EQ(status_code, response->headers().getStatusValue());
    EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
    EXPECT_THAT(response->headers(),
                Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
    EXPECT_EQ(expected_body, Json::parse(response->body()));

    codec_client_->close();
  }

  // Common function for response JSON body configurable checks tests with different scenarios
  void testRespJsonBodyConfChecks(
    const int& max_message_bytes,
    const int& max_message_leaves,
    const int& max_message_nesting_depth,
    const std::string& response_body,
    const Json& expected_body,
    const std::string& status_code
  ) {
    std::string config_json_conf_checks = std::regex_replace(
      config_common_json_conf_checks,
      std::regex("<max_message_bytes>*"),
      fmt::format("max_message_bytes: {}", max_message_bytes)
    );

    config_json_conf_checks = std::regex_replace(
      config_json_conf_checks,
      std::regex("<max_message_leaves>*"),
      fmt::format("max_message_leaves: {}", max_message_leaves)
    );

    config_json_conf_checks = std::regex_replace(
      config_json_conf_checks,
      std::regex("<max_message_nesting_depth>*"),
      fmt::format("max_message_nesting_depth: {}", max_message_nesting_depth)
    );

    initializeFilter(config_json_conf_checks);

    Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://chf1.ericsson.se:443"},
    };
    
    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
    waitForNextUpstreamRequest(0);

    Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}
    };

    // Send response
    upstream_request_->encodeHeaders(response_headers, false);
    Buffer::OwnedImpl response_data(response_body);
    upstream_request_->encodeData(response_data, true);
    ASSERT_TRUE(response->waitForEndStream());

    // Verify upstream request
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));

    // Verify downstream response
    EXPECT_EQ(status_code, response->headers().getStatusValue());
    EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
    EXPECT_THAT(response->headers(),
                Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
    EXPECT_EQ(expected_body, Json::parse(response->body()));

    codec_client_->close();
  }

  // Helper function to generate nested JSON array body
  Json createNestedJson(const int& num_levels) {
    if (num_levels < 1) {
      Json json_body(R"([])");
      return json_body;
    }
    if (num_levels == 1) {
      Json json_body;
      json_body.push_back("v1");
      return json_body;
    }
    Json prev_json_body = createNestedJson(num_levels - 1);
    Json json_body;
    json_body.push_back(fmt::format("v{}", num_levels));
    json_body.push_back(prev_json_body);
    return json_body;
  }
};

/************************************************************************************** 

------------------------------ BEGIN TEST SUITES --------------------------------------

*************************************************************************************** */

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterJsonConfChecksTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

//-------------------- BEGIN TEST REQUEST & RESPONSE JSON BODY ------------------------

// Name: JsonBodyConfChecksAll_allWithinLimits
// Description: Checking both request and response JSON bodies
// with configured size, leaves and depth where JSON bodies 
// are within configured limits.
// Expected Result: Request and response bodies are forwarded.
TEST_P(EricProxyFilterJsonConfChecksTest, JsonBodyConfChecksAll_allWithinLimits) {
  std::string config_json_conf_checks = std::regex_replace(
    config_common_json_conf_checks,
    std::regex("<max_message_bytes>*"),
    "max_message_bytes: 100"
  );

  config_json_conf_checks = std::regex_replace(
    config_json_conf_checks,
    std::regex("<max_message_leaves>*"),
    "max_message_leaves: 3"
  );

  config_json_conf_checks = std::regex_replace(
    config_json_conf_checks,
    std::regex("<max_message_nesting_depth>*"),
    "max_message_nesting_depth: 2"
  );

  initializeFilter(config_json_conf_checks);

  std::string request_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3"})"};
  Http::TestRequestHeaderMapImpl request_headers{
    {":method", "POST"},
    {":path", "/"},
    {":authority", "host"},
    {"3gpp-Sbi-target-apiRoot", "http://chf1.ericsson.se:443"},
    {"content-length", std::to_string(request_body.length())},
    {"content-type", "application/json"}
  };
  
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, request_body);
  waitForNextUpstreamRequest(0);

  std::string response_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3"})"};
  Http::TestResponseHeaderMapImpl response_headers{
    {":status", "200"},
    {"content-length", std::to_string(response_body.length())},
    {"content-type", "application/json"}
  };

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(response_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));

  // Verify downstream response
  // Response body should not be modified
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  Json expected_body = Json::parse(response_body);
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client_->close();
}

//--------------------- END TEST REQUEST & RESPONSE JSON BODY -------------------------

//------------------------ BEGIN TEST REQUEST JSON BODY -------------------------------

// Name: ReqJsonBodyConfChecksAll_sizeExceededLimit1
// Description: Checking request JSON body with configured size, leaves and
// depth where the JSON body exceeds configured size limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, ReqJsonBodyConfChecksAll_sizeExceededLimit1) {
  int max_message_bytes = 100;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 2;

  int original_message_bytes = 101;
  std::string request_body = "";
  for (int idx = 0; idx < original_message_bytes - 2; idx++) {
    absl::StrAppend(&request_body, "a");
  }
  request_body = "\"" + request_body + "\"";

  const Json expected_body{
      R"({"status": 413, "title": "Payload Too Large", "detail": "request_payload_too_large"})"_json};
  std::string status_code = "413";

  testReqJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                            request_body, expected_body, status_code);
}

// Name: ReqJsonBodyConfChecksAll_sizeExceededLimit2
// Description: Checking request JSON body with configured size, leaves and
// depth where the JSON body exceeds configured size limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, ReqJsonBodyConfChecksAll_sizeExceededLimit2) {
  int max_message_bytes = 0;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 2;

  std::string request_body{R"("")"};
  const Json expected_body{
      R"({"status": 413, "title": "Payload Too Large", "detail": "request_payload_too_large"})"_json};
  std::string status_code = "413";

  testReqJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                            request_body, expected_body, status_code);
}

// Name: ReqJsonBodyConfChecksAll_sizeExceededLimit3
// Description: Checking request JSON body with configured size, leaves and
// depth where the JSON body exceeds configured size limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, ReqJsonBodyConfChecksAll_sizeExceededLimit3) {
  int max_message_bytes = 16000000;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 2;

  int original_message_bytes = 16000001;
  std::string request_body = "";
  for (int idx = 0; idx < original_message_bytes - 2; idx++) {
    absl::StrAppend(&request_body, "a");
  }
  request_body = "\"" + request_body + "\"";

  const Json expected_body{
      R"({"status": 413, "title": "Payload Too Large", "detail": "request_payload_too_large"})"_json};
  std::string status_code = "413";

  testReqJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                            request_body, expected_body, status_code);
}

// Name: ReqJsonBodyConfChecksAll_leavesExceededLimit1
// Description: Checking request JSON body with configured size, leaves and
// depth where the JSON body exceeds configured number of leaves limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, ReqJsonBodyConfChecksAll_leavesExceededLimit1) {
  int max_message_bytes = 100;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 2;

  std::string request_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3", "k4":"v4"})"};
  const Json expected_body{
      R"({"status": 413, "title": "Payload Too Large", "detail": "request_json_leaves_limits_exceeded"})"_json};
  std::string status_code = "413";

  testReqJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                            request_body, expected_body, status_code);
}

// Name: ReqJsonBodyConfChecksAll_leavesExceededLimit2
// Description: Checking request JSON body with configured size, leaves and
// depth where the JSON body exceeds configured number of leaves limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, ReqJsonBodyConfChecksAll_leavesExceededLimit2) {
  int max_message_bytes = 100;
  int max_message_leaves = 0;
  int max_message_nesting_depth = 2;

  std::string request_body{R"("")"};
  const Json expected_body{
      R"({"status": 413, "title": "Payload Too Large", "detail": "request_json_leaves_limits_exceeded"})"_json};
  std::string status_code = "413";

  testReqJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                            request_body, expected_body, status_code);
}

// Name: ReqJsonBodyConfChecksAll_leavesExceededLimit3
// Description: Checking request JSON body with configured size, leaves and
// depth where the JSON body exceeds configured number of leaves limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, ReqJsonBodyConfChecksAll_leavesExceededLimit3) {
  int max_message_bytes = 16000000;
  int max_message_leaves = 16000;
  int max_message_nesting_depth = 2;

  int original_message_leaves = 16001;
  Json json_request_body{R"({})"_json};
  for (int idx = 0; idx < original_message_leaves; idx++) {
    json_request_body.push_back({fmt::format("k{}", idx), fmt::format("v{}", idx)});
  }
  std::string request_body = json_request_body.dump();

  const Json expected_body{
      R"({"status": 413, "title": "Payload Too Large", "detail": "request_json_leaves_limits_exceeded"})"_json};
  std::string status_code = "413";

  testReqJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                            request_body, expected_body, status_code);
}

// Name: ReqJsonBodyConfChecksAll_depthExceededLimit1
// Description: Checking request JSON body with configured size, leaves and
// depth where the JSON body exceeds configured depth limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, ReqJsonBodyConfChecksAll_depthExceededLimit1) {
  int max_message_bytes = 100;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 2;

  std::string request_body{R"({"k1":{"k1.1":{"k1.1.1":"v1.1.1"}}, "k2":"v2", "k3":"v3"})"};
  const Json expected_body{
      R"({"status": 413, "title": "Payload Too Large", "detail": "request_json_depth_limits_exceeded"})"_json};
  std::string status_code = "413";

  testReqJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                            request_body, expected_body, status_code);
}

// Name: ReqJsonBodyConfChecksAll_depthExceededLimit2
// Description: Checking request JSON body with configured size, leaves and
// depth where the JSON body exceeds configured depth limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, ReqJsonBodyConfChecksAll_depthExceededLimit2) {
  int max_message_bytes = 100;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 0;

  std::string request_body{R"({"k1":"v1"})"};
  const Json expected_body{
      R"({"status": 413, "title": "Payload Too Large", "detail": "request_json_depth_limits_exceeded"})"_json};
  std::string status_code = "413";

  testReqJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                            request_body, expected_body, status_code);
}

// Name: ReqJsonBodyConfChecksAll_depthExceededLimit3
// Description: Checking request JSON body with configured size, leaves and 
// depth where the JSON body exceeds configured depth limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, ReqJsonBodyConfChecksAll_depthExceededLimit3) {
  int max_message_bytes = 16000000;
  int max_message_leaves = 16000;
  int max_message_nesting_depth = 32;

  int original_message_depth = 33;
  Json json_request_body = createNestedJson(original_message_depth);
  std::string request_body  = json_request_body.dump();

  const Json expected_body{R"({"status": 413, "title": "Payload Too Large", "detail": "request_json_depth_limits_exceeded"})"_json};
  std::string status_code = "413";

  testReqJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth, request_body, expected_body, status_code);
}

// Name: ReqJsonBodyConfChecksAll_invalidJsonBody
// Description: Checking request JSON body with configured size, leaves and
// depth where the JSON body is invalid.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, ReqJsonBodyConfChecksAll_invalidJsonBody) {
  int max_message_bytes = 100;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 2;

  // Send fake downstream request with fake invalid JSON body
  // The fake body is an invalid JSON: last closing } is missing
  std::string request_body{R"({"k1":"v1")"};
  const Json expected_body{
      R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_body"})"_json};
  std::string status_code = "400";

  testReqJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                            request_body, expected_body, status_code);
}

// Name: ReqJsonBodyConfChecksAll_leavesExceededLimit_invalidJsonBody
// Description: Checking request JSON body with configured size, leaves and
// depth where the JSON body exceeds configured number of leaves limit
// first and then the JSON body is invalid.
// Expected Result: Corresponding local reply is sent for leaves check.
TEST_P(EricProxyFilterJsonConfChecksTest,
       ReqJsonBodyConfChecksAll_leavesExceededLimit_invalidJsonBody) {
  int max_message_bytes = 100;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 2;

  std::string request_body{R"({"k1":"v1", "k2":"v2", "k3":"v3", "k4":"v4")"};
  const Json expected_body{
      R"({"status": 413, "title": "Payload Too Large", "detail": "request_json_leaves_limits_exceeded"})"_json};
  std::string status_code = "413";

  testReqJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                            request_body, expected_body, status_code);
}

// Name: ReqJsonBodyConfChecksAll_leavesExceededLimit_depthExceededLimit
// Description: Checking request JSON body with configured size, leaves and
// depth where the JSON body exceeds configured number of leaves limit
// first and then it exceeds configured depth limit.
// Expected Result: Corresponding local reply is sent for depth check.
TEST_P(EricProxyFilterJsonConfChecksTest,
       ReqJsonBodyConfChecksAll_leavesExceededLimit_depthExceededLimit) {
  int max_message_bytes = 100;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 2;

  std::string request_body{
      R"({"k1":"v1", "k2":"v2", "k3":"v3", "k4":"v4", "k5":{"k5.1":{"k5.1.1":"v5.1.1"}}})"};
  const Json expected_body{
      R"({"status": 413, "title": "Payload Too Large", "detail": "request_json_leaves_limits_exceeded"})"_json};
  std::string status_code = "413";

  testReqJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                            request_body, expected_body, status_code);
}

// Name: ReqJsonBodyConfChecksAll_depthExceededLimit_leavesExceededLimit
// Description: Checking request JSON body with configured size, leaves and
// depth where the JSON body exceeds configured depth limit first and then
// it exceeds configured number of leaves limit.
// Expected Result: Corresponding local reply is sent for depth check.
TEST_P(EricProxyFilterJsonConfChecksTest,
       ReqJsonBodyConfChecksAll_depthExceededLimit_leavesExceededLimit) {
  int max_message_bytes = 100;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 2;

  std::string request_body{
      R"({"k1":"v1", "k2":"v2", "k3":"v3", "k4":{"k4.1":{"k4.1.1":"v4.1.1"}}})"};
  const Json expected_body{
      R"({"status": 413, "title": "Payload Too Large", "detail": "request_json_depth_limits_exceeded"})"_json};
  std::string status_code = "413";

  testReqJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                            request_body, expected_body, status_code);
}

//------------------------- END TEST REQUEST JSON BODY --------------------------------

//------------------------ BEGIN TEST RESPONSE JSON BODY ------------------------------

// Name: RespJsonBodyConfChecksAll_sizeExceededLimit1
// Description: Checking response JSON body with configured size, leaves and
// depth where the JSON body exceeds size limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, RespJsonBodyConfChecksAll_sizeExceededLimit1) {
  int max_message_bytes = 100;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 2;

  int original_message_bytes = 101;
  std::string response_body = "";
  for (int idx = 0; idx < original_message_bytes - 2; idx++) {
    absl::StrAppend(&response_body, "a");
  }
  response_body = "\"" + response_body + "\"";

  const Json expected_body{
      R"({"status": 500, "title": "Internal Server Error", "cause": "INSUFFICIENT_RESOURCES", "detail": "response_payload_too_large"})"_json};
  std::string status_code = "500";

  testRespJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                             response_body, expected_body, status_code);
}

// Name: RespJsonBodyConfChecksAll_sizeExceededLimit2
// Description: Checking response JSON body with configured size, leaves and
// depth where the JSON body exceeds size limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, RespJsonBodyConfChecksAll_sizeExceededLimit2) {
  int max_message_bytes = 0;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 2;

  std::string response_body{R"("")"};
  const Json expected_body{
      R"({"status": 500, "title": "Internal Server Error", "cause": "INSUFFICIENT_RESOURCES", "detail": "response_payload_too_large"})"_json};
  std::string status_code = "500";

  testRespJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                             response_body, expected_body, status_code);
}

// Name: RespJsonBodyConfChecksAll_sizeExceededLimit3
// Description: Checking response JSON body with configured size, leaves and
// depth where the JSON body exceeds size limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, RespJsonBodyConfChecksAll_sizeExceededLimit3) {
  int max_message_bytes = 16000000;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 2;

  int original_message_bytes = 16000001;
  std::string response_body = "";
  for (int idx = 0; idx < original_message_bytes - 2; idx++) {
    absl::StrAppend(&response_body, "a");
  }
  response_body = "\"" + response_body + "\"";

  const Json expected_body{
      R"({"status": 500, "title": "Internal Server Error", "cause": "INSUFFICIENT_RESOURCES", "detail": "response_payload_too_large"})"_json};
  std::string status_code = "500";

  testRespJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                             response_body, expected_body, status_code);
}

// Name: RespJsonBodyConfChecksAll_leavesExceededLimit1
// Description: Checking response JSON body with configured size, leaves and
// depth where the JSON body exceeds configured number of leaves limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, RespJsonBodyConfChecksAll_leavesExceededLimit1) {
  int max_message_bytes = 100;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 2;

  std::string response_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3", "k4":"v4"})"};
  const Json expected_body{
      R"({"status": 500, "title": "Internal Server Error", "cause": "INSUFFICIENT_RESOURCES", "detail": "response_json_leaves_limits_exceeded"})"_json};
  std::string status_code = "500";

  testRespJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                             response_body, expected_body, status_code);
}

// Name: RespJsonBodyConfChecksAll_leavesExceededLimit2
// Description: Checking response JSON body with configured size, leaves and
// depth where the JSON body exceeds configured number of leaves limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, RespJsonBodyConfChecksAll_leavesExceededLimit2) {
  int max_message_bytes = 100;
  int max_message_leaves = 0;
  int max_message_nesting_depth = 2;

  std::string response_body{R"("")"};
  const Json expected_body{
      R"({"status": 500, "title": "Internal Server Error", "cause": "INSUFFICIENT_RESOURCES", "detail": "response_json_leaves_limits_exceeded"})"_json};
  std::string status_code = "500";

  testRespJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                             response_body, expected_body, status_code);
}

// Name: RespJsonBodyConfChecksAll_leavesExceededLimit3
// Description: Checking response JSON body with configured size, leaves and
// depth where the JSON body exceeds configured number of leaves limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, RespJsonBodyConfChecksAll_leavesExceededLimit3) {
  int max_message_bytes = 16000000;
  int max_message_leaves = 16000;
  int max_message_nesting_depth = 2;

  int original_message_leaves = 16001;
  Json json_response_body{R"({})"_json};
  for (int idx = 1; idx <= original_message_leaves; idx++) {
    json_response_body.push_back({fmt::format("k{}", idx), fmt::format("v{}", idx)});
  }
  std::string response_body = json_response_body.dump();

  const Json expected_body{
      R"({"status": 500, "title": "Internal Server Error", "cause": "INSUFFICIENT_RESOURCES", "detail": "response_json_leaves_limits_exceeded"})"_json};
  std::string status_code = "500";

  testRespJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                             response_body, expected_body, status_code);
}

// Name: RespJsonBodyConfChecksAll_depthExceededLimit1
// Description: Checking response JSON body with configured size, leaves and
// depth where the JSON body exceeds configured depth limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, RespJsonBodyConfChecksAll_depthExceededLimit1) {
  int max_message_bytes = 100;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 2;

  std::string response_body{R"({"k1":{"k1.1":{"k1.1.1":"v1.1.1"}}, "k2":"v2", "k3":"v3"})"};
  const Json expected_body{
      R"({"status": 500, "title": "Internal Server Error", "cause": "INSUFFICIENT_RESOURCES", "detail": "response_json_depth_limits_exceeded"})"_json};
  std::string status_code = "500";

  testRespJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                             response_body, expected_body, status_code);
}

// Name: RespJsonBodyConfChecksAll_depthExceededLimit2
// Description: Checking response JSON body with configured size, leaves and
// depth where the JSON body exceeds configured depth limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, RespJsonBodyConfChecksAll_depthExceededLimit2) {
  int max_message_bytes = 100;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 0;

  std::string response_body{R"({"k1":"v1"})"};
  const Json expected_body{
      R"({"status": 500, "title": "Internal Server Error", "cause": "INSUFFICIENT_RESOURCES", "detail": "response_json_depth_limits_exceeded"})"_json};
  std::string status_code = "500";

  testRespJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                             response_body, expected_body, status_code);
}

// Name: RespJsonBodyConfChecksAll_depthExceededLimit3
// Description: Checking response JSON body with configured size, leaves and
// depth where the JSON body exceeds configured depth limit.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, RespJsonBodyConfChecksAll_depthExceededLimit3) {
  int max_message_bytes = 16000000;
  int max_message_leaves = 16000;
  int max_message_nesting_depth = 32;

  int original_message_depth = 33;
  Json json_response_body = createNestedJson(original_message_depth);
  std::string response_body = json_response_body.dump();

  const Json expected_body{
      R"({"status": 500, "title": "Internal Server Error", "cause": "INSUFFICIENT_RESOURCES", "detail": "response_json_depth_limits_exceeded"})"_json};
  std::string status_code = "500";

  testRespJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                             response_body, expected_body, status_code);
}

// Name: RespJsonBodyConfChecksAll_invalidJsonBody
// Description: Checking response JSON body with configured size, leaves and
// depth where the JSON body is invalid.
// Expected Result: Corresponding local reply is sent.
TEST_P(EricProxyFilterJsonConfChecksTest, RespJsonBodyConfChecksAll_invalidJsonBody) {
  int max_message_bytes = 100;
  int max_message_leaves = 3;
  int max_message_nesting_depth = 2;

  // Send fake upstream response with fake invalid JSON body
  // The fake body is an invalid JSON: last closing } is missing
  std::string response_body{R"({"k1":"v1")"};
  const Json expected_body{
      R"({"status": 500, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_invalid_json_body"})"_json};
  std::string status_code = "500";

  testRespJsonBodyConfChecks(max_message_bytes, max_message_leaves, max_message_nesting_depth,
                             response_body, expected_body, status_code);
}

//------------------------- END TEST RESPONSE JSON BODY -------------------------------

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
