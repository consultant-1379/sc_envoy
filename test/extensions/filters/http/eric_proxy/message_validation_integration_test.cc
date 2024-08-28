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

class EricProxyFilterMessageValidationIntegrationTest : public HttpIntegrationTest,
                                          public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterMessageValidationIntegrationTest() : HttpIntegrationTest(
    Http::CodecClient::Type::HTTP1,
    GetParam(),
    EricProxyFilterMessageValidationIntegrationTest::ericProxyHttpBaseConfig()
  ) {}

  void SetUp() override {}

  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);

    HttpIntegrationTest::initialize();
  }

  // Common base configuration
  std::string ericProxyHttpBaseConfig() {
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
  )EOF", Platform::null_device_path));
  }

  // Configuration for create body action
  const std::string config_action_create_body = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp_router
  node_type: SCP
  own_internal_port: 80
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - in_req_screening
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  response_filter_cases:
    in_response_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          chf_pool: in_resp_screening
  filter_cases:
    - name: in_req_screening
      filter_rules:
      - name: create_json_body
        condition:
          term_boolean: true
        actions:
        - action_create_body:
            name: "create request body"
            content: '{"message": "new request body"}'
            content_type: "application/json"
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
    - name: in_resp_screening
      filter_rules:
      - name: create_json_body
        condition:
          term_boolean: true
        actions:
        - action_create_body:
            name: "create response body"
            content: '{"message": "new response body"}'
            content_type: "application/json"
)EOF";

  // Configuration for create body action of type text
  const std::string config_action_create_body_text = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp_router
  node_type: SCP
  own_internal_port: 80
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - in_req_screening
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  response_filter_cases:
    in_response_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          chf_pool: in_resp_screening
  filter_cases:
    - name: in_req_screening
      filter_rules:
      - name: create_json_body
        condition:
          term_boolean: true
        actions:
        - action_create_body:
            name: "create request body"
            content: "new request text body"
            content_type: "application/text"
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
    - name: in_resp_screening
      filter_rules:
      - name: create_json_body
        condition:
          term_boolean: true
        actions:
        - action_create_body:
            name: "create response body"
            content: "new response text body"
            content_type: "application/text"
)EOF";

  // Configuration for create body action with variables and no body
  const std::string config_action_create_body_var_no_body = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp_router
  node_type: SCP
  own_internal_port: 80
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - in_req_screening
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  response_filter_cases:
    in_response_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          chf_pool: in_resp_screening
  filter_cases:
    - name: in_req_screening
      filter_data:
      - name: message_from_req_json_body
        body_json_pointer: "/message"
        variable_name: message_from_req_json_body
      filter_rules:
      - name: create_json_body
        condition:
          op_not:
            arg1:
              op_exists: {arg1: {term_var: 'message_from_req_json_body'}}
        actions:
        - action_add_header:
            name: x-req-body-1
            value:
              term_string: "message variable from request json body does not exist"
        - action_create_body:
            name: "create request body"
            content: '{"message": "new request body"}'
            content_type: "application/json"
      - name: message_variable_in_json_body
        condition:
          op_exists: {arg1: {term_var: 'message_from_req_json_body'}}
        actions:
        - action_add_header:
            name: x-req-body-2
            value:
              term_var: 'message_from_req_json_body'
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
    - name: in_resp_screening
      filter_data:
      - name: message_from_resp_json_body
        body_json_pointer: "/message"
        variable_name: message_from_resp_json_body
      filter_rules:
      - name: create_json_body
        condition:
          op_not:
            arg1:
              op_exists: {arg1: {term_var: 'message_from_resp_json_body'}}
        actions:
        - action_add_header:
            name: x-resp-body-1
            value:
              term_string: "message variable from response json body does not exist"
        - action_create_body:
            name: "create response body"
            content: '{"message": "new response body"}'
            content_type: "application/json"
      - name: message_variable_in_json_body
        condition:
          op_exists: {arg1: {term_var: 'message_from_resp_json_body'}}
        actions:
        - action_add_header:
            name: x-resp-body-2
            value:
              term_var: 'message_from_resp_json_body'
)EOF";

  // Configuration for create body action with variables and valid JSON body
  const std::string config_action_create_body_var_with_body = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp_router
  node_type: SCP
  own_internal_port: 80
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - in_req_screening
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  response_filter_cases:
    in_response_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          chf_pool: in_resp_screening
  filter_cases:
    - name: in_req_screening
      filter_data:
      - name: message_from_req_json_body
        body_json_pointer: "/message"
        variable_name: message_from_req_json_body
      filter_rules:
      - name: create_json_body
        condition:
          op_exists: {arg1: {term_var: 'message_from_req_json_body'}}
        actions:
        - action_add_header:
            name: x-req-body-1
            value:
              term_var: 'message_from_req_json_body'
        - action_create_body:
            name: "create request body"
            content: '{"message": "new request body"}'
            content_type: "application/json"
      - name: message_variable_in_json_body
        condition:
          op_exists: {arg1: {term_var: 'message_from_req_json_body'}}
        actions:
        - action_add_header:
            name: x-req-body-2
            value:
              term_var: 'message_from_req_json_body'
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
    - name: in_resp_screening
      filter_data:
      - name: message_from_resp_json_body
        body_json_pointer: "/message"
        variable_name: message_from_resp_json_body
      filter_rules:
      - name: create_json_body
        condition:
          op_exists: {arg1: {term_var: 'message_from_resp_json_body'}}
        actions:
        - action_add_header:
            name: x-resp-body-1
            value:
              term_var: 'message_from_resp_json_body'
        - action_create_body:
            name: "create response body"
            content: '{"message": "new response body"}'
            content_type: "application/json"
      - name: message_variable_in_json_body
        condition:
          op_exists: {arg1: {term_var: 'message_from_resp_json_body'}}
        actions:
        - action_add_header:
            name: x-resp-body-2
            value:
              term_var: 'message_from_resp_json_body'
)EOF";

  // Configuration for op_isvalidjson condition
  const std::string config_condition_op_isvalidjson = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp_router
  node_type: SCP
  own_internal_port: 80
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - in_req_screening
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  response_filter_cases:
    in_response_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          chf_pool: in_resp_screening
  filter_cases:
    - name: in_req_screening
      filter_rules:
      - name: valid_json_body
        condition:
          op_isvalidjson: {request_body: true}
        actions:
        - action_add_header:
            name: x-req-body
            value:
              term_string: "valid json request body"
      - name: invalid_json_body
        condition:
          op_not: {arg1: {op_isvalidjson: {request_body: true}}}
        actions:
        - action_add_header:
            name: x-req-body
            value:
              term_string: "invalid json request body"
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
    - name: in_resp_screening
      filter_rules:
      - name: valid_json_body
        condition:
          op_isvalidjson: {response_body: true}
        actions:
        - action_add_header:
            name: x-resp-body
            value:
              term_string: "valid json response body"
      - name: invalid_json_body
        condition:
          op_not: {arg1: {op_isvalidjson: {response_body: true}}}
        actions:
        - action_add_header:
            name: x-resp-body
            value:
              term_string: "invalid json response body"
)EOF";

  // Configuration for op_isvalidjson condition with inverse request and response.
  // This means in_request_screening case will check for response body and
  // in_resp_screening case will check for request body.
  const std::string config_condition_op_isvalidjson_inverse = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp_router
  node_type: SCP
  own_internal_port: 80
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - in_req_screening
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  response_filter_cases:
    in_response_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          chf_pool: in_resp_screening
  filter_cases:
    - name: in_req_screening
      filter_rules:
      - name: valid_json_body
        condition:
          op_isvalidjson: {response_body: true}
        actions:
        - action_add_header:
            name: x-resp-body
            value:
              term_string: "valid json response body"
      - name: invalid_json_body
        condition:
          op_not: {arg1: {op_isvalidjson: {response_body: true}}}
        actions:
        - action_add_header:
            name: x-resp-body
            value:
              term_string: "invalid json response body"
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
    - name: in_resp_screening
      filter_rules:
      - name: valid_json_body
        condition:
          op_isvalidjson: {request_body: true}
        actions:
        - action_add_header:
            name: x-req-body
            value:
              term_string: "valid json request body"
      - name: invalid_json_body
        condition:
          op_not: {arg1: {op_isvalidjson: {request_body: true}}}
        actions:
        - action_add_header:
            name: x-req-body
            value:
              term_string: "invalid json request body"
)EOF";

  // Configuration for op_isvalidjson condition with create body action
  const std::string config_condition_op_isvalidjson_action_create_body = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp_router
  node_type: SCP
  own_internal_port: 80
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - in_req_screening
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  response_filter_cases:
    in_response_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          chf_pool: in_resp_screening
  filter_cases:
    - name: in_req_screening
      filter_rules:
      - name: invalid_json_body
        condition:
          op_not: {arg1: {op_isvalidjson: {request_body: true}}}
        actions:
        - action_add_header:
            name: x-req-body-1
            value:
              term_string: "invalid json request body"
        - action_create_body:
            name: "create request body"
            content: '{"message": "new request body"}'
            content_type: "application/json"
      - name: valid_json_body
        condition:
          op_isvalidjson: {request_body: true}
        actions:
        - action_add_header:
            name: x-req-body-2
            value:
              term_string: "valid json request body"
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
    - name: in_resp_screening
      filter_rules:
      - name: invalid_json_body
        condition:
          op_not: {arg1: {op_isvalidjson: {response_body: true}}}
        actions:
        - action_add_header:
            name: x-resp-body-1
            value:
              term_string: "invalid json response body"
        - action_create_body:
            name: "create response body"
            content: '{"message": "new response body"}'
            content_type: "application/json"
      - name: valid_json_body
        condition:
          op_isvalidjson: {response_body: true}
        actions:
        - action_add_header:
            name: x-resp-body-2
            value:
              term_string: "valid json response body"
)EOF";

};

/************************************************************************************** 

------------------------------ BEGIN TEST SUITES --------------------------------------

*************************************************************************************** */

//----------------------- BEGIN TEST ACTION CREATE BODY -------------------------------

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterMessageValidationIntegrationTest, 
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

// Name: TestActionCreateBody_NoBody
// Description: A create body action is configured to create a 
// new body for both the request and response.
// A sample request and a corresponding response without bodies are sent.
// Expected Result:
// - A new request body is created.
// - A new response body is created.
// - The content-type header is added according to the content type of the new body.
// - The content-length header is added according to the size of the new body.
TEST_P(EricProxyFilterMessageValidationIntegrationTest, TestActionCreateBody_NoBody) {
  initializeFilter(config_action_create_body);
  // Send fake downstream request
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"}
  };

  Json expected_request_body{R"({"message": "new request body"})"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};

  Json expected_response_body{R"({"message": "new response body"})"_json};

  upstream_request_->encodeHeaders(response_headers, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its new body
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_request_body, Json::parse(upstream_request_->body().toString()));

  // Verify new body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_response_body, Json::parse(response->body()));

  codec_client_->close();
}

// Name: TestActionCreateBody_ValidJsonBody
// Description: A create body action is configured to remove the existing valid JSON body
// and create a new JSON body for both the request and response.
// A sample request and a corresponding response with fake valid JSON bodies are sent.
// Expected Result:
// - The body of the request is removed and a new body is created.
// - The body of the response is removed and a new body is created.
// - The content-type header is adapted to the content type of the new body.
// - The content-length header is adapted to the size of the new body.
TEST_P(EricProxyFilterMessageValidationIntegrationTest, TestActionCreateBody_ValidJsonBody) {
  initializeFilter(config_action_create_body);
  // Send fake downstream request with fake valid JSON body
  std::string request_body{R"({"source":"request body"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(request_body.length())}
  };

  Json expected_request_body{R"({"message": "new request body"})"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(request_headers, request_body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response with fake valid JSON body
  std::string response_body{R"({"source":"response body"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(response_body.length())}
  };

  Json expected_response_body{R"({"message": "new response body"})"_json};

  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(response_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its new body
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_request_body, Json::parse(upstream_request_->body().toString()));

  // Verify new body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_response_body, Json::parse(response->body()));

  codec_client_->close();
}

// Name: TestActionCreateBody_ValidJsonBody_NoContentTypeHeader
// Description: A create body action is configured to remove the existing valid JSON body
// and create a new JSON body for both the request and response.
// A sample request and a corresponding response with fake valid JSON bodies are sent
// without content-type and content-length header.
// Expected Result:
// - The body of the request is removed and a new body is created.
// - The body of the response is removed and a new body is created.
// - The content-type header is added according to the content type of the new body.
// - The content-length header is added according to the size of the new body.
TEST_P(EricProxyFilterMessageValidationIntegrationTest, TestActionCreateBody_ValidJsonBody_NoContentTypeHeader) {
  initializeFilter(config_action_create_body);
  // Send fake downstream request with fake valid JSON body
  std::string request_body{R"({"source":"request body"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"}
  };

  Json expected_request_body{R"({"message": "new request body"})"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(request_headers, request_body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response with fake valid JSON body
  std::string response_body{R"({"source":"response body"})"};
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};

  Json expected_response_body{R"({"message": "new response body"})"_json};

  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(response_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its new body
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_request_body, Json::parse(upstream_request_->body().toString()));

  // Verify new body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_response_body, Json::parse(response->body()));

  codec_client_->close();
}

// Name: TestActionCreateBody_ValidJsonBody_WrongContentTypeHeader
// Description: A create body action is configured to remove the existing valid JSON body
// and create a new JSON body for both the request and response.
// A sample request and a corresponding response with fake valid JSON bodies are sent
// with wrong content-type header.
// Expected Result:
// - The body of the request is removed and a new body is created.
// - The body of the response is removed and a new body is created.
// - The content-type header is adapted to the content type of the new body.
// - The content-length header is adapted to the size of the new body.
TEST_P(EricProxyFilterMessageValidationIntegrationTest, TestActionCreateBody_ValidJsonBody_WrongContentTypeHeader) {
  initializeFilter(config_action_create_body);
  // Send fake downstream request with fake valid JSON body
  std::string request_body{R"({"source":"request body"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-type", "application/text"},
      {"content-length", std::to_string(request_body.length())}
  };

  Json expected_request_body{R"({"message": "new request body"})"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(request_headers, request_body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response with fake valid JSON body
  std::string response_body{R"({"source":"response body"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/text"},
      {"content-length", std::to_string(response_body.length())}
  };

  Json expected_response_body{R"({"message": "new response body"})"_json};

  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(response_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its new body
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_request_body, Json::parse(upstream_request_->body().toString()));

  // Verify new body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_response_body, Json::parse(response->body()));

  codec_client_->close();
}

// Name: TestActionCreateBody_InvalidJsonBody
// Description: A create body action is configured to remove the existing invalid JSON body
// and create a new JSON body for both the request and response.
// A sample request and a corresponding response with fake bodies are sent.
// Expected Result:
// - The body of the request is removed and a new body is created.
// - The body of the response is removed and a new body is created.
// - The content-type header is adapted to the content type of the new body.
// - The content-length header is adapted to the size of the new body.
TEST_P(EricProxyFilterMessageValidationIntegrationTest, TestActionCreateBody_InvalidJsonBody) {
  initializeFilter(config_action_create_body);
  // Send fake downstream request with fake invalid JSON body
  // The fake body is an invalid JSON: last closing } is missing
  std::string request_body{R"({"source":"request body")"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(request_body.length())}
  };

  Json expected_request_body{R"({"message": "new request body"})"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(request_headers, request_body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response with fake invalid JSON body
  // The fake body is an invalid JSON: last closing } is missing
  std::string response_body{R"({"source":"response body")"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(response_body.length())}
  };

  Json expected_response_body{R"({"message": "new response body"})"_json};

  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(response_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its new body
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_request_body, Json::parse(upstream_request_->body().toString()));

  // Verify new body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_response_body, Json::parse(response->body()));

  codec_client_->close();
}

// Name: TestActionCreateBody_TextBody
// Description: A create body action is configured to remove the existing text body
// and create a text body for both the request and response.
// A sample request and a corresponding response with fake text bodies are sent.
// Expected Result:
// - The body of the request is removed and a new body is created.
// - The body of the response is removed and a new body is created.
// - The content-type header is adapted to the content type of the new body.
// - The content-length header is adapted to the size of the new body.
TEST_P(EricProxyFilterMessageValidationIntegrationTest, TestActionCreateBody_TextBody) {
  initializeFilter(config_action_create_body_text);
  // Send fake downstream request with fake text body
  std::string request_body{R"("source is request text body")"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-type", "application/text"},
      {"content-length", std::to_string(request_body.length())}
  };

  std::string expected_request_body{R"(new request text body)"};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(request_headers, request_body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response with fake text body
  std::string response_body{R"("source is response text body")"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/text"},
      {"content-length", std::to_string(response_body.length())}
  };

  std::string expected_response_body{R"(new response text body)"};

  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(response_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its new body
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/text"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_request_body, upstream_request_->body().toString());

  // Verify new body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-type", "application/text"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_response_body, response->body());

  codec_client_->close();
}

// Name: TestActionCreateBody_Var_NoBody
// Description: A create body action is configured to create a 
// new body for both the request and response.
// A sample request and a corresponding response without bodies are sent.
// Expected Result:
// - A new request body is created.
// - A new response body is created.
// - The content-type header is added according to the content type of the new body.
// - The content-length header is added according to the size of the new body.
// - The variables from the body are created after create body action.
TEST_P(EricProxyFilterMessageValidationIntegrationTest, TestActionCreateBody_Var_NoBody) {
  initializeFilter(config_action_create_body_var_no_body);
  // Send fake downstream request
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"}
  };

  Json expected_request_body{R"({"message": "new request body"})"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};

  Json expected_response_body{R"({"message": "new response body"})"_json};

  upstream_request_->encodeHeaders(response_headers, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its new body
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-req-body-1", "message variable from request json body does not exist"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-req-body-2", "new request body"));
  EXPECT_EQ(expected_request_body, Json::parse(upstream_request_->body().toString()));

  // Verify new body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-resp-body-1", "message variable from response json body does not exist"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-resp-body-2", "new response body"));
  EXPECT_EQ(expected_response_body, Json::parse(response->body()));

  codec_client_->close();
}

// Name: TestActionCreateBody_Var_ValidJsonBody
// Description: A create body action is configured to remove the existing valid JSON body
// and create a new JSON body for both the request and response.
// A sample request and a corresponding response with fake valid JSON bodies are sent.
// Expected Result:
// - The body of the request is removed and a new body is created.
// - The body of the response is removed and a new body is created.
// - The content-type header is adapted to the content type of the new body.
// - The content-length header is adapted to the size of the new body.
// - The variables from the body are updated after create body action.
TEST_P(EricProxyFilterMessageValidationIntegrationTest, TestActionCreateBody_Var_ValidJsonBody) {
  initializeFilter(config_action_create_body_var_with_body);
  // Send fake downstream request with fake valid JSON body
  std::string request_body{R"({"message":"original request body"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(request_body.length())}
  };

  Json expected_request_body{R"({"message": "new request body"})"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(request_headers, request_body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response with fake valid JSON body
  std::string response_body{R"({"message":"original response body"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(response_body.length())}
  };

  Json expected_response_body{R"({"message": "new response body"})"_json};

  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(response_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its new body
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-req-body-1", "original request body"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-req-body-2", "new request body"));
  EXPECT_EQ(expected_request_body, Json::parse(upstream_request_->body().toString()));

  // Verify new body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-resp-body-1", "original response body"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-resp-body-2", "new response body"));
  EXPECT_EQ(expected_response_body, Json::parse(response->body()));

  codec_client_->close();
}

//------------------------ END TEST ACTION CREATE BODY --------------------------------

//-------------------- BEGIN TEST CONDITION IS VALID JSON -----------------------------

// Name: TestConditionOpIsValidJson_NoBody
// Description: A condition op_isvalidjson is configured to check if the request
// and response bodies are valid JSON. "No Body" is considered as invalid JSON.
// A sample request and a corresponding response without bodies are sent.
// Expected Result:
// - The op_isvalidjson evaluates to False.
TEST_P(EricProxyFilterMessageValidationIntegrationTest, TestConditionOpIsValidJson_NoBody) {
  initializeFilter(config_condition_op_isvalidjson);
  // Send fake downstream request
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"}
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};

  upstream_request_->encodeHeaders(response_headers, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its new body
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-req-body", "invalid json request body"));

  // Verify new body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-resp-body", "invalid json response body"));

  codec_client_->close();
}

// Name: TestConditionOpIsValidJson_ValidJsonBody
// Description: A condition op_isvalidjson is configured to check if the request
// and response bodies are valid JSON. "No Body" is considered as invalid JSON.
// A sample request and a corresponding response with fake valid JSON bodies are sent.
// Expected Result:
// - The op_isvalidjson evaluates to True.
TEST_P(EricProxyFilterMessageValidationIntegrationTest, TestConditionOpIsValidJson_ValidJsonBody) {
  initializeFilter(config_condition_op_isvalidjson);
  // Send fake downstream request with fake valid JSON body
  std::string request_body{R"({"source":"request body"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(request_body.length())}
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(request_headers, request_body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response with fake valid JSON body
  std::string response_body{R"({"source":"response body"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(response_body.length())}
  };

  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(response_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its new body
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-req-body", "valid json request body"));

  // Verify new body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-resp-body", "valid json response body"));

  codec_client_->close();
}

// Name: TestConditionOpIsValidJson_InvalidJsonBody
// Description: A condition op_isvalidjson is configured to check if the request
// and response bodies are valid JSON. "No Body" is considered as invalid JSON.
// A sample request and a corresponding response with fake invalid JSON bodies are sent.
// Expected Result:
// - The op_isvalidjson evaluates to False.
TEST_P(EricProxyFilterMessageValidationIntegrationTest, TestConditionOpIsValidJson_InvalidJsonBody) {
  initializeFilter(config_condition_op_isvalidjson);
  // Send fake downstream request with fake invalid JSON body
  // The fake body is an invalid JSON: last closing } is missing
  std::string request_body{R"({"source":"request body")"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(request_body.length())}
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(request_headers, request_body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response with fake invalid JSON body
  // The fake body is an invalid JSON: last closing } is missing
  std::string response_body{R"({"source":"response body")"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(response_body.length())}
  };

  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(response_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its new body
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-req-body", "invalid json request body"));

  // Verify new body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-resp-body", "invalid json response body"));

  codec_client_->close();
}

// Name: TestConditionOpIsValidJson_ValidJsonReqBody_InvalidJsonRespBody
// Description: A condition op_isvalidjson is configured to check if the request
// and response bodies are valid JSON. "No Body" is considered as invalid JSON.
// A sample request with fake valid JSON body and a corresponding response with fake invalid JSON body are sent.
// Expected Result:
// - The op_isvalidjson evaluates to True for request body and False for response body.
TEST_P(EricProxyFilterMessageValidationIntegrationTest, TestConditionOpIsValidJson_ValidJsonReqBody_InvalidJsonRespBody) {
  initializeFilter(config_condition_op_isvalidjson);
  // Send fake downstream request with fake valid JSON body
  std::string request_body{R"({"source":"request body"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(request_body.length())}
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(request_headers, request_body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response with fake invalid JSON body
  // The fake body is an invalid JSON: last closing } is missing
  std::string response_body{R"({"source":"response body")"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(response_body.length())}
  };

  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(response_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its new body
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-req-body", "valid json request body"));

  // Verify new body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-resp-body", "invalid json response body"));

  codec_client_->close();
}

// Name: TestConditionOpIsValidJson_ValidJsonBody_Inverse
// Description: A condition op_isvalidjson is configured to check if the request
// and response bodies are valid JSON. "No Body" is considered as invalid JSON.
// A sample request and a corresponding response with fake valid JSON bodies are sent.
// Expected Result:
// - The op_isvalidjson evaluates to True for request body and False for response body.
TEST_P(EricProxyFilterMessageValidationIntegrationTest, TestConditionOpIsValidJson_ValidJsonBody_Inverse) {
  initializeFilter(config_condition_op_isvalidjson_inverse);
  // Send fake downstream request with fake valid JSON body
  std::string request_body{R"({"source":"request body"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(request_body.length())}
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(request_headers, request_body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response with fake valid JSON body
  std::string response_body{R"({"source":"response body"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(response_body.length())}
  };

  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(response_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its new body
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-resp-body", "invalid json response body"));

  // Verify new body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-req-body", "valid json request body"));

  codec_client_->close();
}

// Name: TestConditionOpIsValidJson_ActionCreateBody_NoBody
// Description: A condition op_isvalidjson is configured to check if the request
// and response bodies are valid JSON. "No Body" is considered as invalid JSON.
// A sample request and a corresponding response without bodies are sent.
// Expected Result:
// - The op_isvalidjson evaluates to False for the first time and then, to True 
//   after action_create_body for both request and response.
TEST_P(EricProxyFilterMessageValidationIntegrationTest, TestConditionOpIsValidJson_ActionCreateBody_NoBody) {
  initializeFilter(config_condition_op_isvalidjson_action_create_body);
  // Send fake downstream request
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"}
  };

  Json expected_request_body{R"({"message": "new request body"})"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};

  Json expected_response_body{R"({"message": "new response body"})"_json};

  upstream_request_->encodeHeaders(response_headers, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its new body
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-req-body-1", "invalid json request body"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-req-body-2", "valid json request body"));
  EXPECT_EQ(expected_request_body, Json::parse(upstream_request_->body().toString()));

  // Verify new body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-resp-body-1", "invalid json response body"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-resp-body-2", "valid json response body"));
  EXPECT_EQ(expected_response_body, Json::parse(response->body()));

  codec_client_->close();
}

// Name: TestConditionOpIsValidJson_ActionCreateBody_InvalidJsonBody
// Description: A condition op_isvalidjson is configured to check if the request
// and response bodies are valid JSON. "No Body" is considered as invalid JSON.
// A sample request and a corresponding response with fake invalid JSON bodies are sent.
// Expected Result:
// - The op_isvalidjson evaluates to False for the first time and then, to True 
//   after action_create_body for both request and response.
TEST_P(EricProxyFilterMessageValidationIntegrationTest, TestConditionOpIsValidJson_ActionCreateBody_InvalidJsonBody) {
  initializeFilter(config_condition_op_isvalidjson_action_create_body);
  // Send fake downstream request with fake invalid JSON body
  // The fake body is an invalid JSON: last closing } is missing
  std::string request_body{R"({"source":"request body")"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(request_body.length())}
  };

  Json expected_request_body{R"({"message": "new request body"})"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(request_headers, request_body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response with fake invalid JSON body
  // The fake body is an invalid JSON: last closing } is missing
  std::string response_body{R"({"source":"response body")"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(response_body.length())}
  };

  Json expected_response_body{R"({"message": "new response body"})"_json};

  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(response_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its new body
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "chf_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-req-body-1", "invalid json request body"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-req-body-2", "valid json request body"));
  EXPECT_EQ(expected_request_body, Json::parse(upstream_request_->body().toString()));

  // Verify new body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-resp-body-1", "invalid json response body"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-resp-body-2", "valid json response body"));
  EXPECT_EQ(expected_response_body, Json::parse(response->body()));

  codec_client_->close();
}

//---------------------- END TEST CONDITION IS VALID JSON -----------------------------

/************************************************************************************** 

--------------------------------- END TEST SUITES -------------------------------------

*************************************************************************************** */

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
