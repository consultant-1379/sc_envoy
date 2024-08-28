#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include <iostream>

#include "config_utils/pluggable_configurator.h"
#include "config_utils/endpoint_md_cluster_md_configurator.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterFirewallTest : public PluggableConfigurator {

public:
  EricProxyFilterFirewallTest() = default;

  //------------------------------------------------------------------------
  // Common configuration to test firewall checks for SEPP
  // with request coming from RP in external network and
  // response coming from own network
  std::string configCommonFirewallChecksExtToInt() {
    return fmt::format(R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: Sepp router
  node_type: SEPP
  own_fqdn: sepp.5gc.mnc123.mcc456.3gppnetwork.org
  own_external_port: 443
  default_allowed_service_operations:
  - api_names:
    - nnrf-disc
    api_versions:
    - v1
    is_notification: false
    resource_matchers:
    - /nf-instances
    http_methods:
    - GET
  - api_names:
    - namf-comm
    api_versions:
    - v1
    resource_matchers:
    - /some-amf-operation
    http_methods:
    - POST
  - api_names:
    - namf-comm
    - nchf-comm
    api_versions:
    - v1
    is_notification: false
    resource_matchers:
    - /some-amf-operation
    http_methods:
    - GET
    - POST
  - api_versions:
    - v1
    is_notification: false
    resource_matchers:
    - /some-ausf-operation
    http_methods:
    - GET
  - api_names:
    - Nnrf_NFManagement_NFStatusNotify
    is_notification: true
    http_methods:
    - POST
  request_filter_cases:
    routing:
      ext_nw:
        name: external_network
        ext_nw_fc_config_list:
        - per_rp_fc_config:
            rp_to_fc_map:
              rp_1: default_routing
              rp_2: default_routing
            default_fc_for_rp_not_found: default_routing
  rp_name_table : rp_san_to_name
  key_value_tables:
  - name: rp_san_to_name
    entries:
    - key: sepp.5gc.mnc123.mcc123.3gppnetwork.org
      value: rp_1
    - key: sepp.5gc.mnc456.mcc456.3gppnetwork.org
      value: rp_2
    - key: sepp.5gc.mnc789.mcc789.3gppnetwork.org
      value: rp_3
    - key: sepp.5gc.mnc321.mcc321.3gppnetwork.org
      value: rp_4
  filter_cases:
  - name: default_routing
    filter_rules:
    - name: nrf_pool
      condition:
        op_and:
          arg1:
            op_exists:
              arg1:
                term_reqheader: '3gpp-Sbi-target-apiRoot'
          arg2:
            op_or:
              arg1:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_reqheader: '3gpp-Sbi-target-apiRoot'
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: 'http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80'
              arg2:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_reqheader: '3gpp-Sbi-target-apiRoot'
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: 'http://nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80'
      actions:
      - action_route_to_pool:
          pool_name:
            term_string: nrf_pool
          routing_behaviour: PREFERRED
          preserve_if_indirect: TARGET_API_ROOT
          preferred_target:
            term_header: "3gpp-Sbi-target-apiRoot"
  roaming_partners:
  - name: rp_1
    pool_name: sepp_pool_1
    request_validation:
      check_service_operations:
        custom_allowed_service_operations:
        - api_names:
          - nnrf-disc
          api_versions:
          - v1
          is_notification: false
          resource_matchers:
          - /nf-instances
          http_methods:
          - GET
        custom_denied_service_operations:
        - api_names:
          - nnrf-disc
          api_versions:
          - v1
          is_notification: false
          resource_matchers:
          - /nf-instances
          http_methods:
          - POST
        report_event: true
        action_on_failure:
          drop_message: true
  - name: rp_2
    pool_name: sepp_pool_2
    request_validation:
      check_service_operations:
        custom_allowed_service_operations:
        - api_names:
          - nnrf-disc
          api_versions:
          - v1
          is_notification: false
          resource_matchers:
          - /nf-instances
          http_methods:
          - GET
        report_event: true
        action_on_failure:
          forward_unmodified_message: true
  - name: rp_3
    pool_name: sepp_pool_3
    request_validation:
      check_service_operations:
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 400
            title: "Unauthorized Service Operation"
            detail: "request_unauthorized_service_operation"
            message_format: JSON
  - name: rp_4
    pool_name: sepp_pool_4
)EOF"
    );
  }

  //------------------------------------------------------------------------
  // Configuration for the Envoy Header-to-Metadata filter. Useful to inject Metadata
  // into test-cases. This filter is not present in official deployments.
  const std::string config_header_to_metadata{R"EOF(
name: envoy.filters.http.header_to_metadata
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.header_to_metadata.v3.Config
  request_rules:
    - header: x-eric-sepp-test-san
      on_header_present:
        metadata_namespace: eric.proxy.test
        key: test_san
        type: STRING
    - header: x-eric-sepp-rp-name
      on_header_present:
        metadata_namespace: eric.proxy.test
        key: test_rp_name
        type: STRING
)EOF"};

  //------------------------------------------------------------------------
  // Common functions for access logging
  void useAccessLog(const Json& json_format, bool omit_empty_values) {
    access_log_name_ = TestEnvironment::temporaryPath(TestUtility::uniqueFilename());
    // configure metadata filter
    envoy::config::accesslog::v3::AccessLogFilter access_log_filter;
    envoy::config::accesslog::v3::MetadataFilter md_filter;
    md_filter.mutable_match_if_key_not_found()->set_value(false);
    auto* matcher = md_filter.mutable_matcher();
    matcher->set_filter("eric_event");
    matcher->mutable_path()->Add()->set_key("is_event");
    matcher->mutable_value()->set_present_match(true);
    access_log_filter.mutable_metadata_filter()->MergeFrom(md_filter);
    ASSERT_TRUE(config_helper_.setAccessLog(access_log_name_, json_format, omit_empty_values,
                                            access_log_filter));
  }

  std::string waitForAccessLog(const std::string& filename, uint32_t entry = 0,
                               bool allow_excess_entries = false,
                               Network::ClientConnection* client_connection = nullptr) {

    // Wait a max of 1s for logs to flush to disk.
    std::string contents;
    const int num_iterations = TSAN_TIMEOUT_FACTOR * 1000;
    for (int i = 0; i < num_iterations; ++i) {
      contents = TestEnvironment::readFileToStringForTest(filename);
      std::vector<std::string> entries = absl::StrSplit(contents, '\n', absl::SkipEmpty());
      if (entries.size() >= entry + 1) {
        // Often test authors will waitForAccessLog() for multiple requests, and
        // not increment the entry number for the second wait. Guard against that.
        EXPECT_TRUE(allow_excess_entries || entries.size() == entry + 1)
            << "Waiting for entry index " << entry
            << " but it was not the last entry as there were " << entries.size() << "\n"
            << contents;
        return entries[entry];
      }
      if (i % 25 == 0 && client_connection != nullptr) {
        // The QUIC default delayed ack timer is 25ms. Wait for any pending ack timers to expire,
        // then run dispatcher to send any pending acks.
        client_connection->dispatcher().run(Envoy::Event::Dispatcher::RunType::NonBlock);
      }
      absl::SleepFor(absl::Milliseconds(1));
    }

    return "";
  }

  //------------------------------------------------------------------------
  // Common function for message validation checks tests with different scenarios
  void testMessageValidationChecks(
      ClusterConfigurator& cluster_config, const std::vector<std::string>& filter_configs,
      const Http::TestRequestHeaderMapImpl& request_headers, const std::string& request_body,
      const Http::TestResponseHeaderMapImpl& response_headers, const std::string& response_body,
      const bool& drop_request, const absl::optional<uint32_t>& expected_upstream_index,
      const Http::TestRequestHeaderMapImpl& expected_request_headers,
      const std::string& expected_request_body,
      const Http::TestResponseHeaderMapImpl& expected_response_headers,
      const std::string& expected_response_body,
      const std::map<std::string, absl::optional<std::string>>& expected_access_log) {

    Json access_log_format{R"({
  "version": "%EVENT(LOG_VERSION)%",
  "timestamp": "%START_TIME(%FT%T.%3f%z)%",
  "severity": "%EVENT(SEVERITY)%",
  "message": "%EVENT(MSG)%",
  "metadata": {
    "application_id": "%EVENT(APPL_ID)%",
    "function": "sepp-function",
    "proc_id": "envoy",
    "ul_id": "%EVENT(ULID)%",
    "category": "%EVENT(CATEGORY)%"
    },
  "service_id": "%EVENT(SRC_TYPE)%",
  "extra_data": {
    "sc_event": {
      "id": "SC_EVENT_SEPP_%STREAM_ID%-%EVENT(INDEX)%",
      "type": "%EVENT(TYPE)%",
      "version": "%EVENT(VERSION)%",
      "log_type": "sc-event",
      "action": "%EVENT(ACTION)%",
      "roaming_partner": "%EVENT(RP)%",
      "sub_spec": "%EVENT(SUB_SPEC)%"
    },
    "onap": {
      "nfVendorName": "Ericsson AB"
    }
  },
  "subject": "admin",
  "resp_message": "%EVENT(RESP_MSG)%",
  "resp_code": "%EVENT(RESP_CODE)%"
  })"_json};

    useAccessLog(access_log_format, true);

    initConfig(filter_configs, cluster_config);

    // Send request
    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response;
    if (request_body.empty()) {
      response = codec_client_->makeHeaderOnlyRequest(request_headers);          
    } else {
      response = codec_client_->makeRequestWithBody(request_headers, request_body);
    }

    if (drop_request) {
      // Drops the request by resetting stream
      ASSERT_TRUE(response->waitForReset());
    } else if (!expected_upstream_index.has_value()) {
      // Wait for the response and close the fake upstream connection for local reply
      ASSERT_TRUE(response->waitForEndStream());

      // Verify downstream response
      EXPECT_THAT(response->headers(), Http::IsSupersetOfHeaders(expected_response_headers));
      EXPECT_EQ(response->headers().getContentLengthValue(),
                fmt::format("{}", response->body().size()));
      EXPECT_EQ(response->body(), expected_response_body);
    } else {
      waitForNextUpstreamRequest(expected_upstream_index.value());

      // Send response
      upstream_request_->encodeHeaders(response_headers, false);
      Buffer::OwnedImpl response_data(response_body);
      upstream_request_->encodeData(response_data, true);

      // Wait for the response and close the fake upstream connection
      ASSERT_TRUE(response->waitForEndStream());

      // Verify upstream request
      EXPECT_THAT(upstream_request_->headers(),
                  Http::IsSupersetOfHeaders(expected_request_headers));
      EXPECT_EQ(upstream_request_->body().toString(), expected_request_body);

      // Verify downstream response
      EXPECT_THAT(response->headers(), Http::IsSupersetOfHeaders(expected_response_headers));
      EXPECT_EQ(response->headers().getContentLengthValue(),
                fmt::format("{}", response->body().size()));
      EXPECT_EQ(response->body(), expected_response_body);
    }

    if (!expected_access_log.empty()) {
      // Verify access logs
      auto access_log = waitForAccessLog(access_log_name_);
      ENVOY_LOG(debug, "Access Log: " + access_log);
      verifyJsonElements(expected_access_log, Json::parse(access_log));
    } else {
      ASSERT_TRUE(waitForAccessLog(access_log_name_).empty());
    }

    codec_client_->close();
  }

  // Helper function for checking if some JSON elements are present in a JSON body.
  // The map of expected elements contains as key a json-pointer and the expected value at that position.
  // If a value is absl::nullopt, then this function will check for the **absence** of
  // the key/json-pointer/element.
  void verifyJsonElements(
      const std::map<std::string, absl::optional<std::string>>& expected_json_elements,
      const Json& json_body) {
    for (const auto& expected_json_element : expected_json_elements) {
      try {
        auto json_pointer = Json::json_pointer(expected_json_element.first);
        // Check for absence of the element/key (because no value given)
        if (!expected_json_element.second.has_value()) {
          auto err = absl::StrCat("JSON element ", expected_json_element.first,
            " should not be there but is present");
          EXPECT_FALSE(json_body.contains(json_pointer)) << err;
          continue;
        }
        // Check for presence of the element/key
        auto err = absl::StrCat("JSON element ", expected_json_element.first,
          " is not present, but should");
        EXPECT_TRUE(json_body.contains(json_pointer)) << err;
        // Compare actual value with expected value
        auto actual_value = json_body.at(json_pointer);
        auto expected_value = Json::parse(expected_json_element.second.value());
        EXPECT_EQ(actual_value, expected_value);
      } catch (const Json::parse_error& e) {
        ENVOY_LOG(trace, e.what());
        ASSERT(e.what() == nullptr);
      }
    }
  }
};

/**************************************************************************************

------------------------------ BEGIN TEST SUITES --------------------------------------

*************************************************************************************** */

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterFirewallTest,
                         testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest())));

// ------------------- UNAUTHORIZED SERVICE OPERATION CHECKS --------------------------

// Name: MessageValidation_ExtToInt_RP1_USOC_CustomAllowedMatch_CheckPassed_Forward
// Description: Checks the request validation for request coming from RP1 where the
// Unauthorized Service Operation Checks detect a match in the custom_allowed_list
//
// Expected Result: 
//    Request and response headers and bodies are forwarded.
//    No event is reported.
TEST_P(EricProxyFilterFirewallTest,
       MessageValidation_ExtToInt_RP1_USOC_CustomAllowedMatch_CheckPassed_Forward) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("nrf_pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}}))
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}})));

  std::vector<std::string> filter_configs = {
      config_header_to_metadata,
      configCommonFirewallChecksExtToInt()};

  std::string request_body{};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc123.mcc123.3gppnetwork.org"}};

  std::string response_body{R"({"key":"value"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = false;
  absl::optional<uint32_t> expected_upstream_index = 0;

  std::string expected_request_body = request_body;
  Http::TestRequestHeaderMapImpl expected_request_headers{{"x-eric-proxy", "///"},
                                                          {"x-cluster", "nrf_pool"}};

  std::string expected_response_body = response_body;
  Http::TestResponseHeaderMapImpl expected_response_headers{
      {":status", "200"},
      {"content-length", std::to_string(expected_response_body.length())},
      {"content-type", "application/json"}};

  std::map<std::string, absl::optional<std::string>> expected_access_log{};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: MessageValidation_ExtToInt_RP1_USOC_CustomDeniedMatch_CheckFailed_Dropped
// Description: Checks the request validation for request coming from RP1 where the
// Unauthorized Service Operation Checks detect a match in the custom_denied_list
//
// action_on_failure: dropped
// report_event: true
//
// Expected Result: 
//    Request headers and bodies are dropped.
//    An event is reported.
TEST_P(EricProxyFilterFirewallTest,
       MessageValidation_ExtToInt_RP1_USOC_CustomDeniedMatch_CheckFailed_Dropped) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("nrf_pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}}))
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}})));

  std::vector<std::string> filter_configs = {
      config_header_to_metadata,
      configCommonFirewallChecksExtToInt()};

  std::string request_body{R"({"key":"value"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc123.mcc123.3gppnetwork.org"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  std::string response_body{};
  Http::TestResponseHeaderMapImpl response_headers{};

  bool drop_request = true;
  absl::optional<uint32_t> expected_upstream_index = absl::nullopt;

  std::string expected_request_body{};
  Http::TestRequestHeaderMapImpl expected_request_headers{};

  std::string expected_response_body{};
  Http::TestResponseHeaderMapImpl expected_response_headers{};

  std::map<std::string, absl::optional<std::string>> expected_access_log = {
      {"/resp_code", absl::nullopt},
      {"/resp_message", absl::nullopt},
      {"/message", R"("Unauthorized service operation detected")"},
      {"/extra_data/sc_event/log_type", R"("sc-event")"},
      {"/extra_data/sc_event/type", R"("ERIC_EVENT_SC_UNAUTHORIZED_SERVICE_OPERATION_DETECTED")"},
      {"/extra_data/sc_event/action", R"("dropped")"},
      {"/extra_data/sc_event/roaming_partner", R"("rp_1")"},
      {"/extra_data/sc_event/sub_spec",
       R"({"unauthorized_service_operation":{"attributes":{"api_name":"nnrf-disc","api_version":"v1","resource":"/nf-instances","http_method":"POST","message_type":"service_request"}}})"}};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: MessageValidation_ExtToInt_RP1_USOC_DefaultAllowedMatch_CheckPassed_Forward
// Description: Checks the request validation for request coming from RP1 where the
// Unauthorized Service Operation Checks detect a match in the default_allowed_list
//
// Expected Result: 
//    Request and response headers and bodies are forwarded.
//    No event is reported.
TEST_P(EricProxyFilterFirewallTest,
       MessageValidation_ExtToInt_RP1_USOC_DefaultAllowedMatch_CheckPassed_Forward) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("nrf_pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}}))
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}})));

  std::vector<std::string> filter_configs = {
      config_header_to_metadata,
      configCommonFirewallChecksExtToInt()};

  std::string request_body{R"({"key":"value"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/namf-comm/v1/some-amf-operation"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc123.mcc123.3gppnetwork.org"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  std::string response_body{R"({"key":"value"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = false;
  absl::optional<uint32_t> expected_upstream_index = 0;

  std::string expected_request_body = request_body;
  Http::TestRequestHeaderMapImpl expected_request_headers{{"x-eric-proxy", "///"},
                                                          {"x-cluster", "nrf_pool"}};

  std::string expected_response_body = response_body;
  Http::TestResponseHeaderMapImpl expected_response_headers{
      {":status", "200"},
      {"content-length", std::to_string(expected_response_body.length())},
      {"content-type", "application/json"}};

  std::map<std::string, absl::optional<std::string>> expected_access_log{};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: MessageValidation_ExtToInt_RP1_USOC_DefaultAllowedMatch_MultipleApiNames_CheckPassed_Forward
// Description: Checks the request validation for request coming from RP1 where the Unauthorized Service
// Operation Checks detect a match in the default_allowed_list with multiple API names in configuration
//
// Expected Result: 
//    Request and response headers and bodies are forwarded.
//    No event is reported.
TEST_P(EricProxyFilterFirewallTest,
       MessageValidation_ExtToInt_RP1_USOC_DefaultAllowedMatch_MultipleApiNames_CheckPassed_Forward) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("nrf_pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}}))
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}})));

  std::vector<std::string> filter_configs = {
      config_header_to_metadata,
      configCommonFirewallChecksExtToInt()};

  std::string request_body{};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/namf-comm/v1/some-amf-operation"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc123.mcc123.3gppnetwork.org"}};

  std::string response_body{R"({"key":"value"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = false;
  absl::optional<uint32_t> expected_upstream_index = 0;

  std::string expected_request_body = request_body;
  Http::TestRequestHeaderMapImpl expected_request_headers{{"x-eric-proxy", "///"},
                                                          {"x-cluster", "nrf_pool"}};

  std::string expected_response_body = response_body;
  Http::TestResponseHeaderMapImpl expected_response_headers{
      {":status", "200"},
      {"content-length", std::to_string(expected_response_body.length())},
      {"content-type", "application/json"}};

  std::map<std::string, absl::optional<std::string>> expected_access_log{};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: MessageValidation_ExtToInt_RP1_USOC_DefaultAllowedMatch_NoApiNames_CheckPassed_Forward
// Description: Checks the request validation for request coming from RP1 where the Unauthorized Service
// Operation Checks detect a match in the default_allowed_list with no API names in configuration
//
// Expected Result: 
//    Request and response headers and bodies are forwarded.
//    No event is reported.
TEST_P(EricProxyFilterFirewallTest,
       MessageValidation_ExtToInt_RP1_USOC_DefaultAllowedMatch_NoApiNames_CheckPassed_Forward) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("nrf_pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}}))
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}})));

  std::vector<std::string> filter_configs = {
      config_header_to_metadata,
      configCommonFirewallChecksExtToInt()};

  std::string request_body{};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nausf-comm/v1/some-ausf-operation"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc123.mcc123.3gppnetwork.org"}};

  std::string response_body{R"({"key":"value"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = false;
  absl::optional<uint32_t> expected_upstream_index = 0;

  std::string expected_request_body = request_body;
  Http::TestRequestHeaderMapImpl expected_request_headers{{"x-eric-proxy", "///"},
                                                          {"x-cluster", "nrf_pool"}};

  std::string expected_response_body = response_body;
  Http::TestResponseHeaderMapImpl expected_response_headers{
      {":status", "200"},
      {"content-length", std::to_string(expected_response_body.length())},
      {"content-type", "application/json"}};

  std::map<std::string, absl::optional<std::string>> expected_access_log{};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: MessageValidation_ExtToInt_RP1_USOC_DefaultAllowedMatch_Notification_CheckPassed_Forward
// Description: Checks the request validation for request coming from RP1 where the Unauthorized
// Service Operation Checks detect a match in the default_allowed_list for notification
//
// Expected Result: 
//    Request and response headers and bodies are forwarded.
//    No event is reported.
TEST_P(EricProxyFilterFirewallTest,
       MessageValidation_ExtToInt_RP1_USOC_DefaultAllowedMatch_Notification_CheckPassed_Forward) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("nrf_pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}}))
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}})));

  std::vector<std::string> filter_configs = {
      config_header_to_metadata,
      configCommonFirewallChecksExtToInt()};

  std::string request_body{R"({"key":"value"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc123.mcc123.3gppnetwork.org"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  std::string response_body{R"({"key":"value"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = false;
  absl::optional<uint32_t> expected_upstream_index = 0;

  std::string expected_request_body = request_body;
  Http::TestRequestHeaderMapImpl expected_request_headers{{"x-eric-proxy", "///"},
                                                          {"x-cluster", "nrf_pool"}};

  std::string expected_response_body = response_body;
  Http::TestResponseHeaderMapImpl expected_response_headers{
      {":status", "200"},
      {"content-length", std::to_string(expected_response_body.length())},
      {"content-type", "application/json"}};

  std::map<std::string, absl::optional<std::string>> expected_access_log{};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: MessageValidation_ExtToInt_RP2_USOC_NoMatch_CheckFailed_Forward
// Description: Checks the request validation for request coming from RP2 where the
// Unauthorized Service Operation Checks detect no match in any list
//
// action_on_failure: forward_unmodified
// report_event: true
//
// Expected Result: 
//    Request and response headers and bodies are forwarded.
//    An event is reported.
TEST_P(EricProxyFilterFirewallTest,
       MessageValidation_ExtToInt_RP2_USOC_NoMatch_CheckFailed_Forward) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("nrf_pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}}))
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}})));

  std::vector<std::string> filter_configs = {
      config_header_to_metadata,
      configCommonFirewallChecksExtToInt()};

  std::string request_body{R"({"key":"value"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nsmf-comm/v1/some-smf-operation"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_2"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc456.mcc456.3gppnetwork.org"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  std::string response_body{R"({"key":"value"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = false;
  absl::optional<uint32_t> expected_upstream_index = 0;

  std::string expected_request_body = request_body;
  Http::TestRequestHeaderMapImpl expected_request_headers{{"x-eric-proxy", "///"},
                                                          {"x-cluster", "nrf_pool"}};

  std::string expected_response_body = response_body;
  Http::TestResponseHeaderMapImpl expected_response_headers{
      {":status", "200"},
      {"content-length", std::to_string(expected_response_body.length())},
      {"content-type", "application/json"}};

  std::map<std::string, absl::optional<std::string>> expected_access_log = {
      {"/resp_code", absl::nullopt},
      {"/resp_message", absl::nullopt},
      {"/message", R"("Unauthorized service operation detected")"},
      {"/extra_data/sc_event/log_type", R"("sc-event")"},
      {"/extra_data/sc_event/type", R"("ERIC_EVENT_SC_UNAUTHORIZED_SERVICE_OPERATION_DETECTED")"},
      {"/extra_data/sc_event/action", R"("ignored")"},
      {"/extra_data/sc_event/roaming_partner", R"("rp_2")"},
      {"/extra_data/sc_event/sub_spec",
       R"({"unauthorized_service_operation":{"attributes":{"api_name":"nsmf-comm","api_version":"v1","resource":"/some-smf-operation","http_method":"POST","message_type":"service_request"}}})"}};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: MessageValidation_ExtToInt_RP3_USOC_NoMatch_CheckFailed_RespondWithError
// Description: Checks the request validation for request coming from RP3 where
// the Unauthorized Service Operation Checks detect no match in any list
//
// action_on_failure: respond_with_error
// report_event: true
//
// Expected Result: 
//    Request headers and bodies are rejected with error.
//    An event is reported.
TEST_P(EricProxyFilterFirewallTest,
       MessageValidation_ExtToInt_RP3_USOC_NoMatch_CheckFailed_RespondWithError) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("nrf_pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}}))
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}})));

  std::vector<std::string> filter_configs = {
      config_header_to_metadata,
      configCommonFirewallChecksExtToInt()};

  std::string request_body{R"({"key":"value"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nsmf-comm/v1/some-smf-operation"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_3"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc789.mcc789.3gppnetwork.org"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  std::string response_body{};
  Http::TestResponseHeaderMapImpl response_headers{};

  bool drop_request = false;
  absl::optional<uint32_t> expected_upstream_index = absl::nullopt;

  std::string expected_request_body = request_body;
  Http::TestRequestHeaderMapImpl expected_request_headers{{"x-eric-proxy", "///"},
                                                          {"x-cluster", "nrf_pool"}};

  std::string expected_response_body{R"({"status": 400, "title": "Unauthorized Service Operation", "detail": "request_unauthorized_service_operation"})"};
  Http::TestResponseHeaderMapImpl expected_response_headers{
      {":status", "400"},
      {"content-length", std::to_string(expected_response_body.length())},
      {"content-type", "application/problem+json"},
      {"server", "envoy"}};

  std::map<std::string, absl::optional<std::string>> expected_access_log = {
      {"/resp_code", R"("400")"},
      {"/resp_message", R"("request_unauthorized_service_operation")"},
      {"/message", R"("Unauthorized service operation detected")"},
      {"/extra_data/sc_event/log_type", R"("sc-event")"},
      {"/extra_data/sc_event/type", R"("ERIC_EVENT_SC_UNAUTHORIZED_SERVICE_OPERATION_DETECTED")"},
      {"/extra_data/sc_event/action", R"("rejected")"},
      {"/extra_data/sc_event/roaming_partner", R"("rp_3")"},
      {"/extra_data/sc_event/sub_spec",
       R"({"unauthorized_service_operation":{"attributes":{"api_name":"nsmf-comm","api_version":"v1","resource":"/some-smf-operation","http_method":"POST","message_type":"service_request"}}})"}};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: MessageValidation_ExtToInt_RP4_USOC_NotConfigured_Forward
// Description: No request validation configured for request coming from RP4
//
// Expected Result: 
//    Request and response headers and bodies are forwarded.
//    No event is reported.
TEST_P(EricProxyFilterFirewallTest,
       MessageValidation_ExtToInt_RP4_USOC_NotConfigured_Forward) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("nrf_pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}}))
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}})));

  std::vector<std::string> filter_configs = {
      config_header_to_metadata,
      configCommonFirewallChecksExtToInt()};

  std::string request_body{R"({"key":"value"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nsmf-comm/v1/some-smf-operation"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_4"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc321.mcc321.3gppnetwork.org"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  std::string response_body{R"({"key":"value"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = false;
  absl::optional<uint32_t> expected_upstream_index = 0;

  std::string expected_request_body = request_body;
  Http::TestRequestHeaderMapImpl expected_request_headers{{"x-eric-proxy", "///"},
                                                          {"x-cluster", "nrf_pool"}};

  std::string expected_response_body = response_body;
  Http::TestResponseHeaderMapImpl expected_response_headers{
      {":status", "200"},
      {"content-length", std::to_string(expected_response_body.length())},
      {"content-type", "application/json"}};

  std::map<std::string, absl::optional<std::string>> expected_access_log{};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
