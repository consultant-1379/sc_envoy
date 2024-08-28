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

class EricProxyFilterFirewallTest : public PluggableConfiguratorMultipart {

public:
  EricProxyFilterFirewallTest() {
    body_suffix = "\r\n--boundary\r\nContent-type: text/plain\r\n\r\nThis is a text/binary ";
    body_suffix.push_back('\0'); // necessary because otherwise the \0 terminates the string
    body_suffix.append("\002body part\r\n--boundary--\r\n..and an epilogue");
    mp_overhead = body_prefix.length() + body_suffix.length();
  }

  // Multipart body prefix+suffix
  const std::string content_type{"multipart/related; boundary=boundary"};
  const std::string body_prefix{"This is the preamble"
                                "\r\n--boundary\r\nContent-type: application/json\r\n\r\n"};
  std::string body_suffix;
  int mp_overhead;
  
  //------------------------------------------------------------------------
  // Common configuration to test firewall checks for SEPP
  // with request coming from RP in external network and
  // response coming from own network
  std::string configCommonFirewallChecksExtToInt(const std::string& request_check_headers = "",
                                                 const std::string& response_check_headers = "",
                                                 int global_max_message_bytes = 100, int per_rp_max_message_bytes = 50) {
    return fmt::format(R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: Sepp router
  node_type: SEPP
  own_fqdn: sepp.5gc.mnc123.mcc456.3gppnetwork.org
  own_external_port: 443
  request_validation:
    check_message_bytes:
      max_message_bytes: {global_max_message_bytes}
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 413
          title: "Payload Too Large"
          detail: "request_payload_too_large"
          message_format: JSON
    check_json_leaves:
      max_message_leaves: 6
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 413
          title: "Payload Too Large"
          detail: "request_json_leaves_limits_exceeded"
          message_format: JSON
    check_json_depth:
      max_message_nesting_depth: 4
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 413
          title: "Payload Too Large"
          detail: "request_json_depth_limits_exceeded"
          message_format: JSON
  response_validation:
    check_message_bytes:
      max_message_bytes: {global_max_message_bytes}
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 500
          title: "Internal Server Error"
          cause: "INSUFFICIENT_RESOURCES"
          detail: "response_payload_too_large"
          message_format: JSON
    check_json_leaves:
      max_message_leaves: 6
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 500
          title: "Internal Server Error"
          cause: "INSUFFICIENT_RESOURCES"
          detail: "response_json_leaves_limits_exceeded"
          message_format: JSON
    check_json_depth:
      max_message_nesting_depth: 4
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
{request_check_headers}
      check_message_bytes:
        max_message_bytes: {per_rp_max_message_bytes}
        report_event: true
        action_on_failure:
          drop_message: true
      check_json_syntax:
        report_event: true
        action_on_failure:
          drop_message: true
      check_json_leaves:
        max_message_leaves: 3
        report_event: true
        action_on_failure:
          drop_message: true
      check_json_depth:
        max_message_nesting_depth: 2
        report_event: true
        action_on_failure:
          drop_message: true
    response_validation:
{response_check_headers}
      check_message_bytes:
        max_message_bytes: {per_rp_max_message_bytes}
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            cause: "INSUFFICIENT_RESOURCES"
            detail: "response_payload_too_large"
            message_format: JSON
      check_json_syntax:
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            detail: "response_invalid_json_body"
            message_format: JSON
      check_json_leaves:
        max_message_leaves: 3
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            cause: "INSUFFICIENT_RESOURCES"
            detail: "response_json_leaves_limits_exceeded"
            message_format: JSON
      check_json_depth:
        max_message_nesting_depth: 2
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            cause: "INSUFFICIENT_RESOURCES"
            detail: "response_json_depth_limits_exceeded"
            message_format: JSON
  - name: rp_2
    pool_name: sepp_pool_2
    request_validation:
      check_message_bytes:
        max_message_bytes: {per_rp_max_message_bytes}
        report_event: true
        action_on_failure:
          drop_message: true
      check_json_syntax:
        report_event: true
        action_on_failure:
          drop_message: true
    response_validation:
      check_message_bytes:
        max_message_bytes: {per_rp_max_message_bytes}
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            cause: "INSUFFICIENT_RESOURCES"
            detail: "response_payload_too_large"
            message_format: JSON
      check_json_syntax:
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            detail: "response_invalid_json_body"
            message_format: JSON
  - name: rp_3
    pool_name: sepp_pool_3
)EOF",
                       "request_check_headers"_a = request_check_headers,
                       "response_check_headers"_a = response_check_headers,
                       "global_max_message_bytes"_a = global_max_message_bytes,
                       "per_rp_max_message_bytes"_a = per_rp_max_message_bytes);
  }

  //------------------------------------------------------------------------
  // Common configuration to test firewall checks for SEPP
  // with request coming from own network and response
  // coming from RP in external network
  std::string configCommonFirewallChecksIntToExt(const std::string& request_check_headers = "",
                                                 const std::string& response_check_headers = "",
                                                 int global_max_message_bytes = 100, int per_rp_max_message_bytes = 50) {
    return fmt::format(R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.5gc.mnc123.mcc456.3gppnetwork.org
  own_internal_port: 80
  request_validation:
    check_message_bytes:
      max_message_bytes: {global_max_message_bytes}
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 413
          title: "Payload Too Large"
          detail: "request_payload_too_large"
          message_format: JSON
    check_json_leaves:
      max_message_leaves: 6
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 413
          title: "Payload Too Large"
          detail: "request_json_leaves_limits_exceeded"
          message_format: JSON
    check_json_depth:
      max_message_nesting_depth: 4
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 413
          title: "Payload Too Large"
          detail: "request_json_depth_limits_exceeded"
          message_format: JSON
  response_validation:
    check_message_bytes:
      max_message_bytes: {global_max_message_bytes}
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 500
          title: "Internal Server Error"
          cause: "INSUFFICIENT_RESOURCES"
          detail: "response_payload_too_large"
          message_format: JSON
    check_json_leaves:
      max_message_leaves: 6
      report_event: false
      action_on_failure:
        respond_with_error:
          status: 500
          title: "Internal Server Error"
          cause: "INSUFFICIENT_RESOURCES"
          detail: "response_json_leaves_limits_exceeded"
          message_format: JSON
    check_json_depth:
      max_message_nesting_depth: 4
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
    filter_data:
    - name: apiRoot_data
      header: 3gpp-Sbi-target-apiRoot
      extractor_regex: mnc(?P<mnc>\d+).mcc(?P<mcc>\d+)
    filter_rules:
    - name: rp1_pool
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
    - name: rp2_pool
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
  roaming_partners:
  - name: rp_1
    pool_name: sepp_pool_1
    request_validation:
{request_check_headers}
      check_message_bytes:
        max_message_bytes: {per_rp_max_message_bytes}
        report_event: true
        action_on_failure:
          drop_message: true
      check_json_syntax:
        report_event: true
        action_on_failure:
          drop_message: true
      check_json_leaves:
        max_message_leaves: 3
        report_event: true
        action_on_failure:
          drop_message: true
      check_json_depth:
        max_message_nesting_depth: 2
        report_event: true
        action_on_failure:
          drop_message: true
    response_validation:
{response_check_headers}
      check_message_bytes:
        max_message_bytes: {per_rp_max_message_bytes}
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            cause: "INSUFFICIENT_RESOURCES"
            detail: "response_payload_too_large"
            message_format: JSON
      check_json_syntax:
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            detail: "response_invalid_json_body"
            message_format: JSON
      check_json_leaves:
        max_message_leaves: 3
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            cause: "INSUFFICIENT_RESOURCES"
            detail: "response_json_leaves_limits_exceeded"
            message_format: JSON
      check_json_depth:
        max_message_nesting_depth: 2
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            cause: "INSUFFICIENT_RESOURCES"
            detail: "response_json_depth_limits_exceeded"
            message_format: JSON
  - name: rp_2
    pool_name: sepp_pool_2
)EOF",
                       "request_check_headers"_a = request_check_headers,
                       "response_check_headers"_a = response_check_headers,
                       "global_max_message_bytes"_a = global_max_message_bytes,
                       "per_rp_max_message_bytes"_a = per_rp_max_message_bytes);
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

  // Helper function to return the access log format configuration
  Json accessLogFormat() {
    return {R"({
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
  }

  //------------------------------------------------------------------------
  // Common function for message validation checks tests with different scenarios,
  void testMessageValidationChecks(
      ClusterConfigurator& cluster_config, const std::vector<std::string>& filter_configs,
      Http::TestRequestHeaderMapImpl& request_headers, const std::string& request_body,
      Http::TestResponseHeaderMapImpl& response_headers, const std::string& response_body,
      const bool& drop_request, const uint32_t& expected_upstream_index,
      Http::TestRequestHeaderMapImpl& expected_request_headers,
      const std::string& expected_request_body,
      Http::TestResponseHeaderMapImpl& expected_response_headers,
      const std::string& expected_response_body,
      const std::map<std::string, absl::optional<std::string>>& expected_access_log,
      bool adapt_expected_headers_to_multipart = true) {
    useAccessLog(accessLogFormat(), true);
    initConfig(filter_configs, cluster_config);

    IntegrationStreamDecoderPtr response;

    // Make request, single- or multipart
    if (getBodyContentType() == BodyContentType::MULTIPART_RELATED) {
      // Create multipart request body and set headers
      std::string multipart_request_body = absl::StrCat(body_prefix, request_body, body_suffix);
      request_headers.removeContentLength();
      request_headers.removeContentType();
      request_headers.addCopy(Http::LowerCaseString("content-length"),
                              std::to_string(multipart_request_body.length()));
      request_headers.addCopy(Http::LowerCaseString("content-type"), content_type);
      // Send request
      codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
      response = codec_client_->makeRequestWithBody(request_headers, multipart_request_body);
    } else {
      // Send non-multipart body request
      codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
      response = codec_client_->makeRequestWithBody(request_headers, request_body);
    }

    if (drop_request) {
      // Drops the request by resetting stream
      ASSERT_TRUE(response->waitForReset());
    } else {
      waitForNextUpstreamRequest(expected_upstream_index);

      // Send response
      if (getBodyContentType() == BodyContentType::MULTIPART_RELATED) {
        // Create multipart response body and set headers
        response_headers.removeContentLength();
        response_headers.removeContentType();
        std::string multipart_response_body = absl::StrCat(body_prefix, response_body, body_suffix);
        response_headers.addCopy(Http::LowerCaseString("content-length"),
                                 std::to_string(multipart_response_body.length()));
        response_headers.addCopy(Http::LowerCaseString("content-type"), content_type);
        upstream_request_->encodeHeaders(response_headers, false);
        Buffer::OwnedImpl response_data(multipart_response_body);
        upstream_request_->encodeData(response_data, true);
      } else { // Non-multipart body
        upstream_request_->encodeHeaders(response_headers, false);
        Buffer::OwnedImpl response_data(response_body);
        upstream_request_->encodeData(response_data, true);
      }

      // Wait for the response and close the fake upstream connection
      ASSERT_TRUE(response->waitForEndStream());

      // Verify upstream request
      if (getBodyContentType() == BodyContentType::MULTIPART_RELATED) {
        expected_request_headers.removeContentLength();
        expected_request_headers.removeContentType();
        expected_request_headers.addCopy(Http::LowerCaseString("content-length"),
                                         std::to_string(expected_request_body.length() + mp_overhead));
        expected_request_headers.addCopy(Http::LowerCaseString("content-type"), content_type);
        EXPECT_THAT(upstream_request_->headers(),
                    Http::IsSupersetOfHeaders(expected_request_headers));
        Body req_body(&(upstream_request_->body()), content_type);
        EXPECT_EQ(Json::parse(expected_request_body), *(req_body.getBodyAsJson()));
      } else {  // Non-multipart
        EXPECT_THAT(upstream_request_->headers(),
                    Http::IsSupersetOfHeaders(expected_request_headers));
        EXPECT_EQ(upstream_request_->body().toString(), expected_request_body);
      }

      // Verify downstream response
      if (getBodyContentType() == BodyContentType::MULTIPART_RELATED) {
        // Adapt expected headers to multipart (size and content-type).
        // This is usually wanted, but if we expect a direct (=error) response,
        // it's not desired.
        if (adapt_expected_headers_to_multipart) {
          expected_response_headers.removeContentLength();
          expected_response_headers.removeContentType();
          expected_response_headers.addCopy(
              Http::LowerCaseString("content-length"),
              std::to_string(expected_response_body.length() + mp_overhead));
          expected_response_headers.addCopy(Http::LowerCaseString("content-type"), content_type);
        }
        EXPECT_THAT(response->headers(), Http::IsSupersetOfHeaders(expected_response_headers));
        Body resp_body;
        resp_body.setBodyFromString(response->body(), content_type);
        EXPECT_EQ(Json::parse(expected_response_body), *(resp_body.getBodyAsJson()));
      } else {  // Non-multipart
        EXPECT_THAT(response->headers(), Http::IsSupersetOfHeaders(expected_response_headers));
        EXPECT_EQ(response->headers().getContentLengthValue(),
                  fmt::format("{}", response->body().size()));
        EXPECT_EQ(response->body(), expected_response_body);
      }
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

  // Helper function to generate a body of particular size in bytes
  std::string createBodyInBytes(const int& size_in_bytes) {
    std::string body = "";
    for (int idx = 0; idx < size_in_bytes - 2; idx++) {
      absl::StrAppend(&body, "a");
    }
    body = "\"" + body + "\"";
    return body;
  }

  // Helper function to generate a JSON body of particular number of leaves
  std::string createJsonLeaves(const int& num_leaves) {
    Json json_request_body{R"({})"_json};
    for (int idx = 0; idx < num_leaves; idx++) {
      json_request_body.push_back({fmt::format("k{}", idx), fmt::format("v{}", idx)});
    }
    return json_request_body.dump();
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

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterFirewallTest,
                         testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         testing::Values(BodyContentType::APPLICATION_JSON,
                                         BodyContentType::MULTIPART_RELATED)));

//------------------ BEGIN TEST REQUEST & RESPONSE VALIDATION -------------------------

// Name: MessageValidation_ExtToInt_RP1_allBodyChecks_allowedHeaderChecks_allChecksPass
// Description: Checking both request and response validation for request
// coming from RP1 where global request validation checks are replaced by
// local request validation checks and all checks pass.
// For header checks, only allowed header checks are performed in
// request and no header checks are performed in response.
// Expected Result: Request and response headers and bodies are forwarded.
TEST_P(EricProxyFilterFirewallTest,
       MessageValidation_ExtToInt_RP1_allBodyChecks_allowedHeaderChecks_allChecksPass) {
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

  // SEPP and external listener: only request header checks are performed
  const std::string request_check_headers{R"EOF(
      check_headers:
        allowed_headers:
          values:
            ":method": true
            ":path": true
            ":authority": true
            "3gpp-sbi-target-apiroot": true
            "x-eric-sepp-rp-name": true
            "x-eric-sepp-test-san": true
            "content-length": true
            "content-type": true
            ":scheme": true
            "x-forwarded-proto": true
            "x-request-id": true
        report_event: true
        action_on_failure:
          drop_message: true
  )EOF"};

  // SEPP and external listener: no response header checks are performed
  const std::string response_check_headers{R"EOF(
      check_headers:
        denied_headers:
          values:
            ":status": true
            "content-length": true
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            detail: "response_invalid_headers"
            message_format: JSON
  )EOF"};

  std::vector<std::string> filter_configs = {
      config_header_to_metadata,
      configCommonFirewallChecksExtToInt(request_check_headers, response_check_headers,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 100 + mp_overhead : 100,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 50 + mp_overhead : 50)};

  std::string request_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc123.mcc123.3gppnetwork.org"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  std::string response_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = false;
  uint32_t expected_upstream_index = 0;

  std::string expected_request_body = request_body;
  Http::TestRequestHeaderMapImpl expected_request_headers{{"x-eric-proxy", "///"},
                                                          {"x-cluster", "nrf_pool"}};

  std::string expected_response_body = response_body;
  Http::TestResponseHeaderMapImpl expected_response_headers{
      {":status", "200"},
      {"content-length", std::to_string(expected_response_body.length())},
      {"content-type", "application/json"}};

  std::map<std::string, absl::optional<std::string>> expected_access_log = {};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: MessageValidation_ExtToInt_RP1_allBodyChecks_deniedHeaderChecks_allChecksPass
// Description: Checking both request and response validation for request
// coming from RP1 where global request validation checks are replaced by
// local request validation checks and all checks pass.
// For header checks, only denied header checks are performed in
// request and no header checks are performed in response.
// Expected Result: Request and response headers and bodies are forwarded.
TEST_P(EricProxyFilterFirewallTest,
       MessageValidation_ExtToInt_RP1_allBodyChecks_deniedHeaderChecks_allChecksPass) {
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

  // SEPP and external listener: only request header checks are performed
  const std::string request_check_headers{R"EOF(
      check_headers:
        denied_headers:
          values:
            "denied-header1": true
            "denied-header2": true
        report_event: true
        action_on_failure:
          drop_message: true
  )EOF"};

  // SEPP and external listener: no response header checks are performed
  const std::string response_check_headers{R"EOF(
      check_headers:
        allowed_headers:
          values:
            ":status": true
            "content-length": true
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            detail: "response_invalid_headers"
            message_format: JSON
  )EOF"};

  std::vector<std::string> filter_configs = {
      config_header_to_metadata,
      configCommonFirewallChecksExtToInt(request_check_headers, response_check_headers,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 100 + mp_overhead : 100,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 50 + mp_overhead : 50)};

  std::string request_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc123.mcc123.3gppnetwork.org"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  std::string response_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = false;
  uint32_t expected_upstream_index = 0;

  std::string expected_request_body = request_body;
  Http::TestRequestHeaderMapImpl expected_request_headers{{"x-eric-proxy", "///"},
                                                          {"x-cluster", "nrf_pool"}};

  std::string expected_response_body = response_body;
  Http::TestResponseHeaderMapImpl expected_response_headers{
      {":status", "200"},
      {"content-length", std::to_string(expected_response_body.length())},
      {"content-type", "application/json"}};

  std::map<std::string, absl::optional<std::string>> expected_access_log = {};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: MessageValidation_IntToExt_RP1_allBodyChecks_allowedHeaderChecks_allChecksPass
// Description: Checking both request and response validation for response
// coming from RP1 where global response validation checks are replaced by
// local response validation checks and all checks pass.
// For header checks, only allowed header checks are performed in
// response and no header checks are performed in request.
// Expected Result: Request and response headers and bodies are forwarded.
TEST_P(EricProxyFilterFirewallTest,
       MessageValidation_IntToExt_RP1_allBodyChecks_allowedHeaderChecks_allChecksPass) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator()
          .withClusterBuilder(
              ClusterBuilder()
                  .withName("sepp_pool_1")
                  .withEndpoint(EndpointBuilder()
                                    .withHostName("sepp.5gc.mnc123.mcc123.3gppnetwork.org:443")
                                    .withHostMd({{"support", {"Indirect"}}})))
          .withClusterBuilder(
              ClusterBuilder()
                  .withName("sepp_pool_2")
                  .withEndpoint(EndpointBuilder()
                                    .withHostName("sepp.5gc.mnc456.mcc456.3gppnetwork.org:443")
                                    .withHostMd({{"support", {"Indirect"}}})));

  // SEPP and internal listener: no request header checks are performed
  const std::string request_check_headers{R"EOF(
      check_headers:
        denied_headers:
          values:
            ":method": true
            ":path": true
        report_event: true
        action_on_failure:
          drop_message: true
  )EOF"};

  // SEPP and internal listener: only response header checks are performed
  const std::string response_check_headers{R"EOF(
      check_headers:
        allowed_headers:
          values:
            ":status": true
            "content-length": true
            "content-type": true
            "x-envoy-upstream-service-time": true
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            detail: "response_invalid_headers"
            message_format: JSON
  )EOF"};

  std::vector<std::string> filter_configs = {
      configCommonFirewallChecksIntToExt(request_check_headers, response_check_headers,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 100 + mp_overhead : 100,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 50 + mp_overhead : 50)};

  std::string request_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  std::string response_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = false;
  uint32_t expected_upstream_index = 0;

  std::string expected_request_body = request_body;
  Http::TestRequestHeaderMapImpl expected_request_headers{{"x-eric-proxy", "///"},
                                                          {"x-cluster", "sepp_pool_1"}};

  std::string expected_response_body = response_body;
  Http::TestResponseHeaderMapImpl expected_response_headers{
      {":status", "200"},
      {"content-length", std::to_string(expected_response_body.length())},
      {"content-type", "application/json"}};

  std::map<std::string, absl::optional<std::string>> expected_access_log = {};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: MessageValidation_IntToExt_RP1_allBodyChecks_deniedHeaderChecks_allChecksPass
// Description: Checking both request and response validation for response
// coming from RP1 where global response validation checks are replaced by
// local response validation checks and all checks pass.
// For header checks, only denied header checks are performed in
// response and no header checks are performed in request.
// Expected Result: Request and response headers and bodies are forwarded.
TEST_P(EricProxyFilterFirewallTest,
       MessageValidation_IntToExt_RP1_allBodyChecks_deniedHeaderChecks_allChecksPass) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator()
          .withClusterBuilder(
              ClusterBuilder()
                  .withName("sepp_pool_1")
                  .withEndpoint(EndpointBuilder()
                                    .withHostName("sepp.5gc.mnc123.mcc123.3gppnetwork.org:443")
                                    .withHostMd({{"support", {"Indirect"}}})))
          .withClusterBuilder(
              ClusterBuilder()
                  .withName("sepp_pool_2")
                  .withEndpoint(EndpointBuilder()
                                    .withHostName("sepp.5gc.mnc456.mcc456.3gppnetwork.org:443")
                                    .withHostMd({{"support", {"Indirect"}}})));

  // SEPP and internal listener: no request header checks are performed
  const std::string request_check_headers{R"EOF(
      check_headers:
        allowed_headers:
          values:
            ":method": true
            ":path": true
        report_event: true
        action_on_failure:
          drop_message: true
  )EOF"};

  // SEPP and internal listener: only response header checks are performed
  const std::string response_check_headers{R"EOF(
      check_headers:
        denied_headers:
          values:
            "denied-header1": true
            "denied-header2": true
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            detail: "response_invalid_headers"
            message_format: JSON
  )EOF"};

  std::vector<std::string> filter_configs = {
      configCommonFirewallChecksIntToExt(request_check_headers, response_check_headers,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 100 + mp_overhead : 100,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 50 + mp_overhead : 50)};

  std::string request_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  std::string response_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = false;
  uint32_t expected_upstream_index = 0;

  std::string expected_request_body = request_body;
  Http::TestRequestHeaderMapImpl expected_request_headers{{"x-eric-proxy", "///"},
                                                          {"x-cluster", "sepp_pool_1"}};

  std::string expected_response_body = response_body;
  Http::TestResponseHeaderMapImpl expected_response_headers{
      {":status", "200"},
      {"content-length", std::to_string(expected_response_body.length())},
      {"content-type", "application/json"}};

  std::map<std::string, absl::optional<std::string>> expected_access_log = {};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

//------------------- END TEST REQUEST & RESPONSE VALIDATION --------------------------

//------------------------ BEGIN TEST REQUEST VALIDATION ------------------------------

// Name: RequestValidation_ExtToInt_RP1_reqAllowedHeaderCheckfails
// Description: Checking request validation for request coming from RP1
// where global request validation checks are replaced by local request
// validation checks and request allowed header check fails.
// Expected Result: Configured action on failure is triggered and request is dropped.
TEST_P(EricProxyFilterFirewallTest, RequestValidation_ExtToInt_RP1_reqAllowedHeaderCheckfails) {
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

  // SEPP and external listener: only request header checks are performed
  const std::string request_check_headers{R"EOF(
      check_headers:
        allowed_headers:
          values:
            ":method": true
            ":path": true
        report_event: true
        action_on_failure:
          drop_message: true
  )EOF"};

  // SEPP and external listener: no response header checks are performed
  const std::string response_check_headers{R"EOF(
      check_headers:
        denied_headers:
          values:
            ":status": true
            "content-length": true
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            detail: "response_invalid_headers"
            message_format: JSON
  )EOF"};

  std::vector<std::string> filter_configs = {
      config_header_to_metadata,
      configCommonFirewallChecksExtToInt(request_check_headers, response_check_headers,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 100 + mp_overhead : 100,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 50 + mp_overhead : 50)};

  std::string request_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc123.mcc123.3gppnetwork.org"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  std::string response_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = true;
  uint32_t expected_upstream_index = -1;

  std::string expected_request_body = {};
  Http::TestRequestHeaderMapImpl expected_request_headers{};

  std::string expected_response_body = {};
  Http::TestResponseHeaderMapImpl expected_response_headers{};

  std::map<std::string, absl::optional<std::string>> expected_access_log = {
      {"/resp_code", absl::nullopt},
      {"/resp_message", absl::nullopt},
      {"/message", R"("Header in received HTTP request message not allowed")"},
      {"/extra_data/sc_event/log_type", R"("sc-event")"},
      {"/extra_data/sc_event/type", R"("ERIC_EVENT_SC_HTTP_HEADER_NOT_ALLOWED")"},
      {"/extra_data/sc_event/action", R"("dropped")"},
      {"/extra_data/sc_event/roaming_partner", R"("rp_1")"},
      {"/extra_data/sc_event/sub_spec",
       R"({"headers":{"not_allowed":[":authority",":scheme","3gpp-sbi-target-apiroot","x-eric-sepp-rp-name",
       "x-eric-sepp-test-san","content-length","content-type","x-forwarded-proto","x-request-id"]}})"}};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: RequestValidation_ExtToInt_RP1_reqDeniedHeaderCheckfails
// Description: Checking request validation for request coming from RP1
// where global request validation checks are replaced by local request
// validation checks and request denied header check fails.
// Expected Result: Configured action on failure is triggered and request is dropped.
TEST_P(EricProxyFilterFirewallTest, RequestValidation_ExtToInt_RP1_reqDeniedHeaderCheckfails) {
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

  // SEPP and external listener: only request header checks are performed
  const std::string request_check_headers{R"EOF(
      check_headers:
        denied_headers:
          values:
            ":method": true
        report_event: true
        action_on_failure:
          drop_message: true
  )EOF"};

  // SEPP and external listener: no response header checks are performed
  const std::string response_check_headers{R"EOF(
      check_headers:
        allowed_headers:
          values:
            ":status": true
            "content-length": true
        report_event: true
        action_on_failure:
          respond_with_error:
            status: 500
            title: "Internal Server Error"
            detail: "response_invalid_headers"
            message_format: JSON
  )EOF"};

  std::vector<std::string> filter_configs = {
      config_header_to_metadata,
      configCommonFirewallChecksExtToInt(request_check_headers, response_check_headers,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 100 + mp_overhead : 100,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 50 + mp_overhead : 50)};

  std::string request_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3"})"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc123.mcc123.3gppnetwork.org"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  std::string response_body{R"({"k1":{"k1.1":"v1.1"}, "k2":"v2", "k3":"v3"})"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = true;
  uint32_t expected_upstream_index = -1;

  std::string expected_request_body = {};
  Http::TestRequestHeaderMapImpl expected_request_headers{};

  std::string expected_response_body = {};
  Http::TestResponseHeaderMapImpl expected_response_headers{};

  std::map<std::string, absl::optional<std::string>> expected_access_log = {
      {"/resp_code", absl::nullopt},
      {"/resp_message", absl::nullopt},
      {"/message", R"("Header in received HTTP request message not allowed")"},
      {"/extra_data/sc_event/log_type", R"("sc-event")"},
      {"/extra_data/sc_event/type", R"("ERIC_EVENT_SC_HTTP_HEADER_NOT_ALLOWED")"},
      {"/extra_data/sc_event/action", R"("dropped")"},
      {"/extra_data/sc_event/roaming_partner", R"("rp_1")"},
      {"/extra_data/sc_event/sub_spec", R"({"headers":{"not_allowed":[":method"]}})"}};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: RequestValidation_ExtToInt_RP1_sizeExceededLimit
// Description: Checking request validation for request coming from RP1
// where global request validation checks are replaced by local request
// validation checks and body exceeds configured size limit.
// Expected Result: Configured action on failure is triggered and request is dropped.
TEST_P(EricProxyFilterFirewallTest, RequestValidation_ExtToInt_RP1_sizeExceededLimit) {
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
  std::vector<std::string> filter_configs = {config_header_to_metadata,
                                             configCommonFirewallChecksExtToInt("", "",
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 100 + mp_overhead : 100,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 75-50 + mp_overhead : 50)};

  int original_request_bytes = 75;
  std::string request_body = createBodyInBytes(original_request_bytes);
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc123.mcc123.3gppnetwork.org"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  int original_response_bytes = 75;
  std::string response_body = createBodyInBytes(original_response_bytes);
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = true;
  uint32_t expected_upstream_index = -1;

  std::string expected_request_body = {};
  Http::TestRequestHeaderMapImpl expected_request_headers{};

  std::string expected_response_body = {};
  Http::TestResponseHeaderMapImpl expected_response_headers{};

  std::map<std::string, absl::optional<std::string>> expected_access_log = {
      {"/resp_code", absl::nullopt},
      {"/resp_message", absl::nullopt},
      {"/message", R"("Body of received HTTP request message exceeds the size limit of )" + std::to_string(getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 75 - 50 + mp_overhead : 50) + R"( bytes")"},
      {"/extra_data/sc_event/log_type", R"("sc-event")"},
      {"/extra_data/sc_event/type", R"("ERIC_EVENT_SC_HTTP_BODY_TOO_LONG")"},
      {"/extra_data/sc_event/action", R"("dropped")"},
      {"/extra_data/sc_event/roaming_partner", R"("rp_1")"},
      {"/extra_data/sc_event/sub_spec",
       R"({"body":{"issues":[{"err":"body_too_long","msg":"Message body size limit exceeded"}]}})"}};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: RequestValidation_ExtToInt_RP1_invalidJsonSyntax
// Description: Checking request validation for request coming from RP1
// where global request validation checks are replaced by local request
// validation checks and JSON body has invalid syntax.
// Expected Result: Configured action on failure is triggered and request is dropped.
TEST_P(EricProxyFilterFirewallTest, RequestValidation_ExtToInt_RP1_invalidJsonSyntax) {
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
  std::vector<std::string> filter_configs = {config_header_to_metadata,
                                             configCommonFirewallChecksExtToInt("", "",
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 100 + mp_overhead : 100,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 50 + mp_overhead : 50)};

  // Send fake downstream request with fake invalid JSON body
  // The fake body is an invalid JSON: last closing } is missing
  std::string request_body{R"({"k1":"v1")"};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc123.mcc123.3gppnetwork.org"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  // Send fake downstream response with fake invalid JSON body
  // The fake body is an invalid JSON: last closing } is missing
  std::string response_body{R"({"k1":"v1")"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = true;
  uint32_t expected_upstream_index = -1;

  std::string expected_request_body = {};
  Http::TestRequestHeaderMapImpl expected_request_headers{};

  std::string expected_response_body = {};
  Http::TestResponseHeaderMapImpl expected_response_headers{};

  std::map<std::string, absl::optional<std::string>> expected_access_log = {
      {"/resp_code", absl::nullopt},
      {"/resp_message", absl::nullopt},
      {"/message",
       R"("JSON body in received HTTP request message could not be parsed due to syntax errors")"},
      {"/extra_data/sc_event/log_type", R"("sc-event")"},
      {"/extra_data/sc_event/type", R"("ERIC_EVENT_SC_HTTP_JSON_BODY_SYNTAX_ERR")"},
      {"/extra_data/sc_event/action", R"("dropped")"},
      {"/extra_data/sc_event/roaming_partner", R"("rp_1")"},
      {"/extra_data/sc_event/sub_spec",
       R"x({"json_body":{"issues":[{"err":"syntax","msg":"Body contains syntax error(s)"}]}})x"}};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: RequestValidation_ExtToInt_RP1_leavesExceededLimit
// Description: Checking request validation for request coming from RP1
// where global request validation checks are replaced by local request
// validation checks and JSON body exceeds configured number of leaves
// limit.
// Expected Result: Configured action on failure is triggered and request is dropped.
TEST_P(EricProxyFilterFirewallTest, RequestValidation_ExtToInt_RP1_leavesExceededLimit) {
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
  std::vector<std::string> filter_configs = {config_header_to_metadata,
                                             configCommonFirewallChecksExtToInt("", "",
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 100 + mp_overhead : 100,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 50 + mp_overhead : 50)};

  int original_request_leaves = 4;
  std::string request_body = createJsonLeaves(original_request_leaves);
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc123.mcc123.3gppnetwork.org"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  int original_response_leaves = 4;
  std::string response_body = createJsonLeaves(original_response_leaves);
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = true;
  uint32_t expected_upstream_index = -1;

  std::string expected_request_body = {};
  Http::TestRequestHeaderMapImpl expected_request_headers{};

  std::string expected_response_body = {};
  Http::TestResponseHeaderMapImpl expected_response_headers{};

  std::map<std::string, absl::optional<std::string>> expected_access_log = {
      {"/resp_code", absl::nullopt},
      {"/resp_message", absl::nullopt},
      {"/message", R"("JSON body in received HTTP request message exceeds the limit of 3 leaves")"},
      {"/extra_data/sc_event/log_type", R"("sc-event")"},
      {"/extra_data/sc_event/type", R"("ERIC_EVENT_SC_HTTP_JSON_BODY_TOO_MANY_LEAVES")"},
      {"/extra_data/sc_event/action", R"("dropped")"},
      {"/extra_data/sc_event/roaming_partner", R"("rp_1")"},
      {"/extra_data/sc_event/sub_spec",
       R"({"json_body":{"issues":[{"err":"too_many_leaves","msg":"Maximum JSON leaves limit exceeded"}]}})"}};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

// Name: RequestValidation_ExtToInt_RP1_depthExceededLimit
// Description: Checking request validation for request coming from RP1
// where global request validation checks are replaced by local request
// validation checks and JSON body exceeds configured nesting depth
// limit.
// Expected Result: Configured action on failure is triggered and request is dropped.
TEST_P(EricProxyFilterFirewallTest, RequestValidation_ExtToInt_RP1_depthExceededLimit) {
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
  std::vector<std::string> filter_configs = {config_header_to_metadata,
                                             configCommonFirewallChecksExtToInt("", "",
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 100 + mp_overhead : 100,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 50 + mp_overhead : 50)};

  int original_request_depth = 3;
  std::string request_body = createNestedJson(original_request_depth).dump();
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc123.mcc123.3gppnetwork.org"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  int original_response_depth = 3;
  std::string response_body = createNestedJson(original_response_depth).dump();
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = true;
  uint32_t expected_upstream_index = -1;

  std::string expected_request_body = {};
  Http::TestRequestHeaderMapImpl expected_request_headers{};

  std::string expected_response_body = {};
  Http::TestResponseHeaderMapImpl expected_response_headers{};

  std::map<std::string, absl::optional<std::string>> expected_access_log = {
      {"/resp_code", absl::nullopt},
      {"/resp_message", absl::nullopt},
      {"/message",
       R"("JSON body in received HTTP request message exceeds the nesting depth limit of 2")"},
      {"/extra_data/sc_event/log_type", R"("sc-event")"},
      {"/extra_data/sc_event/type", R"("ERIC_EVENT_SC_HTTP_JSON_BODY_MAX_DEPTH_EXCEEDED")"},
      {"/extra_data/sc_event/action", R"("dropped")"},
      {"/extra_data/sc_event/roaming_partner", R"("rp_1")"},
      {"/extra_data/sc_event/sub_spec",
       R"({"json_body":{"issues":[{"err":"nesting_level_too_deep","msg":"Maximum JSON nesting depth limit exceeded"}]}})"}};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log);
}

//------------------------- END TEST REQUEST VALIDATION -------------------------------

//------------------------ BEGIN TEST RESPONSE VALIDATION -----------------------------

// Name: ResponseValidation_IntToExt_RP1_sizeExceededLimit
// Description: Checking response validation for response coming from RP1
// where global response validation checks are replaced by local response
// validation checks and body exceeds configured size limit.
// Expected Result: Configured action on failure is triggered and respond with error.
TEST_P(EricProxyFilterFirewallTest, ResponseValidation_IntToExt_RP1_sizeExceededLimit) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator()
          .withClusterBuilder(
              ClusterBuilder()
                  .withName("sepp_pool_1")
                  .withEndpoint(EndpointBuilder()
                                    .withHostName("sepp.5gc.mnc123.mcc123.3gppnetwork.org:443")
                                    .withHostMd({{"support", {"Indirect"}}})))
          .withClusterBuilder(
              ClusterBuilder()
                  .withName("sepp_pool_2")
                  .withEndpoint(EndpointBuilder()
                                    .withHostName("sepp.5gc.mnc456.mcc456.3gppnetwork.org:443")
                                    .withHostMd({{"support", {"Indirect"}}})));
  std::vector<std::string> filter_configs = {configCommonFirewallChecksIntToExt(
      "", "",
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 100 + mp_overhead : 100,
      getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 75 - 50 + mp_overhead : 50)};

  int original_request_bytes = 75;
  std::string request_body = createBodyInBytes(original_request_bytes);
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"content-length", std::to_string(request_body.length())},
      {"content-type", "application/json"}};

  int original_response_bytes = 75;
  std::string response_body = createBodyInBytes(original_response_bytes);
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"}};

  bool drop_request = false;
  uint32_t expected_upstream_index = 0;

  std::string expected_request_body = request_body;
  Http::TestRequestHeaderMapImpl expected_request_headers{{"x-eric-proxy", "///"},
                                                          {"x-cluster", "sepp_pool_1"}};

  std::string expected_response_body = {
      R"({"status": 500, "title": "Internal Server Error", "detail": "response_payload_too_large", "cause": "INSUFFICIENT_RESOURCES"})"};
  Http::TestResponseHeaderMapImpl expected_response_headers{
      {":status", "500"},
      {"content-length", std::to_string(expected_response_body.length())},
      {"content-type", "application/problem+json"}};

  std::map<std::string, absl::optional<std::string>> expected_access_log = {
      {"/resp_code", R"("500")"},
      {"/resp_message", R"("response_payload_too_large")"},
      {"/message",
       R"("Body of received HTTP response message exceeds the size limit of )" + std::to_string(getBodyContentType() == BodyContentType::MULTIPART_RELATED ? 75 - 50 + mp_overhead : 50) + R"( bytes")"},
      {"/extra_data/sc_event/log_type", R"("sc-event")"},
      {"/extra_data/sc_event/type", R"("ERIC_EVENT_SC_HTTP_BODY_TOO_LONG")"},
      {"/extra_data/sc_event/action", R"("rejected")"},
      {"/extra_data/sc_event/roaming_partner", R"("rp_1")"},
      {"/extra_data/sc_event/sub_spec",
       R"({"body":{"issues":[{"err":"body_too_long","msg":"Message body size limit exceeded"}]}})"}};

  testMessageValidationChecks(cluster_config, filter_configs, request_headers, request_body,
                              response_headers, response_body, drop_request,
                              expected_upstream_index, expected_request_headers,
                              expected_request_body, expected_response_headers,
                              expected_response_body, expected_access_log, false);
}

//------------------------- END TEST RESPONSE VALIDATION ------------------------------

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
