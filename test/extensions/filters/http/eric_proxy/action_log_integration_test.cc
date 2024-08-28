#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "test/integration/http_integration.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricvProxyFilterActionLogIntegrationTest : public HttpIntegrationTest, public testing::Test {
public:
  EricvProxyFilterActionLogIntegrationTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, Network::Address::IpVersion::v4,
                            EricvProxyFilterActionLogIntegrationTest::ericProxyHttpProxyConfig()) {}
  /**
   * Initializer for an individual integration test.
   */
  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);
    HttpIntegrationTest::initialize();
  }


  // Helper function to test event reporting with different
  // values.
  // The "tc_name" selects which action-log is executed when the request
  // is processed.
  void eventTestHelper(std::string tc_name, std::string expected_str1,
      std::string expected_str2) {
    // This configures the access log format and also redirects the access log
    // output so that later waitForAccessLog() can return the access log contents
    useAccessLog(
          "{\"timestamp\":\"%START_TIME(%FT%T.%3f%z)%\", \"severity\":\"%EVENT(SEVERITY)%\", "
          "\"service_id\":\"eric-scp\",\"extra_data\":{\"event_id\":\"%STREAM_ID%-%EVENT(INDEX)%\", "
          "\"event_type\":\"%EVENT(TYPE)%\", \"event_category\":\"%EVENT(CATEGORY)%\", "
          "\"event_action\":\"%EVENT(ACTION)%\", "
          "\"event_text\":\"%EVENT(MSG)%\"}");
    initializeFilter(event_config);
    Http::TestRequestHeaderMapImpl headers{
        {":method", "GET"},
        {":path", "/"},
        {":authority", "host"},
        {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-456:80"},
        {"tc", tc_name},
    };
    Http::TestResponseHeaderMapImpl response_headers{
        {"server", "envoy"},
        {":status", "200"},
    };
    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = sendRequestAndWaitForResponse(headers, 0, response_headers, 0);

    auto access_log = waitForAccessLog(access_log_name_);
    ENVOY_LOG(debug, "Access Log: " + access_log);

    EXPECT_THAT(access_log, testing::HasSubstr(expected_str1));
    EXPECT_THAT(access_log, testing::HasSubstr(expected_str2));
    cleanupUpstreamAndDownstream();
  }

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
)EOF",
                                                                Platform::null_device_path));
  }

#pragma region config
  const std::string config{R"EOF(
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
      - name: apiRoot_header
        header: 3gpp-Sbi-target-apiRoot
        variable_name: apiRoot_hdr
      - name: supi
        header: x-test-supi
        variable_name: supi
      filter_rules:
      - name: csepp_to_rp_A
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_log:
            log_level: ERROR
            max_log_message_length: 100
            log_values:
            - term_var: 'mnc'
            - term_string: " aaa "
            - term_var: 'mnc'
      - name: csepp_to_rp_A_2
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '579' }}
        actions:
        - action_log:
            log_level: ERROR
            max_log_message_length: 3
            log_values:
            - term_var: 'mnc'
            - term_string: " aaa "
            - term_var: 'mnc'
      - name: psepp_to_dfw
        condition:
          op_equals: 
            typed_config1:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_var: supi 
            typed_config2: 
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_string: '12345' 
        actions:
        - action_log:
            log_level: ERROR
            max_log_message_length: 50
            log_values:
            - term_var: 'supi'
            - term_string: " aaa "
            - term_boolean: true
            - term_string: " bbb "
            - term_reqheader: ':method'
            - term_string: " ccc "
            - term_number: 1
      - name: test_header_log
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'Hdr2RP'}
        actions:
        - action_log:
            log_level: WARN
            max_log_message_length: 50
            log_values:
            - term_reqheader: "tc"
            - term_string: " bbb "
            - term_number: 1.78989889
            - term_string: " ccc "
            - term_boolean: false
      - name: test_filter_params
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'test2'}
        actions:
        - action_log:
            log_level: INFO
            max_log_message_length: 500
            log_values:
            - term_string: "tc header: "
            - term_reqheader: "tc"
            - term_string: " mnc: "
            - term_var: mnc
            - term_string: " mcc: "
            - term_var: mcc
            - term_string: " apiRoot_header as var: "
            - term_var: apiRoot_hdr
            - term_string: " apiRoot_header as header: "
            - term_reqheader: 3gpp-Sbi-target-apiRoot
            - term_string: " supi var: "
            - term_var: supi
            - term_string: "END"
      - name: test_no_params
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'test3'}
        actions:
        - action_log:
            log_level: TRACE
            max_log_message_length: 500
            log_values:
            - term_string: " mnc: "
            - term_var: mnc
            - term_string: " mcc: "
            - term_var: mcc
            - term_string: " apiRoot_header as var: "
            - term_var: apiRoot_hdr
            - term_string: " apiRoot_header as header: "
            - term_reqheader: 3gpp-Sbi-target-apiRoot
            - term_string: " supi var: "
            - term_var: supi
            - term_string: "END"
      - name: test_headers
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'test4'}
        actions:
        - action_log:
            log_level: DEBUG
            max_log_message_length: 500
            log_values:
            - term_string: " apiRoot_header: "
            - term_reqheader: 3gpp-Sbi-target-apiRoot
            - term_string: " :method: "
            - term_reqheader: ":method"
            - term_string: " :path: "
            - term_reqheader: ":path"
            - term_string: " :authority: "
            - term_reqheader: ":authority"
            - term_string: " tc header: "
            - term_reqheader: "tc"
            - term_string: " response header: "
            - term_respheader: ":status"
            - term_string: "END"
      - name: test_headers
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'test5'}
        actions:
        - action_log:
            log_level: WARN
            max_log_message_length: 500
            log_values:
            - term_string: "req body: "
            - term_body: "request"
            - term_string: " resp body: "
            - term_body: "response"
            - term_string: "END"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF"};
#pragma endregion config

  const std::string event_config{R"EOF(
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
      - name: apiRoot_header
        header: 3gpp-Sbi-target-apiRoot
        variable_name: apiRoot_hdr
      filter_rules:
      - name: event1
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'event1'}
        actions:
        - action_report_event:
            event_type: HTTP_SYNTAX_ERROR
            event_category: SECURITY
            event_severity: INFO
            event_message_values:
            - term_var: 'mnc'
            - term_string: " e1e "
            - term_var: 'mcc'
            event_action: REJECTED
      - name: event2
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'event2'}
        actions:
        - action_report_event:
            event_type: HTTP_HEADER_TOO_MANY
            event_category: SECURITY
            event_severity: DEBUG
            event_message_values:
            - term_var: 'mnc'
            - term_string: " e2e "
            - term_var: 'mcc'
            event_action: DROPPED
      - name: event3
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'event3'}
        actions:
        - action_report_event:
            event_type: HTTP_HEADER_TOO_LONG
            event_category: SECURITY
            event_severity: WARNING
            event_message_values:
            - term_var: 'mnc'
            - term_string: " e3e "
            - term_var: 'mcc'
            event_action: IGNORED
      - name: event4
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'event4'}
        actions:
        - action_report_event:
            event_type: HTTP_HEADER_NOT_ALLOWED
            event_category: SECURITY
            event_severity: ERROR
            event_message_values:
            - term_var: 'mnc'
            - term_string: " e4e "
            - term_var: 'mcc'
            event_action: REPAIRED
      - name: event5
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'event5'}
        actions:
        - action_report_event:
            event_type: HTTP_BODY_TOO_LONG
            event_category: SECURITY
            event_severity: CRITICAL
            event_message_values:
            - term_var: 'mnc'
            - term_string: " e5e "
            - term_var: 'mcc'
            event_action: DROPPED
      - name: event6
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'event6'}
        actions:
        - action_report_event:
            event_type: HTTP_BODY_EXTRA_BODIES
            event_category: SECURITY
            event_severity: CRITICAL
            event_message_values:
            - term_var: 'mnc'
            - term_string: " e6e "
            - term_var: 'mcc'
            event_action: DROPPED
      - name: event7
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'event7'}
        actions:
        - action_report_event:
            event_type: HTTP_JSON_BODY_SYNTAX_ERR
            event_category: SECURITY
            event_severity: CRITICAL
            event_message_values:
            - term_var: 'mnc'
            - term_string: " e7e "
            - term_var: 'mcc'
            event_action: DROPPED
      - name: event8
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'event8'}
        actions:
        - action_report_event:
            event_type: HTTP_JSON_BODY_TOO_MANY_LEAVES
            event_category: SECURITY
            event_severity: CRITICAL
            event_message_values:
            - term_var: 'mnc'
            - term_string: " e8e "
            - term_var: 'mcc'
            event_action: DROPPED
      - name: event9
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'event9'}
        actions:
        - action_report_event:
            event_type: HTTP_JSON_BODY_MAX_DEPTH_EXCEEDED
            event_category: SECURITY
            event_severity: CRITICAL
            event_message_values:
            - term_var: 'mnc'
            - term_string: " e9e "
            - term_var: 'mcc'
            event_action: DROPPED
      - name: event10
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'event10'}
        actions:
        - action_report_event:
            event_type: UNAUTHORIZED_SERVICE_OPERATION_DETECTED
            event_category: SECURITY
            event_severity: CRITICAL
            event_message_values:
            - term_var: 'mnc'
            - term_string: " e10e "
            - term_var: 'mcc'
            event_action: DROPPED
      - name: event11
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'event11'}
        actions:
        - action_report_event:
            event_type: BARRED_HTTP1
            event_category: SECURITY
            event_severity: CRITICAL
            event_message_values:
            - term_var: 'mnc'
            - term_string: " e11e "
            - term_var: 'mcc'
            event_action: DROPPED
      - name: event12
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'event12'}
        actions:
        - action_report_event:
            event_type: USER_DEFINED_EVENT
            event_category: SECURITY
            event_severity: CRITICAL
            event_message_values:
            - term_var: 'mnc'
            - term_string: " e12e "
            - term_var: 'mcc'
            event_action: DROPPED
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF"};
};

//--------------------------------------------------------------------------------------------

// Should log on "error" level a combination of variables and fixed strings:
// "<mnc> aaa <mnc>" ==> "123 aaa 123"
// Uses configuration in filter_rule "csepp_to_rp_A"
TEST_F(EricvProxyFilterActionLogIntegrationTest, log_error_mcc_123) {
  initializeFilter(config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
  };
  Http::TestResponseHeaderMapImpl response_headers{
      {"server", "envoy"},
      {":status", "200"},
  };
  codec_client_ = makeHttpConnection(lookupPort("http"));
  EXPECT_LOG_CONTAINS("error", "123 aaa 123", {
    auto response = sendRequestAndWaitForResponse(headers, 0, response_headers, 0);
  });
  cleanupUpstreamAndDownstream();
}

// Should log on "error" level "<mnc> aaa <mnc>", but truncate to the
// first 3 characters => "579..."
// Uses configuration in filter_rule "csepp_to_rp_A_2"
TEST_F(EricvProxyFilterActionLogIntegrationTest, log_error_mcc_579) {
  initializeFilter(config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-579-mcc-579:80"},
  };
  Http::TestResponseHeaderMapImpl response_headers{
      {"server", "envoy"},
      {":status", "200"},
  };
  codec_client_ = makeHttpConnection(lookupPort("http"));
  EXPECT_LOG_CONTAINS("error", "579...", {
    auto response = sendRequestAndWaitForResponse(headers, 0, response_headers, 0);
  });
  cleanupUpstreamAndDownstream();
}

// Should log on "error"-level a message composed of various (all?) log_value
// types.
// Uses configuration in filter_rule "psepp_to_dfw"
TEST_F(EricvProxyFilterActionLogIntegrationTest, log_error_supi_with_const) {
  initializeFilter(config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-supi", "12345"},
  };
  Http::TestResponseHeaderMapImpl response_headers{
      {"server", "envoy"},
      {":status", "200"},
  };
  codec_client_ = makeHttpConnection(lookupPort("http"));
  EXPECT_LOG_CONTAINS("error", "12345 aaa true bbb GET ccc 1", {
    auto response = sendRequestAndWaitForResponse(headers, 0, response_headers, 0);
  });
  cleanupUpstreamAndDownstream();
}

// Should log on "warn"-level a message composed of several log_values.
// Uses configuration in filter_rule "test_header_log"
TEST_F(EricvProxyFilterActionLogIntegrationTest, log_warn_header_with_const) {
  initializeFilter(config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"tc", "Hdr2RP"},
  };
  Http::TestResponseHeaderMapImpl response_headers{
      {"server", "envoy"},
      {":status", "200"},
  };
  codec_client_ = makeHttpConnection(lookupPort("http"));
  EXPECT_LOG_CONTAINS("warn", "Hdr2RP bbb 1.7899 ccc false", {
    auto response = sendRequestAndWaitForResponse(headers, 0, response_headers, 0);
  });
  cleanupUpstreamAndDownstream();
}

// Log a message on "info" level. The message shall print the variable
// "supi", but that isn't defined -> print nothing instead.
// (x-test-supi is not initialized/has no value)
// Uses configuration in the filter_rule "test_filter_params"
TEST_F(EricvProxyFilterActionLogIntegrationTest, log_info_empty_supi) {
  initializeFilter(config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"tc", "test2"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-5-mnc-7-mcc-8:80"},
  };
  Http::TestResponseHeaderMapImpl response_headers{
      {"server", "envoy"},
      {":status", "200"},
  };
  codec_client_ = makeHttpConnection(lookupPort("http"));
  EXPECT_LOG_CONTAINS(
      "info",
      "tc header: test2 mnc: 7 mcc: 8 apiRoot_header as var: http://eric-chfsim-5-mnc-7-mcc-8:80 "
      "apiRoot_header as header: http://eric-chfsim-5-mnc-7-mcc-8:80 supi var: END",
      { auto response = sendRequestAndWaitForResponse(headers, 0, response_headers, 0); });
  cleanupUpstreamAndDownstream();
}

// Test with all non-existing variables. Expected result is that only
// the fixed strings are printed. Log-level is "TRACE".
// Uses configuration in the filter_rule "test_no_params"
TEST_F(EricvProxyFilterActionLogIntegrationTest, log_trace_non_existing_vars) {
  initializeFilter(config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"tc", "test3"},
  };
  Http::TestResponseHeaderMapImpl response_headers{
      {"server", "envoy"},
      {":status", "200"},
  };
  codec_client_ = makeHttpConnection(lookupPort("http"));
  EXPECT_LOG_CONTAINS(
      "trace", "mnc:  mcc:  apiRoot_header as var:  apiRoot_header as header:  supi var: END", {
        auto response = sendRequestAndWaitForResponse(headers, 0, response_headers, 0);
      });
  cleanupUpstreamAndDownstream();
}

// Test headers on "debug" level: Insert request headers into the message
// and also insert a response-header which is not available at the time of
// logging. It is expected to remain empty.
// Uses configuration in filter_case "test_headers".
TEST_F(EricvProxyFilterActionLogIntegrationTest, log_debug_all_headers) {
  initializeFilter(config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"tc", "test4"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-5-mnc-7-mcc-8:80"},
  };
  Http::TestResponseHeaderMapImpl response_headers{
      {"server", "envoy"},
      {":status", "200"},
  };
  codec_client_ = makeHttpConnection(lookupPort("http"));
  EXPECT_LOG_CONTAINS(
      "debug",
      "apiRoot_header: http://eric-chfsim-5-mnc-7-mcc-8:80 :method: GET :path: / :authority: "
      "host tc header: test4 response header: END", {
      auto response = sendRequestAndWaitForResponse(headers, 0, response_headers, 0);
  });
  cleanupUpstreamAndDownstream();
}

// Send a request with a body of 10x "a" and response with also a body of 10x "a".
// Log on "warn" level the request- and response-body.
// Expected result is that the request body is printed in the log message but the
// response body is not. This is because the action-log is in the request path.
TEST_F(EricvProxyFilterActionLogIntegrationTest, log_warn_body_req) {
  initializeFilter(config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"tc", "test5"},
  };
  Http::TestResponseHeaderMapImpl response_headers{
      {"server", "envoy"},
      {":status", "200"},
  };
  codec_client_ = makeHttpConnection(lookupPort("http"));
  EXPECT_LOG_CONTAINS(
      "warn", " req body: aaaaaaaaaa resp body: END",
      { auto response = sendRequestAndWaitForResponse(headers, 10, response_headers, 10); });
  cleanupUpstreamAndDownstream();
}

// TODO: add a test that logs in the response path: req-headers, resp-headers,
// req-body, resp-body, variables set in the request path, variables set in the
// response path.


//------------------------------------------------------------------------
//--- Event-Reporting Tests ----------------------------------------------
// Not all variable/header/body/text values are tested here because the
// function that assembles the event_text is the same as the one that
// assembles the log message -> the tests above cover the assembly of the
// message/text already.
//------------------------------------------------------------------------

// Report an event from an action. The event-text consists of variables and fixed text.
TEST_F(EricvProxyFilterActionLogIntegrationTest, report_event1) {
  GTEST_SKIP();
  eventTestHelper("event1",
      R"EOT("severity":"info", "service_id":"eric-scp","extra_data":{"event_id":)EOT",
      R"EOT("event_type":"ERIC_EVENT_SC_HTTP_SYNTAX_ERROR", "event_category":"security", "event_action":"rejected", "event_text":"123 e1e 456")EOT"
  );
}

// Same as the previous one but with different values in the action_report_event
// Report an event from an action. The event-text consists of variables and fixed text.
TEST_F(EricvProxyFilterActionLogIntegrationTest, report_event2) {
  GTEST_SKIP();
  eventTestHelper("event2",
    R"EOT("severity":"debug", "service_id":"eric-scp","extra_data":{"event_id":)EOT",
    R"EOT("event_type":"ERIC_EVENT_SC_HTTP_HEADER_TOO_MANY", "event_category":"security", "event_action":"dropped", "event_text":"123 e2e 456")EOT"
  );
}

// Same as the previous one but with different values in the action_report_event
// Report an event from an action. The event-text consists of variables and fixed text.
TEST_F(EricvProxyFilterActionLogIntegrationTest, report_event3) {
  GTEST_SKIP();
  eventTestHelper("event3",
    R"EOT("severity":"warning", "service_id":"eric-scp","extra_data":{"event_id":)EOT",
    R"EOT("event_type":"ERIC_EVENT_SC_HTTP_HEADER_TOO_LONG", "event_category":"security", "event_action":"ignored", "event_text":"123 e3e 456")EOT"
  );
}

// Same as the previous one but with different values in the action_report_event
// Report an event from an action. The event-text consists of variables and fixed text.
TEST_F(EricvProxyFilterActionLogIntegrationTest, report_event4) {
  GTEST_SKIP();
  eventTestHelper("event4",
    R"EOT("severity":"error", "service_id":"eric-scp","extra_data":{"event_id":)EOT",
    R"EOT("event_type":"ERIC_EVENT_SC_HTTP_HEADER_NOT_ALLOWED", "event_category":"security", "event_action":"repaired", "event_text":"123 e4e 456")EOT"
  );
}

// Same as the previous one but with different values in the action_report_event
// Report an event from an action. The event-text consists of variables and fixed text.
// From here on, only change the event-type, all the other fields have already been tested.
TEST_F(EricvProxyFilterActionLogIntegrationTest, report_event5) {
  GTEST_SKIP();
  eventTestHelper("event5",
    R"EOT("severity":"critical", "service_id":"eric-scp","extra_data":{"event_id":)EOT",
    R"EOT("event_type":"ERIC_EVENT_SC_HTTP_BODY_TOO_LONG", "event_category":"security", "event_action":"dropped", "event_text":"123 e5e 456")EOT"
  );
}

// Same as the previous one but with different values in the action_report_event
// Report an event from an action. The event-text consists of variables and fixed text.
TEST_F(EricvProxyFilterActionLogIntegrationTest, report_event6) {
  GTEST_SKIP();
  eventTestHelper("event6",
    R"EOT("severity":"critical", "service_id":"eric-scp","extra_data":{"event_id":)EOT",
    R"EOT("event_type":"ERIC_EVENT_SC_HTTP_BODY_EXTRA_BODIES", "event_category":"security", "event_action":"dropped", "event_text":"123 e6e 456")EOT"
  );
}

// Same as the previous one but with different values in the action_report_event
// Report an event from an action. The event-text consists of variables and fixed text.
TEST_F(EricvProxyFilterActionLogIntegrationTest, report_event7) {
  GTEST_SKIP();
  eventTestHelper(
      "event7", R"EOT("severity":"critical", "service_id":"eric-scp","extra_data":{"event_id":)EOT",
      R"EOT("event_type":"ERIC_EVENT_SC_HTTP_JSON_BODY_SYNTAX_ERR", "event_category":"security", "event_action":"dropped", "event_text":"123 e7e 456")EOT");
}

// Same as the previous one but with different values in the action_report_event
// Report an event from an action. The event-text consists of variables and fixed text.
TEST_F(EricvProxyFilterActionLogIntegrationTest, report_event8) {
  GTEST_SKIP();
  eventTestHelper(
      "event8", R"EOT("severity":"critical", "service_id":"eric-scp","extra_data":{"event_id":)EOT",
      R"EOT("event_type":"ERIC_EVENT_SC_HTTP_JSON_BODY_TOO_MANY_LEAVES", "event_category":"security", "event_action":"dropped", "event_text":"123 e8e 456")EOT");
}

// Same as the previous one but with different values in the action_report_event
// Report an event from an action. The event-text consists of variables and fixed text.
TEST_F(EricvProxyFilterActionLogIntegrationTest, report_event9) {
  GTEST_SKIP();
  eventTestHelper(
      "event9", R"EOT("severity":"critical", "service_id":"eric-scp","extra_data":{"event_id":)EOT",
      R"EOT("event_type":"ERIC_EVENT_SC_HTTP_JSON_BODY_MAX_DEPTH_EXCEEDED", "event_category":"security", "event_action":"dropped", "event_text":"123 e9e 456")EOT");
}

// Same as the previous one but with different values in the action_report_event
// Report an event from an action. The event-text consists of variables and fixed text.
TEST_F(EricvProxyFilterActionLogIntegrationTest, report_event10) {
  GTEST_SKIP();
  eventTestHelper(
      "event10", R"EOT("severity":"critical", "service_id":"eric-scp","extra_data":{"event_id":)EOT",
      R"EOT("event_type":"ERIC_EVENT_SC_UNAUTHORIZED_SERVICE_OPERATION_DETECTED", "event_category":"security", "event_action":"dropped", "event_text":"123 e10e 456")EOT");
}

// Same as the previous one but with different values in the action_report_event
// Report an event from an action. The event-text consists of variables and fixed text.
TEST_F(EricvProxyFilterActionLogIntegrationTest, report_event11) {
  GTEST_SKIP();
  eventTestHelper("event11",
    R"EOT("severity":"critical", "service_id":"eric-scp","extra_data":{"event_id":)EOT",
    R"EOT("event_type":"ERIC_EVENT_SC_BARRED_HTTP1", "event_category":"security", "event_action":"dropped", "event_text":"123 e11e 456")EOT"
  );
}

// Same as the previous one but with different values in the action_report_event
// Report an event from an action. The event-text consists of variables and fixed text.
TEST_F(EricvProxyFilterActionLogIntegrationTest, report_event12) {
  GTEST_SKIP();
  eventTestHelper("event12",
    R"EOT("severity":"critical", "service_id":"eric-scp","extra_data":{"event_id":)EOT",
    R"EOT("event_type":"ERIC_EVENT_SC_USER_DEFINED_EVENT", "event_category":"security", "event_action":"dropped", "event_text":"123 e12e 456")EOT"
  );
}

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
