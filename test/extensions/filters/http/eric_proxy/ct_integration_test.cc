#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"
#include <optional>
#include <ostream>
#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterCtIntegrationTest : public HttpIntegrationTest,
                                    public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterCtIntegrationTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(),
                            EricProxyFilterCtIntegrationTest::ericProxyHttpProxyConfig()) {}
  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);
    setUpstreamCount(2);
    HttpIntegrationTest::initialize();
  }

  void execTestWithBasicAssertions(Http::TestRequestHeaderMapImpl req_headers,
                                   const std::string& slf_resp_status_code,
                                   const std::string& slf_resp_body,
                                   const std::string& expected_nslf_path, // for comparing path of Nslf request
                                   const std::string& expected_nrf_group,
                                   Http::TestRequestHeaderMapImpl expected_req_headers,
                                   std::optional<Http::TestRequestHeaderMapImpl> expected_slf_req_headers =  std::nullopt)
  {
    IntegrationCodecClientPtr codec_client;
    FakeHttpConnectionPtr fake_upstream_connection;
    FakeStreamPtr request_stream;

    codec_client = makeHttpConnection(lookupPort("http"));
    auto response = codec_client->makeHeaderOnlyRequest(req_headers);
    FakeStreamPtr slf_request_stream = sendSlfResponse(slf_resp_status_code, slf_resp_body);

    EXPECT_THAT(slf_request_stream->headers(), Http::HeaderValueOf(":path", expected_nslf_path));
    if(expected_nrf_group.empty()) {
      EXPECT_TRUE(slf_request_stream->headers().get(Http::LowerCaseString("nrf-group")).empty());
    } else {
      EXPECT_THAT(slf_request_stream->headers(), Http::HeaderValueOf("nrf-group", expected_nrf_group));
    }

    ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
    ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));

    ASSERT_TRUE(slf_request_stream->waitForEndStream(*dispatcher_));
    ASSERT_TRUE(fake_slf_connection_->close());

    ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

    ASSERT_TRUE(fake_upstream_connection->close());
    ASSERT_TRUE(response->waitForEndStream());

    // Validate that all expected headers are present and have the correct value:
    EXPECT_THAT(request_stream->headers(), Http::IsSupersetOfHeaders(expected_req_headers));

    // Validate that all expected slf request headers are present and have the correct value:
    if (expected_slf_req_headers) {
      EXPECT_THAT(slf_request_stream->headers(), Http::IsSupersetOfHeaders(expected_slf_req_headers.value()));
    }

    codec_client->close();

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
              hostname: cluster_0_host_0
            metadata:
              filter_metadata:
                envoy.eric_proxy:
                  support:
                  - Indirect
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
              hostname: cluster_1_host_0
            metadata:
              filter_metadata:
                envoy.eric_proxy:
                  support:
                  - NF
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
  }

// Configuration for routing when notifications are sent from NF Producer to be routed to
// appropriate peer SCP after slf-lookup (related to case handled by DND-38747)
std::string config_notify = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp_router
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  filter_cases:
    - name: default_routing
      filter_data:
      - name: <3gpp-id>
        header: x-test-<3gpp-id>
        variable_name: <3gpp-id>
      filter_rules:

      - name: psepp_to_pref
        condition:
          op_equals:
            typed_config1:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_var: <3gpp-id>
            typed_config2:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_string: '12345'
        actions:
        - action_slf_lookup:
            <3gpp-id>_var: <3gpp-id>
            destination_variable: region
            cluster_name: cluster_1
            nrf_group_name: nrfgroup_1
            timeout: 1000
            fc_id_missing: fc_id_missing
            fc_id_not_found: fc_id_not_found
            fc_dest_unknown: fc_dest_unknown
            fc_lookup_failure: fc_lookup_failure
        - action_route_to_pool:
            pool_name:
              term_var: region
            routing_behaviour: ROUND_ROBIN
            keep_authority_header: true

      - name: scp_default
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: universal_pool
            routing_behaviour: PREFERRED
            preserve_if_indirect: ABSOLUTE_PATH
            preferred_target:
              term_header: ":authority"

    - name:  fc_id_missing
      filter_rules:
      - name:  fr_id_missing
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_level: INFO
              log_values:
              - term_string: "fr_id_missing triggered"
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_id_missing"
    - name:  fc_id_not_found
      filter_rules:
      - name:  fr_id_not_found
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_id_not_found triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_id_not_found"
    - name:  fc_dest_unknown
      filter_rules:
      - name:  fr_dest_unknown
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_dest_unknown triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_dest_unknown"
    - name:  fc_lookup_failure
      filter_rules:
      - name:  fr_lookup_failure
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_lookup_failure triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_lookup_failure"
          - action_route_to_pool:
              pool_name:
                term_string: wrong_pool
              routing_behaviour: ROUND_ROBIN



)EOF";

  // Configuration for basic positive tests
  std::string config_basic = R"EOF(
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
      - name: <3gpp-id>
        header: x-test-<3gpp-id>
        variable_name: <3gpp-id>
      filter_rules:
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
            routing_behaviour: STRICT
      - name: psepp_to_pref
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: <3gpp-id> }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '12345' }}
        actions:
        - action_slf_lookup:
            <3gpp-id>_var: <3gpp-id>
            destination_variable: region
            cluster_name: cluster_1
            nrf_group_name: nrfgroup_1
            timeout: 1000
            fc_id_missing: fc_id_missing
            fc_id_not_found: fc_id_not_found
            fc_dest_unknown: fc_dest_unknown
            fc_lookup_failure: fc_lookup_failure
        - action_route_to_pool:
            pool_name:
              term_var: region
            routing_behaviour: ROUND_ROBIN
    - name:  fc_id_missing
      filter_rules:
      - name:  fr_id_missing
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_id_missing triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_id_missing"
    - name:  fc_id_not_found
      filter_rules:
      - name:  fr_id_not_found
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_id_not_found triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_id_not_found"
    - name:  fc_dest_unknown
      filter_rules:
      - name:  fr_dest_unknown
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_dest_unknown triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_dest_unknown"
    - name:  fc_lookup_failure
      filter_rules:
      - name:  fr_lookup_failure
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_lookup_failure triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_lookup_failure"
          - action_route_to_pool:
              pool_name:
                term_string: wrong_pool
              routing_behaviour: ROUND_ROBIN

  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";


  // Configuration for basic positive tests
  std::string config_basic_json_pointer = R"EOF(
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
      - name: <3gpp-id>
        body_json_pointer: '/subscriberIdentifier'
        variable_name: <3gpp-id>
      filter_rules:
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
            routing_behaviour: STRICT
      - name: psepp_to_pref
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: <3gpp-id> }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '12345' }}
        actions:
        - action_slf_lookup:
            <3gpp-id>_var: <3gpp-id>
            destination_variable: region
            nrf_group_name: nrfgroup_1
            cluster_name: cluster_1
            timeout: 1000
            fc_id_missing: fc_id_missing
            fc_id_not_found: fc_id_not_found
            fc_dest_unknown: fc_dest_unknown
            fc_lookup_failure: fc_lookup_failure
        - action_route_to_pool:
            pool_name:
              term_var: region
            routing_behaviour: ROUND_ROBIN
      - name: psepp_to_pref_DND_30754
        condition:
          op_not: {arg1: {op_exists: {arg1: {term_var: '<3gpp-id>' }}}}
        actions:
        - action_slf_lookup:
            <3gpp-id>_var: <3gpp-id>
            destination_variable: region
            cluster_name: cluster_1
            timeout: 1000
            fc_id_missing: fc_id_missing
            fc_id_not_found: fc_id_not_found
            fc_dest_unknown: fc_dest_unknown
            fc_lookup_failure: fc_lookup_failure
        - action_route_to_pool:
            pool_name:
              term_var: region
            routing_behaviour: ROUND_ROBIN
    - name:  fc_id_missing
      filter_rules:
      - name:  fr_id_missing
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_id_missing triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_id_missing"
    - name:  fc_id_not_found
      filter_rules:
      - name:  fr_id_not_found
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_id_not_found triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_id_not_found"
    - name:  fc_dest_unknown
      filter_rules:
      - name:  fr_dest_unknown
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_dest_unknown triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_dest_unknown"
    - name:  fc_lookup_failure
      filter_rules:
      - name:  fr_lookup_failure
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_lookup_failure triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_lookup_failure"
          - action_route_to_pool:
              pool_name:
                term_string: wrong_pool
              routing_behaviour: ROUND_ROBIN

  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

 // Configuration for basic positive tests custom NF Typess
   std::string config_basic_customNFTypes = R"EOF(
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
      - name: <3gpp-id>
        header: x-test-<3gpp-id>
        variable_name: <3gpp-id>
      filter_rules:
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
            routing_behaviour: STRICT
      - name: psepp_to_pref
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: <3gpp-id> }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '12345' }}
        actions:
        - action_slf_lookup:
            <3gpp-id>_var: <3gpp-id>
            req_nf_type: AMF
            target_nf_type: UDM
            nrf_group_name: nrfgroup_1
            destination_variable: region
            cluster_name: cluster_1
            timeout: 1000
            fc_id_missing: fc_id_missing
            fc_id_not_found: fc_id_not_found
            fc_dest_unknown: fc_dest_unknown
            fc_lookup_failure: fc_lookup_failure
        - action_route_to_pool:
            pool_name:
              term_var: region
            routing_behaviour: ROUND_ROBIN
    - name:  fc_id_missing
      filter_rules:
      - name:  fr_id_missing
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_id_missing triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_id_missing"
    - name:  fc_id_not_found
      filter_rules:
      - name:  fr_id_not_found
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_id_not_found triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_id_not_found"
    - name:  fc_dest_unknown
      filter_rules:
      - name:  fr_dest_unknown
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_dest_unknown triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_dest_unknown"
    - name:  fc_lookup_failure
      filter_rules:
      - name:  fr_lookup_failure
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_lookup_failure triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_lookup_failure"
          - action_route_to_pool:
              pool_name:
                term_string: wrong_pool
              routing_behaviour: ROUND_ROBIN

  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  // Configuration for basic positive tests with KVT
  std::string config_basic_kvt = R"EOF(
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
      filter_data:
      - name: apiRoot_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      - name: apiRoot_header
        header: 3gpp-Sbi-target-apiRoot
        variable_name: apiRoot_hdr
      - name: chfsim_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: eric-(?P<chfsim>chfsim-\d+?)-.+
      - name: <3gpp-id>
        header: x-test-<3gpp-id>
        variable_name: <3gpp-id>
      filter_rules:
      - name: slf_kvt_basic_123
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: <3gpp-id> }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_slf_lookup:
            <3gpp-id>_var: <3gpp-id>
            destination_variable: region
            cluster_name: cluster_1
            timeout: 1000
            nrf_group_name: nrfgroup_1
            fc_id_missing: fc_id_missing
            fc_id_not_found: fc_id_not_found
            fc_dest_unknown: fc_dest_unknown
            fc_lookup_failure: fc_lookup_failure
        - action_modify_variable:
            name: region
            table_lookup:
              table_name: region_to_cluster
              key:
                term_var: region
        - action_route_to_pool:
            pool_name:
              term_var: region
            routing_behaviour: ROUND_ROBIN
      - name: slf_kvt_no_table_1234
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: <3gpp-id> }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '1234' }}
        actions:
        - action_slf_lookup:
            <3gpp-id>_var: <3gpp-id>
            destination_variable: region
            cluster_name: cluster_1
            timeout: 1000
            fc_id_missing: fc_id_missing
            fc_id_not_found: fc_id_not_found
            fc_dest_unknown: fc_dest_unknown
            fc_lookup_failure: fc_lookup_failure
        - action_modify_variable:
            name: region
            table_lookup:
              table_name: region_table_not_existing
              key:
                term_var: region
        - action_route_to_pool:
            pool_name:
              term_var: region
            routing_behaviour: ROUND_ROBIN
      - name: slf_kvt_input_from_string_1235
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: <3gpp-id> }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '1235' }}
        actions:
        - action_slf_lookup:
            <3gpp-id>_var: <3gpp-id>
            destination_variable: region
            cluster_name: cluster_1
            timeout: 1000
            nrf_group_name: nrfgroup_1
            fc_id_missing: fc_id_missing
            fc_id_not_found: fc_id_not_found
            fc_dest_unknown: fc_dest_unknown
            fc_lookup_failure: fc_lookup_failure
        - action_modify_variable:
            name: region
            table_lookup:
              table_name: region_to_cluster
              key:
                term_string: region_B
        - action_route_to_pool:
            pool_name:
              term_var: region
            routing_behaviour: ROUND_ROBIN
      - name: slf_kvt_input_from_string_1236
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: <3gpp-id> }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '1236' }}
        actions:
        - action_slf_lookup:
            <3gpp-id>_var: <3gpp-id>
            destination_variable: region
            nrf_group_name: nrfgroup_1
            cluster_name: cluster_1
            timeout: 1000
            fc_id_missing: fc_id_missing
            fc_id_not_found: fc_id_not_found
            fc_dest_unknown: fc_dest_unknown
            fc_lookup_failure: fc_lookup_failure
        - action_modify_variable:
            name: region
            table_lookup:
              table_name: region_to_cluster
              key:
                term_header: x-test-region
        - action_route_to_pool:
            pool_name:
              term_var: region
            routing_behaviour: ROUND_ROBIN
    - name:  fc_id_missing
      filter_rules:
      - name:  fr_id_missing
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_id_missing triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_id_missing"
    - name:  fc_id_not_found
      filter_rules:
      - name:  fr_id_not_found
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_id_not_found triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_id_not_found"
    - name:  fc_dest_unknown
      filter_rules:
      - name:  fr_dest_unknown
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_dest_unknown triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_dest_unknown"
    - name:  fc_lookup_failure
      filter_rules:
      - name:  fr_lookup_failure
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_lookup_failure triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_lookup_failure"
          - action_route_to_pool:
              pool_name:
                term_string: wrong_pool
              routing_behaviour: ROUND_ROBIN

  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A

  key_value_tables:
   - name: region_to_cluster
     entries:
       - key: region_A
         value: cluster_regionA
       - key: region_B
         value: cluster_regionB
)EOF";

  // Configuration for basic positive tests
  std::string config_basic_no_ep_cluster_2 = R"EOF(
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
      - name: <3gpp-id>
        header: x-test-<3gpp-id>
        variable_name: <3gpp-id>
      filter_rules:
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
            routing_behaviour: STRICT
      - name: psepp_to_pref
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: <3gpp-id> }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '12345' }}
        actions:
        - action_slf_lookup:
            <3gpp-id>_var: <3gpp-id>
            nrf_group_name: nrfgroup_1
            destination_variable: region
            cluster_name: cluster_2
            timeout: 1000
            fc_id_missing: fc_id_missing
            fc_id_not_found: fc_id_not_found
            fc_dest_unknown: fc_dest_unknown
            fc_lookup_failure: fc_lookup_failure
        - action_route_to_pool:
            pool_name:
              term_var: region
            routing_behaviour: ROUND_ROBIN

    - name:  fc_id_missing
      filter_rules:
      - name:  fr_id_missing
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_id_missing triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_id_missing"
    - name:  fc_id_not_found
      filter_rules:
      - name:  fr_id_not_found
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_id_not_found triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_id_not_found"
    - name:  fc_dest_unknown
      filter_rules:
      - name:  fr_dest_unknown
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_dest_unknown triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_dest_unknown"
    - name:  fc_lookup_failure
      filter_rules:
      - name:  fr_lookup_failure
        condition:
          term_boolean: true
        actions:
          - action_log:
              max_log_message_length: 500
              log_values:
              - term_string: "fr_lookup_failure triggered"
              log_level: INFO
          - action_add_header:
              name: x-slf-fc-triggered
              value:
                term_string: "fc_lookup_failure"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A

)EOF";

  // Configuration for action-slf-lookup followed by egress screening
  std::string config_slf_lookup_egress_screening = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
    out_request_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          'region_A': out_req_screening_cp
          'region_B': out_req_screening_wp
          'region_C': out_req_screening_wp
  filter_cases:
    - name: default_routing
      filter_data:
      - name: supi
        header: x-test-supi
        variable_name: supi
      filter_rules:
      - name: slf-lookup
        condition:
          term_boolean: true
        actions:
        - action_slf_lookup:
            supi_var: supi
            nrf_group_name: nrfgroup_1
            destination_variable: region
            cluster_name: cluster_1
            timeout: 1000
            fc_id_missing: fc_id_missing
            fc_id_not_found: fc_id_not_found
            fc_dest_unknown: fc_dest_unknown
            fc_lookup_failure: fc_lookup_failure
        - action_route_to_pool:
            pool_name:
              term_var: region
            routing_behaviour: ROUND_ROBIN
    - name: out_req_screening_cp
      filter_rules:
      - name: add_header_correct_pool
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: egress_screening
            value:
              term_string: "correct pool"
    - name: out_req_screening_wp
      filter_rules:
      - name: add_header_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: egress_screening
            value:
              term_string: "wrong pool"

)EOF";

  const std::string config_cdn_loop_filter = R"EOF(
name: envoy.filters.http.cdn_loop
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.cdn_loop.v3.CdnLoopConfig
  cdn_id: "2.0 scp.ericsson.se"
)EOF";


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

  // SLF response with region_A on highest priority
  std::string slfResponseResponseRegionA() {
    return R"EOF(
      {
        "addresses":
        [
          {
            "fqdn": "region_A",
            "priority": 1
          },
          {
            "fqdn": "region_B",
            "priority": 3
          },
          {
            "fqdn": "region_C",
            "priority": 4
          }
        ]
      }
      )EOF";
  }

  std::string slfResponseResponseRegionC() {
    return R"EOF(
      {
        "addresses":
        [
          {
            "fqdn": "region_C",
            "priority": 1
          },
          {
            "fqdn": "region_B",
            "priority": 3
          },
          {
            "fqdn": "region_A",
            "priority": 4
          }
        ]
      }
      )EOF";
  }

  // SLF response with no priorities
  std::string slfResponseResponseNoPriorities() {
    return R"EOF(
      {
        "addresses":
        [
          {
            "fqdn": "region_A",
          },
          {
            "fqdn": "region_B",
          },
          {
            "fqdn": "region_C",
          }
        ]
      }
      )EOF";
  }

  // Helpers
  std::string slfResponseResponseNoAddresses() { return R"EOF({"addresses":[]})EOF"; }
  std::string slfResponseResponseNoJson() { return R"EOF(NO JSON)EOF"; }

  // Fake SLF Functionality: Send a response from "SLF" to Envoy with the supplied
  // status code and body.  Return the stream.
  FakeStreamPtr sendSlfResponse(const std::string& status, const std::string& body) {
    ENVOY_LOG(debug, "sendSlfResponse()");
    if (!fake_slf_connection_) {
      AssertionResult result =
          fake_upstreams_[1]->waitForHttpConnection(*dispatcher_, fake_slf_connection_);
      RELEASE_ASSERT(result, result.message());
    }

    FakeStreamPtr request_stream;
    AssertionResult result = fake_slf_connection_->waitForNewStream(*dispatcher_, request_stream);
    RELEASE_ASSERT(result, result.message());
    result = request_stream->waitForEndStream(*dispatcher_);

    RELEASE_ASSERT(result, result.message());
    if (body.empty()) {
      request_stream->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", status}}, true);
    } else {
      request_stream->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", status}}, false);
      Buffer::OwnedImpl responseBuffer(body);
      request_stream->encodeData(responseBuffer, true);
    }

    return request_stream;
  }

  FakeStreamPtr noSlfResponse() {
    ENVOY_LOG(debug, "noSlfResponse()");
    if (!fake_slf_connection_) {
      AssertionResult result =
          fake_upstreams_[1]->waitForHttpConnection(*dispatcher_, fake_slf_connection_);
      RELEASE_ASSERT(result, result.message());
    }

    FakeStreamPtr request_stream;
    AssertionResult result = fake_slf_connection_->waitForNewStream(*dispatcher_, request_stream);
    RELEASE_ASSERT(result, result.message());
    result = request_stream->waitForEndStream(*dispatcher_);
    RELEASE_ASSERT(result, result.message());

    return request_stream;
  }

  FakeHttpConnectionPtr fake_slf_connection_;
};


INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterCtIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

//------ Basic Positive Tests ---------------------------------------------

// SUPI Tests
// x-cluster header is set to the region with the highest priority region_A
// The value returned from the SLF is used directly as the cluster name.
// Successful outcome is expected.
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookup_supi) {
  auto supi_test = std::regex_replace(config_basic, std::regex("<3gpp-id>*"),"supi");
  initializeFilter(supi_test);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-supi", "12345"},
      {"3gpp-sbi-correlation-info", "supi-12345"},
      {"user-agent", "AMF"},
  };

  std::optional<Http::TestRequestHeaderMapImpl> exp_slf_req_headers{
    {{"3gpp-sbi-correlation-info", "supi-12345"}, {"user-agent", "SCP"}}};

  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&supi=12345&limit=1";
  execTestWithBasicAssertions(headers,
                              "200",
                              slfResponseResponseRegionA(),
                              nslf_path,
                              "nrfgroup_1",
                              {{"x-eric-proxy","///"},
                               {"x-cluster", "region_A"},
                               {"user-agent", "AMF"}},
                              exp_slf_req_headers);
}

// SLF Lookup followed by egress screening
// x-cluster header is set to the region with the highest priority region_A
// The value returned from the SLF is used directly as the cluster name.
// Successful outcome is expected.
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookup_supi_egress_scr) {
  initializeFilter(config_slf_lookup_egress_screening);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-supi", "12345"},
      {"user-agent", "AMF"},
  };

  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&supi=12345&limit=1";

  std::optional<Http::TestRequestHeaderMapImpl> exp_slf_req_headers{{{"user-agent", "SEPP"}}};

  execTestWithBasicAssertions(headers,
                              "200",
                              slfResponseResponseRegionA(),
                              nslf_path,
                              "nrfgroup_1",
                              {{"x-eric-proxy","///"},    // exp. headers upstream req.
                               {"x-cluster", "region_A"},
                               {"egress_screening", "correct pool"},
                               {"user-agent", "AMF"}},
                              exp_slf_req_headers);  // exp. headers slf req
}

// x-cluster header is set to the region with the highest priority region_A
// The value returned from the SLF is translated from a region name to the
// cluster name with the help of a key-value table and action-modify-variable.
// Successful outcome is expected.
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookupWithKvt_supi) {
  auto supi_test_kvt = std::regex_replace(config_basic_kvt, std::regex("<3gpp-id>*"),"supi");
  initializeFilter(supi_test_kvt);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-supi", "123"},
  };
  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&supi=123&limit=1";
  execTestWithBasicAssertions(headers,
                              "200",slfResponseResponseRegionA(),
                              nslf_path, "nrfgroup_1",
                              {{"x-eric-proxy","///"}, {"x-cluster", "cluster_regionA"}});
}

// x-cluster header is set to the region with the highest priority region_C
// The value returned from the SLF is translated from a region name to the
// cluster name with the help of a key-value table and action-modify-variable.
// The kvt-table exists, but does not have an entry for "region_C", which means the mapped
// value is "", and with this the x-cluster header must be "".
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookupWithKvtNoKvtEntryForRegion_supi) {
  auto supi_test_kvt = std::regex_replace(config_basic_kvt, std::regex("<3gpp-id>*"),"supi");
  initializeFilter(supi_test_kvt);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-supi", "123"},
  };
  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&supi=123&limit=1";
  execTestWithBasicAssertions(headers,
                              "200",slfResponseResponseRegionC(),
                              nslf_path, "nrfgroup_1",
                              {{"x-eric-proxy","///"}, {"x-cluster", ""}});
}

// x-cluster header is set to the region with the highest priority region_A.
// The table to look up the cluster name does not exist in the Envoy configuration.
// A kvt-table lookup for a non-existing table returns "", which is the cluster we expect.
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookupWithKvtNoKvtTableMatched_supi) {
  auto supi_test_kvt = std::regex_replace(config_basic_kvt, std::regex("<3gpp-id>*"),"supi");
  initializeFilter(supi_test_kvt);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-supi", "1234"},
  };

  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&supi=1234&limit=1";
  execTestWithBasicAssertions(headers,
                              "200",slfResponseResponseRegionA(),
                              nslf_path, "",
                              {{"x-eric-proxy","///"}, {"x-cluster", ""}});
}

// x-cluster header is set to region_B due to kvt lookup with a term_string input
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookupWithKvtInputFromString_supi) {
  auto supi_test_kvt = std::regex_replace(config_basic_kvt,std::regex("<3gpp-id>*"),"supi");
  initializeFilter(supi_test_kvt);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-supi", "1235"},
  };

  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&supi=1235&limit=1";
  execTestWithBasicAssertions(headers,
                              "200",slfResponseResponseRegionA(),
                              nslf_path, "nrfgroup_1",
                              {{"x-eric-proxy","///"}, {"x-cluster", "cluster_regionB"}});
}

// x-cluster header is set to region_B due to kvt lookup with a term_header input
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookupWithKvtInputFromHeader_supi) {
  auto supi_test_kvt = std::regex_replace(config_basic_kvt,std::regex("<3gpp-id>*"),"supi");
  initializeFilter(supi_test_kvt);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-supi", "1236"},
      {"x-test-region", "region_B"},
  };

  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&supi=1236&limit=1";
  execTestWithBasicAssertions(headers,
                              "200",slfResponseResponseRegionA(),
                              nslf_path, "nrfgroup_1",
                              {{"x-eric-proxy","///"},{"x-cluster", "cluster_regionB"}});
}

// x-cluster header is set to the region with the highest priority region_A
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookupCdnLoopDetected_supi) {
  config_helper_.addFilter(config_cdn_loop_filter);
  auto supi_test = std::regex_replace(config_basic,std::regex("<3gpp-id>*"),"supi");
  config_helper_.addFilter(supi_test);
  setUpstreamCount(2);
  HttpIntegrationTest::initialize();
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
      {"x-test-supi", "12345"},
      {"via", "2.0 scp.ericsson.se"},
      {"content-length", std::to_string(body.length())}
  };

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));

  auto response = codec_client->makeRequestWithBody(headers, body);
  //auto response = codec_client->makeHeaderOnlyRequest(headers);

  FakeStreamPtr slf_request_stream = sendSlfResponse("200", slfResponseResponseRegionA());

  //ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  //ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));

  ASSERT_TRUE(slf_request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_slf_connection_->close());

  //ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

  //ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("400", response->headers().getStatusValue());

  codec_client->close();
}

// x-cluster header is set to the region with the highest priority region_A
// No address in SUPI response indicates no fqdn stepping identity_not_found counter
TEST_P(EricProxyFilterCtIntegrationTest, TestLookupNoAddressFound_supi) {
  auto supi_test = std::regex_replace(config_basic,std::regex("<3gpp-id>*"),"supi");
  initializeFilter(supi_test);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-chfsim-1-mnc-456-mcc-456:443"},
      {"x-test-supi", "12345"},
  };
  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&supi=12345&limit=1";
  execTestWithBasicAssertions(headers,
                              "200",slfResponseResponseNoAddresses(),
                              nslf_path, "nrfgroup_1",
                              {{"x-slf-fc-triggered", "fc_id_not_found"}});

  EXPECT_EQ(1UL,test_server_->counter("http.eric_proxy.n8e.West1.g3p.slf_lookup.slf_lookup_identity_not_found")->value());
}

// x-cluster header is set to the region with the highest priority region_A
// No address in SUPI response indicates no fqdn stepping identity_not_found counter
// DND-30754 envoy crash if supi is not found (null)
TEST_P(EricProxyFilterCtIntegrationTest, TestLookupNoAddressFound_supi_null_DND_30754) {
  auto supi_test = std::regex_replace(config_basic_json_pointer,std::regex("<3gpp-id>*"),"supi");
  initializeFilter(supi_test);
    std::string body{R"(
    {
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

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));

  auto response = codec_client->makeRequestWithBody(headers, body);

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));

  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-slf-fc-triggered", "fc_id_missing"));

  codec_client->close();
}


TEST_P(EricProxyFilterCtIntegrationTest, TestLookupNoJson_supi) {
  auto supi_test = std::regex_replace(config_basic,std::regex("<3gpp-id>*"),"supi");
  initializeFilter(supi_test);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-chfsim-1-mnc-456-mcc-456:443"},
      {"x-test-supi", "12345"},
  };

  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&supi=12345&limit=1";
  execTestWithBasicAssertions(headers,
                              "200",slfResponseResponseNoJson(),
                              nslf_path, "nrfgroup_1",
                              {{"x-slf-fc-triggered", "fc_lookup_failure"}});

}

// 404 status code from SLF lookup indicates a SlfDestination Unknown
// should step slf_lookup_destination_unknown counter

TEST_P(EricProxyFilterCtIntegrationTest, TestSlfLookupDestinationUnknown_supi) {
  auto supi_test = std::regex_replace(config_basic,std::regex("<3gpp-id>*"),"supi");
  initializeFilter(supi_test);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-chfsim-1-mnc-456-mcc-456:443"},
      {"x-test-supi", "12345"},
  };

  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&supi=12345&limit=1";
  execTestWithBasicAssertions(headers,
                              "404",slfResponseResponseNoJson(),
                              nslf_path, "nrfgroup_1",
                              {{"x-slf-fc-triggered", "fc_dest_unknown"}});

  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.g3p.slf_lookup.slf_lookup_destination_unknown")->value());
}


// x-cluster header is set to the region with the highest priority region_A
// Check slf_unreachable counter
TEST_P(EricProxyFilterCtIntegrationTest, TestUnsuccessfulLookup_NoHealthyUpstream_supi) {
   auto supi_test_no_ep = std::regex_replace(config_basic_no_ep_cluster_2,std::regex("<3gpp-id>*"),"supi");
  initializeFilter(supi_test_no_ep);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-supi", "12345"},
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

  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-slf-fc-triggered", "fc_lookup_failure"));

  ENVOY_LOG(trace, printCounters(test_server_));
  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.g3p.slf_lookup.slf_lookup_service_unreachable")->value());

  codec_client->close();
}

//Request Timeout Expect slf_lookup_lookup_failure counter to be stepped

TEST_P(EricProxyFilterCtIntegrationTest, TestLookupNoResponseFromSlf_supi) {
  auto supi_test = std::regex_replace(config_basic,std::regex("<3gpp-id>*"),"supi");
  initializeFilter(supi_test);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-chfsim-1-mnc-456-mcc-456:443"},
      {"x-test-supi", "12345"},
  };

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(headers);
  FakeStreamPtr slf_request_stream = noSlfResponse();

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));

  ASSERT_TRUE(slf_request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_slf_connection_->close());

  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(request_stream->headers(),
              Http::HeaderValueOf("x-slf-fc-triggered", "fc_lookup_failure"));
  ENVOY_LOG(trace, printCounters(test_server_));
    EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.g3p.slf_lookup.slf_lookup_lookup_failure")->value());

  codec_client->close();
}

TEST_P(EricProxyFilterCtIntegrationTest, TestLookupClientResetBeforeNoResponseFromSlf_supi) {
  auto supi_test = std::regex_replace(config_basic,std::regex("<3gpp-id>*"),"supi");
  initializeFilter(supi_test);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-chfsim-1-mnc-456-mcc-456:443"},
      {"x-test-supi", "12345"},
  };

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(headers);
  FakeStreamPtr slf_request_stream = noSlfResponse();

  ENVOY_LOG(trace, printCounters(test_server_));
  codec_client->close();
  ASSERT_TRUE(slf_request_stream->waitForEndStream(*dispatcher_));
}




//------ Basic Positive Tests ---------------------------------------------
// x-cluster header is set to the region with the highest priority region_A
// GPSI Tests
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookup_gpsi) {
  auto gpsi_test = std::regex_replace(config_basic,std::regex("<3gpp-id>*"),"gpsi");
  initializeFilter(gpsi_test);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-gpsi", "12345"},
  };
  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&gpsi=12345&limit=1";
  execTestWithBasicAssertions(headers,
                              "200", slfResponseResponseRegionA(),
                              nslf_path, "nrfgroup_1",
                              {{"x-eric-proxy","///"}, {"x-cluster", "region_A"}});
}

// x-cluster header is set to the region with the highest priority region_A
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookupWithKvt_gpsi) {
  auto gpsi_test_kvt = std::regex_replace(config_basic_kvt,std::regex("<3gpp-id>*"),"gpsi");
  initializeFilter(gpsi_test_kvt);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-gpsi", "123"},
  };
  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&gpsi=123&limit=1";
  execTestWithBasicAssertions(headers,
                              "200", slfResponseResponseRegionA(),
                              nslf_path, "nrfgroup_1",
                              {{"x-eric-proxy","///"}, {"x-cluster", "cluster_regionA"}});
}

// x-cluster header is set to the region with the highest priority region_C
// The kvt-table exists, but does not have an entry for "region_C", which means the mapped
// value is "", and with this the x-cluster header must me "".
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookupWithKvtNoKvtEntryForRegion_gpsi) {

  auto gpsi_test_kvt = std::regex_replace(config_basic_kvt,std::regex("<3gpp-id>*"),"gpsi");
  initializeFilter(gpsi_test_kvt);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-gpsi", "123"},
  };
  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&gpsi=123&limit=1";
  execTestWithBasicAssertions(headers,
                              "200", slfResponseResponseRegionC(),
                              nslf_path, "nrfgroup_1",
                              {{"x-eric-proxy","///"}, {"x-cluster", ""}});
}

// x-cluster header is set to the region with the highest priority region_A.
// The table to look up the cluster name does not exist in the Envoy configuration.
// A kvt-table lookup for a non-existing table returns "", which is the cluster we expect.
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookupWithKvtNoKvtTableMatched_gpsi) {
  auto gpsi_test_kvt = std::regex_replace(config_basic_kvt,std::regex("<3gpp-id>*"),"gpsi");
  initializeFilter(gpsi_test_kvt);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-gpsi", "1234"},
  };
  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&gpsi=1234&limit=1";
  execTestWithBasicAssertions(headers,
                              "200", slfResponseResponseRegionA(),
                              nslf_path, "",
                              {{"x-eric-proxy","///"}, {"x-cluster", ""}});
}

// x-cluster header is set to region_B due to kvt lookup with a term_string input
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookupWithKvtInputFromString_gpsi) {
  auto gpsi_test_kvt = std::regex_replace(config_basic_kvt,std::regex("<3gpp-id>*"),"gpsi");
  initializeFilter(gpsi_test_kvt);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-gpsi", "1235"},
  };
  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&gpsi=1235&limit=1";
  execTestWithBasicAssertions(headers,
                              "200", slfResponseResponseRegionA(),
                              nslf_path, "nrfgroup_1",
                              {{"x-eric-proxy","///"}, {"x-cluster", "cluster_regionB"}});
}

// x-cluster header is set to region_B due to kvt lookup with a term_header input
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookupWithKvtInputFromHeader_gpsi) {
  auto gpsi_test_kvt = std::regex_replace(config_basic_kvt,std::regex("<3gpp-id>*"),"gpsi");
  initializeFilter(gpsi_test_kvt);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-gpsi", "1236"},
      {"x-test-region", "region_B"},
  };
  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&gpsi=1236&limit=1";
  execTestWithBasicAssertions(headers,
                              "200", slfResponseResponseRegionA(),
                              nslf_path, "nrfgroup_1",
                              {{"x-eric-proxy","///"}, {"x-cluster", "cluster_regionB"}});
}

// To route based on authority
TEST_P(EricProxyFilterCtIntegrationTest, TestNotify) {
  auto gpsi_test_notify = std::regex_replace(config_notify,std::regex("<3gpp-id>*"),"gpsi");
  initializeFilter(gpsi_test_notify);
  Http::TestRequestHeaderMapImpl headers{
    {":method","POST"},
    {":path","/"},
    {":authority","notify-host"},
    {"x-test-gpsi", "12345"},
    {"x-test-region", "region_B"},
  };

  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&gpsi=12345&limit=1";
  execTestWithBasicAssertions(headers,
                              "200", slfResponseResponseRegionA(),
                              nslf_path, "nrfgroup_1",
                              {{"x-eric-proxy","///"}, {":authority","notify-host"}});
}

// x-cluster header is set to the region with the highest priority region_A
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookupCdnLoopDetected_gpsi) {
  config_helper_.addFilter(config_cdn_loop_filter);
  auto gpsi_test = std::regex_replace(config_basic,std::regex("<3gpp-id>*"),"gpsi");
  config_helper_.addFilter(gpsi_test);
  setUpstreamCount(2);
  HttpIntegrationTest::initialize();
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
      {"x-test-gpsi", "12345"},
      {"via", "2.0 scp.ericsson.se"},
      {"content-length", std::to_string(body.length())}
  };

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));

  auto response = codec_client->makeRequestWithBody(headers, body);
  //auto response = codec_client->makeHeaderOnlyRequest(headers);

  FakeStreamPtr slf_request_stream = sendSlfResponse("200", slfResponseResponseRegionA());

  //ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  //ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));

  ASSERT_TRUE(slf_request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_slf_connection_->close());

  //ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

  //ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("400", response->headers().getStatusValue());

  codec_client->close();
}

// x-cluster header is set to the region with the highest priority region_A
TEST_P(EricProxyFilterCtIntegrationTest, TestLookupNoAddressFound_gpsi) {
  auto gpsi_test = std::regex_replace(config_basic,std::regex("<3gpp-id>*"),"gpsi");
  initializeFilter(gpsi_test);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-chfsim-1-mnc-456-mcc-456:443"},
      {"x-test-gpsi", "12345"},
  };
  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&gpsi=12345&limit=1";
  execTestWithBasicAssertions(headers,
                              "200", slfResponseResponseNoAddresses(),
                              nslf_path, "nrfgroup_1",
                              {{"x-slf-fc-triggered", "fc_id_not_found"}});

  EXPECT_EQ(1UL,test_server_->counter("http.eric_proxy.n8e.West1.g3p.slf_lookup.slf_lookup_identity_not_found")->value());
}

TEST_P(EricProxyFilterCtIntegrationTest, TestLookupNoJson_gpsi) {
  auto gpsi_test = std::regex_replace(config_basic,std::regex("<3gpp-id>*"),"gpsi");
  initializeFilter(gpsi_test);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-chfsim-1-mnc-456-mcc-456:443"},
      {"x-test-gpsi", "12345"},
  };
  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&gpsi=12345&limit=1";
  execTestWithBasicAssertions(headers,
                              "200", slfResponseResponseNoJson(),
                              nslf_path, "nrfgroup_1",
                              {{"x-slf-fc-triggered", "fc_lookup_failure"}});
}


// 404 status code from SLF lookup indicates a SlfDestination Unknown
// should step slf_lookup_destination_unknown counter

TEST_P(EricProxyFilterCtIntegrationTest, TestSlfLookupDestinationUnknown_gpsi) {
  auto gpsi_test = std::regex_replace(config_basic,std::regex("<3gpp-id>*"),"gpsi");
  initializeFilter(gpsi_test);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-chfsim-1-mnc-456-mcc-456:443"},
      {"x-test-gpsi", "12345"},
  };

  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=SCP&target-nf-type=CHF&gpsi=12345&limit=1";
  execTestWithBasicAssertions(headers,
                              "404", slfResponseResponseNoJson(),
                              nslf_path, "nrfgroup_1",
                              {{"x-slf-fc-triggered", "fc_dest_unknown"}});

  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.g3p.slf_lookup.slf_lookup_destination_unknown")->value());
}


// x-cluster header is set to the region with the highest priority region_A
TEST_P(EricProxyFilterCtIntegrationTest, TestUnsuccessfulLookup_NoHealthyUpstream_gpsi) {
   auto gpsi_test_no_ep = std::regex_replace(config_basic_no_ep_cluster_2,std::regex("<3gpp-id>*"),"gpsi");
  initializeFilter(gpsi_test_no_ep);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-gpsi", "12345"},
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

  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-slf-fc-triggered", "fc_lookup_failure"));

  EXPECT_EQ(1UL, test_server_->counter("http.eric_proxy.n8e.West1.g3p.slf_lookup.slf_lookup_service_unreachable")->value());

  codec_client->close();
}

TEST_P(EricProxyFilterCtIntegrationTest, TestLookupNoResponseFromSlf_gpsi) {
  auto gpsi_test = std::regex_replace(config_basic,std::regex("<3gpp-id>*"),"gpsi");
  initializeFilter(gpsi_test);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-chfsim-1-mnc-456-mcc-456:443"},
      {"x-test-gpsi", "12345"},
  };

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(headers);
  FakeStreamPtr slf_request_stream = noSlfResponse();

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));

  ASSERT_TRUE(slf_request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_slf_connection_->close());

  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(request_stream->headers(),
              Http::HeaderValueOf("x-slf-fc-triggered", "fc_lookup_failure"));

  codec_client->close();
}

TEST_P(EricProxyFilterCtIntegrationTest, TestLookupClientResetBeforeNoResponseFromSlf_gpsi) {
  auto gpsi_test = std::regex_replace(config_basic,std::regex("<3gpp-id>*"),"gpsi");
  initializeFilter(gpsi_test);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-chfsim-1-mnc-456-mcc-456:443"},
      {"x-test-gpsi", "12345"},
  };

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(headers);
  FakeStreamPtr slf_request_stream = noSlfResponse();

  codec_client->close();
  ASSERT_TRUE(slf_request_stream->waitForEndStream(*dispatcher_));
}


// Enhancements for integration tests checking :path of Nslf interface message
TEST_P(EricProxyFilterCtIntegrationTest, TestSuccessfulLookupcustomNfTypes) {
  auto supi_test_nfTypes = std::regex_replace(config_basic_customNFTypes,std::regex("<3gpp-id>*"),"supi");
  initializeFilter(supi_test_nfTypes);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-test-supi", "12345"},
  };
  std::string nslf_path = "/nslf-disc/v0/addresses?requester-nf-type=AMF&target-nf-type=UDM&supi=12345&limit=1";
  execTestWithBasicAssertions(headers,
                              "200",slfResponseResponseRegionA(),
                              nslf_path, "nrfgroup_1",
                              {{"x-eric-proxy","///"} ,{"x-cluster","region_A"}});
}


} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
