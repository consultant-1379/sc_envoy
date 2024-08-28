#include "source/common/common/logger.h"
#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "test/integration/http_integration.h"
#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterScreeningIntegrationTest
    : public HttpIntegrationTest,
      public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterScreeningIntegrationTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(),
                            EricProxyFilterScreeningIntegrationTest::ericProxyHttpProxyConfig()) {}
  /**
   * Initializer for an individual integration test.
   */
  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);

    HttpIntegrationTest::initialize();
  }

  const std::string config_one_fc = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
  own_internal_port: 80
  key_value_tables:
    - name: lookup_table
      entries:
        - key: x-it-header-table-lookup-val
          value: x-it-header-table-lookup-fake-val
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
      - name: apiRoot_data2
        header: 3gpp-Sbi-target-apiRoot2
        variable_name: mcc
      - name: apiRoot_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      - name: new_fqdn_value
        header: new_fqdn
        variable_name: new_fqdn
      - name: location_header
        header: location
        extractor_regex: (?P<pre>https?://)(?P<mid>[^/]+)(?P<post>/.*)
      filter_rules:
      - name: csepp_to_rp_A
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_add_header:
            name: x-it-header-name-added
            value:
              term_string: x-it-header-value-added 
        - action_add_header:
            name: x-it-header-name-addnewvalue
            value:
              term_string: x-it-header-value-added-new
            if_exists: ADD
        - action_add_header:
            name: x-it-header-name-replaced-by-add
            value:
              term_string: x-it-header-value-replaced-by-add
            if_exists: REPLACE
        - action_modify_header:
            name: abc
            append_value:
              term_header: def
        - action_modify_header:
            name: abc
            prepend_value:
              term_header: ghi
        - action_modify_header:
            name: location
            replace_value:
              term_var: new_fqdn
        - action_modify_header:
            name: location
            prepend_value:
              term_var: pre
        - action_modify_header:
            name: location
            append_value:
              term_var: post
        - action_modify_header:
            name: x-it-header-name-replaced
            replace_value:
              term_string: x-it-header-value-replaced
        - action_modify_header:
            name: x-it-header-name-modified
            append_value:
              term_string: x-it-header-value-appended
        - action_modify_header:
            name: x-it-header-name-modified
            prepend_value:
              term_string: x-it-header-value-prepended
        - action_modify_header:
            name: x-it-header-name-modified1
            append_value:
              term_string: x-it-header-value-appended1
            prepend_value:
              term_string: x-it-header-value-prepended1
        - action_modify_header:
            name: x-it-header-name-prepended
            prepend_value:
              term_string: x-it-header-value-prepended
        - action_modify_header:
            name: x-it-header-tbl-lookup
            use_string_modifiers:
              string_modifiers:
              - table_lookup:
                  lookup_table_name: lookup_table
                  do_nothing: true
        - action_modify_query_param:
            key_name: query-param-key
            use_string_modifiers:
              string_modifiers:
              - table_lookup:
                  lookup_table_name: lookup_table
                  do_nothing: true
        - action_remove_header:
            name: x-it-header-name-removed
        - action_remove_header:
            name: x-eric-proxy
        - action_modify_header:
            name: :status
            replace_value:
              term_string: '200'
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: psepp_to_dfw
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: STRICT
    - name: response_processing
      filter_rules:
      - name: add_resp_header
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: x-added-by-response
            value:
              term_string: "response path triggered"
        - action_remove_header:
            name: x-eric-proxy
        - action_exit_filter_case: true
      - name: not_reached_add_header
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: x-should-not-be-added-by-response
            value:
              term_string: "this rule/action should not be reached"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_three_fc = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
      - name: apiRoot_data2
        header: 3gpp-Sbi-target-apiRoot2
        variable_name: mcc
      - name: apiRoot_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      - name: new_fqdn_value
        header: new_fqdn
        variable_name: new_fqdn
      - name: location_header
        header: location
        extractor_regex: (?P<pre>https?://)(?P<mid>[^/]+)(?P<post>/.*)
      filter_rules:
      - name: csepp_to_rp_A
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_modify_header:
            name: abc
            append_value:
              term_header: def
        - action_modify_header:
            name: abc
            prepend_value:
              term_header: ghi
        - action_modify_header:
            name: location
            replace_value:
              term_var: new_fqdn
        - action_modify_header:
            name: location
            prepend_value:
              term_var: pre
        - action_modify_header:
            name: location
            append_value:
              term_var: post
        - action_add_header:
            name: x-it-header-name-added
            value:
              term_string: x-it-header-value-added
            if_exists: NO_ACTION 
        - action_add_header:
            name: x-it-header-name-addnewvalue
            value:
              term_string: x-it-header-value-added-new
            if_exists: ADD
        - action_add_header:
            name: x-it-header-name-replaced-by-add
            value:
              term_string: x-it-header-value-replaced-by-add
            if_exists: REPLACE
        - action_modify_header:
            name: x-it-header-name-replaced
            replace_value:
              term_string: x-it-header-value-replaced
        - action_modify_header:
            name: x-it-header-name-modified
            append_value:
              term_string: x-it-header-value-appended
        - action_modify_header:
            name: x-it-header-name-modified
            prepend_value:
              term_string: x-it-header-value-prepended
        - action_modify_header:
            name: x-it-header-name-modified1
            append_value:
              term_string: x-it-header-value-appended1
            prepend_value:
              term_string: x-it-header-value-prepended1
        - action_modify_header:
            name: x-it-header-name-prepended
            prepend_value:
              term_string: x-it-header-value-prepended
        - action_remove_header:
            name: x-it-header-name-removed
        - action_goto_filter_case: continuation_fc
      - name: direct_response_plain
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '987' }}
        actions:
        - action_reject_message:
            status: 543
            title: "reject test"
            message_format: PLAIN_TEXT
      - name: direct_response_json1
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '988' }}
        actions:
        - action_reject_message:
            status: 544
            title: "reject test json1"
            message_format: JSON
            detail: "test detail"
      - name: direct_response_json2
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '989' }}
        actions:
        - action_reject_message:
            status: 545
            title: "reject test json2"
            message_format: JSON
      - name: drop_message
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '950' }}
        actions:
        - action_log:
            max_log_message_length: 500
            log_values:
            - term_string: "### Log message from test-case: ERROR ###"
            log_level: ERROR
        - action_log:
            max_log_message_length: 500
            log_values:
            - term_string: "### Log message from test-case: WARN ###"
            log_level: WARN
        - action_log:
            max_log_message_length: 500
            log_values:
            - term_string: "### Log message from test-case: INFO ###"
            log_level: INFO
        - action_log:
            max_log_message_length: 500
            log_values:
            - term_string: "### Log message from test-case: DEBUG ###"
            log_level: DEBUG
        - action_log:
            max_log_message_length: 500
            log_values:
            - term_string: "### Log message from test-case TRACE ###"
            log_level: TRACE
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
        - action_remove_header:
            name: x-eric-proxy
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
      - name: add_resp_header
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: x-added-by-response
            value:
              term_string: "response path triggered"
        - action_remove_header:
            name: x-eric-proxy
        - action_exit_filter_case: true
      - name: not_reached_add_header
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: x-should-not-be-added-by-response
            value:
              term_string: "this rule/action should not be reached"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_modify_multiple_headers = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
        - action_modify_header:
            name: x-dummy-header
            append_value:
              term_string: vappended
        - action_modify_header:
            name: x-dummy-header
            prepend_value:
              term_string: vprepended
    - name: response_processing
      filter_rules:
      - name: resp_rule_log
        condition:
          term_boolean: true
        actions:
        - action_log:
            max_log_message_length: 500
            log_values:
            - term_string: "### Just an action in a fake response ###"
            log_level: INFO
)EOF";

  const std::string config_five_fc = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
  own_fqdn: scp.own_fqdn.com
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
        - action_add_header:
            name: dummy-header
            value:
              term_string: value
            if_exists: ADD
        - action_add_header:
            name: dummy-header
            value:
              term_string: value2
            if_exists: ADD
        - action_add_header:
            name: via
            value:
              term_string: value
            if_exists: ADD
        - action_add_header:
            name: via
            value:
              term_string: value2
            if_exists: ADD
    - name: response_processing
      filter_rules:
      - name: resp_rule_log
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: response-dummy-header
            value:
              term_string: response-value
            if_exists: ADD
        - action_add_header:
            name: response-dummy-header
            value:
              term_string: response-value2
            if_exists: ADD
        - action_add_header:
            name: via
            value:
              term_string: response-value
            if_exists: ADD
        - action_add_header:
            name: via
            value:
              term_string: response-value2
            if_exists: ADD
)EOF";

  const std::string config_six_fc = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
        - action_add_header:
            name: dummy-header
            value:
              term_string: ""
        - action_modify_header:
            name: dummy-header
            append_value:
              term_string: -appended
    - name: response_processing
      filter_rules:
      - name: resp_rule_log
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: response-dummy-header
            value:
              term_string: ""
        - action_modify_header:
            name: response-dummy-header
            append_value:
              term_string: -appended
)EOF";

  const std::string config_predexp_after_header_mods = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
      - name: locality_header
        header: locality
        variable_name: locality
      filter_rules:
      - name: loc1
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: locality }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'datacenter1' }}
        actions:
        - action_modify_header:
            name: locality
            replace_value:
              term_string: datacenter2
        - action_add_header:
            name: x-loc1
            value:
              term_string: "locality 1 rule executed"
      - name: psepp_to_dfw
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: locality }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'datacenter2' }}
        actions:
        - action_add_header:
            name: x-loc2
            value:
              term_string: "locality 2 rule executed"
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
    - name: response_processing
      filter_rules:
      - name: add_resp_header
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: x-added-by-response
            value:
              term_string: "response path triggered"
        - action_remove_header:
            name: x-eric-proxy
        - action_exit_filter_case: true
      - name: not_reached_add_header
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: x-should-not-be-added-by-response
            value:
              term_string: "this rule/action should not be reached"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  // Phase 1 and 6 are from config_three_fc
  // NOTE: Routing is done in phase 1, not in 2!!!
  const std::string config_ph_1_2_3_4_5_6 = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
        - rc_ph2
    out_request_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          sepp_rp_A: sc_ph3
  response_filter_cases:
    in_response_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          sepp_rp_A: sc_ph4
    out_response_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - response_processing
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: apiRoot_data2
        header: 3gpp-Sbi-target-apiRoot2
        variable_name: mcc
      - name: apiRoot_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      - name: new_fqdn_value
        header: new_fqdn
        variable_name: new_fqdn
      - name: location_header
        header: location
        extractor_regex: (?P<pre>https?://)(?P<mid>[^/]+)(?P<post>/.*)
      filter_rules:
      - name: csepp_to_rp_A
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_modify_header:
            name: abc
            append_value:
              term_header: def
        - action_modify_header:
            name: abc
            prepend_value:
              term_header: ghi
        - action_modify_header:
            name: location
            replace_value:
              term_var: new_fqdn
        - action_modify_header:
            name: location
            prepend_value:
              term_var: pre
        - action_modify_header:
            name: location
            append_value:
              term_var: post
        - action_add_header:
            name: x-it-header-name-added
            value:
              term_string: x-it-header-value-added
            if_exists: NO_ACTION 
        - action_add_header:
            name: x-it-header-name-addnewvalue
            value:
              term_string: x-it-header-value-added-new
            if_exists: ADD
        - action_add_header:
            name: x-it-header-name-replaced-by-add
            value:
              term_string: x-it-header-value-replaced-by-add
            if_exists: REPLACE
        - action_modify_header:
            name: x-it-header-name-replaced
            replace_value:
              term_string: x-it-header-value-replaced
        - action_modify_header:
            name: x-it-header-name-modified
            append_value:
              term_string: x-it-header-value-appended
        - action_modify_header:
            name: x-it-header-name-modified
            prepend_value:
              term_string: x-it-header-value-prepended
        - action_modify_header:
            name: x-it-header-name-modified1
            append_value:
              term_string: x-it-header-value-appended1
            prepend_value:
              term_string: x-it-header-value-prepended1
        - action_modify_header:
            name: x-it-header-name-prepended
            prepend_value:
              term_string: x-it-header-value-prepended
        - action_remove_header:
            name: x-it-header-name-removed
        - action_goto_filter_case: continuation_fc
      - name: direct_response_plain
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '987' }}
        actions:
        - action_reject_message:
            status: 543
            title: "reject test"
            message_format: PLAIN_TEXT
      - name: direct_response_json1
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '988' }}
        actions:
        - action_reject_message:
            status: 544
            title: "reject test json1"
            message_format: JSON
            detail: "test detail"
      - name: direct_response_json2
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '989' }}
        actions:
        - action_reject_message:
            status: 545
            title: "reject test json2"
            message_format: JSON
      - name: drop_message
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '950' }}
        actions:
        - action_log:
            max_log_message_length: 500
            log_values:
            - term_string: "### Log message from test-case: ERROR ###"
            log_level: ERROR
        - action_log:
            max_log_message_length: 500
            log_values:
            - term_string: "### Log message from test-case: WARN ###"
            log_level: WARN
        - action_log:
            max_log_message_length: 500
            log_values:
            - term_string: "### Log message from test-case: INFO ###"
            log_level: INFO
        - action_log:
            max_log_message_length: 500
            log_values:
            - term_string: "### Log message from test-case: DEBUG ###"
            log_level: DEBUG
        - action_log:
            max_log_message_length: 500
            log_values:
            - term_string: "### Log message from test-case TRACE ###"
            log_level: TRACE
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
        - action_remove_header:
            name: x-eric-proxy
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
    - name: rc_ph2
      filter_rules:
      - name: dummy_ph2
        condition:
           term_boolean: true
        actions:
        - action_add_header:
            name: x-it-header-name-added
            value:
              term_string: x-it-header-value-added-routing_ph2
            if_exists: NO_ACTION
    - name: sc_ph3
      filter_rules:
      - name: dummy_ph3
        condition:
           term_boolean: true
        actions:
        - action_add_header:
            name: x-it-header-name-added
            value:
              term_string: x-it-header-value-added-screening_ph3
            if_exists: NO_ACTION
    - name: sc_ph4
      filter_rules:
      - name: dummy_ph4
        condition:
           term_boolean: true
        actions:
        - action_add_header:
            name: x-added-by-response_ph4
            value:
              term_string: x-it-header-value-added-screening_ph4
            if_exists: NO_ACTION
    - name: response_processing
      filter_rules:
      - name: add_resp_header
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: x-added-by-response
            value:
              term_string: "response path triggered"
        - action_remove_header:
            name: x-eric-proxy
        - action_exit_filter_case: true
      - name: not_reached_add_header
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: x-should-not-be-added-by-response
            value:
              term_string: "this rule/action should not be reached"

  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_modify_status_code_json = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
    filter_rules:
    - name: action_reject
      condition:
        term_boolean: true
      actions:
      - action_reject_message:
          status: 544
          title: "reject test json1"
          message_format: JSON
          detail: "test detail"
  - name: response_processing
    filter_rules:
    - name: action_modify_status_code
      condition:
        term_boolean: true
      actions:
      - action_modify_status_code:
          status: 500
          title: "modify status code json"
          message_format: JSON
          detail: "test detail modified"
)EOF";

  const std::string config_modify_status_code_json_DND_31754 = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
    filter_rules:
    - name: action_reject
      condition:
        term_boolean: true
      actions:
      - action_reject_message:
          status: 544
          title: "reject test json1"
          message_format: JSON
          detail: "test detail"
  - name: response_processing
    filter_rules:    
    - name: action_modify_status_code
      condition:
        term_boolean: true
      actions:
      - action_add_header:
          name: x-it-header-name-added
          value:
            term_string: x-it-header-value-added
      - action_modify_status_code:
          status: 500
          title: "modify status code json"
          message_format: JSON
)EOF";

  const std::string config_reject_json_modify_status_code_json_no_title = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
    filter_rules:
    - name: action_reject
      condition:
        term_boolean: true
      actions:
      - action_reject_message:
          status: 544
          title: "reject test json1"
          message_format: JSON
          detail: "test detail"
          cause: "test cause"
  - name: response_processing
    filter_rules:
    - name: action_modify_status_code
      condition:
        term_boolean: true
      actions:
      - action_add_header:
          name: x-it-header-name-added
          value:
            term_string: x-it-header-value-added
      - action_modify_status_code:
          status: 500
          message_format: JSON
)EOF";

  const std::string config_reject_json_modify_status_code_json = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
    filter_rules:
    - name: action_reject
      condition:
        term_boolean: true
      actions:
      - action_reject_message:
          status: 544
          title: "reject test json1"
          message_format: JSON
          detail: "test detail"
  - name: response_processing
    filter_rules:    
    - name: action_modify_status_code
      condition:
        term_boolean: true
      actions:
      - action_add_header:
          name: x-it-header-name-added
          value:
            term_string: x-it-header-value-added 
      - action_modify_status_code:
          status: 500
          message_format: JSON
          title: "test title modified"
          cause: "test cause added"
)EOF";

  const std::string config_reject_plain_modify_status_code_json_no_title = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
    filter_rules:
    - name: action_reject
      condition:
        term_boolean: true
      actions:
      - action_reject_message:
          status: 544
          title: "reject test plain"
          message_format: PLAIN_TEXT
          detail: "test detail"
  - name: response_processing
    filter_rules:
    - name: action_modify_status_code
      condition:
        term_boolean: true
      actions:
      - action_add_header:
          name: x-it-header-name-added
          value:
            term_string: x-it-header-value-added 
      - action_modify_status_code:
          status: 500
          message_format: JSON
)EOF";

  const std::string config_reject_plain_modify_status_code_json = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
    filter_rules:
    - name: action_reject
      condition:
        term_boolean: true
      actions:
      - action_reject_message:
          status: 544
          title: "reject test plain"
          message_format: PLAIN_TEXT
          detail: "test detail"
  - name: response_processing
    filter_rules:    
    - name: action_modify_status_code
      condition:
        term_boolean: true
      actions:
      - action_add_header:
          name: x-it-header-name-added
          value:
            term_string: x-it-header-value-added 
      - action_modify_status_code:
          status: 500
          title: "test title modified"
          detail: "test detail modified"
          cause: "test cause modified"
          message_format: JSON
)EOF";

  const std::string config_modify_status_code_plain_text = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
  - name: response_processing
    filter_rules:
    - name: action_modify_status_code
      condition:
        term_boolean: true
      actions:
      - action_modify_status_code:
          title: "modify status code plain text"
          message_format: PLAIN_TEXT
          detail: "test detail ignored"
)EOF";

  const std::string config_modify_status_code_no_body_configured = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
  - name: response_processing
    filter_rules:
    - name: action_modify_status_code
      condition:
        term_boolean: true
      actions:
      - action_modify_status_code:
          status: 201
          detail: "test details ignored"
          message_format: PLAIN_TEXT
)EOF";

  const std::string config_modify_status_code_status_title = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
  - name: response_processing
    filter_rules:
    - name: action_modify_status_code
      condition:
        term_boolean: true
      actions:
      - action_modify_status_code:
          status: 588
          title: "test title modified" 
)EOF";

  const std::string config_modify_status_code_status = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
  - name: response_processing
    filter_rules:
    - name: action_modify_status_code
      condition:
        term_boolean: true
      actions:
      - action_modify_status_code:
          status: 588
)EOF";

  const std::string config_drop_response = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
  - name: response_processing
    filter_rules:
    - name: action_modify_status_code
      condition:
        term_boolean: true
      actions:
      - action_drop_message: true
)EOF";

  // Configuration to test:
  // condition: req.header, resp.header
  // filter-data: header, request-header, response-header
  // Instead of an and-condition this configuration uses goto-fc
  // (the "AND" five lines below this one) so that it's easier to see
  // which condition failed.
  //
  // In request-direction, this is tested:
  // var.tar_header == var.tar_req_header
  // AND
  // var.tar_header == 'abc'
  // AND
  // var.tar_header == req.header['3gpp-Sbi-target-apiRoot']
  //
  // In the response direction, this is tested:
  // req.header['3gpp-Sbi-target-apiRoot'] == 'abc'
  // AND
  // var.tar_req_header_in_resp == 'abc'  # read in message-data in response
  // AND
  // var.loc_header == var.loc_resp_header
  // AND
  // var.loc_header == 'def'
  // AND
  // var.loc_header == resp.header['location']
  const std::string config_req_resp_headers = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
  own_internal_port: 80
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - fc_request_processing
  response_filter_cases:
    out_response_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - fc_response_processing
  filter_cases:
    - name: fc_request_processing
      filter_data:
      - name: header
        header: 3gpp-Sbi-target-apiRoot
        variable_name: tar_header
      - name: request_header
        request_header: 3gpp-Sbi-target-apiRoot
        variable_name: tar_req_header
      filter_rules:
      - name: var_tar_header_equals_var_tar_req_header
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: tar_header }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: tar_req_header }}
        actions:
        - action_goto_filter_case: fc_same_headers
      - name: test_failed
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool_1
            routing_behaviour: ROUND_ROBIN

    - name: fc_same_headers
      filter_data:
      - name: header
        header: 3gpp-Sbi-target-apiRoot
        variable_name: tar_header
      filter_rules:
      - name: var_tar_header_equals_string_abc
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: tar_header }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'abc' }}
        actions:
        - action_goto_filter_case: fc_header_is_abc
      - name: test_failed
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool_2
            routing_behaviour: ROUND_ROBIN

    - name: fc_header_is_abc
      filter_data:
      - name: header
        header: 3gpp-Sbi-target-apiRoot
        variable_name: tar_header
      filter_rules:
      - name: var_tar_header_equals_req_header
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: tar_header }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: '3gpp-Sbi-target-apiRoot' }}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: correct_pool
            routing_behaviour: ROUND_ROBIN
      - name: test_failed_req
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool_3
            routing_behaviour: ROUND_ROBIN

    - name: fc_response_processing
      filter_rules:
      - name: req_test_header_equals_string_abc
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: '3gpp-Sbi-target-apiRoot' }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'abc' }}
        actions:
        - action_goto_filter_case: fc_req_header_correct
      - name: test_failed
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: x-test-result-10
            value: { term_string: failed_10 }

    - name: fc_req_header_correct
      filter_data:
      - name: request_header
        request_header: 3gpp-Sbi-target-apiRoot
        variable_name: tar_req_header_in_resp
      filter_rules:
      - name: var_tar_req_header_in_resp_equals_string_abc
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: tar_req_header_in_resp }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'abc' }}
        actions:
        - action_goto_filter_case: fc_header_is_abc_in_resp
      - name: test_failed
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: x-test-result-11
            value: { term_string: failed_11 }

    - name: fc_header_is_abc_in_resp
      filter_data:
      - name: loc_header
        header: location
        variable_name: loc_header
      - name: loc_resp_header
        response_header: location
        variable_name: loc_resp_header
      filter_rules:
      - name: var_loc_header_equals_loc_resp_header
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: loc_header }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: loc_resp_header }}
        actions:
        - action_goto_filter_case: fc_same_loc_headers
      - name: test_failed
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: x-test-result-12
            value: { term_string: failed_12 }

    - name: fc_same_loc_headers
      filter_data:
      - name: loc_header
        header: location
        variable_name: loc_header
      filter_rules:
      - name: var_loc_req_header_in_resp_equals_string_def
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: loc_header }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'def' }}
        actions:
        - action_goto_filter_case: fc_header_is_def_in_resp
      - name: test_failed
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: x-test-result-13
            value: { term_string: failed_13 }

    - name: fc_header_is_def_in_resp
      filter_data:
      - name: loc_header
        header: location
        variable_name: loc_header
      filter_rules:
      - name: var_loc_req_header_in_resp_equals_resp_header_loc
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: loc_header }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_respheader: location }}
        actions:
        - action_add_header:
            name: x-test-result
            value: { term_string: passed }
        - action_exit_filter_case: true
      - name: test_failed
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: x-test-result-14
            value: { term_string: failed_14 }

    - name: fc_test_failed_resp
      filter_rules:
        name: fall_through_failed_resp
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: x-test-result
            value: { term_string: failed }
)EOF";

  // Bug from Anna DND-32215
  // Configuration to test:
  // resp.header['location'] == 'dummy-header-value-1,dummy-header-value-2' -> false // WRONG should
  // be true
  const std::string config_req_resp_headers_dnd_32215 = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
  own_internal_port: 80
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - fc_req_dummy_headers
  filter_cases:
    - name: fc_req_dummy_headers
      filter_data:
      - name: reqHeaderData
        request_header: dummy-header
        variable_name: reqheader
      filter_rules:
      - name: dummy_hdr_req_two_vals
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: dummy-header }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'dummy-header-val-1,dummy-header-val-2' }}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: correct-pool
            routing_behaviour: ROUND_ROBIN
      - name: test_failed
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong-pool
            routing_behaviour: ROUND_ROBIN

)EOF";

  // Bug from Anna DND-32215
  // Configuration to test:
  // resp.header['location'] == 'dummy-header-value-1' and resp.header['location'] ==
  // 'dummy-header-value-2' -> true // WRONG should be false
  const std::string config_req_resp_headers_dnd_32215_2 = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
  own_internal_port: 80
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - fc_req_dummy_headers
  filter_cases:
    - name: fc_req_dummy_headers
      filter_data:
      - name: dummy_header
        request_header: dummy-header
        variable_name: dummy_header
      filter_rules:
      - name: wrong_route
        condition:
          op_and:
            arg1:
              op_equals:
                typed_config1:
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_reqheader: dummy-header
                typed_config2:
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_string: 'dummy-header-val-1'
            arg2:
              op_equals:
                typed_config1:
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_reqheader: dummy-header
                typed_config2:
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_string: 'dummy-header-val-2'
        actions:
          - action_route_to_pool:
              pool_name:
                term_string: wrong-pool
              routing_behaviour: ROUND_ROBIN
      - name: fall_through
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: correct-pool

)EOF";

  // DFS-3112: How to modify an action-reject response in screening-6
  const std::string config_status_in_response = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: screening_ph1_ph6
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
      filter_rules:
      - name: reject
        condition:
          term_boolean: true
        actions:
        - action_reject_message:
            status: 700
            title: "reject test"
            message_format: PLAIN_TEXT
    - name: response_processing
      filter_rules:
      - name: 'log status'
        condition:
          term_boolean: true
        actions:
        - action_log:
            max_log_message_length: 500
            log_values:
            - term_string: ":status = "
            - term_respheader: ":status"
            log_level: INFO
            max_log_message_length: 100
      - name: 'add header'
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_respheader: ':status' }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '700' }}
        actions:
        - action_add_header:
            name: new-header
            value:
              term_string: 'correct value'
        - action_modify_header:
            name: :status
            replace_value:
              term_string: '200'
        - action_log:
            max_log_message_length: 500
            log_values:
            - term_string: "### :status = '700' matched ###"
            log_level: INFO
            max_log_message_length: 100
        - action_exit_filter_case: true
      - name: failed
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: new-header
            value:
              term_string: 'wrong value'
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

  void testMultipleHeaderActions(const std::string& api_root) {
    Http::TestRequestHeaderMapImpl headers{
        {":method", "GET"},
        {":path", "/"},
        {":authority", "host"},
        {"3gpp-Sbi-target-apiRoot", api_root},
        {"abc", "ABC"},
        {"def", "DEF"},
        {"ghi", "GHI"},
        {"location", "http://old.old.old/postfix123"},
        {"new_fqdn", "new.new.new"},
        {"x-it-header-name-addnewvalue", "x-it-header-value-orig"},
        {"x-it-header-name-replaced-by-add", "x-it-header-value-orig"},
        {"x-it-header-name-replaced", "x-it-header-value-orig"},
        {"x-it-header-name-replaced", "x-it-header-value-orig2"},
        {"x-it-header-name-removed", "x-it-header-value-removed"},
        {"x-it-header-name-removed", "x-it-header-value-removed2"},
        {"x-it-header-name-modified", "x-it-header-value-orig"},
        {"x-it-header-name-modified1", "x-it-header-value-orig1"},
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

    // Request headers on upstream:
    EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
    EXPECT_THAT(request_stream->headers(),
                Http::HeaderValueOf("x-it-header-name-added", "x-it-header-value-added"));
    // action-add-header
    EXPECT_EQ(request_stream->headers()
                  .get(Http::LowerCaseString("x-it-header-name-addnewvalue"))[0]
                  ->value()
                  .getStringView(),
              "x-it-header-value-orig");
    EXPECT_EQ(request_stream->headers()
                  .get(Http::LowerCaseString("x-it-header-name-addnewvalue"))[1]
                  ->value()
                  .getStringView(),
              "x-it-header-value-added-new");
    EXPECT_THAT(request_stream->headers(),
                Http::HeaderValueOf("x-it-header-name-replaced-by-add",
                                    "x-it-header-value-replaced-by-add"));

    EXPECT_THAT(request_stream->headers(),
                Http::HeaderValueOf("x-it-header-name-replaced", "x-it-header-value-replaced"));
    EXPECT_THAT(request_stream->headers(),
                Http::HeaderValueOf(
                    "x-it-header-name-modified",
                    "x-it-header-value-prependedx-it-header-value-origx-it-header-value-appended"));
    EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("abc", "GHIABCDEF"));
    EXPECT_THAT(request_stream->headers(),
                Http::HeaderValueOf("location", "http://new.new.new/postfix123"));
    EXPECT_TRUE(
        request_stream->headers().get(Http::LowerCaseString("x-it-header-name-removed")).empty());

    // Response headers to downstream:
    EXPECT_THAT(response->headers(),
                Http::HeaderValueOf("x-added-by-response", "response path triggered"));
    EXPECT_TRUE(response->headers().get(Http::LowerCaseString("x-lua")).empty());
    EXPECT_TRUE(response->headers()
                    .get(Http::LowerCaseString("x-should-not-be-added-by-response"))
                    .empty());

    codec_client->close();
  }

  void testAddMultipleHeader(const std::string& api_root) {
    Http::TestRequestHeaderMapImpl headers{
        {":method", "GET"},
        {":path", "/"},
        {":authority", "host"},
        {"3gpp-Sbi-target-apiRoot", api_root},
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

    // Request headers on upstream:
    EXPECT_EQ(request_stream->headers().get(Http::LowerCaseString("dummy-header"))[0]->value().getStringView(), "value");
    EXPECT_EQ(request_stream->headers().get(Http::LowerCaseString("dummy-header"))[1]->value().getStringView(), "value2");
    EXPECT_EQ(request_stream->headers().get(Http::LowerCaseString("via"))[0]->value().getStringView(), "value,value2,2.0 SCP-scp.own_fqdn.com");

    // Request headers on downstream:
    EXPECT_EQ(response->headers().get(Http::LowerCaseString("response-dummy-header"))[0]->value().getStringView(), "response-value");
    EXPECT_EQ(response->headers().get(Http::LowerCaseString("response-dummy-header"))[1]->value().getStringView(), "response-value2");
    EXPECT_EQ(response->headers().get(Http::LowerCaseString("via"))[0]->value().getStringView(), "2.0 SCP-scp.own_fqdn.com,response-value,response-value2");
    codec_client->close();
  }

  void testAddAndModifyHeader(const std::string& api_root) {
    Http::TestRequestHeaderMapImpl headers{
        {":method", "GET"},
        {":path", "/"},
        {":authority", "host"},
        {"3gpp-Sbi-target-apiRoot", api_root},
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

    // Request headers on upstream:
    EXPECT_EQ(request_stream->headers()
                  .get(Http::LowerCaseString("dummy-header"))[0]
                  ->value()
                  .getStringView(),
              "-appended");

    // Request headers on downstream:
    EXPECT_EQ(response->headers()
                  .get(Http::LowerCaseString("response-dummy-header"))[0]
                  ->value()
                  .getStringView(),
              "-appended");
    codec_client->close();
  }

  void testActionReject(const std::string& api_root, IntegrationCodecClientPtr& codec_client,
                        IntegrationStreamDecoderPtr& response) {
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

  void testActionModifyStatusCode(IntegrationCodecClientPtr& codec_client,
                                  IntegrationStreamDecoderPtr& response,
                                  Http::TestResponseHeaderMapImpl resp_headers,
                                  const std::string& response_body) {
    Http::TestRequestHeaderMapImpl headers{
        {":method", "GET"},
        {":path", "/"},
        {":authority", "host"},
    };

    codec_client = makeHttpConnection(lookupPort("http"));
    response = codec_client->makeHeaderOnlyRequest(headers);
    FakeStreamPtr faked_request_stream = sendFakeRequestAndRespond(resp_headers, response_body);

    ASSERT_TRUE(faked_request_stream->waitForEndStream(*dispatcher_));
    ASSERT_TRUE(fake_connection_->close());

    ASSERT_TRUE(response->waitForEndStream());
  }

  FakeStreamPtr sendFakeRequestAndRespond(Http::TestResponseHeaderMapImpl resp_headers,
                                          const std::string& body) {
    ENVOY_LOG(debug, "sendFakeRequest()");
    if (!fake_connection_) {

      AssertionResult result =
          fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_connection_);

      RELEASE_ASSERT(result, result.message());
    }
    FakeStreamPtr request_stream;
    AssertionResult result = fake_connection_->waitForNewStream(*dispatcher_, request_stream);
    RELEASE_ASSERT(result, result.message());
    result = request_stream->waitForEndStream(*dispatcher_);
    RELEASE_ASSERT(result, result.message());
    if (body.empty()) {
      request_stream->encodeHeaders(resp_headers, true);
    } else {
      request_stream->encodeHeaders(resp_headers, false);
      Buffer::OwnedImpl responseBuffer(body);
      ENVOY_LOG(debug, "encode Data is called {}", responseBuffer.toString());
      request_stream->encodeData(responseBuffer, true);
    }
    ENVOY_LOG(debug, "sendFakeRequest() end");
    return request_stream;
  }

  FakeHttpConnectionPtr fake_connection_;
};

//--------------------------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterScreeningIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

// Anna's bug

TEST_P(EricProxyFilterScreeningIntegrationTest, repeated_header_req_resp_handling) {
  initializeFilter(config_req_resp_headers_dnd_32215);
  Http::TestRequestHeaderMapImpl headers{{":method", "GET"},
                                         {":path", "/"},
                                         {":authority", "host"},
                                         {"dummy-header", "dummy-header-val-1"},
                                         {"dummy-header", "dummy-header-val-2"}};

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

  // Request headers on upstream:
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "correct-pool"));

  codec_client->close();
}

TEST_P(EricProxyFilterScreeningIntegrationTest, repeated_header_req_resp_handling_2) {
  initializeFilter(config_req_resp_headers_dnd_32215_2);
  Http::TestRequestHeaderMapImpl headers{{":method", "GET"},
                                         {":path", "/"},
                                         {":authority", "host"},
                                         {"dummy-header", "dummy-header-val-1"},
                                         {"dummy-header", "dummy-header-val-2"}};

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

  // Request headers on upstream:
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "correct-pool"));
 
  codec_client->close();
}

// Table lookup tests for header and query param modify actions
TEST_P(EricProxyFilterScreeningIntegrationTest, queryModify_tbl_lookup) {
  initializeFilter(config_one_fc);
    Http::TestRequestHeaderMapImpl headers{
        {":method", "GET"},
        {":path", "/apiroot?query-param-key=x-it-header-table-lookup-val&gh=990"},
        {":authority", "host"},
        {"3gpp-Sbi-target-apiRoot","https://eric-chfsim-1-mnc-123-mcc-123:80" },
        {"abc", "ABC"},
        {"def", "DEF"},
        {"ghi", "GHI"},
        {"location", "http://old.old.old/postfix123"},
        {"new_fqdn", "new.new.new"},
        {"x-it-header-name-addnewvalue", "x-it-header-value-orig"},
        {"x-it-header-name-replaced-by-add", "x-it-header-value-orig"},
        {"x-it-header-name-replaced", "x-it-header-value-orig"},
        {"x-it-header-name-replaced", "x-it-header-value-orig2"},
        {"x-it-header-name-removed", "x-it-header-value-removed"},
        {"x-it-header-name-removed", "x-it-header-value-removed2"},
        {"x-it-header-name-modified", "x-it-header-value-orig"},
        {"x-it-header-name-modified1", "x-it-header-value-orig1"},
        {"x-it-header-tbl-lookup", "x-it-header-table-lookup-val"},
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

  // Request headers on upstream:
  auto req_query_params = Http::Utility::QueryParamsMulti::parseQueryString(
      request_stream->headers().get(Http::LowerCaseString(":path"))[0]->value().getStringView());
  const auto query_param = req_query_params.getFirstValue("query-param-key");

  EXPECT_EQ(query_param.value_or("empty"), "x-it-header-table-lookup-fake-val");

  codec_client->close();
}

TEST_P(EricProxyFilterScreeningIntegrationTest, headerModify_tbl_lookup) {
  initializeFilter(config_one_fc);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "hhtps://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"abc", "ABC"},
      {"def", "DEF"},
      {"ghi", "GHI"},
      {"location", "http://old.old.old/postfix123"},
      {"new_fqdn", "new.new.new"},
      {"x-it-header-name-addnewvalue", "x-it-header-value-orig"},
      {"x-it-header-name-replaced-by-add", "x-it-header-value-orig"},
      {"x-it-header-name-replaced", "x-it-header-value-orig"},
      {"x-it-header-name-replaced", "x-it-header-value-orig2"},
      {"x-it-header-name-removed", "x-it-header-value-removed"},
      {"x-it-header-name-removed", "x-it-header-value-removed2"},
      {"x-it-header-name-modified", "x-it-header-value-orig"},
      {"x-it-header-name-modified1", "x-it-header-value-orig1"},
      {"x-it-header-tbl-lookup", "x-it-header-table-lookup-val"},
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

  // Request headers on upstream:
  EXPECT_THAT(request_stream->headers(),
              Http::HeaderValueOf("x-it-header-tbl-lookup", "x-it-header-table-lookup-fake-val"));
  codec_client->close();
}

// Basic test to add, remove, replace HTTP headers
TEST_P(EricProxyFilterScreeningIntegrationTest, headerAddModDel_one_FC) {
  initializeFilter(config_one_fc);
  testMultipleHeaderActions("https://eric-chfsim-1-mnc-123-mcc-123:80");
}

// Basic test to add, remove, replace HTTP headers. Same as before, but the configuration contains
// action-goto-filter-case so that the header modifications are spread over three different
// filter-cases
TEST_P(EricProxyFilterScreeningIntegrationTest, headerAddModDel_three_FC) {
  initializeFilter(config_three_fc);
  testMultipleHeaderActions("https://eric-chfsim-1-mnc-123-mcc-123:80");
}

// Modify multiple headers with the same name in ingress screening
// We come in with two headers of the same name and prepend and append a string.
// Expected outcome is that both headers have the strings appended/prepended.
TEST_P(EricProxyFilterScreeningIntegrationTest, modifyMultipleHeaders) {
  initializeFilter(config_modify_multiple_headers);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"x-dummy-header", "x-dummy-header-v1"},
      {"x-dummy-header", "x-dummy-header-v2"},
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

  // Request headers on upstream:
  EXPECT_EQ(request_stream->headers()
                .get(Http::LowerCaseString("x-dummy-header"))[0]
                ->value()
                .getStringView(),
            "vprependedx-dummy-header-v1vappended");
  EXPECT_EQ(request_stream->headers()
                .get(Http::LowerCaseString("x-dummy-header"))[1]
                ->value()
                .getStringView(),
            "vprependedx-dummy-header-v2vappended");
  codec_client->close();
}

// (eedala) This is definitely not testing 5 filter-cases
TEST_P(EricProxyFilterScreeningIntegrationTest, headerAdd_five_FC) {
  initializeFilter(config_five_fc);
  testAddMultipleHeader("http://eric-chfsim-1-mnc-123-mcc-123:80");
}

// DND-31031
// (eedala) This is definitely not testing 6 filter-cases
TEST_P(EricProxyFilterScreeningIntegrationTest, headerAdd_Modify_six_FC) {
  initializeFilter(config_six_fc);
  testAddAndModifyHeader("http://eric-chfsim-1-mnc-123-mcc-123:80");
}

// Test that action-reject-message works, content-type plain-text configured
TEST_P(EricProxyFilterScreeningIntegrationTest, reject_message_plain) {
  initializeFilter(config_three_fc);
  IntegrationCodecClientPtr codec_client;
  IntegrationStreamDecoderPtr response;
  testActionReject("http://eric-chfsim-1-mnc-987-mcc-987:80", codec_client, response);

  EXPECT_EQ("543", response->headers().getStatusValue());
  EXPECT_EQ("text/plain", response->headers().getContentTypeValue());
  EXPECT_EQ("reject test", response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());
  codec_client->close();
}

// Test that action-reject-message works, content-type json configured
TEST_P(EricProxyFilterScreeningIntegrationTest, reject_message_json1) {
  initializeFilter(config_three_fc);
  IntegrationCodecClientPtr codec_client;
  IntegrationStreamDecoderPtr response;
  testActionReject("http://eric-chfsim-1-mnc-988-mcc-988:80", codec_client, response);

  EXPECT_EQ("544", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ("{\"status\": 544, \"title\": \"reject test json1\", \"detail\": \"test detail\"}",
            response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());
  codec_client->close();
}

// Test that action-reject-message works, content-type json by default
TEST_P(EricProxyFilterScreeningIntegrationTest, reject_message_json2) {
  initializeFilter(config_three_fc);
  IntegrationCodecClientPtr codec_client;
  IntegrationStreamDecoderPtr response;
  testActionReject("http://eric-chfsim-1-mnc-989-mcc-989:80", codec_client, response);

  EXPECT_EQ("545", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ("{\"status\": 545, \"title\": \"reject test json2\"}", response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());
  codec_client->close();
}

// Test that action-reject-message works, and a response action is not triggered (DND-26376)
TEST_P(EricProxyFilterScreeningIntegrationTest, reject_message_plain_no_response_screening) {
  // add filters in reverse order expected in the filter chain
  config_helper_.addFilter(config_ph_1_2_3_4_5_6);
  initialize();
  // initializeFilter(config_three_fc_plus_dummy_filter_chain);
  IntegrationCodecClientPtr codec_client;
  IntegrationStreamDecoderPtr response;
  testActionReject("http://eric-chfsim-1-mnc-987-mcc-987:80", codec_client, response);

  EXPECT_EQ("543", response->headers().getStatusValue());
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString("x-added-by-response-ph4")).empty());
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString("x-added-by-response-ph5")).empty());
  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("x-added-by-response", "response path triggered"));
  codec_client->close();
}

// Test that action-modify-status-code works, status, title details, content-type json configured,
// receives reject message to modify (configured s' t' d' JSON, original response s t d JSON => s'
// t' d' JSON)
TEST_P(EricProxyFilterScreeningIntegrationTest, modify_status_code_json) {
  initializeFilter(config_modify_status_code_json);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
  };
  IntegrationCodecClientPtr codec_client;
  IntegrationStreamDecoderPtr response;
  codec_client = makeHttpConnection(lookupPort("http"));
  response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("500", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());

  EXPECT_NO_THROW({
    EXPECT_EQ(
        R"({"status": 500, "title": "modify status code json", "detail": "test detail modified"})"_json,
        Json::parse(response->body()));
  });

  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());
  codec_client->close();
}

// Test that action-modify-status-code works, status, title details, content-type json configured,
// receives reject message to modify (configured s' t' d' JSON, original response s t d JSON => s'
// t' d' JSON)
TEST_P(EricProxyFilterScreeningIntegrationTest, modify_status_code_json_DND_31754) {
  initializeFilter(config_modify_status_code_json_DND_31754);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
  };
  IntegrationCodecClientPtr codec_client;
  IntegrationStreamDecoderPtr response;
  codec_client = makeHttpConnection(lookupPort("http"));
  response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("500", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_NO_THROW({
    EXPECT_EQ(
        R"({"status": 500, "title": "modify status code json", "detail": "test detail"})"_json,
        Json::parse(response->body()));
  });
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());

  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("x-it-header-name-added", "x-it-header-value-added"));

  codec_client->close();
}

// Test that action-modify-status-code works, status configured, receives reject message to modify
// (configured s' , original response s t d JSON => s' t d JSON)
TEST_P(EricProxyFilterScreeningIntegrationTest,
       reject_json_modify_status_code_json_DND_31754_no_title) {
  initializeFilter(config_reject_json_modify_status_code_json_no_title);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
  };
  IntegrationCodecClientPtr codec_client;
  IntegrationStreamDecoderPtr response;
  codec_client = makeHttpConnection(lookupPort("http"));
  response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("500", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_NO_THROW({
    EXPECT_EQ(
        R"({"status": 500, "title": "reject test json1", "detail": "test detail", "cause": "test cause"})"_json,
        Json::parse(response->body()));
  });
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());

  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("x-it-header-name-added", "x-it-header-value-added"));

  codec_client->close();
}

// Test that action-modify-status-code works, status configured, receives reject message to modify
// (configured s' , original response s t d JSON => s' t d JSON)
TEST_P(EricProxyFilterScreeningIntegrationTest, reject_json_modify_status_code_json_DND_31754) {
  initializeFilter(config_reject_json_modify_status_code_json);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
  };
  IntegrationCodecClientPtr codec_client;
  IntegrationStreamDecoderPtr response;
  codec_client = makeHttpConnection(lookupPort("http"));
  response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("500", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_NO_THROW({
    EXPECT_EQ(
        R"({"status": 500, "title": "test title modified", "detail": "test detail", "cause": "test cause added"})"_json,
        Json::parse(response->body()));
  });
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());

  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("x-it-header-name-added", "x-it-header-value-added"));

  codec_client->close();
}

// Test that action-modify-status-code works, status configured, receives reject message to modify
// (configured s' , original response s t d JSON => s' t d JSON)
TEST_P(EricProxyFilterScreeningIntegrationTest,
       reject_plain_modify_status_code_json_DND_31754_no_title) {
  initializeFilter(config_reject_plain_modify_status_code_json_no_title);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
  };
  IntegrationCodecClientPtr codec_client;
  IntegrationStreamDecoderPtr response;
  codec_client = makeHttpConnection(lookupPort("http"));
  response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("500", response->headers().getStatusValue());
  EXPECT_EQ("text/plain", response->headers().getContentTypeValue());
  EXPECT_EQ("reject test plain", response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());

  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("x-it-header-name-added", "x-it-header-value-added"));

  codec_client->close();
}

// Test that action-modify-status-code works, status configured, receives reject message to modify
// (configured s' , original response s t d JSON => s' t d JSON)
TEST_P(EricProxyFilterScreeningIntegrationTest, reject_plain_modify_status_code_json_DND_31754) {
  initializeFilter(config_reject_plain_modify_status_code_json);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
  };
  IntegrationCodecClientPtr codec_client;
  IntegrationStreamDecoderPtr response;
  codec_client = makeHttpConnection(lookupPort("http"));
  response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("500", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_NO_THROW({
    EXPECT_EQ(
        R"({"status": 500, "title": "test title modified", "detail": "test detail modified", "cause": "test cause modified"})"_json,
        Json::parse(response->body()));
  });
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());

  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("x-it-header-name-added", "x-it-header-value-added"));

  codec_client->close();
}

// Test that action-modify-status-code works, title, details, content-type plain text configured,
// status code not configured (configured - t' d' PLAIN_TEXT, original response s t d JSON => s t' -
// PLAIN_TEXT)
TEST_P(EricProxyFilterScreeningIntegrationTest, modify_status_code_plain) {
  initializeFilter(config_modify_status_code_plain_text);
  IntegrationCodecClientPtr codec_client;
  IntegrationStreamDecoderPtr response;

  Http::TestResponseHeaderMapImpl respHeaders{
      {":status", "577"},
      {"content-type", "application/problem+json"},
  };

  testActionModifyStatusCode(
      codec_client, response, respHeaders,
      R"EOF({"status": "577", "title": "Network Authentication required", "detail": "this is a test response"})EOF");

  EXPECT_EQ("577", response->headers().getStatusValue()); // should not change
  EXPECT_EQ("text/plain", response->headers().getContentTypeValue());
  EXPECT_EQ("modify status code plain text", response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());
  codec_client->close();
}

// Test that action-modify-status-code works, no title configured, content-type stays the same by
// default, body is not modified, status should be changed (configured s' - d' PLAIN_TEXT, original
// response s t d JSON => s' t d JSON) This test does not work yet because the body of the response
// sent with sendFakeRequest in testActionModifyStatusCode is not passed to encodeData and therefore
// empty in actionModifyStatusCode. That causes the content type and body value assertion to fail.
TEST_P(EricProxyFilterScreeningIntegrationTest, modify_status_code_header_only) {

  initializeFilter(config_modify_status_code_no_body_configured);
  IntegrationCodecClientPtr codec_client;
  IntegrationStreamDecoderPtr response;

  std::string fakeRespBody = R"EOF({"Result": "OK"})EOF";

  Http::TestResponseHeaderMapImpl respHeaders{
      {":status", "200"},
      {"content-type", "application/json"},
      {"content-length", fmt::format("{}", fakeRespBody.size())}};

  testActionModifyStatusCode(codec_client, response, respHeaders, fakeRespBody);

  EXPECT_EQ("201", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_EQ(fakeRespBody, response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());
  codec_client->close();
}

// Test that action-modify-status-code works, status code and title configured, content-type JSON by
// default, received details passed if orig. response content type = "application/problem+json"
// (configured s' t' - -, original response s t d JSON => s' t' - JSON)
TEST_P(EricProxyFilterScreeningIntegrationTest, modify_status_code_status_title) {

  initializeFilter(config_modify_status_code_status_title);
  IntegrationCodecClientPtr codec_client;
  IntegrationStreamDecoderPtr response;

  std::string fakeRespBody =
      R"EOF({"status": "577", "title": "Network Authentication required", "detail": "this is a test response", "cause": "test cause" })EOF";

  Http::TestResponseHeaderMapImpl respHeaders{
      {":status", "577"},
      {"content-type", "application/problem+json"},
      {"content-length", fmt::format("{}", fakeRespBody.size())}};

  testActionModifyStatusCode(codec_client, response, respHeaders, fakeRespBody);

  EXPECT_EQ("588", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_NO_THROW({
    EXPECT_EQ(
        R"({"status": 588, "title": "test title modified", "detail": "this is a test response", "cause": "test cause"})"_json,
        Json::parse(response->body()));
  });
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());
  codec_client->close();
}

// Test that action-modify-status-code works, status code configured, title, details, content-type
// not configured, original body not present, should send no body (configured s' - - -, original
// response s - - -  => s' - - - )
TEST_P(EricProxyFilterScreeningIntegrationTest, modify_status_code_status) {

  initializeFilter(config_modify_status_code_status);
  IntegrationCodecClientPtr codec_client;
  IntegrationStreamDecoderPtr response;

  std::string fakeRespBody = "";

  Http::TestResponseHeaderMapImpl respHeaders{
      {":status", "577"}, {"content-length", fmt::format("{}", fakeRespBody.size())}};

  testActionModifyStatusCode(codec_client, response, respHeaders, fakeRespBody);

  EXPECT_EQ("588", response->headers().getStatusValue());
  EXPECT_EQ("", response->headers().getContentTypeValue());
  EXPECT_EQ("", response->body());
  EXPECT_EQ(fmt::format("{}", fakeRespBody.size()), response->headers().getContentLengthValue());
  codec_client->close();
}

// Test that action-drop-message works
TEST_P(EricProxyFilterScreeningIntegrationTest, drop_message) {
  initializeFilter(config_three_fc);

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

  codec_client->close();
}

// Test that action-drop-message works also in order to drop a response
TEST_P(EricProxyFilterScreeningIntegrationTest, drop_message_in_response_path) {
  initializeFilter(config_drop_response);

  std::string api_root{"http://eric-chfsim-1-mnc-989-mcc-950:80"};
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", api_root},
  };

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  auto codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForReset());

  codec_client->close();
}

// Test that a modified header can be used in a subsequent predicate-expression
TEST_P(EricProxyFilterScreeningIntegrationTest, mod_header) {
  initializeFilter(config_predexp_after_header_mods);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"locality", "datacenter1"},
  };

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  auto codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForEndStream());

  // Request headers on upstream:
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-loc1", "locality 1 rule executed"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-loc2", "locality 2 rule executed"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("locality", "datacenter2"));

  codec_client->close();
}

//---------------------------------------------------------------
// Tests for:
// condition: req.header, resp.header
// filter-data: header, request-header, response-header
// Instead of an and-condition this configuration uses goto-fc
// (the "AND" five lines below this one) so that it's easier to see
// which condition failed.
//
// In request-direction, this is tested:
// var.tar_header == var.tar_req_header
// AND
// var.tar_header == 'abc'
// AND
// var.tar_header == req.header['3gpp-Sbi-target-apiRoot']
//
// In the response direction, this is tested:
// req.header['3gpp-Sbi-target-apiRoot'] == 'abc'
// AND
// var.tar_req_header_in_resp == 'abc'  # read in message-data in response
// AND
// var.loc_header == var.loc_resp_header
// AND
// var.loc_header == 'def'
// AND
// var.loc_header == resp.header['location']
TEST_P(EricProxyFilterScreeningIntegrationTest, reqRespHeaders) {
  initializeFilter(config_req_resp_headers);

  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},     {":path", "/"},
      {":authority", "host"}, {"3gpp-sbi-target-apiroot", "abc"},
      {"testheader", "klm"},
  };

  Http::TestResponseHeaderMapImpl resp_headers{{":status", "200"}, {"location", "def"}};

  // Send request:
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(req_headers);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(resp_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Validate request headers on upstream:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "correct_pool"));

  // Validate response headers on downstream:
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "def"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-test-result", "passed"));
}

// DFS-3112: User wants to add headers to a direct response (action_reject).
// Our action_reject does not allow this. The workaround is to reject with status=700,
// detect that status code in screening-6, and change status and add the required
// headers.
// User reports that we cannot detect status 700 in the screening-6 phase.
TEST_P(EricProxyFilterScreeningIntegrationTest, statusInResponse) {
  initializeFilter(config_status_in_response);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
  };

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  // We expect :status to be changed to 200 and the "new-header" having the correct
  // value which indicates that the match :status == '700' was successful
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("new-header", "correct value"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("new-header", "correct value"));
  codec_client->close();
}
} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
