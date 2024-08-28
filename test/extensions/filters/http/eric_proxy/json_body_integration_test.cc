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
    config_helper_.addFilter(config_cdn_filter);
    HttpIntegrationTest::initialize();
  }

  const std::string config_body_mod_json_patch = R"EOF(
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      filter_data:
      - name: json_object_from_body
        body_json_pointer: "/nfConsumerIdentification"
        variable_name: json_object_from_body
      filter_rules:
      - name: modify_req_body_json_patch
        condition:
          op_exists: {arg1:  {term_var: 'json_object_from_body'}}
        actions:
        - action_modify_json_body:
            name: "test json patch handling"
            json_operation:
              json_patch:  '[{"op": "replace", "path": "/subscriberIdentifier", "value": "supi-replaced-by-json-patch"}]'
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
    - name: default_egress_screening
      filter_rules:
      - name: modify_resp_body_json_patch
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test json patch handling"
            json_operation:
              json_patch:  '[{"op": "replace", "path": "/subscriberIdentifier", "value": "supi-replaced-by-json-patch"}]'
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  std::string config_body_mod_add_to_json = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  own_internal_port: 80
  request_validation:
    check_message_bytes:
      max_message_bytes: 65535
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
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
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
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

  std::string config_body_mods_large_body = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  own_internal_port: 80
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - caseReq
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - routing
  filter_cases:
    - name: caseReq
      "filter_data": [ { "name": "apiRoot_data", "header": "3gpp-Sbi-target-apiRoot", "extractor_regex": "^(http(s?)://)?(?P\u003cnf\u003e.+?)\\..+?\\.(?P\u003cmnc\u003e.+?)\\..+?\\.(?P\u003cmcc\u003e.+?)\\..*" } ]
      "filter_rules": [ { "name": "rule_1", "condition": { "op_and": { "arg1": { "op_equals": { "typed_config1": { "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value", "term_var": "mnc" }, "typed_config2": { "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value", "term_string": "012" } } }, "arg2": { "op_equals": { "typed_config1": { "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value", "term_var": "mcc" }, "typed_config2": { "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value", "term_string": "210" } } } } }, "actions": [ { "action_modify_json_body": { "name": "action_1", "json_operation": { "add_to_json": { "value": { "term_string": "\"dummy-body-value-1\"" }, "json_pointer": { "term_string": "/pDUSessionChargingInformation/userInformation/new-key-1" } } } } }, { "action_modify_json_body": { "name": "action_2", "json_operation": { "add_to_json": { "value": { "term_string": "1129" }, "json_pointer": { "term_string": "/nfConsumerIdentification/aRoot1/bRoot2/new-key-2" } } } } }, { "action_modify_json_body": { "name": "action_3", "json_operation": { "add_to_json": { "value": { "term_string": "false" }, "json_pointer": { "term_string": "/pDUSessionChargingInformation/userInformation/unauthenticatedFlag" }, "if_element_exists": "REPLACE" } } } }, { "action_modify_json_body": { "name": "action_4", "json_operation": { "add_to_json": { "value": { "term_string": "null" }, "json_pointer": { "term_string": "/nfConsumerIdentification/nodeFunctionality" }, "if_element_exists": "REPLACE" } } } }, { "action_modify_json_body": { "name": "action_5", "json_operation": { "add_to_json": { "value": { "term_string": "{\"key1\":\"value1\"}" }, "json_pointer": { "term_string": "/nfConsumerIdentification/nFPLMNID/new-key-5" }, "if_path_not_exists": "DO_NOTHING" } } } }, { "action_modify_json_body": { "name": "action_6", "json_operation": { "add_to_json": { "value": { "term_string": "[\"dummy-body-value-1\", \"value2\", 25]" }, "json_pointer": { "term_string": "/pDUSessionChargingInformation/pduSessionInformation/servingNodeID/0/new-key-6" } } } } }, { "action_modify_json_body": { "name": "action_7", "json_operation": { "add_to_json": { "value": { "term_string": "\"dummy-body-value-1\"" }, "json_pointer": { "term_string": "/nfConsumerIdentification/nonExistent1/new-key-7" }, "if_path_not_exists": "DO_NOTHING" } } } }, { "action_modify_json_body": { "name": "action_8", "json_operation": { "add_to_json": { "value": { "term_string": "\"dummy-body-value-1\"" }, "json_pointer": { "term_string": "/invocationSequenceNumber" } } } } } ] } ]
    - name: routing
      filter_rules:
        condition:
          term_boolean: true
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

// CDN Filter config
  const std::string config_cdn_filter = R"EOF(
name: envoy.filters.http.cdn_loop
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.cdn_loop.v3.CdnLoopConfig
  cdn_id: "2.0 scp.mnc.012.mcc.210.ericsson.se"
)EOF";

  const std::string config_body_mod_add_to_json_string_from_var = R"EOF(
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      - name: json_object_from_body
        body_json_pointer: "/nfConsumerIdentification"
        variable_name: json_object_from_body      
      filter_rules:
      - name: modify_req_body_add_to_json
        condition:
          op_exists: {arg1:  {term_var: 'supi'}}
        actions:
        - action_modify_json_body:
            name: "test modify request body"
            json_operation:
              add_to_json:
                value:
                  term_var: 'supi'
                json_pointer:
                  term_string: "/subscriberIdentifier_added"
                if_path_not_exists:  DO_NOTHING
                if_element_exists:  NO_ACTION
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
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
                  term_var: 'supi'
                json_pointer:
                  term_string: "/subscriberIdentifier_added"
                if_path_not_exists:  DO_NOTHING
                if_element_exists:  NO_ACTION
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_body_mod_add_to_json_string_from_var2 = R"EOF(
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
        variable_name: values
      filter_rules:
      - name: modify_req_body_add_to_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "Empty body "
            json_operation:
              remove_from_json:
                json_pointer:
                  term_string: ""
        - action_modify_json_body:
            name: "Add object with array"
            json_operation:
              add_to_json:
                value:
                  term_var: 'values'
                json_pointer:
                  term_string: "/key1"
                if_path_not_exists:  CREATE
                if_element_exists:  REPLACE
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_body_mod_add_to_json_string_from_var_DND_32778 = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: SCREENING_1_6_1
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
      - name: whole_body
        body_json_pointer: ""
        variable_name: values
      filter_rules:
      - name: modify_req_body_add_to_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "action1: Replace value at index0"
            json_operation:
              add_to_json:
                value:
                  term_string: 'new-value0'
                json_pointer:
                  term_string: "/0"
                if_path_not_exists:  CREATE
                if_element_exists:  REPLACE
        - action_modify_json_body:
            name: "action2: Add object with array"
            json_operation:
              add_to_json:
                value:
                  term_var: 'values'
                json_pointer:
                  term_string: "/new-key1"
                if_path_not_exists:  CREATE
                if_element_exists:  REPLACE
    - name: default_routing
      filter_rules:
      - name: route_to_rp
        condition:
          term_boolean: true
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_body_mod_add_to_json_string_from_var_DND_32778_1 = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: SCREENING_1_6_1
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
      - name: whole_body
        body_json_pointer: ""
        variable_name: values
      filter_rules:
      - name: modify_req_body_add_to_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "action1: Replace value at index0"
            json_operation:
              add_to_json:
                value:
                  term_string: 'new-value0'
                json_pointer:
                  term_string: "/"
                if_path_not_exists:  CREATE
                if_element_exists:  REPLACE
        - action_modify_json_body:
            name: "action2: Add object with array"
            json_operation:
              add_to_json:
                value:
                  term_var: 'values'
                json_pointer:
                  term_string: "/new-key1"
                if_path_not_exists:  CREATE
                if_element_exists:  REPLACE
    - name: default_routing
      filter_rules:
      - name: route_to_rp
        condition:
          term_boolean: true
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_body_mod_add_to_json_string_from_var_DND_32778_2 = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: SCREENING_1_6_1
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
      - name: whole_body
        body_json_pointer: "/"
        variable_name: values
      filter_rules:
      - name: modify_req_body_add_to_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "action1: Replace value at index0"
            json_operation:
              add_to_json:
                value:
                  term_string: 'new-value0'
                json_pointer:
                  term_string: "/"
                if_path_not_exists:  CREATE
                if_element_exists:  REPLACE
        - action_modify_json_body:
            name: "action2: Add object with array"
            json_operation:
              add_to_json:
                value:
                  term_var: 'values'
                json_pointer:
                  term_string: "/new-key1"
                if_path_not_exists:  CREATE
                if_element_exists:  REPLACE
    - name: default_routing
      filter_rules:
      - name: route_to_rp
        condition:
          term_boolean: true
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_body_mod_replace_in_json = R"EOF(
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      filter_data:
      - name: json_object_from_body
        body_json_pointer: "/nfConsumerIdentification"
        variable_name: json_object_from_body      
      filter_rules:
      - name: modify_req_body_replace_in_json
        condition:
          op_exists: {arg1:  {term_var: 'json_object_from_body'}}
        actions:
        - action_modify_json_body:
            name: "test modify request body"
            json_operation:
              replace_in_json:
                value:
                  term_string: '12345678'
                json_pointer:
                  term_string: "/subscriberIdentifier"
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
    - name: default_egress_screening
      filter_rules:
      - name: modify_resp_body_replace_in_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test modify response body"
            json_operation:
              replace_in_json:
                value:
                  term_string: '12345678'
                json_pointer:
                  term_string: "/subscriberIdentifier"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";


  const std::string config_body_mod_replace_in_json_req_mp = R"EOF(
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      filter_data:
      - name: json_object_from_body
        body_json_pointer: "/nfConsumerIdentification"
        variable_name: json_object_from_body      
      filter_rules:
      - name: modify_req_body_replace_in_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test modify request body"
            json_operation:
              replace_in_json:
                value:
                  term_string: '12345678'
                json_pointer:
                  term_string: "/subscriberIdentifier"
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
    - name: default_egress_screening
      filter_rules:
      - name: modify_resp_body_replace_in_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test modify response body"
            json_operation:
              replace_in_json:
                value:
                  term_string: '12345678'
                json_pointer:
                  term_string: "/subscriberIdentifier"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";


  const std::string config_body_mod_replace_in_json_object_from_var = R"EOF(
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      filter_data:
      - name: json_object_from_body
        body_json_pointer: "/nfConsumerIdentification"
        variable_name: json_object_from_body      
      filter_rules:
      - name: modify_req_body_replace_in_json
        condition:
          op_exists: {arg1:  {term_var: 'json_object_from_body'}}
        actions:
        - action_modify_json_body:
            name: "test modify request body"
            json_operation:
              replace_in_json:
                value:
                  term_var: 'json_object_from_body'
                json_pointer:
                  term_string: "/subscriberIdentifier"
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
    - name: default_egress_screening
      filter_rules:
      - name: modify_resp_body_replace_in_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test modify response body"
            json_operation:
              replace_in_json:
                value:
                  term_var: 'json_object_from_body'
                json_pointer:
                  term_string: "/subscriberIdentifier"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_body_mod_remove_from_json = R"EOF(
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      filter_data:
      - name: json_object_from_body
        body_json_pointer: "/nfConsumerIdentification"
        variable_name: json_object_from_body      
      filter_rules:
      - name: modify_req_body_remove_from_json
        condition:
          op_exists: {arg1:  {term_var: 'json_object_from_body'}}
        actions:
        - action_modify_json_body:
            name: "test json remove handling"
            json_operation:
              remove_from_json:
                json_pointer:
                  term_string: "/subscriberIdentifier"
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
    - name: default_egress_screening
      filter_rules:
      - name: modify_resp_body_remove_from_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test json remove handling"
            json_operation:
              remove_from_json:
                json_pointer:
                  term_string: "/subscriberIdentifier"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

#pragma region dnd_40786
  const std::string config_dnd_40786{R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp_routing_screening
  filter_cases:
  - name: default_routing
    filter_data:
    - name: apiRoot_data
      header: 3gpp-Sbi-target-apiRoot
      extractor_regex: "^(http(s?)://)?(?P<nf>.+?)\\..+?\\.(?P<mnc>.+?)\\..+?\\.(?P<mcc>.+?)\\..*"
    - name: data-body-1
      body_json_pointer: "/pDUSessionChargingInformation/userInformation/unauthenticatedFlag"
      variable_name: variable_body_1
    - name: data-body-2
      body_json_pointer: "/pDUSessionChargingInformation/pduSessionInformation/pduAddress/IPv4dynamicAddressFlag"
      variable_name: variable_body_2
    - name: data-body-3
      body_json_pointer: "/pDUSessionChargingInformation/pduSessionInformation/pduAddress/IPv6dynamicAddressFlag"
      variable_name: variable_body_3
    filter_rules:
    - name: rule1
      condition:
        op_and:
          arg1:
            op_and:
              arg1:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_var: variable_body_1
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_boolean: false
              arg2:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_var: variable_body_2
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_boolean: true
          arg2:
            op_equals:
              typed_config1:
                "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                term_var: variable_body_3
              typed_config2:
                "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                term_boolean: true
      actions:
      - action_add_header:
          name: x-eric-fop
          value:
            term_string: fob1
          if_exists: REPLACE
      - action_route_to_pool:
          pool_name:
            term_string: Pool_PSEPP1
          routing_behaviour: ROUND_ROBIN
          preserve_if_indirect: TARGET_API_ROOT
  - name: caseReq
    filter_data:
    - name: apiRoot_data
      header: 3gpp-Sbi-target-apiRoot
      extractor_regex: "^(http(s?)://)?(?P<nf>.+?)\\..+?\\.(?P<mnc>.+?)\\..+?\\.(?P<mcc>.+?)\\..*"
    - name: data-body-1
      body_json_pointer: "/pDUSessionChargingInformation/userInformation/unauthenticatedFlag"
      variable_name: variable_body_1
    - name: data-body-2
      body_json_pointer: "/pDUSessionChargingInformation/pduSessionInformation/pduAddress/IPv4dynamicAddressFlag"
      variable_name: variable_body_2
    - name: data-body-3
      body_json_pointer: "/pDUSessionChargingInformation/pduSessionInformation/pduAddress/IPv6dynamicAddressFlag"
      variable_name: variable_body_3
    filter_rules:
    - name: rule_1
      condition:
        op_and:
          arg1:
            op_and:
              arg1:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_var: variable_body_1
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_boolean: true
              arg2:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_var: variable_body_2
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_boolean: true
          arg2:
            op_equals:
              typed_config1:
                "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                term_var: variable_body_3
              typed_config2:
                "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                term_boolean: false
      actions:
      - action_modify_json_body:
          name: action_1
          json_operation:
            replace_in_json:
              value:
                term_string: 'false'
              json_pointer:
                term_string: "/pDUSessionChargingInformation/userInformation/unauthenticatedFlag"
    - name: rule_2
      condition:
        op_and:
          arg1:
            op_and:
              arg1:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_var: variable_body_1
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_boolean: false
              arg2:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_var: variable_body_2
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_boolean: true
          arg2:
            op_equals:
              typed_config1:
                "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                term_var: variable_body_3
              typed_config2:
                "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                term_boolean: false
      actions:
      - action_modify_json_body:
          name: action_1
          json_operation:
            replace_in_json:
              value:
                term_var: variable_body_2
              json_pointer:
                term_string: "/pDUSessionChargingInformation/pduSessionInformation/pduAddress/IPv6dynamicAddressFlag"
  - name: caseResp
    filter_data:
    - name: apiRoot_data
      header: 3gpp-Sbi-target-apiRoot
      extractor_regex: "^(http(s?)://)?(?P<nf>.+?)\\..+?\\.(?P<mnc>.+?)\\..+?\\.(?P<mcc>.+?)\\..*"
    - name: data-body-1
      body_json_pointer: "/pDUSessionChargingInformation/userInformation/unauthenticatedFlag"
      variable_name: variable_body_1
    - name: data-body-2
      body_json_pointer: "/pDUSessionChargingInformation/pduSessionInformation/pduAddress/IPv4dynamicAddressFlag"
      variable_name: variable_body_2
    - name: data-body-3
      body_json_pointer: "/pDUSessionChargingInformation/pduSessionInformation/pduAddress/IPv6dynamicAddressFlag"
      variable_name: variable_body_3
    filter_rules:
    - name: rule_1
      condition:
        op_and:
          arg1:
            op_and:
              arg1:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_var: variable_body_1
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_boolean: false
              arg2:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_var: variable_body_2
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_boolean: true
          arg2:
            op_equals:
              typed_config1:
                "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                term_var: variable_body_3
              typed_config2:
                "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                term_boolean: true
      actions:
      - action_modify_json_body:
          name: action_1
          json_operation:
            replace_in_json:
              value:
                term_var: variable_body_1
              json_pointer:
                term_string: "/pDUSessionChargingInformation/pduSessionInformation/pduAddress/IPv4dynamicAddressFlag"
    - name: rule_2
      condition:
        op_and:
          arg1:
            op_and:
              arg1:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_var: variable_body_1
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_boolean: false
              arg2:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_var: variable_body_2
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_boolean: false
          arg2:
            op_equals:
              typed_config1:
                "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                term_var: variable_body_3
              typed_config2:
                "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                term_boolean: true
      actions:
      - action_modify_json_body:
          name: action_1
          json_operation:
            replace_in_json:
              value:
                term_string: 'true'
              json_pointer:
                term_string: "/pDUSessionChargingInformation/userInformation/unauthenticatedFlag"
  own_fqdn: scp.mnc.012.mcc.210.ericsson.se
  own_internal_port: 30535
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: Network_1
        start_fc_list:
        - caseReq
    routing:
      own_nw:
        name: Network_1
        start_fc_list:
        - default_routing
  response_filter_cases:
    out_response_screening:
      own_nw:
        name: Network_1
        start_fc_list:
        - caseResp
  )EOF"};
#pragma endregion dnd_40786

  const std::string config_body_mod_remove_full_json = R"EOF(
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      filter_data:
      - name: json_object_from_body
        body_json_pointer: "/nfConsumerIdentification"
        variable_name: json_object_from_body      
      filter_rules:
      - name: modify_req_body_remove_full_json
        condition:
          op_exists: {arg1:  {term_var: 'json_object_from_body'}}
        actions:
        - action_modify_json_body:
            name: "test json remove handling"
            json_operation:
              remove_from_json:
                json_pointer:
                  term_string: ""
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
    - name: default_egress_screening
      filter_rules:
      - name: modify_resp_body_remove_full_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test json remove handling"
            json_operation:
              remove_from_json:
                json_pointer:
                  term_string: ""
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_body_mod_path_not_exists = R"EOF(
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
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      - name: json_object_from_body
        body_json_pointer: "/nfConsumerIdentification"
        variable_name: json_object_from_body      
      filter_rules:
      - name: modify_req_body_add_to_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test modify request body"
            json_operation:
              add_to_json:
                value:
                  term_string: '"10.11.12.253"'
                json_pointer:
                  term_string: "/nfServices/ipEndPoints/0/ipv4Address"
                if_path_not_exists:  CREATE
                if_element_exists:  NO_ACTION
        - action_modify_json_body:
            name: "test modify request body"
            json_operation:
              add_to_json:
                value:
                  term_string: '"2001:1b70:8230:5501:4401:3301:2201:1101"'
                json_pointer:
                  term_string: "/nfServices/ipEndPoints/1/ipv6Address"
                if_path_not_exists:  DO_NOTHING
                if_element_exists:  NO_ACTION
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_body_mod_element_exists = R"EOF(
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
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
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
                  term_string: '"312"'
                json_pointer:
                  term_string: "/nfConsumerIdentification/nfPLMNID/mcc"
                if_path_not_exists:  DO_NOTHING
                if_element_exists:  NO_ACTION
        - action_modify_json_body:
            name: "test modify request body"
            json_operation:
              add_to_json:
                value:
                  term_string: '281'
                json_pointer:
                  term_string: "/nfConsumerIdentification/nfPLMNID/mnc"
                if_path_not_exists:  DO_NOTHING
                if_element_exists:  REPLACE
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_body_mod_replace_root_from_var = R"EOF(
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      filter_data:
      - name: json_object_from_body
        body_json_pointer: "/nfConsumerIdentification/nfPLMNID"
        variable_name: json_object_from_body      
      filter_rules:
      - name: modify_req_body_replace_in_json
        condition:
          op_exists: {arg1:  {term_var: 'json_object_from_body'}}
        actions:
        - action_modify_json_body:
            name: "test modify request body"
            json_operation:
              replace_in_json:
                value:
                  term_var: 'json_object_from_body'
                json_pointer:
                  term_string: ""
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
    - name: default_egress_screening
      filter_rules:
      - name: modify_resp_body_replace_in_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test modify response body"
            json_operation:
              replace_in_json:
                value:
                  term_var: 'json_object_from_body'
                json_pointer:
                  term_string: ""
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_body_mod_table_lookup = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  own_internal_port: 80
  key_value_tables:
    - name: lookup_table
      entries:
        - key: example_fqdn_1.com
          value: fake_example_fqdn_1.com
        - key: example_fqdn_2.com
          value: fake_example_fqdn_2.com
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      filter_data:
      - name: json_object_from_body
        body_json_pointer: "/nfConsumerIdentification"
        variable_name: json_object_from_body      
      filter_rules:
      - name: modify_req_body_replace_in_json
        condition:
          op_exists: {arg1:  {term_var: 'json_object_from_body'}}
        actions:
        - action_modify_json_body:
            name: "test modify request body"
            json_operation:
              modify_json_value:
                string_modifiers:
                - table_lookup:
                    lookup_table_name: lookup_table
                    do_nothing: true
                json_pointer:
                  term_string: "/nfConsumerIdentification/nfPLMNID/fqdn"
                enable_exception_handling: true
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
    - name: default_egress_screening
      filter_rules:
      - name: modify_resp_body_replace_in_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test modify response body"
            json_operation:
              modify_json_value:
                string_modifiers:
                - table_lookup:
                    lookup_table_name: lookup_table
                    do_nothing: true
                json_pointer:
                  term_string: "/nfConsumerIdentification/nfPLMNID/fqdn"
                enable_exception_handling: true
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_body_mod_replace_by_different_type = R"EOF(
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      filter_data:
      - name: json_object_from_body
        body_json_pointer: "/nfConsumerIdentification"
        variable_name: json_object_from_body      
      filter_rules:
      - name: modify_req_body_replace_in_json
        condition:
          op_exists: {arg1:  {term_var: 'json_object_from_body'}}
        actions:
        - action_modify_json_body:
            name: "test modify request body"
            json_operation:
              replace_in_json:
                value:
                  term_string: '312'
                json_pointer:
                  term_string: "/nfConsumerIdentification/nfPLMNID/mcc"
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
    - name: default_egress_screening
      filter_rules:
      - name: modify_resp_body_replace_in_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test modify response body"
            json_operation:
              replace_in_json:
                value:
                  term_string: '"281"'
                json_pointer:
                  term_string: "/nfConsumerIdentification/nfPLMNID/mnc"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_body_mod_path_not_exists_req_resp = R"EOF(
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      - name: json_object_from_body
        body_json_pointer: "/nfConsumerIdentification"
        variable_name: json_object_from_body      
      filter_rules:
      - name: modify_req_body_add_to_json
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test modify request body"
            json_operation:
              add_to_json:
                value:
                  term_string: '"10.11.12.253"'
                json_pointer:
                  term_string: "/nfServices/ipEndPoints/0/ipv4Address"
                if_path_not_exists:  CREATE
                if_element_exists:  NO_ACTION
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
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
                  term_string: '"10.11.12.253"'
                json_pointer:
                  term_string: "/nfServices/ipEndPoints/0/ipv4Address"
                if_path_not_exists:  CREATE
                if_element_exists:  NO_ACTION
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_body_mod_multiple_mod = R"EOF(
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      - name: json_object_from_body
        body_json_pointer: "/nfConsumerIdentification"
        variable_name: json_object_from_body      
      filter_rules:
      - name: modify_req_body_multiple_actions
        condition:
          op_exists: {arg1:  {term_var: 'json_object_from_body'}}
        actions:
        - action_modify_json_body:
            name: "test add to request body"
            json_operation:
              add_to_json:
                value:
                  term_string: '"supi-added"'
                json_pointer:
                  term_string: "/subscriberIdentifier1"
                if_path_not_exists:  DO_NOTHING
                if_element_exists:  NO_ACTION
        - action_modify_json_body:
            name: "test remove from request body"
            json_operation:
              remove_from_json:
                json_pointer:
                  term_string: "/subscriberIdentifier"
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
    - name: default_egress_screening
      filter_rules:
      - name: modify_resp_body_multiple_actions
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test add to response body"
            json_operation:
              add_to_json:
                value:
                  term_string: '"supi-added"'
                json_pointer:
                  term_string: "/subscriberIdentifier1"
                if_path_not_exists:  DO_NOTHING
                if_element_exists:  NO_ACTION
        - action_modify_json_body:
            name: "test remove from response body"
            json_operation:
              remove_from_json:
                json_pointer:
                  term_string: "/subscriberIdentifier"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_body_mod_multiple_mod_array = R"EOF(
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      - name: json_object_from_body
        body_json_pointer: "/nfConsumerIdentification"
        variable_name: json_object_from_body      
      filter_rules:
      - name: modify_req_body_multiple_actions
        condition:
          op_exists: {arg1:  {term_var: 'json_object_from_body'}}
        actions:
        - action_modify_json_body:
            name: "test remove from array in request body"
            json_operation:
              remove_from_json:
                json_pointer:
                  term_string: "/subscriberIdentifier/2"
        - action_modify_json_body:
            name: "test add to array in request body"
            json_operation:
              add_to_json:
                value:
                  term_string: '"supi-added"'
                json_pointer:
                  term_string: "/subscriberIdentifier/3"
                if_path_not_exists:  DO_NOTHING
                if_element_exists:  NO_ACTION
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
    - name: default_egress_screening
      filter_rules:
      - name: modify_resp_body_multiple_actions
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test remove from array in response body"
            json_operation:
              remove_from_json:
                json_pointer:
                  term_string: "/subscriberIdentifier/2"
        - action_modify_json_body:
            name: "test add to array in response body"
            json_operation:
              add_to_json:
                value:
                  term_string: '"supi-added"'
                json_pointer:
                  term_string: "/subscriberIdentifier/3"
                if_path_not_exists:  DO_NOTHING
                if_element_exists:  NO_ACTION
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_bug_dnd_31191 = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  own_internal_port: 80
  name: screening_1_6
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - caseReqIn
  response_filter_cases:
    out_response_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - caseRespOut
  filter_cases:
    - name: caseRespOut
      filter_data:
      - name: x_origin_seppsim_data
        header: x-origin
        extractor_regex: eric-(?P<seppsim>seppsim-.+?)-.+
      - name: data-body-1
        body_json_pointer: "/pDUSessionChargingInformation/userInformation/servedGPSI"
        variable_name: variable_body_1
      - name: data-body-2
        body_json_pointer: "/pDUSessionChargingInformation/chargingId"
        variable_name: variable_body_2
      - name: data-body-3
        body_json_pointer: "/pDUSessionChargingInformation/pduSessionInformation/pduAddress/IPv6dynamicAddressFlag"
        variable_name: variable_body_3
      - name: data-body-4
        body_json_pointer: "/pDUSessionChargingInformation/pduSessionInformation/qoSInformation"
        variable_name: variable_body_4
      - name: data-body-5
        body_json_pointer: "/pDUSessionChargingInformation/pduSessionInformation/servingNodeID/0"
        variable_name: variable_body_5
      - name: data-body-6
        body_json_pointer: "/multipleUnitUsage"
        variable_name: variable_body_6
      - name: data-body-7
        body_json_pointer: "/subscriberIdentifier"
        variable_name: variable_body_7
      - name: data-body-8
        body_json_pointer: "/subscriberIdentifier"
        variable_name: variable_body_8
      - name: data-body-9
        body_json_pointer: "/nfConsumerIdentification/nonExistent1"
        variable_name: variable_body_9
      filter_rules:
      - name: ruleOut_3
        condition:
          op_equals:
            typed_config1:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_var: seppsim
            typed_config2:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_string: seppsim-c
        actions:
        - action_modify_json_body:
            name: action_1
            json_operation:
              add_to_json:
                value:
                  term_var: variable_body_1
                json_pointer:
                  term_string: "/pDUSessionChargingInformation/userInformation/new-key-1"
        - action_modify_json_body:
            name: action_2
            json_operation:
              add_to_json:
                value:
                  term_var: variable_body_2
                json_pointer:
                  term_string: "/nfConsumerIdentification/aRoot1/bRoot2/new-key-2"
        - action_modify_json_body:
            name: action_3
            json_operation:
              add_to_json:
                value:
                  term_var: variable_body_3
                json_pointer:
                  term_string: "/pDUSessionChargingInformation/userInformation/unauthenticatedFlag"
                if_element_exists: REPLACE
        - action_modify_json_body:
            name: action_4
            json_operation:
              add_to_json:
                value:
                  term_var: variable_body_4
                json_pointer:
                  term_string: "/nfConsumerIdentification/nodeFunctionality"
                if_element_exists: REPLACE
        - action_modify_json_body:
            name: action_5
            json_operation:
              add_to_json:
                value:
                  term_var: variable_body_5
                json_pointer:
                  term_string: "/nfConsumerIdentification/nFPLMNID/new-key-5"
                if_path_not_exists: DO_NOTHING
        - action_modify_json_body:
            name: action_6
            json_operation:
              add_to_json:
                value:
                  term_var: variable_body_6
                json_pointer:
                  term_string: "/pDUSessionChargingInformation/pduSessionInformation/servingNodeID/0/new-key-6"
        - action_modify_json_body:
            name: action_7
            json_operation:
              add_to_json:
                value:
                  term_var: variable_body_7
                json_pointer:
                  term_string: "/nfConsumerIdentification/nonExistent1/new-key-7"
                if_path_not_exists: DO_NOTHING
        - action_modify_json_body:
            name: action_8
            json_operation:
              add_to_json:
                value:
                  term_var: variable_body_8
                json_pointer:
                  term_string: "/invocationSequenceNumber"
        - action_modify_json_body:
            name: action_9
            json_operation:
              add_to_json:
                value:
                  term_var: variable_body_9
                json_pointer:
                  term_string: "/pDUSessionChargingInformation/userInformation/servedPEI"
)EOF";

  const std::string config_json_pointer_bool_num_null = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  own_internal_port: 80
  name: integrationTest
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - caseReq
  filter_cases:
    - name: caseReq
      filter_data:
      - name: data-body-1
        body_json_pointer: "/emergencyServices"
        variable_name: variable_body_b
      - name: data-body-2
        body_json_pointer: "/num"
        variable_name: variable_body_n
      - name: data-body-3
        body_json_pointer: "/nix"
        variable_name: variable_body_u
      filter_rules:
      - name: "rule boolean"
        condition:
          op_equals:
            typed_config1:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_var: variable_body_b
            typed_config2:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: bool_pool
            routing_behaviour: ROUND_ROBIN
      - name: "rule number"
        condition:
          op_equals:
            typed_config1:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_var: variable_body_n
            typed_config2:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_number: 2
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: num_pool
            routing_behaviour: ROUND_ROBIN
      - name: "rule null"
        condition:
          op_equals:
            typed_config1:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_var: variable_body_l
            typed_config2:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_string: ""
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: null_pool
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";

const std::string config_json_body_pointer_extractor_regex = R"EOF(
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
      filter_data:
      - name: json_number_from_body
        body_json_pointer: "/nfConsumerIdentification/nfPLMNID/mnc"
        extractor_regex: (?P<number>\d+)
      filter_rules:
      - name: not_exist_var_number
        condition:
          op_not: {arg1: {op_exists: {arg1:  {term_var: 'number'}}}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: numberNotExists
            routing_behaviour: ROUND_ROBIN
      - name: wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";

const std::string config_body_mod_modify_json_value = R"EOF(
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      - name: prefix
        body_json_pointer: "/modifiers/0/prefix"
        variable_name: prefix_from_body
      - name: prefix_target
        body_json_pointer: "/modifiers/0/target"
        variable_name: prefix_target 
      - name: suffix
        body_json_pointer: "/modifiers/1/suffix"
        variable_name: suffix_from_body   
      - name: suffix_target
        body_json_pointer: "/modifiers/1/target"
        variable_name: suffix_target 
      filter_rules:
      - name: modify_req_body_add_to_json
        condition:
          op_exists: {arg1:  {term_var: 'supi'}}
        actions:
        - action_modify_json_body:
            name: "prepend and append string and header values to subscriberIdentifier"
            json_operation:
              modify_json_value:
                json_pointer:
                  term_string: "/subscriberIdentifier"
                string_modifiers:
                  - prepend:
                      term_string: "pref_string_"
                  - append: 
                      term_string: "_suff_string"
                  - prepend:
                      term_header: "prefix_header"
                  - append:
                      term_header: "suffix_header"
        - action_modify_json_body:
            name: "prepend value from var to value at pointer from var"
            json_operation:
              modify_json_value:
                json_pointer:
                  term_var: "prefix_target"
                string_modifiers:
                  - prepend:
                      term_var: "prefix_from_body"
        - action_modify_json_body:
            name: "append value from var to value at pointer from var"
            json_operation:
              modify_json_value:
                json_pointer:
                  term_var: "suffix_target"
                string_modifiers:
                  - append:
                      term_var: "suffix_from_body"
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: STRICT
    - name: default_egress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      - name: prefix
        body_json_pointer: "/modifiers/2/prefix"
        variable_name: prefix_from_body
      - name: prefix_target
        body_json_pointer: "/modifiers/2/target"
        variable_name: prefix_target 
      - name: suffix
        body_json_pointer: "/modifiers/3/suffix"
        variable_name: suffix_from_body   
      - name: suffix_target
        body_json_pointer: "/modifiers/3/target"
        variable_name: suffix_target 
      filter_rules:
      - name: modify_resp_body_add_to_json
        condition:
          op_exists: {arg1:  {term_var: 'supi'}}
        actions:
        - action_modify_json_body:
            name: "prepend and append string and header values to subscriberIdentifier (in response)"
            json_operation:
              modify_json_value:
                json_pointer:
                  term_string: "/subscriberIdentifier"
                string_modifiers:
                  - prepend:
                      term_string: "pref_string_resp_"
                  - append: 
                      term_string: "_suff_string_resp"
                  - prepend:
                      term_header: "prefix_header_resp"
                  - append:
                      term_header: "suffix_header_resp"
        - action_modify_json_body:
            name: "prepend value from var to value at pointer from var (in response)"
            json_operation:
              modify_json_value:
                json_pointer:
                  term_var: "prefix_target"
                string_modifiers:
                  - prepend:
                      term_var: "prefix_from_body"
        - action_modify_json_body:
            name: "append value from var to value at pointer from var (in response)"
            json_operation:
              modify_json_value:
                json_pointer:
                  term_var: "suffix_target"
                string_modifiers:
                  - append:
                      term_var: "suffix_from_body"
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

const std::string config_body_mod_modify_json_value_negative = R"EOF(
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      - name: prefix
        body_json_pointer: "/modifiers/0/prefix"
        variable_name: prefix_from_body
      - name: suffix
        body_json_pointer: "/modifiers/1/suffix"
        variable_name: suffix_from_body   
      - name: suffix_target
        body_json_pointer: "/modifiers/1/target"
        variable_name: suffix_target 
      filter_rules:
      - name: modify_req_body_add_to_json
        condition:
          op_exists: {arg1:  {term_var: 'supi'}}
        actions:
        - action_modify_json_body:
            name: "prepend and append string and header values to subscriberIdentifier"
            json_operation:
              modify_json_value:
                json_pointer:
                  term_string: "/subscriberIdentifier_not_exists"
                string_modifiers:
                  - append:
                      term_header: "suffix_header"
        - action_modify_json_body:
            name: "prepend value from var to value at pointer from var"
            json_operation:
              modify_json_value:
                string_modifiers:
                  - prepend:
                      term_var: "prefix_from_body"
        - action_modify_json_body:
            name: "append value from var to value at pointer from var"
            json_operation:
              modify_json_value:
                json_pointer:
                  term_var: "suffix_target"
                string_modifiers:
                  - append:
                      term_var: "suffix_from_body_not_exists"
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: STRICT
    - name: default_egress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      - name: prefix
        body_json_pointer: "/modifiers/2/prefix"
        variable_name: prefix_from_body
      - name: suffix
        body_json_pointer: "/modifiers/3/suffix"
        variable_name: suffix_from_body   
      - name: suffix_target
        body_json_pointer: "/modifiers/3/target"
        variable_name: suffix_target 
      filter_rules:
      - name: modify_resp_body_add_to_json
        condition:
          op_exists: {arg1:  {term_var: 'supi'}}
        actions:
        - action_modify_json_body:
            name: "prepend and append string and header values to subscriberIdentifier (in response)"
            json_operation:
              modify_json_value:
                json_pointer:
                  term_string: "/subscriberIdentifier_not_exists"
                string_modifiers:
                  - prepend:
                      term_string: "pref_string_resp_"
        - action_modify_json_body:
            name: "prepend value from var to value at pointer from var (in response)"
            json_operation:
              modify_json_value:
                string_modifiers:
                  - prepend:
                      term_var: "prefix_from_body"
        - action_modify_json_body:
            name: "append value from var to value at pointer from var (in response)"
            json_operation:
              modify_json_value:
                json_pointer:
                  term_var: "suffix_target_not_exists"
                string_modifiers:
                  - append:
                      term_var: "suffix_from_body"
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  const std::string config_body_mod_json_search_and_replace = R"EOF(
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
        - default_egress_screening
  filter_cases:
    - name: default_ingress_screening
      filter_data:
      - name: supi
        body_json_pointer: "/subscriberIdentifier"
        variable_name: supi
      filter_rules:
      - name: modify_req_body_json_search_and_replace
        condition:
          op_exists: {arg1:  {term_var: 'supi'}}
        actions:
        - action_modify_json_body:
            name: "test modify json search and replace"
            json_operation:
              modify_json_value:
                string_modifiers:
                  - search_and_replace:
                      search_value:
                        term_string: "imsi-"
                      search_options:
                        regex_search: true
                      replace_value:   
                        term_string: "PREFIX-IMSI-"
                      replace_options:
                        replace_all_occurances: true
                json_pointer:
                  term_string: "/subscriberIdentifier"
        - action_modify_header:
            name: x-hnrf-uri
            use_string_modifiers:
              string_modifiers:
                - search_and_replace:
                    search_value:
                      term_string: "10\\.1\\.2\\.3:30060"
                    search_options:
                      regex_search: true
                    replace_value:   
                      term_string: "192.168.10.20:80"
                    replace_options:
                      replace_all_occurances: true
        - action_modify_query_param:
            key_name: hnrf-uri
            use_string_modifiers:
              string_modifiers:
                - search_and_replace:
                    search_value:
                      term_string: "10\\.1\\.2\\.3:30060"
                    search_options:
                      regex_search: true
                    replace_value:   
                      term_string: "192.168.10.20:80"
                    replace_options:
                      replace_all_occurances: true
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: route_to_wrong_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
    - name: default_egress_screening
      filter_rules:
      - name: modify_resp_body_json_search_and_replace
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test modify json search and replace"
            json_operation:
              modify_json_value:
                string_modifiers:
                  - search_and_replace:
                      search_value:
                        term_string: "imsi-"
                      search_options:
                        regex_search: true
                      replace_value:   
                        term_string: "PREFIX-IMSI-"
                      replace_options:
                        replace_all_occurances: true
                json_pointer:
                  term_string: "/subscriberIdentifier"
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

//DND-40786
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBoolModification) {
  initializeFilter(config_dnd_40786);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/napi-test/v1/message-screening/mirror"},
      {":authority", "scp.mnc.012.mcc.210.ericsson.se:30535"},
      {"3gpp-sbi-target-apiroot", "http://nfUdm1.mnc.012.mcc.210.ericsson.se:8292"},
  };
  const std::string body{R"({"subscriberIdentifier":"imsi-460030700000001","nfConsumerIdentification":{"nFName":"123e-e8b-1d3-a46-421","nFIPv4Address":"192.168.0.1","nFIPv6Address":"2001:db8:85a3:8d3:1319:8a2e:370:7348","nFPLMNID":{"mcc":"311","mnc":"280"},"nodeFunctionality":"SMF"},"invocationTimeStamp":"2019-03-28T14:30:50Z","invocationSequenceNumber":0,"multipleUnitUsage":[{"ratingGroup":100,"requestedUnit":{"time":123,"totalVolume":211,"uplinkVolume":123,"downlinkVolume":1234,"serviceSpecificUnits":6543},"uPFID":"123e-e8b-1d3-a46-421"}],"pDUSessionChargingInformation":{"chargingId":123,"userInformation":{"servedGPSI":"msisdn-77117777","servedPEI":"imei-234567891098765","unauthenticatedFlag":true,"roamerInOut":"OUT_BOUND"},"userLocationinfo":{"eutraLocation":{"tai":{"plmnId":{"mcc":"374","mnc":"645"},"tac":"ab01"},"ecgi":{"plmnId":{"mcc":"374","mnc":"645"},"eutraCellId":"abcAB12"},"ageOfLocationInformation":32766,"ueLocationTimestamp":"2019-03-28T14:30:50Z","geographicalInformation":"234556ABCDEF2345","geodeticInformation":"ABCDEFAB123456789023","globalNgenbId":{"plmnId":{"mcc":"374","mnc":"645"},"n3IwfId":"ABCD123","ngRanNodeId":"MacroNGeNB-abc92"}},"nrLocation":{"tai":{"plmnId":{"mcc":"374","mnc":"645"},"tac":"ab01"},"ncgi":{"plmnId":{"mcc":"374","mnc":"645"},"nrCellId":"ABCabc123"},"ageOfLocationInformation":1,"ueLocationTimestamp":"2019-03-28T14:30:50Z","geographicalInformation":"AB12334765498F12","geodeticInformation":"AB12334765498F12ACBF","globalGnbId":{"plmnId":{"mcc":"374","mnc":"645"},"n3IwfId":"ABCD123","ngRanNodeId":"MacroNGeNB-abc92"}},"n3gaLocation":{"n3gppTai":{"plmnId":{"mcc":"374","mnc":"645"},"tac":"ab01"},"n3IwfId":"ABCD123","ueIpv4Addr":"192.168.0.1","ueIpv6Addr":"2001:db8:85a3:8d3:1319:8a2e:370:7348","portNumber":1}},"userLocationTime":"2019-03-28T14:30:50Z","uetimeZone":"+05:30","pduSessionInformation":{"networkSlicingInfo":{"sNSSAI":{"sst":0,"sd":"Aaa123"}},"pduSessionID":1,"pduType":"IPV4","sscMode":"SSC_MODE_1","hPlmnId":{"mcc":"374","mnc":"645"},"servingNodeID":[{"plmnId":{"mcc":"311","mnc":"280"},"amfId":"ABab09"}],"servingNetworkFunctionID":{"servingNetworkFunctionName":"SMF","servingNetworkFunctionInstanceid":"SMF_Instanceid_1","gUAMI":{"plmnId":{"mcc":"311","mnc":"280"},"amfId":"ABab09"}},"ratType":"EUTRA","dnnId":"DN-AAA","chargingCharacteristics":"AB","chargingCharacteristicsSelectionMode":"HOME_DEFAULT","startTime":"2019-03-28T14:30:50Z","3gppPSDataOffStatus":"ACTIVE","pduAddress":{"pduIPv4Address":"192.168.0.1","pduIPv6Address":"2001:db8:85a3:8d3:1319:8a2e:370:7348","pduAddressprefixlength":0,"IPv4dynamicAddressFlag":true,"IPv6dynamicAddressFlag":false},"qoSInformation":"test127","servingCNPlmnId":{"mcc":"311","mnc":"280"}},"unitCountInactivityTimer":125}})"};
  const std::string exp_body{R"({"invocationSequenceNumber":0,"invocationTimeStamp":"2019-03-28T14:30:50Z","multipleUnitUsage":[{"ratingGroup":100,"requestedUnit":{"downlinkVolume":1234,"serviceSpecificUnits":6543,"time":123,"totalVolume":211,"uplinkVolume":123},"uPFID":"123e-e8b-1d3-a46-421"}],"nfConsumerIdentification":{"nFIPv4Address":"192.168.0.1","nFIPv6Address":"2001:db8:85a3:8d3:1319:8a2e:370:7348","nFName":"123e-e8b-1d3-a46-421","nFPLMNID":{"mcc":"311","mnc":"280"},"nodeFunctionality":"SMF"},"pDUSessionChargingInformation":{"chargingId":123,"pduSessionInformation":{"3gppPSDataOffStatus":"ACTIVE","chargingCharacteristics":"AB","chargingCharacteristicsSelectionMode":"HOME_DEFAULT","dnnId":"DN-AAA","hPlmnId":{"mcc":"374","mnc":"645"},"networkSlicingInfo":{"sNSSAI":{"sd":"Aaa123","sst":0}},"pduAddress":{"IPv4dynamicAddressFlag":true,"IPv6dynamicAddressFlag":true,"pduAddressprefixlength":0,"pduIPv4Address":"192.168.0.1","pduIPv6Address":"2001:db8:85a3:8d3:1319:8a2e:370:7348"},"pduSessionID":1,"pduType":"IPV4","qoSInformation":"test127","ratType":"EUTRA","servingCNPlmnId":{"mcc":"311","mnc":"280"},"servingNetworkFunctionID":{"gUAMI":{"amfId":"ABab09","plmnId":{"mcc":"311","mnc":"280"}},"servingNetworkFunctionInstanceid":"SMF_Instanceid_1","servingNetworkFunctionName":"SMF"},"servingNodeID":[{"amfId":"ABab09","plmnId":{"mcc":"311","mnc":"280"}}],"sscMode":"SSC_MODE_1","startTime":"2019-03-28T14:30:50Z"},"uetimeZone":"+05:30","unitCountInactivityTimer":125,"userInformation":{"roamerInOut":"OUT_BOUND","servedGPSI":"msisdn-77117777","servedPEI":"imei-234567891098765","unauthenticatedFlag":false},"userLocationTime":"2019-03-28T14:30:50Z","userLocationinfo":{"eutraLocation":{"ageOfLocationInformation":32766,"ecgi":{"eutraCellId":"abcAB12","plmnId":{"mcc":"374","mnc":"645"}},"geodeticInformation":"ABCDEFAB123456789023","geographicalInformation":"234556ABCDEF2345","globalNgenbId":{"n3IwfId":"ABCD123","ngRanNodeId":"MacroNGeNB-abc92","plmnId":{"mcc":"374","mnc":"645"}},"tai":{"plmnId":{"mcc":"374","mnc":"645"},"tac":"ab01"},"ueLocationTimestamp":"2019-03-28T14:30:50Z"},"n3gaLocation":{"n3IwfId":"ABCD123","n3gppTai":{"plmnId":{"mcc":"374","mnc":"645"},"tac":"ab01"},"portNumber":1,"ueIpv4Addr":"192.168.0.1","ueIpv6Addr":"2001:db8:85a3:8d3:1319:8a2e:370:7348"},"nrLocation":{"ageOfLocationInformation":1,"geodeticInformation":"AB12334765498F12ACBF","geographicalInformation":"AB12334765498F12","globalGnbId":{"n3IwfId":"ABCD123","ngRanNodeId":"MacroNGeNB-abc92","plmnId":{"mcc":"374","mnc":"645"}},"ncgi":{"nrCellId":"ABCabc123","plmnId":{"mcc":"374","mnc":"645"}},"tai":{"plmnId":{"mcc":"374","mnc":"645"},"tac":"ab01"},"ueLocationTimestamp":"2019-03-28T14:30:50Z"}}},"subscriberIdentifier":"imsi-460030700000001"})"};
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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(exp_body, upstream_request_->body().toString());


  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "Pool_PSEPP1"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-fop", "fob1"));

  codec_client_->close();
}

TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_DND_31191) {
  initializeFilter(config_bug_dnd_31191);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/nudm-sdm/v2/shared-data?shared-data-ids=24016-123,24016-456"},
      {":authority", "eric-seppsim-p3-mcc-262-mnc-73:80"},
  }; 
  std::string body{R"([{"sharedDataId":"68042-XHq0gsd"}])"};


  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(headers);
  
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // Send fake upstream response, using same body as in request:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(body.length())},
      {"content-type", "application/json"},
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());
  

  std::cerr << "RESPONSE HEADERS" << std::endl;
  response->headers().iterate([](const Http::HeaderEntry& header) ->  Http::HeaderMap::Iterate {
    std::cerr << header.key().getStringView()
              << ':'
              << header.value().getStringView()
              << std::endl;
    return Http::HeaderMap::Iterate::Continue;
  });

  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-type", "application/json"));  
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(body.length())));

  codec_client_->close();
}

// Name: TestJsonBodyMod_json_patch
// Description: A JSON patch operation is configured to replace the value of the 
// "subscriberIdentifier" attribute in the JSON body of all handled requests.
// A sample request, including an existing "subscriberIdentifier" in the body, is sent.
// Expected Result:
// - The body of the request is modified, i.e. the subscriberIdentifier is 
//   replaced by the configured value. The rest of the body stays the same.
// - The content-length header is adapted to the size of the modified body
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_json_patch) {
  initializeFilter(config_body_mod_json_patch);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
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
  Json expected_body{R"(
      {
        "subscriberIdentifier": "supi-replaced-by-json-patch",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client_->close();
}

// Name: TestJsonBodyMod_add_to_json
// Description: An add_to_json operation is configured to add a new element "subscriberIdentifier1"
// with a constant string value in the JSON body of all handled requests.
// A sample request, including an existing "subscriberIdentifier" in the body, is sent.
// Expected Result:
// - The body of the request is modified, i.e. the new element "subscriberIdentifier1" is added
//   and has the value "supi-added", while the rest of the body stays the same.
// - The content-length header is adapted to the size of the modified body
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_add_to_json) {
  initializeFilter(config_body_mod_add_to_json);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
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

  Json expected_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "subscriberIdentifier1": "supi-added",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
    )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client_->close();
}

// Name: TestJsonBodyMod_add_to_json_string_from_var
// Description: An add_to_json operation is configured to add a new element "subscriberIdentifier_added"
// in the JSON body of all handled requests. The value of the new element should be a string taken from
// a message data variable. A sample request is sent, including the message data to be extracted.
// Expected Result:
// - The body of the request is modified, i.e. the new element "subscriberIdentifier_added" is added and
//   has the value "imsi-460001357924610", extracted from the "subscriberIdentifier" attribute in the
//   original body. The rest of the body stays the same.
// - The content-length header is adapted to the size of the modified body.
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_add_to_json_string_from_var) {
  initializeFilter(config_body_mod_add_to_json_string_from_var);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
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

  Json expected_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "subscriberIdentifier_added": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client_->close();

}

// Name: TestJsonBodyMod_add_to_json_string_from_var2
// EEDALA 2022-07-27: I added this testcase after talking to Alexandros Paximidakis
//                    Currently it crashes Envoy. Not sure if there is a connection to DND-32778.
// Description: A body with an array of three strings is received. Store that array in a variable,
// empty the body, and then add an object to the body with "key1" as key and the array from the
// variable as the value.
// Expected Result:
// - The body of the request is replaced.
// - Instead of the original array it has now an object on top level
// - The object has a single key with the array as its value
// - The content-length header is adapted to the size of the modified body.
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_add_to_json_string_from_var2) {
  initializeFilter(config_body_mod_add_to_json_string_from_var2);
  std::string body{R"(
  ["value1", "value2", "value3"]
  )"};
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", std::to_string(body.length())}
  };

  Json expected_body{R"(
      {
        "key1": ["value1", "value2", "value3"]
      }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  codec_client_->close();

}

// Name: TestJsonBodyMod_add_to_json_string_from_var_DND_32778
// EEDRAK 2022-08-01: I added this testcase due to bug DND-32778.
// Description: A body with an array of three strings is received. Store that array in a variable.
// Trying to modifiy the body with json-pointer: /new-key1 will lead to a reject with staus 400.
// Expected Result:
// - The request is rejected with status 400, but no envoy crash
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_add_to_json_string_from_var_DND_32778) {
  //GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still ongoing";

  //initializeFilter(config_body_mod_add_to_json_string_from_var_DND_32778);
  config_helper_.addFilter(config_body_mod_add_to_json_string_from_var_DND_32778);
  initialize();
  std::string body{R"(
  ["value1", "value2", "value3"]
  )"};
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", std::to_string(body.length())}
  };

  std::string expected_body = R"(
    {"status": 400,"title": "Bad Request","cause": "UNSPECIFIED_MSG_FAILURE","detail": "request_json_operation_failed"}
  )";

  Json expected_body_json = Json::parse(expected_body);

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());

  // Verify modified body in downstream response
  EXPECT_EQ(expected_body_json, Json::parse(response->body()));
  codec_client_->close();

}

// Name: TestJsonBodyMod_add_to_json_string_from_var_DND_32778_1
// EEDRAK 2022-08-01: I added this testcase due to bug DND-32778.
// Description: A body with an array of three strings is received. Store that array in a variable.
// Trying to modifiy the body with json-pointer: /  will lead to a reject with staus 400.
// Expected Result:
// - The request is rejected with status 400, but no envoy crash
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_add_to_json_string_from_var_DND_32778_1) {
  //GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still ongoing";

  //initializeFilter(config_body_mod_add_to_json_string_from_var_DND_32778_1);
  config_helper_.addFilter(config_body_mod_add_to_json_string_from_var_DND_32778_1);
  initialize();
  std::string body{R"(
  ["value1", "value2", "value3"]
  )"};
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", std::to_string(body.length())}
  };

  std::string expected_body = R"(
    {"status": 400,"title": "Bad Request","cause": "UNSPECIFIED_MSG_FAILURE","detail": "request_json_operation_failed"}
  )";

  Json expected_body_json = Json::parse(expected_body);

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());

  // Verify modified body in downstream response
  EXPECT_EQ(expected_body_json, Json::parse(response->body()));
  codec_client_->close();

}

// Name: TestJsonBodyMod_add_to_json_string_from_var_DND_32778_2
// EEDRAK 2022-08-01: I added this testcase due to bug DND-32778 add. issues.
// Description: A body with an array of three strings is received. Attempt to store that array in a variable
// using json pointer "/".
// - The request is rejected with status 400, but no envoy crash
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_add_to_json_string_from_var_DND_32778_2) {
  //GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still ongoing";

  //initializeFilter(config_body_mod_add_to_json_string_from_var_DND_32778_1);
  config_helper_.addFilter(config_body_mod_add_to_json_string_from_var_DND_32778_2);
  initialize();
  std::string body{R"(
  ["value1", "value2", "value3"]
  )"};
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", std::to_string(body.length())}
  };

  std::string expected_body = R"(
    {"status": 400,"title": "Bad Request","cause": "UNSPECIFIED_MSG_FAILURE","detail": "request_json_operation_failed"}
  )";

  Json expected_body_json = Json::parse(expected_body);

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());

  // Verify modified body in downstream response
  EXPECT_EQ(expected_body_json, Json::parse(response->body()));
  codec_client_->close();

}


// Name: TestJsonBodyMod_replace_in_json
// Description: A replace_in_json operation is configured to replace the value of the "subscriberIdentifier" 
// attribute in the JSON body of all handled requests by a constant string value.
// A sample request, including an existing "subscriberIdentifier" in the body, is sent.
// Expected Result:
// - The body of the request is modified, i.e. the subscriberIdentifier is 
//   replaced by the configured value "12345678", while the rest of the body
//   stays as is.
// - The content-length header is adapted to the size of the modified body
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_replace_in_json) {
  initializeFilter(config_body_mod_replace_in_json);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
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

  Json expected_body{R"(
      {
        "subscriberIdentifier": 12345678,
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client_->close();
}


// Name: TestJsonBodyMod_replace_in_jsonMP (Multipart-body version of
//       TestJsonBodyMod_replace_in_json)
// Description: A replace_in_json operation is configured to replace the value of the "subscriberIdentifier" 
// attribute in the JSON body of all handled requests by a constant string value.
// A sample request, including an existing "subscriberIdentifier" in the body, is sent.
// Expected Result:
// - The body of the request is modified, i.e. the subscriberIdentifier is 
//   replaced by the configured value "12345678", while the rest of the body
//   stays as is.
// - The content-length header is adapted to the size of the modified body
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_replace_in_jsonMP) {
  initializeFilter(config_body_mod_replace_in_json);
  std::string body_prefix{
    "This is the preamble"
    "\r\n--boundary\r\nContent-type: application/json\r\n\r\n"
  };
  std::string json_body{
    R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  
  std::string body_suffix{
    "\r\n--boundary\r\nContent-type: text/plain\r\n\r\n"
    "This is a text body part"
    "\r\n--boundary--\r\n"
    "..and an epilogue"
  };
  std::string whole_body = absl::StrCat(body_prefix, json_body, body_suffix);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", std::to_string(whole_body.length())},
      {"content-type", "multipart/related; boundary=boundary"},
  };

  Json expected_json{R"(
      {
        "subscriberIdentifier": 12345678,
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, whole_body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  std::string content_type{"multipart/related; boundary=boundary"};

  // Send fake upstream response, using same body as in request:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(whole_body.length())},
      {"content-type", content_type},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(whole_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  Body req_body(&(upstream_request_->body()), content_type);
  EXPECT_EQ(expected_json, *(req_body.getBodyAsJson()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  Body resp_body;
  resp_body.setBodyFromString(response->body(), content_type);
  EXPECT_EQ(expected_json, *(resp_body.getBodyAsJson()));

  codec_client_->close();
}


// Name: TestJsonBodyMod_replace_in_jsonMP (Multipart-body version of
//       TestJsonBodyMod_replace_in_json)
// Description: A replace_in_json operation is configured to replace the value of the "subscriberIdentifier" 
// attribute in the JSON body of all handled requests by a constant string value.
// A sample request, including an existing "subscriberIdentifier" in the body, is sent.
// Expected Result:
// - The body of the request is modified, i.e. the subscriberIdentifier is 
//   replaced by the configured value "12345678", while the rest of the body
//   stays as is.
// - The content-length header is adapted to the size of the modified body
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_replace_in_jsonNotMP) {
  initializeFilter(config_body_mod_replace_in_json);

  std::string whole_body{
    R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
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
      {"content-length", std::to_string(whole_body.length())},
      {"content-type", "multipart/related; boundary=boundary"},
  };

  Json expected_json{R"(
      {
        "subscriberIdentifier": 12345678,
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, whole_body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  std::string content_type{"multipart/related; boundary=boundary"};

  // Send fake upstream response, using same body as in request:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(whole_body.length())},
      {"content-type", content_type},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(whole_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  Body req_body(&(upstream_request_->body()), content_type);
  EXPECT_EQ(expected_json, *(req_body.getBodyAsJson()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  Body resp_body;
  resp_body.setBodyFromString(response->body(), content_type);
  EXPECT_EQ(expected_json, *(resp_body.getBodyAsJson()));

  codec_client_->close();
}



// Name: TestJsonBodyMod_replace_in_jsonMP2 (Multipart-body version of
//       TestJsonBodyMod_replace_in_json, variant)
// Description: A replace_in_json operation is configured to replace the value of the "subscriberIdentifier" 
// attribute in the JSON body of all handled requests by a constant string value.
// A sample request, including an existing "subscriberIdentifier" in the body, is sent.
// The JSON body is not the first body part and there is no "start" parameter
// pointing to the JSON body part.
// Expected Result:
// - The body of the request is  modified, i.e. the subscriberIdentifier is 
//    replaced by the configured value "12345678"
// - The request is processed ok to be tolerant to small errors
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_replace_in_jsonMP2) {
  initializeFilter(config_body_mod_replace_in_json);
  std::string body_prefix{
    "This is the preamble"
    "\r\n--boundary\r\nContent-type: text/plain\r\n\r\n"
    "This is a text body part"
    "\r\n--boundary\r\nContent-type: application/json\r\n\r\n"
  };
  std::string json_body{
    R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  
  std::string body_suffix{
    "\r\n--boundary--\r\n"
    "..and an epilogue"
  };
  std::string whole_body = absl::StrCat(body_prefix, json_body, body_suffix);

  std::string content_type{"multipart/related; boundary=boundary"};
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", std::to_string(whole_body.length())},
      {"content-type", content_type},
  };

  Json expected_json{R"(
      {
        "subscriberIdentifier": 12345678,
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, whole_body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  

  // Send fake upstream response, using same body as in request:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(whole_body.length())},
      {"content-type", content_type},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(whole_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  Body req_body(&(upstream_request_->body()), content_type);
  EXPECT_EQ(expected_json, *(req_body.getBodyAsJson()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  Body resp_body;
  resp_body.setBodyFromString(response->body(), content_type);
  EXPECT_EQ(expected_json, *(resp_body.getBodyAsJson()));

  codec_client_->close();
}


// Name: TestJsonBodyModBodyIsBinaryReqMP
// Description: A replace_in_json operation is configured to replace the value of the "subscriberIdentifier" 
// attribute in the JSON body of all handled requests by a constant string value.
// A sample request, including an existing "subscriberIdentifier" in the body, is sent.
// The first body part is wrongly having "content-type: application/json" but is not
// JSON.
// The action modify-json-body is executed/attempted, fails, and a 400 response is sent.
// Expected Result:
// - JSON parsing of the wrongly-marked non-JSON body part fails
// - Request processing stops
// - 400 response sent
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyModBodyIsBinaryReqMP) {
  initializeFilter(config_body_mod_replace_in_json_req_mp);
  std::string body_prefix{
    // content-type is wrong here:
    "\r\n--boundary\r\nContent-type: application/json\r\n\r\n"
    "This is a text/binary \001 \002 body part"
    "\r\n--boundary\r\nContent-type: application/json\r\n\r\n"
  };
  std::string json_body{
    R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  
  std::string body_suffix{
    "\r\n--boundary--\r\n"
  };
  std::string whole_body = absl::StrCat(body_prefix, json_body, body_suffix);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", std::to_string(whole_body.length())},
      {"content-type", "multipart/related; boundary=boundary"},
  };

  Json expected_json{R"(
      {
        "subscriberIdentifier": 12345678,
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, whole_body);

  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "400"));
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));

  codec_client_->close();
}

// Name: TestJsonBodyModBodyIsBinaryReqMP2
// Description: A replace_in_json operation is configured to replace the value of the "subscriberIdentifier" 
// attribute in the JSON body of all handled requests by a constant string value.
// A sample request, including an existing "subscriberIdentifier" in the body, is sent.
// There are 2 body parts, but none is JSON.
// The action modify-json-body is executed/attempted, fails, and a 400 response is sent.
// Expected Result:
// - JSON parsing of the non-JSON body part fails
// - Request processing stops
// - 400 response sent
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyModBodyIsBinaryReqMP2) {
  initializeFilter(config_body_mod_replace_in_json_req_mp);
  std::string body_prefix{
    // content-type is wrong here:
    "\r\n--boundary\r\nContent-type: application/binary\r\n\r\n"
    "This is a text/binary \001 \002 body part"
    "\r\n--boundary\r\nContent-type: application/binary\r\n\r\n"
    "This is the second text/binary \001 \002 body part"
  };
 
  std::string body_suffix{
    "\r\n--boundary--\r\n"
  };
  std::string whole_body = absl::StrCat(body_prefix, body_suffix);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", std::to_string(whole_body.length())},
      {"content-type", "multipart/related; boundary=boundary"},
  };

  Json expected_json{R"(
      {
        "subscriberIdentifier": 12345678,
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, whole_body);

  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "400"));
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));

  codec_client_->close();
}

// Name: TestJsonBodyModBodyIsBinaryRespMP
// Description: A replace_in_json operation is configured to replace the value of the "subscriberIdentifier" 
// attribute in the JSON body of all handled requests by a constant string value.
// A sample request, including an existing "subscriberIdentifier" in the body, is sent.
// The first body part is wrongly having "content-type: application/json" but is not
// JSON.
// Note that in the request path, the JSON is accessed through a filter-data json-pointer
// which is un-set because JSON parsing failed and the condition guarding the action
// modify-json-body fails, so the action is not exectuted.
// However, in the response path, the condition is just "true" so the action
// modify-json-body is executed/attempted, fails, and a 500 response is sent.
// Expected Result:
// - The body of the request is not modified, i.e. the subscriberIdentifier is 
//   not replaced by the configured value "12345678"
// - Normal handling of un-parsable JSON (= variable extracted from JSON body
//   does not exist)
// - In the response screening, the action modify-json-body fails and a 500 response
//   is  sent.
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyModBodyIsBinaryRespMP) {
  initializeFilter(config_body_mod_replace_in_json);
  std::string body_prefix{
    // content-type is wrong here:
    "\r\n--boundary\r\nContent-type: application/json\r\n\r\n"
    "This is a text/binary \001 \002 body part"
    "\r\n--boundary\r\nContent-type: application/json\r\n\r\n"
  };
  std::string json_body{
    R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  
  std::string body_suffix{
    "\r\n--boundary--\r\n"
  };
  std::string whole_body = absl::StrCat(body_prefix, json_body, body_suffix);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", std::to_string(whole_body.length())},
      {"content-type", "multipart/related; boundary=boundary"},
  };

  Json expected_json{R"(
      {
        "subscriberIdentifier": 12345678,
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, whole_body);

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  std::string content_type{"multipart/related; boundary=boundary"};

  // Send fake upstream response, using same body as in request:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(whole_body.length())},
      {"content-type", content_type},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(whole_body);
  upstream_request_->encodeData(response_data, true);

  // Verify upstream request and that the body is not modified:
  // "wrong_pool" is correct here because the JSON decoding fails, so it's normal
  // JSON parsing behaviour to not have the variable "json_object_from_body" set
  // and the next routing rule is unconditionally to "wrong_pool".
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "wrong_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  // We expect an un-modified body
  EXPECT_EQ(upstream_request_->body().toString(), whole_body);

  ASSERT_TRUE(response->waitForEndStream());

  // Since JSON parsing in the response screening will fail, expect a 500 answer
  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "500"));
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));

  codec_client_->close();
}



// Name: TestJsonBodyMod_replace_in_json_object_from_var
// Description: A replace_in_json operation is configured to replace the value of the "subscriberIdentifier" 
// attribute (orginally a string) in the JSON body of all handled requests by a JSON object from the message 
// data (value of the 'nfConsumerIdentification' attribute of the original body).
// A sample request, including an existing "subscriberIdentifier" in the body, is sent.
// Expected Result:
// - The body of the request is modified, i.e. the subscriberIdentifier is 
//   replaced by the message data extracted from the 'nfConsumerIdentification'
//   attribute (JSON object) in the body, while the rest of the body stays as is.
// - The content-length header is adapted to the size of the modified body
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_replace_in_json_object_from_var) {
  initializeFilter(config_body_mod_replace_in_json_object_from_var);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
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

  Json expected_body{R"(
      {
        "subscriberIdentifier": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
            "mcc": "311",
            "mnc": 280
          },
          "nodeFunctionality": "SMF"
        },
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client_->close();
}

// Name: TestJsonBodyMod_remove_from_json
// Description: A remove_from_json operation is configured to remove the element "subscriberIdentifier" 
// from the JSON body of all handled requests.
// A sample request, including an existing "subscriberIdentifier" in the body, is sent.
// Expected Result:
// - The bodies of the request and of the response is modified, i.e. the "subscriberIdentifier" element 
//   is removed. The rest of the body stays the same.
// - The content-length header is adapted to the size of the modified body.
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_remove_from_json) {
  initializeFilter(config_body_mod_remove_from_json);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
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

  Json expected_body{R"(
      {
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client_->close();

}

// Name: TestJsonBodyMod_remove_full_json
// Description: A remove_from_json operation is configured to remove the whole JSON body of all handled request
// and response messages.
// A sample request, including a JSON body, is sent.
// Expected Result:
// - The existing JSON object is removed from the bodies of the request and of the response message. The body now
//   equals the JSON value 'null'.
// - The content-length header is adapted to the size of the modified body.
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_remove_full_json) {
  initializeFilter(config_body_mod_remove_full_json);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
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

  Json expected_body{R"(
      null
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  std::cout << "response body: " << response->body() << std::endl;
  std::cout << "upstream_request_ body: " << upstream_request_->body().toString() << std::endl;

  // Verify the upstream request and that its JSON body is removed:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // Verify removed body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client_->close();

}

// Name: TestJsonBodyMod_path_not_exists
// Description: Two add_to_json operations are configured to add a string in the body of all
// handled requests. The if_path_not_exists is set to 'CREATE' for the first action and set to
// 'DO_NOTHING' for the second action. A sample request is sent, that does not include any of the
// paths referenced from the two add_to_json actions.
// Expected Result:
// - The path referenced by the first add_to_json action (if_path_not_exists=CREATE) is created
//   and the string value is added under this path. The path referenced from the second 
//   add_to_json action (if_path_not_exists=DO_NOTHING) is not created and the string is not added.
// - The content-length header is adapted to the size of the modified body.
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_path_not_exists) {
  initializeFilter(config_body_mod_path_not_exists);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
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

  Json expected_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
            "mcc": "311",
            "mnc": 280
          },
          "nodeFunctionality": "SMF"
        },
        "nfServices": {
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253"
            }
          ]
        }        
      }
  )"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // close the fake upstream connection
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  codec_client_->close();
}

// Name: TestJsonBodyMod_element_exists
// Description: Two add_to_json operations are configured to add a string in the body of all
// handled requests. The if_element_exists is set to 'NO_ACTION' for the first action and set to
// 'REPLACE' for the second action. A sample request is sent, that does already include both elements
// to be added by the two actions in the body.
// Expected Result:
// - The element referenced by the first add_to_json action (if_element_exists=NO_ACTION) is not
//   replaced. The element referenced by the second add_to_json action (if_element_exists=REPLACE) is 
//   replaced by the new value.
// - The content-length header is adapted to the size of the modified body.
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_element_exists) {
  initializeFilter(config_body_mod_element_exists);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
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

  Json expected_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 281
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  
  // close the fake upstream connection
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  codec_client_->close();
}

// Name: TestJsonBodyMod_replace_root_from_var
// Description: A replace_in_json operation is configured referencing the root of the body to 
// replace the complete JSON object in the body. The old JSON body object should be replaced by
// one of its child elements 'nfPLMNID'.
// A sample request including a JSON object and its child element 'nfPLMNID'.
// Expected Result:
// - The full body of the request is replaced by the value of its child element 'nfPLMNID' 
// - The content-length header is adapted to the size of the modified body
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_replace_root_from_var) {
  initializeFilter(config_body_mod_replace_root_from_var);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
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

  Json expected_body{R"(
      {
        "mcc": "311",
        "mnc": 280
      }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client_->close();
}


/// Dummy Tests to check action-modify-json-body 
// with table lookup

TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_table_lookup) {
  initializeFilter(config_body_mod_table_lookup);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "example_fqdn_1.com"
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

  Json expected_body_req{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fake_example_fqdn_1.com"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

  Json expected_body_resp{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fake_example_fqdn_1.com"

          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body_req, Json::parse(upstream_request_->body().toString()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body_resp, Json::parse(response->body()));

  codec_client_->close();
}

// Name: TestJsonBodyMod_replace_by_different_type
// Description: A replace_in_json operation is configured to replace the value of the "mcc"
// and "mnc" values by a new value of different type, e.g. replace integer by string.
// A sample request, including the "mcc" and "mnc" values in the body, is sent.
// Expected Result:
// - The body of the request is modified, replacing the "mcc" value of type string by a new 
//   integer value.
// - The body of the response is modified, replacing the "mnc" value of type integer by a new
//   string value.
// - The content-length headers in request and response are adapted to the size of the modified body
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_replace_by_different_type) {
  initializeFilter(config_body_mod_replace_by_different_type);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
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

  Json expected_body_req{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": 312,
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

  Json expected_body_resp{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": "281"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body_req, Json::parse(upstream_request_->body().toString()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body_resp, Json::parse(response->body()));

  codec_client_->close();
}

// Name: TestJsonBodyMod_path_not_exists_req_resp
// Description: An add_to_json operation is configured for all handled requests and responses to add
// a string value in an array that does not exist in the JSON body. The path and the array should be 
// created (if_path_not_exists=CREATE).
// A sample request that does not include the referenced array and the path to it.
// Expected Result:
// - The array and the path to it are created and the string value is added as a new array element
//   in both JSON bodies, of the request and of the response.
// - The content-length header is adapted to the size of the modified body
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_path_not_exists_req_resp) {
  initializeFilter(config_body_mod_path_not_exists_req_resp);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
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

  Json expected_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
            "mcc": "311",
            "mnc": 280
          },
          "nodeFunctionality": "SMF"
        },
        "nfServices": {
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253"
            }
          ]
        }        
      }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client_->close();
}

// Name: TestJsonBodyMod_add_to_json_malformed
// Description: An add_to_json operation is configured to add a new element "subscriberIdentifier1" 
// with a constant string value in the JSON body of all handled requests.
// A sample request, with a malformed body is sent.
// Expected Result:
// - ???
// - The content-length header is adapted to the size of the modified body
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_add_to_json_malformed) {
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
  
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", std::to_string(body.length())}
  };

  Json expected_body{R"(
      {
        "status": 500, 
        "title": "Internal Server Error", 
        "cause": "SYSTEM_FAILURE", 
        "detail": "response_json_operation_failed"
      }
  )"_json};
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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
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

// Name: TestJsonBodyMod_add_to_json_empty_body
// Description: An add_to_json operation is configured to add a new element (if_path_not_exists=CREATE)
// in all handled request and response messages.
// A sample request with an empty body (even without an empty JSON object) is sent.
// Expected Result:
// - The bodies in request and response are not modified because no valid JSON object could be found and
//   therefore all body modifications are skipped.
// - The content-length header is adapted to the size of the modified body.
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_add_to_json_empty_body) {
  initializeFilter(config_body_mod_path_not_exists_req_resp);
  
  // Empty body
  std::string body{R"()"};

  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", std::to_string(body.length())}
  };

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify that the body in the upstream request was not modified and content-length header matches.
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(upstream_request_->body().toString(), "");

  // Verify that the body in the response was not modified and content-length header matches.
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(response->body(), "");

  codec_client_->close();
}

// Name: TestJsonBodyMod_add_to_json_null_body
// Description: An add_to_json operation is configured to add a new element (if_path_not_exists=CREATE)
// in all handled request and response messages.
// A sample request with an empty body, only including the JSON value 'null', is sent.
// Expected Result:
// - The bodies in request and response are modified. A new JSON object is created including the new path
//   and value as specified in the ad_to_json operation.
// - The content-length header is adapted to the size of the modified body.
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_add_to_json_null_body) {
  initializeFilter(config_body_mod_path_not_exists_req_resp);
  
  // Empty body
  std::string body{R"(null)"};

  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", std::to_string(body.length())}
  };
  Json expected_body{R"(
      {
        "nfServices": {
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253"
            }
          ]
        }
      }
    )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify that the body in the upstream request was not modified and content-length header matches.
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // Verify that the body in the response was not modified and content-length header matches.
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client_->close();
}

// Name: TestJsonBodyMod_multiple_mod
// Description: Two consecutive JSON operations are configured to first add a new element 
// "subscriberIdentifier1" and in a second step remove the element "subscriberIdentifier" 
// from the JSON body of all handled requests.
// A sample request, including an existing "subscriberIdentifier" in the body, is sent.
// Expected Result:
// - The body of the request is modified, i.e. the "subscriberIdentifier" element is removed 
//   and a new element "subscriberIdentifier1" is added. The rest of the body stays the same.
// - The content-length header is adapted to the size of the modified body.
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_multiple_mod) {
  initializeFilter(config_body_mod_multiple_mod);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
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

  Json expected_body{R"(
      {
        "subscriberIdentifier1": "supi-added",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client_->close();

}

// Name: TestJsonBodyMod_multiple_mod_array
// Description: Two consecutive JSON operations are configured to first remove the third (last) 
// element in an array of the JSON body in all handled requests and in a second step tries to 
// add a fourth (index=3) element to the same array.
// A sample request, including an array of size 3, is sent.
// Expected Result:
// - The body of the request is modified, i.e. the third element in the array is
//   removed but the new element at index=3 is not added because the index is out 
//   of bounds. The rest of the body stays the same.
// - The content-length header is adapted to the size of the modified body
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_multiple_mod_array) {
  initializeFilter(config_body_mod_multiple_mod_array);
  std::string body{R"(
      {
        "subscriberIdentifier": ["imsi-460001357924610", "imsi-460001357924611", "imsi-460001357924612"],
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
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

  Json expected_body{R"(
      {
        "subscriberIdentifier": ["imsi-460001357924610", "imsi-460001357924611"],
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);


  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client_->close();

}

//----------- json-body-pointer and extractor-regex ----------------------
// Extract a number from json body and use that in an extractor regex
// Expected is that the variable does not exist because an extractor regex
// on a non-string source does not match -> stores emtpy string in all variables
// -> empty string in an "exists" results in false
TEST_P(EricProxyFilterBodyIntegrationTest, TestNumberInExtractorRegex) {
  initializeFilter(config_json_body_pointer_extractor_regex);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
            "nfPLMNID": {
                "mcc": 311,
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

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection_->close());
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "numberNotExists"));
  codec_client_->close();
}

// Attempt to extract a non-existing element from a json body and use
// that in an extractor regex
// Expected is that the variable is set to the empty string.
// Reason is that variables set by an extractor-regex either have a value
// or the empty string, but can never be null.
TEST_P(EricProxyFilterBodyIntegrationTest, TestNonExistingElementInExtractorRegex) {
  initializeFilter(config_json_body_pointer_extractor_regex);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
            "nfPLMNID": {
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

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection_->close());
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "numberNotExists"));
  codec_client_->close();
}

// send a request with a large payload but under buffer filter's size
// json body operator causes the payload to pass said limit
// verify local reply is received
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_overflow) {

  // remove egress screening json body modification for this TC
  const std::string s = "term_boolean: true";
  std::size_t indx = config_body_mod_add_to_json.rfind("term_boolean: true");
  if (std::string::npos != indx) {
    config_body_mod_add_to_json.replace(indx, s.length(), "term_boolean: false");
  }
  initializeFilter(config_body_mod_add_to_json);
  Json body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

  auto calculate_length = 65535 /*max configured size*/ -
                          (body.dump().length() + 9 /*"garbage" length */ + 2 /*(" ")*/ +
                           1 /*garbage": '_'*/ + 1 /*garbage": "bbbbbbbbb"','*/);
  body["garbage"] = std::string(calculate_length, 'b');
  std::string body_str = body.dump();
  Http::TestRequestHeaderMapImpl headers{{":method", "POST"},
                                         {":path", "/"},
                                         {":authority", "host"},
                                         {"content-length", std::to_string(body_str.length())}};

  Json expected_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "subscriberIdentifier1": "supi-added",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
    )"_json};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body_str);
  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ("413", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ(
      "{\"status\": 413, \"title\": \"Payload Too Large\", \"detail\": \"request_payload_too_large\"}",
      response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());

  codec_client_->close();
}


// Name: TestJsonBodyModsLargeBody
// Description: Test with a large JSON body from a CI testcase and the corresponding
// modifications.
// This is to reproduce a bug Anna found while verifying the "no more buffer filter"
// changes.
// Expected Result:
// - The body of the request is modified
// - The content-length header is adapted to the size of the modified body
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyModsLargeBody) {
  initializeFilter(config_body_mods_large_body);

  std::string body{R"({"subscriberIdentifier":"imsi-460030700000001","nfConsumerIdentification":{"nFName":"123e-e8b-1d3-a46-421","nFIPv4Address":"192.168.0.1","nFIPv6Address":"2001:db8:85a3:8d3:1319:8a2e:370:7348","nFPLMNID":{"mcc":"311","mnc":"280"},"nodeFunctionality":"SMF"},"invocationTimeStamp":"2019-03-28T14:30:50Z","invocationSequenceNumber":0,"multipleUnitUsage":[{"ratingGroup":100,"requestedUnit":{"time":123,"totalVolume":211,"uplinkVolume":123,"downlinkVolume":1234,"serviceSpecificUnits":6543},"uPFID":"123e-e8b-1d3-a46-421"}],"pDUSessionChargingInformation":{"chargingId":123,"userInformation":{"servedGPSI":"msisdn-77117777","servedPEI":"imei-234567891098765","unauthenticatedFlag":true,"roamerInOut":"OUT_BOUND"},"userLocationinfo":{"eutraLocation":{"tai":{"plmnId":{"mcc":"374","mnc":"645"},"tac":"ab01"},"ecgi":{"plmnId":{"mcc":"374","mnc":"645"},"eutraCellId":"abcAB12"},"ageOfLocationInformation":32766,"ueLocationTimestamp":"2019-03-28T14:30:50Z","geographicalInformation":"234556ABCDEF2345","geodeticInformation":"ABCDEFAB123456789023","globalNgenbId":{"plmnId":{"mcc":"374","mnc":"645"},"n3IwfId":"ABCD123","ngRanNodeId":"MacroNGeNB-abc92"}},"nrLocation":{"tai":{"plmnId":{"mcc":"374","mnc":"645"},"tac":"ab01"},"ncgi":{"plmnId":{"mcc":"374","mnc":"645"},"nrCellId":"ABCabc123"},"ageOfLocationInformation":1,"ueLocationTimestamp":"2019-03-28T14:30:50Z","geographicalInformation":"AB12334765498F12","geodeticInformation":"AB12334765498F12ACBF","globalGnbId":{"plmnId":{"mcc":"374","mnc":"645"},"n3IwfId":"ABCD123","ngRanNodeId":"MacroNGeNB-abc92"}},"n3gaLocation":{"n3gppTai":{"plmnId":{"mcc":"374","mnc":"645"},"tac":"ab01"},"n3IwfId":"ABCD123","ueIpv4Addr":"192.168.0.1","ueIpv6Addr":"2001:db8:85a3:8d3:1319:8a2e:370:7348","portNumber":1}},"userLocationTime":"2019-03-28T14:30:50Z","uetimeZone":"+05:30","pduSessionInformation":{"networkSlicingInfo":{"sNSSAI":{"sst":0,"sd":"Aaa123"}},"pduSessionID":1,"pduType":"IPV4","sscMode":"SSC_MODE_1","hPlmnId":{"mcc":"374","mnc":"645"},"servingNodeID":[{"plmnId":{"mcc":"311","mnc":"280"},"amfId":"ABab09"}],"servingNetworkFunctionID":{"servingNetworkFunctionName":"SMF","servingNetworkFunctionInstanceid":"SMF_Instanceid_1","gUAMI":{"plmnId":{"mcc":"311","mnc":"280"},"amfId":"ABab09"}},"ratType":"EUTRA","dnnId":"DN-AAA","chargingCharacteristics":"AB","chargingCharacteristicsSelectionMode":"HOME_DEFAULT","startTime":"2019-03-28T14:30:50Z","3gppPSDataOffStatus":"ACTIVE","pduAddress":{"pduIPv4Address":"192.168.0.1","pduIPv6Address":"2001:db8:85a3:8d3:1319:8a2e:370:7348","pduAddressprefixlength":0,"IPv4dynamicAddressFlag":true,"IPv6dynamicAddressFlag":false},"qoSInformation":"test127","servingCNPlmnId":{"mcc":"311","mnc":"280"}},"unitCountInactivityTimer":125}})"};
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"content-length", std::to_string(body.length())},
      {"3gpp-Sbi-Target-apiRoot", "http://nfUdm1.mnc.012.mcc.210.ericsson.se:9012"},
  };

Json expected_body{R"({ "subscriberIdentifier": "imsi-460030700000001", "nfConsumerIdentification": { "nFName": "123e-e8b-1d3-a46-421", "nFIPv4Address": "192.168.0.1", "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348", "nFPLMNID": { "mcc": "311", "mnc": "280", "new-key-5": {"key1": "value1"} }, "nodeFunctionality": null, "aRoot1": { "bRoot2": { "new-key-2": 1129 } } }, "invocationTimeStamp": "2019-03-28T14:30:50Z", "invocationSequenceNumber": 0, "multipleUnitUsage": [ { "ratingGroup": 100, "requestedUnit": { "time": 123, "totalVolume": 211, "uplinkVolume": 123, "downlinkVolume": 1234, "serviceSpecificUnits": 6543 }, "uPFID": "123e-e8b-1d3-a46-421" } ], "pDUSessionChargingInformation": { "chargingId": 123, "userInformation": { "servedGPSI": "msisdn-77117777", "servedPEI": "imei-234567891098765", "unauthenticatedFlag": false, "roamerInOut": "OUT_BOUND", "new-key-1": "dummy-body-value-1" }, "userLocationinfo": { "eutraLocation": { "tai": { "plmnId": { "mcc": "374", "mnc": "645" }, "tac": "ab01" }, "ecgi": { "plmnId": { "mcc": "374", "mnc": "645" }, "eutraCellId": "abcAB12" }, "ageOfLocationInformation": 32766, "ueLocationTimestamp": "2019-03-28T14:30:50Z", "geographicalInformation": "234556ABCDEF2345", "geodeticInformation": "ABCDEFAB123456789023", "globalNgenbId": { "plmnId": { "mcc": "374", "mnc": "645" }, "n3IwfId": "ABCD123", "ngRanNodeId": "MacroNGeNB-abc92" } }, "nrLocation": { "tai": { "plmnId": { "mcc": "374", "mnc": "645" }, "tac": "ab01" }, "ncgi": { "plmnId": { "mcc": "374", "mnc": "645" }, "nrCellId": "ABCabc123" }, "ageOfLocationInformation": 1, "ueLocationTimestamp": "2019-03-28T14:30:50Z", "geographicalInformation": "AB12334765498F12", "geodeticInformation": "AB12334765498F12ACBF", "globalGnbId": { "plmnId": { "mcc": "374", "mnc": "645" }, "n3IwfId": "ABCD123", "ngRanNodeId": "MacroNGeNB-abc92" } }, "n3gaLocation": { "n3gppTai": { "plmnId": { "mcc": "374", "mnc": "645" }, "tac": "ab01" }, "n3IwfId": "ABCD123", "ueIpv4Addr": "192.168.0.1", "ueIpv6Addr": "2001:db8:85a3:8d3:1319:8a2e:370:7348", "portNumber": 1 } }, "userLocationTime": "2019-03-28T14:30:50Z", "uetimeZone": "+05:30", "pduSessionInformation": { "networkSlicingInfo": { "sNSSAI": { "sst": 0, "sd": "Aaa123" } }, "pduSessionID": 1, "pduType": "IPV4", "sscMode": "SSC_MODE_1", "hPlmnId": { "mcc": "374", "mnc": "645" }, "servingNodeID": [ { "plmnId": { "mcc": "311", "mnc": "280" }, "amfId": "ABab09", "new-key-6": [ "dummy-body-value-1", "value2", 25 ] } ], "servingNetworkFunctionID": { "servingNetworkFunctionName": "SMF", "servingNetworkFunctionInstanceid": "SMF_Instanceid_1", "gUAMI": { "plmnId": { "mcc": "311", "mnc": "280" }, "amfId": "ABab09" } }, "ratType": "EUTRA", "dnnId": "DN-AAA", "chargingCharacteristics": "AB", "chargingCharacteristicsSelectionMode": "HOME_DEFAULT", "startTime": "2019-03-28T14:30:50Z", "3gppPSDataOffStatus": "ACTIVE", "pduAddress": { "pduIPv4Address": "192.168.0.1", "pduIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348", "pduAddressprefixlength": 0, "IPv4dynamicAddressFlag": true, "IPv6dynamicAddressFlag": false }, "qoSInformation": "test127", "servingCNPlmnId": { "mcc": "311", "mnc": "280" } }, "unitCountInactivityTimer": 125 } }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  codec_client_->close();
}

//------------------------------------------------------------------------
// Test that comparison of a boolean "true" extracted from the request body with
// a constant "true" succeeds
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyBoolEquals) {
  initializeFilter(config_json_pointer_bool_num_null);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/nudm-sdm/v2/shared-data?shared-data-ids=24016-123,24016-456"},
      {":authority", "eric-seppsim-p3-mcc-262-mnc-73:80"},
  };
  std::string body{R"({"emergencyServices":true, "sharedDataId":"68042-XHq0gsd"})"};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));

  // Validate that the condition evaluated correctly
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "bool_pool"));

  // Send fake upstream response, using same body as in request:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(body.length())},
      {"content-type", "application/json"},
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));

  codec_client_->close();
}

// Test that comparison of a boolean "false" extracted from the request body with
// a constant "true" fails
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyBoolNotEquals) {
  initializeFilter(config_json_pointer_bool_num_null);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/nudm-sdm/v2/shared-data?shared-data-ids=24016-123,24016-456"},
      {":authority", "eric-seppsim-p3-mcc-262-mnc-73:80"},
  };
  std::string body{R"({"emergencyServices":false, "sharedDataId":"68042-XHq0gsd"})"};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));

  // Validate that the condition evaluated correctly
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "wrong_pool"));

  // Send fake upstream response, using same body as in request:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(body.length())},
      {"content-type", "application/json"},
  };
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));

  codec_client_->close();
}

// Test that comparison of a number 2 extracted from the request body with
// a constant number 2 succeeds
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyNumEquals) {
  initializeFilter(config_json_pointer_bool_num_null);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/nudm-sdm/v2/shared-data?shared-data-ids=24016-123,24016-456"},
      {":authority", "eric-seppsim-p3-mcc-262-mnc-73:80"},
  };
  std::string body{R"({"sharedDataId":"68042-XHq0gsd", "num": 2})"};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));

  // Validate that the condition evaluated correctly
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "num_pool"));

  // Send fake upstream response, using same body as in request:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(body.length())},
      {"content-type", "application/json"},
  };
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));

  codec_client_->close();
}


// Test that comparison of a number 3 extracted from the request body with
// a constant number 2 fails
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyNumNotEquals) {
  initializeFilter(config_json_pointer_bool_num_null);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/nudm-sdm/v2/shared-data?shared-data-ids=24016-123,24016-456"},
      {":authority", "eric-seppsim-p3-mcc-262-mnc-73:80"},
  };
  std::string body{R"({"sharedDataId":"68042-XHq0gsd", "num": 3})"};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));

  // Validate that the condition evaluated correctly
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "wrong_pool"));

  // Send fake upstream response, using same body as in request:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(body.length())},
      {"content-type", "application/json"},
  };
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));

  codec_client_->close();
}


// Name: TestJsonBodyMod_modify_json_value
// Description: modify_json_value operations are configured to append and prepend strings to values that 
// are placed in different locations of the JSON body. The strings are either constantly defined in the 
// configuration (term_string), extracted from a header (term_header) or taken from a filter data 
// variable (term_var). The operations are defined on request and response paths and a sample request is
// sent. The resulting JSON bodies of request and response are verified to comprise the extended string values.
// Expected Result:
// - String values are properly retrieved from the configuration/header/variables and appended/prepended
//   to the subscriberIdentifier and the nfName string values in the JSON body of the request and response. 
// - The content-length headers in request and response are adapted to the size of the modified body.
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_modify_json_value) {
  initializeFilter(config_body_mod_modify_json_value);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        },
        "modifiers": [
          {
            "type": "prepend",
            "target": "/subscriberIdentifier",
            "prefix": "pref_body_"
          },
          {
            "type": "append",
            "target": "/nfConsumerIdentification/nfName",
            "suffix": "_suff_body"
          },
          {
            "type": "prepend",
            "target": "/subscriberIdentifier",
            "prefix": "pref_body_resp_"
          },
          {
            "type": "append",
            "target": "/nfConsumerIdentification/nfName",
            "suffix": "_suff_body_resp"
          }
        ]
      }
  )"};
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"prefix_header", "pref_hdr_"},
      {"suffix_header", "_suff_hdr"},
      {"content-length", std::to_string(body.length())}
  };

  Json expected_body_req{R"(
      {
        "subscriberIdentifier": "pref_body_pref_hdr_pref_string_imsi-460001357924610_suff_string_suff_hdr",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421_suff_body",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        },
        "modifiers": [
          {
            "type": "prepend",
            "target": "/subscriberIdentifier",
            "prefix": "pref_body_"
          },
          {
            "type": "append",
            "target": "/nfConsumerIdentification/nfName",
            "suffix": "_suff_body"
          },
          {
            "type": "prepend",
            "target": "/subscriberIdentifier",
            "prefix": "pref_body_resp_"
          },
          {
            "type": "append",
            "target": "/nfConsumerIdentification/nfName",
            "suffix": "_suff_body_resp"
          }
        ]
      }
  )"_json};

  Json expected_body_resp{R"(
      {
        "modifiers": [
          {
            "prefix": "pref_body_",
            "target": "/subscriberIdentifier",
            "type": "prepend"
          },
          {
            "suffix": "_suff_body",
            "target": "/nfConsumerIdentification/nfName",
            "type": "append"
          },
          {
            "prefix": "pref_body_resp_",
            "target": "/subscriberIdentifier",
            "type": "prepend"
          },
          {
            "suffix": "_suff_body_resp",
            "target": "/nfConsumerIdentification/nfName",
            "type": "append"
          }
        ],
        "nfConsumerIdentification": {
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfName": "123e-e8b-1d3-a46-421_suff_body_resp",
          "nfPLMNID": {
            "mcc": "311",
            "mnc": 280
          },
          "nodeFunctionality": "SMF"
        },
        "subscriberIdentifier": "pref_body_resp_pref_hdr_resp_pref_string_resp_imsi-460001357924610_suff_string_resp_suff_hdr_resp"
      }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"},
      {"prefix_header_resp", "pref_hdr_resp_"},
      {"suffix_header_resp", "_suff_hdr_resp"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body_req, Json::parse(upstream_request_->body().toString()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body_resp, Json::parse(response->body()));

  codec_client_->close();

}


// Name: TestJsonBodyMod_modify_json_value_neg_test
// Description: Negative cases of the modify_json_value operation are tested by configuring such operations to
// append or prepend strings to certain places in the message, which are not defined or where the json_pointer 
// or the value to be appended/prepended is not defined.
// Expected Result:
// - The JSON body of the request and response messages stay unmodified.
// - The content-length headers in request and response match the size of the unmodified body.
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_modify_json_value_neg_test) {
  initializeFilter(config_body_mod_modify_json_value_negative);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        },
        "modifiers": [
          {
            "type": "prepend",
            "target": "/subscriberIdentifier",
            "prefix": "pref_body_"
          },
          {
            "type": "append",
            "target": "/nfConsumerIdentification/nfName",
            "suffix": "_suff_body"
          },
          {
            "type": "prepend",
            "target": "/subscriberIdentifier",
            "prefix": "pref_body_resp_"
          },
          {
            "type": "append",
            "target": "/nfConsumerIdentification/nfName",
            "suffix": "_suff_body_resp"
          }
        ]
      }
  )"};
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"prefix_header", "pref_hdr_"},
      {"suffix_header", "_suff_hdr"},
      {"content-length", std::to_string(body.length())}
  };

  Json expected_body_req{R"(
      {
        "subscriberIdentifier": "pref_body_pref_hdr_pref_string_imsi-460001357924610_suff_string_suff_hdr",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421_suff_body",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        },
        "modifiers": [
          {
            "type": "prepend",
            "target": "/subscriberIdentifier",
            "prefix": "pref_body_"
          },
          {
            "type": "append",
            "target": "/nfConsumerIdentification/nfName",
            "suffix": "_suff_body"
          },
          {
            "type": "prepend",
            "target": "/subscriberIdentifier",
            "prefix": "pref_body_resp_"
          },
          {
            "type": "append",
            "target": "/nfConsumerIdentification/nfName",
            "suffix": "_suff_body_resp"
          }
        ]
      }
  )"_json};

  Json expected_body_resp{R"(
      {
        "modifiers": [
          {
            "prefix": "pref_body_",
            "target": "/subscriberIdentifier",
            "type": "prepend"
          },
          {
            "suffix": "_suff_body",
            "target": "/nfConsumerIdentification/nfName",
            "type": "append"
          },
          {
            "prefix": "pref_body_resp_",
            "target": "/subscriberIdentifier",
            "type": "prepend"
          },
          {
            "suffix": "_suff_body_resp",
            "target": "/nfConsumerIdentification/nfName",
            "type": "append"
          }
        ],
        "nfConsumerIdentification": {
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfName": "123e-e8b-1d3-a46-421_suff_body_resp",
          "nfPLMNID": {
            "mcc": "311",
            "mnc": 280
          },
          "nodeFunctionality": "SMF"
        },
        "subscriberIdentifier": "pref_body_resp_pref_hdr_resp_pref_string_resp_imsi-460001357924610_suff_string_resp_suff_hdr_resp"
      }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"},
      {"prefix_header_resp", "pref_hdr_resp_"},
      {"suffix_header_resp", "_suff_hdr_resp"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(Json::parse(body), Json::parse(upstream_request_->body().toString()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(Json::parse(body), Json::parse(response->body()));

  codec_client_->close();

}

/* NOT USED --- NULL TYPE NOT SUPPORTET YET
// Test that comparison of a null value extracted from the request body with
// a string constant "" succeeds
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyNullEquals) {
  initializeFilter(config_json_pointer_bool_num_null);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/nudm-sdm/v2/shared-data?shared-data-ids=24016-123,24016-456"},
      {":authority", "eric-seppsim-p3-mcc-262-mnc-73:80"},
  };
  std::string body{R"({"sharedDataId":"68042-XHq0gsd", "nix": null})"};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(headers, body);

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));

  // Validate that the condition evaluated correctly
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "null_pool"));

  // Send fake upstream response, using same body as in request:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(body.length())},
      {"content-type", "application/json"},
  };
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "200"));

  codec_client_->close();
}
*/

// Name: TestJsonBodyMod_search_and_replace
// Description: A search and replace operation is configured to replace the
// certain searched part inside the value of the "subscriberIdentifier"
// attribute in the JSON body of all handled requests.
// A sample request, including an existing "subscriberIdentifier" in the body, is sent.
// Expected Result:
// - The body of the request is modified, i.e. the subscriberIdentifier is 
//   replaced by the configured value. The rest of the body stays the same.
// - The content-length header is adapted to the size of the modified body
TEST_P(EricProxyFilterBodyIntegrationTest, TestJsonBodyMod_search_and_replace) {
  initializeFilter(config_body_mod_json_search_and_replace);
  std::string body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x"},
      {"x-hnrf-uri", "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x"},
      {":authority", "host"},
      {"content-length", std::to_string(body.length())}
  };
  Json expected_body{R"(
      {
        "subscriberIdentifier": "PREFIX-IMSI-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};

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
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection_->close());

  // Verify upstream request and its modified body:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-hnrf-uri", "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // Verify modified body in downstream response
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  codec_client_->close();
}

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
