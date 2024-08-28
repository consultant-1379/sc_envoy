#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "test/integration/utility.h"
#include "include/nlohmann/json.hpp"
#include <cstddef>
#include <ostream>
#include <string>

#include "config_utils/pluggable_configurator.h"
#include "config_utils/endpoint_md_cluster_md_configurator.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterSeppThFqdnScramblingTest : public PluggableConfigurator {
public:
  EricProxyFilterSeppThFqdnScramblingTest() = default;

  //------------------------------------------------------------------------
  // Configuration to test TH FQDN mapping/scrambling for int to ext traffic
  const std::string config_int_to_ext{R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.5gc.mnc123.mcc456.3gppnetwork.org
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  key_value_tables:
  - name: map_table
    entries:
    - key: nrf1.5gc.mnc123.mcc456.3gppnetwork.org
      value: fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org
    - key: nrf2.5gc.mnc123.mcc456.3gppnetwork.org
      value: fakenrf2.5gc.mnc123.mcc456.3gppnetwork.org
  - name: demap_table
    entries:
    - key: fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org
      value: nrf1.5gc.mnc123.mcc456.3gppnetwork.org
    - key: fakenrf2.5gc.mnc123.mcc456.3gppnetwork.org
      value: nrf2.5gc.mnc123.mcc456.3gppnetwork.org
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
    topology_hiding:
      service_profile:
        topology_hiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: REQUEST
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                term_boolean: true
              actions:
              - action_modify_query_param:
                  key_name: hnrf-uri
                  use_string_modifiers:
                    string_modifiers:
                    - table_lookup:
                        lookup_table_name: map_table
                        do_nothing: true
              - action_modify_header:
                  name: callback-uri
                  use_string_modifiers:
                    string_modifiers:
                    - table_lookup:
                        lookup_table_name: map_table
                        fc_unsuccessful_operation: fc_failover_1
        topology_unhiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: RESPONSE
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_respheader: :status
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: '200'
              actions:
              - action_modify_header:
                  name: location
                  use_string_modifiers:
                    string_modifiers:
                    - table_lookup:
                        lookup_table_name: demap_table
                        do_nothing: true
              - action_modify_json_body:
                  name: "topology_unhiding_response_body"
                  json_operation:
                    modify_json_value:
                      json_pointer:
                        term_string: "/nfInstances/*/nfServices/*/callbackUri"
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc_failover_1
                      enable_exception_handling: true
        unsuccessful_operation_filter_cases:
        - name: fc_failover_1
          filter_rules:
          - name: fr_failover_1
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-failover-1
                value:
                  term_string: x-failover-1-val
  - name: rp_2
    pool_name: sepp_pool_2
    topology_hiding:
      encryption_profiles:
      - encryption_identifier: AA101
        scrambling_key: 12345678abcdefgh12345678abcdefgh
        initial_vector: abcdef123456
      - encryption_identifier: AB101
        scrambling_key: abcdefgh12345678abcdefgh12345678
        initial_vector: abcdef123456
      active_encryption_identifier: AB101
      service_profile:
        topology_hiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: REQUEST
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                term_boolean: true
              actions:
              - action_modify_query_param:
                  key_name: hnrf-uri
                  use_string_modifiers:
                    string_modifiers:
                    - scrambling_profile:
                        do_nothing: true
              - action_modify_header:
                  name: callback-uri
                  use_string_modifiers:
                    string_modifiers:
                    - scrambling_profile:
                        fc_unsuccessful_operation: fc_failover_1
        topology_unhiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: RESPONSE
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_respheader: :status
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: '200'
              actions:
              - action_modify_header:
                  name: location
                  use_string_modifiers:
                    string_modifiers:
                    - scrambling_profile:
                        do_nothing: true
              - action_modify_json_body:
                  name: "topology_unhiding_response_body"
                  json_operation:
                    modify_json_value:
                      json_pointer:
                        term_string: "/nfInstances/*/nfServices/*/callbackUri"
                      string_modifiers:
                      - scrambling_profile:
                          fc_unsuccessful_operation: fc_failover_1
                      enable_exception_handling: true
        unsuccessful_operation_filter_cases:
        - name: fc_failover_1
          filter_rules:
          - name: fr_failover_1
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-failover-1
                value:
                  term_string: x-failover-1-val
)EOF"};

  //------------------------------------------------------------------------
  // Configuration to test TH FQDN mapping/scrambling for ext to int traffic
  const std::string config_ext_to_int{R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.5gc.mnc123.mcc456.3gppnetwork.org
  own_external_port: 443
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
  - name: map_table
    entries:
    - key: nrf1.5gc.mnc123.mcc456.3gppnetwork.org
      value: fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org
    - key: nrf2.5gc.mnc123.mcc456.3gppnetwork.org
      value: fakenrf2.5gc.mnc123.mcc456.3gppnetwork.org
  - name: demap_table
    entries:
    - key: fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org
      value: nrf1.5gc.mnc123.mcc456.3gppnetwork.org
    - key: fakenrf2.5gc.mnc123.mcc456.3gppnetwork.org
      value: nrf2.5gc.mnc123.mcc456.3gppnetwork.org
  filter_cases:
  - name: default_routing
    filter_rules:
    - name: nrf_pool
      condition:
        op_and:
          arg1:
            op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
          arg2:
            op_or:
              arg1:
                op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-Sbi-target-apiRoot'},
                            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80'}}                 
              arg2:
                op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-Sbi-target-apiRoot'},
                            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80'}}
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
    topology_hiding:
      service_profile:
        topology_unhiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: REQUEST
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                term_boolean: true
              actions:
              - action_modify_header:
                  name: 3gpp-Sbi-target-apiRoot
                  use_string_modifiers:
                    string_modifiers:
                    - table_lookup:
                        lookup_table_name: demap_table
                        do_nothing: true
        topology_hiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: RESPONSE
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_respheader: :status
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: '200'
              actions:
              - action_modify_header:
                  name: x-response-origin
                  use_string_modifiers:
                    string_modifiers:
                    - table_lookup:
                        lookup_table_name: map_table
                        do_nothing: true
        unsuccessful_operation_filter_cases:
        - name: fc_failover_1
          filter_rules:
          - name: fr_failover_1
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-failover-1
                value:
                  term_string: x-failover-1-val
  - name: rp_2
    pool_name: sepp_pool_2
    topology_hiding:
      encryption_profiles:
      - encryption_identifier: AA101
        scrambling_key: 12345678abcdefgh12345678abcdefgh
        initial_vector: abcdef123456
      - encryption_identifier: AB101
        scrambling_key: abcdefgh12345678abcdefgh12345678
        initial_vector: abcdef123456
      active_encryption_identifier: AB101
      service_profile:
        topology_unhiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: REQUEST
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                term_boolean: true
              actions:
              - action_modify_header:
                  name: 3gpp-Sbi-target-apiRoot
                  use_string_modifiers:
                    string_modifiers:
                    - scrambling_profile:
                        do_nothing: true
        topology_hiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: RESPONSE
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_respheader: :status
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: '200'
              actions:
              - action_modify_header:
                  name: x-response-origin
                  use_string_modifiers:
                    string_modifiers:
                    - scrambling_profile:
                        do_nothing: true
        unsuccessful_operation_filter_cases:
        - name: fc_failover_1
          filter_rules:
          - name: fr_failover_1
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-failover-1
                value:
                  term_string: x-failover-1-val
)EOF"};

  //------------------------------------------------------------------------
  // Configuration to test TH FQDN mapping/scrambling for ext to int traffic
  const std::string config_ext_to_int_differentRoamingPartnerNames{R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.5gc.mnc123.mcc456.3gppnetwork.org
  own_external_port: 443
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
  - name: map_table
    entries:
    - key: nrf1.5gc.mnc123.mcc456.3gppnetwork.org
      value: fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org
    - key: nrf2.5gc.mnc123.mcc456.3gppnetwork.org
      value: fakenrf2.5gc.mnc123.mcc456.3gppnetwork.org
  - name: demap_table
    entries:
    - key: fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org
      value: nrf1.5gc.mnc123.mcc456.3gppnetwork.org
    - key: fakenrf2.5gc.mnc123.mcc456.3gppnetwork.org
      value: nrf2.5gc.mnc123.mcc456.3gppnetwork.org
  filter_cases:
  - name: default_routing
    filter_rules:
    - name: nrf_pool
      condition:
        op_and:
          arg1:
            op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
          arg2:
            op_or:
              arg1:
                op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-Sbi-target-apiRoot'},
                            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80'}}                 
              arg2:
                op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-Sbi-target-apiRoot'},
                            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80'}}
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
    topology_hiding:
      service_profile:
        topology_unhiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: REQUEST
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                term_boolean: true
              actions:
              - action_modify_header:
                  name: 3gpp-Sbi-target-apiRoot
                  use_string_modifiers:
                    string_modifiers:
                    - table_lookup:
                        lookup_table_name: demap_table
                        do_nothing: true
        topology_hiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: RESPONSE
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_respheader: :status
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: '200'
              actions:
              - action_modify_header:
                  name: x-response-origin
                  use_string_modifiers:
                    string_modifiers:
                    - table_lookup:
                        lookup_table_name: map_table
                        do_nothing: true
        unsuccessful_operation_filter_cases:
        - name: fc_failover_1
          filter_rules:
          - name: fr_failover_1
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-failover-1
                value:
                  term_string: x-failover-1-val
  - name: rp_2
    pool_name: sepp_pool_2
    topology_hiding:
      encryption_profiles:
      - encryption_identifier: AA101
        scrambling_key: 12345678abcdefgh12345678abcdefgh
        initial_vector: abcdef123456
      - encryption_identifier: AB101
        scrambling_key: abcdefgh12345678abcdefgh12345678
        initial_vector: abcdef123456
      active_encryption_identifier: AB101
      service_profile:
        topology_unhiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: REQUEST
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                term_boolean: true
              actions:
              - action_modify_header:
                  name: 3gpp-Sbi-target-apiRoot
                  use_string_modifiers:
                    string_modifiers:
                    - scrambling_profile:
                        do_nothing: true
        topology_hiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: RESPONSE
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_respheader: :status
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: '200'
              actions:
              - action_modify_header:
                  name: x-response-origin
                  use_string_modifiers:
                    string_modifiers:
                    - scrambling_profile:
                        do_nothing: true
        unsuccessful_operation_filter_cases:
        - name: fc_failover_1
          filter_rules:
          - name: fr_failover_1
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-failover-1
                value:
                  term_string: x-failover-1-val
)EOF"};

  // Configuration to test TH FQDN mapping/scrambling for int to ext traffic
  // with multiple matching service cases
  const std::string config_int_to_ext_multiple_sc{R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.5gc.mnc123.mcc456.3gppnetwork.org
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  key_value_tables:
  - name: map_table
    entries:
    - key: nrf1.5gc.mnc123.mcc456.3gppnetwork.org
      value: fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org
    - key: nrf2.5gc.mnc123.mcc456.3gppnetwork.org
      value: fakenrf2.5gc.mnc123.mcc456.3gppnetwork.org
  - name: demap_table
    entries:
    - key: fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org
      value: nrf1.5gc.mnc123.mcc456.3gppnetwork.org
    - key: fakenrf2.5gc.mnc123.mcc456.3gppnetwork.org
      value: nrf2.5gc.mnc123.mcc456.3gppnetwork.org
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
    topology_hiding:
      service_profile:
        topology_hiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: REQUEST
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                term_boolean: true
              actions:
              - action_modify_query_param:
                  key_name: hnrf-uri
                  use_string_modifiers:
                    string_modifiers:
                    - table_lookup:
                        lookup_table_name: map_table
                        do_nothing: true
        - service_case_name: sc_2
          service_type:
            api_name: Nnrf_NFManagement_NFStatusNotify
            api_version: v1
            direction: REQUEST
            is_notification: true
            http_method: POST
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                term_boolean: true
              actions:
              - action_modify_query_param:
                  key_name: hnrf-uri
                  use_string_modifiers:
                    string_modifiers:
                    - table_lookup:
                        lookup_table_name: map_table
                        do_nothing: true
        - service_case_name: sc_3
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: REQUEST
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                term_boolean: true
              actions:
              - action_modify_header:
                  name: callback-uri
                  use_string_modifiers:
                    string_modifiers:
                    - table_lookup:
                        lookup_table_name: map_table
                        fc_unsuccessful_operation: fc_failover_1
        topology_unhiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: RESPONSE
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_respheader: :status
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: '200'
              actions:
              - action_modify_json_body:
                  name: "topology_unhiding_response_body"
                  json_operation:
                    modify_json_value:
                      json_pointer:
                        term_string: "/nfInstances/*/nfServices/*/callbackUri"
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc_failover_1
                      enable_exception_handling: true
        - service_case_name: sc_2
          service_type:
            api_name: Nnrf_NFManagement_NFStatusNotify
            api_version: v1
            direction: REQUEST
            is_notification: true
            http_method: POST
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_respheader: :status
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: '200'
              actions:
              - action_modify_json_body:
                  name: "topology_unhiding_response_body"
                  json_operation:
                    modify_json_value:
                      json_pointer:
                        term_string: "/nfInstances/*/nfServices/*/callbackUri"
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc_failover_1
                      enable_exception_handling: true
        - service_case_name: sc_3
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: RESPONSE
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_respheader: :status
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: '200'
              actions:
              - action_modify_header:
                  name: location
                  use_string_modifiers:
                    string_modifiers:
                    - table_lookup:
                        lookup_table_name: demap_table
                        do_nothing: true
        unsuccessful_operation_filter_cases:
        - name: fc_failover_1
          filter_rules:
          - name: fr_failover_1
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-failover-1
                value:
                  term_string: x-failover-1-val
  - name: rp_2
    pool_name: sepp_pool_2
    topology_hiding:
      encryption_profiles:
      - encryption_identifier: AA101
        scrambling_key: 12345678abcdefgh12345678abcdefgh
        initial_vector: abcdef123456
      - encryption_identifier: AB101
        scrambling_key: abcdefgh12345678abcdefgh12345678
        initial_vector: abcdef123456
      active_encryption_identifier: AB101
      service_profile:
        topology_hiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: REQUEST
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                term_boolean: true
              actions:
              - action_modify_query_param:
                  key_name: hnrf-uri
                  use_string_modifiers:
                    string_modifiers:
                    - scrambling_profile:
                        do_nothing: true
        - service_case_name: sc_2
          service_type:
            api_name: Nnrf_NFManagement_NFStatusNotify
            api_version: v1
            direction: REQUEST
            is_notification: true
            http_method: POST
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                term_boolean: true
              actions:
              - action_modify_query_param:
                  key_name: hnrf-uri
                  use_string_modifiers:
                    string_modifiers:
                    - scrambling_profile:
                        do_nothing: true
        - service_case_name: sc_3
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: REQUEST
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                term_boolean: true
              actions:
              - action_modify_header:
                  name: callback-uri
                  use_string_modifiers:
                    string_modifiers:
                    - scrambling_profile:
                        fc_unsuccessful_operation: fc_failover_1
        topology_unhiding_service_cases:
        - service_case_name: sc_1
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: RESPONSE
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_respheader: :status
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: '200'
              actions:
              - action_modify_json_body:
                  name: "topology_unhiding_response_body"
                  json_operation:
                    modify_json_value:
                      json_pointer:
                        term_string: "/nfInstances/*/nfServices/*/callbackUri"
                      string_modifiers:
                      - scrambling_profile:
                          fc_unsuccessful_operation: fc_failover_1
                      enable_exception_handling: true
        - service_case_name: sc_2
          service_type:
            api_name: Nnrf_NFManagement_NFStatusNotify
            api_version: v1
            direction: REQUEST
            is_notification: true
            http_method: POST
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_respheader: :status
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: '200'
              actions:
              - action_modify_json_body:
                  name: "topology_unhiding_response_body"
                  json_operation:
                    modify_json_value:
                      json_pointer:
                        term_string: "/nfInstances/*/nfServices/*/callbackUri"
                      string_modifiers:
                      - scrambling_profile:
                          fc_unsuccessful_operation: fc_failover_1
                      enable_exception_handling: true
        - service_case_name: sc_3
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: RESPONSE
            http_method: GET
          filter_case:
            name: fc_1
            filter_rules:
            - name: fr_1
              condition: 
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_respheader: :status
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: '200'
              actions:
              - action_modify_header:
                  name: location
                  use_string_modifiers:
                    string_modifiers:
                    - scrambling_profile:
                        do_nothing: true
        unsuccessful_operation_filter_cases:
        - name: fc_failover_1
          filter_rules:
          - name: fr_failover_1
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-failover-1
                value:
                  term_string: x-failover-1-val
)EOF"};

 //------------------------------------------------------------------------
  // Configuration to test SCDS-1738: unscrambling of multipart JSON body fails
  // TH FQDN un-scrambling for ext to int traffic
  const std::string config_ext_to_int_scds_1738{R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.5gc.mnc123.mcc456.3gppnetwork.org
  own_external_port: 443
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
  - name: map_table
    entries:
    - key: nrf1.5gc.mnc123.mcc456.3gppnetwork.org
      value: fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org
    - key: nrf2.5gc.mnc123.mcc456.3gppnetwork.org
      value: fakenrf2.5gc.mnc123.mcc456.3gppnetwork.org
  - name: demap_table
    entries:
    - key: fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org
      value: nrf1.5gc.mnc123.mcc456.3gppnetwork.org
    - key: fakenrf2.5gc.mnc123.mcc456.3gppnetwork.org
      value: nrf2.5gc.mnc123.mcc456.3gppnetwork.org
  filter_cases:
  - name: default_routing
    filter_rules:
    - name: nrf_pool
      condition:
        op_and:
          arg1:
            op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
          arg2:
            op_or:
              arg1:
                op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-Sbi-target-apiRoot'},
                            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80'}}
              arg2:
                op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-Sbi-target-apiRoot'},
                            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80'}}
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
    topology_hiding:
      service_profile:
        topology_unhiding_service_cases:
        - service_case_name: sc_1uh
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: REQUEST
            http_method: GET
          filter_case:
            name: fc_1uh
            filter_rules:
            - name: fr_1uh
              condition:
                term_boolean: true
              actions:
              - action_modify_header:
                  name: 3gpp-Sbi-target-apiRoot
                  use_string_modifiers:
                    string_modifiers:
                    - table_lookup:
                        lookup_table_name: demap_table
                        do_nothing: true
              - action_modify_json_body:
                  name: "topology_unhiding_response_body"
                  json_operation:
                    modify_json_value:
                      json_pointer:
                        term_string: "/nfInstances/*/nfServices/*/callbackUri"
                      string_modifiers:
                      - scrambling_profile:
                          fc_unsuccessful_operation: fc_failover_1
                      enable_exception_handling: true
        topology_hiding_service_cases:
        - service_case_name: sc_1h
          service_type:
            api_name: nnrf-disc
            api_version: v1h
            direction: RESPONSE
            http_method: GET
          filter_case:
            name: fc_1h
            filter_rules:
            - name: fr_1h
              condition:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_respheader: :status
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: '200'
              actions:
              - action_modify_header:
                  name: x-response-origin
                  use_string_modifiers:
                    string_modifiers:
                    - table_lookup:
                        lookup_table_name: map_table
                        do_nothing: true
        unsuccessful_operation_filter_cases:
        - name: fc_failover_1
          filter_rules:
          - name: fr_failover_1
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-failover-1
                value:
                  term_string: x-failover-1-val
  - name: rp_2
    pool_name: sepp_pool_2
    topology_hiding:
      encryption_profiles:
      - encryption_identifier: AA101
        scrambling_key: 12345678abcdefgh12345678abcdefgh
        initial_vector: abcdef123456
      - encryption_identifier: AB101
        scrambling_key: abcdefgh12345678abcdefgh12345678
        initial_vector: abcdef123456
      active_encryption_identifier: AB101
      service_profile:
        topology_unhiding_service_cases:
        - service_case_name: sc_1uh
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: REQUEST
            http_method: GET
          filter_case:
            name: fc_1uh
            filter_rules:
            - name: fr_1uh
              condition:
                term_boolean: true
              actions:
              - action_modify_header:
                  name: 3gpp-Sbi-target-apiRoot
                  use_string_modifiers:
                    string_modifiers:
                    - scrambling_profile:
                        do_nothing: true
              - action_modify_json_body:
                  name: "topology_unhiding_response_body"
                  json_operation:
                    modify_json_value:
                      json_pointer:
                        term_string: "/nfInstances/*/nfServices/*/callbackUri"
                      string_modifiers:
                      - scrambling_profile:
                          fc_unsuccessful_operation: fc_failover_1
                      enable_exception_handling: true
        topology_hiding_service_cases:
        - service_case_name: sc_1h
          service_type:
            api_name: nnrf-disc
            api_version: v1
            direction: RESPONSE
            http_method: GET
          filter_case:
            name: fc_1h
            filter_rules:
            - name: fr_1h
              condition:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_respheader: :status
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: '200'
              actions:
              - action_modify_header:
                  name: x-response-origin
                  use_string_modifiers:
                    string_modifiers:
                    - scrambling_profile:
                        do_nothing: true
        unsuccessful_operation_filter_cases:
        - name: fc_failover_1
          filter_rules:
          - name: fr_failover_1
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-failover-1
                value:
                  term_string: x-failover-1-val
)EOF"};

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
  - header: x-eric-sepp-test-rp-name
    on_header_present:
      metadata_namespace: eric.proxy.test
      key: test_rp_name
      type: STRING
)EOF"};

  //------------------------------------------------------------------------
  // NF Discovery response body (NF Instances)
  // (SearchResult -> nfInstances)
  const std::string nf_disc_resp_body{R"(
{
  "validityPeriod": 60,
  "nfInstances": [
    {
      "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
      "nfInstanceName": "nfInstanceName_1",
      "nfType": "SMF",
      "fqdn": "fqdn1.5gc.mnc123.mcc456.3gppnetwork.org",
      "nfServices": [
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce100",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "fqdn11.5gc.mnc123.mcc456.3gppnetwork.org",
          "callbackUri": "http://cbfqdn11.5gc.mnc123.mcc456.3gppnetwork.org:80",
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9091
            }
          ]
        }
      ]
    },
    {
      "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce101",
      "nfInstanceName": "nfInstanceName_2",
      "nfType": "SMF",
      "fqdn": "fqdn2.5gc.mnc123.mcc456.3gppnetwork.org",
      "nfServices": [
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce102",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "fqdn21.5gc.mnc123.mcc456.3gppnetwork.org",
          "callbackUri": "http://cbfqdn21.5gc.mnc123.mcc456.3gppnetwork.org:80",
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9093
            }
          ]
        },
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce103",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "fqdn22.5gc.mnc123.mcc456.3gppnetwork.org",
          "callbackUri": "http://cbfqdn22.5gc.mnc123.mcc456.3gppnetwork.org:80",
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9094
            }
          ]
        }
      ]
    }
  ],
  "searchId": null,
  "numNfInstComplete": null,
  "preferredSearch": null,
  "nrfSupportedFeatures": "nsmf-auth"
}
)"};

  // Test parameters for all tests below, to factor them out
  // so that we can use them for multipart-body tests as well
  // as for the classic single-body tests.
  struct TestParameters {
    EndpointMetadataClusterConfigurator cluster_config;
    std::vector<std::string> filter_configs;
    Http::TestRequestHeaderMapImpl request_headers;
    Http::TestResponseHeaderMapImpl response_headers;
    std::string request_body;
    Json response_json_body;
    std::string response_body;
    uint32_t expected_upstream_index;
    std::map<std::string, std::string> expected_request_headers;
    std::map<std::string, std::string> expected_response_headers;
    std::map<std::string, std::string> expected_query_params;
    Json expected_request_body;
    Json expected_response_json_body;
    Json expected_response_body;
    std::map<std::string, uint32_t> expected_counters;
  };

  void testThServiceProfile(TestParameters tp) {

    initConfig(tp.filter_configs, tp.cluster_config);

    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response;

    if (!tp.request_body.empty()) {
      tp.request_headers.addCopy(Http::LowerCaseString("content-length"),
                              std::to_string(tp.request_body.length()));
      tp.request_headers.addCopy(Http::LowerCaseString("content-type"), "application/json");
      response = codec_client_->makeRequestWithBody(tp.request_headers, tp.request_body);
    } else {
      response = codec_client_->makeHeaderOnlyRequest(tp.request_headers);
    }

    waitForNextUpstreamRequest(tp.expected_upstream_index);

    // Send response
    if (!tp.response_body.empty()) {
      tp.response_headers.addCopy(Http::LowerCaseString("content-length"),
                               std::to_string(tp.response_body.length()));
      tp.response_headers.addCopy(Http::LowerCaseString("content-type"), "application/json");
      upstream_request_->encodeHeaders(tp.response_headers, false);
      Buffer::OwnedImpl response_data(tp.response_body);
      upstream_request_->encodeData(response_data, true);
    } else {
      upstream_request_->encodeHeaders(tp.response_headers, true);
    }

    ASSERT_TRUE(response->waitForEndStream());

    for (std::map<std::string, std::string>::const_iterator itr = tp.expected_request_headers.begin();
         itr != tp.expected_request_headers.end(); ++itr) {
      EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(itr->first, itr->second));
    }

    if (!tp.expected_query_params.empty()) {
      const auto request_query_params = Http::Utility::QueryParamsMulti::parseQueryString(
          upstream_request_->headers()
              .get(Http::LowerCaseString(":path"))[0]
              ->value()
              .getStringView());
      for (const auto& expected_query_param : tp.expected_query_params) {
        const auto query_param = request_query_params.getFirstValue(expected_query_param.first);
        if (query_param.has_value()) {
          EXPECT_EQ(expected_query_param.second, query_param.value());
        }
      }
    }

    if (!tp.expected_request_body.empty()) {
      EXPECT_EQ(tp.expected_request_body, Json::parse(upstream_request_->body().toString()));
    }

    for (std::map<std::string, std::string>::const_iterator itr = tp.expected_response_headers.begin();
         itr != tp.expected_response_headers.end(); ++itr) {
      EXPECT_THAT(response->headers(), Http::HeaderValueOf(itr->first, itr->second));
    }

    if (!tp.expected_response_body.empty()) {
      EXPECT_EQ(tp.expected_response_body, Json::parse(response->body()));
    }

    ENVOY_LOG(trace, printCounters(test_server_, "http.ingress.n8e.g3p.topology_hiding"));

    for (const auto& counter : tp.expected_counters) {
      EXPECT_EQ(counter.second, test_server_->counter(counter.first)->value());
    }

    codec_client_->close();
  }

  void testThServiceProfileMP(TestParameters tp) {

    initConfig(tp.filter_configs, tp.cluster_config);

    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response;

    const std::string content_type{"MULTIpart/ReLaTeD; bOUndAry=Boundary"};
    const std::string body_prefix{"This is the preamble"
                                  "\r\n--Boundary\r\nContent-type: application/json\r\n\r\n"};
    std::string body_suffix("\r\n--Boundary\r\nContent-type: text/plain\r\n\r\nThis is a text/binary ");
    body_suffix.push_back('\0');  // necessary because otherwise the \0 terminates the string
    body_suffix.append("\002body part\r\n--Boundary--\r\n..and an epilogue");

    if (!tp.request_body.empty()) {
      std::string multipart_body = absl::StrCat(body_prefix, tp.request_body, body_suffix);
      tp.request_headers.addCopy(Http::LowerCaseString("content-length"),
                              std::to_string(multipart_body.length()));
      tp.request_headers.addCopy(Http::LowerCaseString("content-type"), content_type);
      response = codec_client_->makeRequestWithBody(tp.request_headers, multipart_body);
    } else {
      // No body -> no multipart body
      response = codec_client_->makeHeaderOnlyRequest(tp.request_headers);
    }

    waitForNextUpstreamRequest(tp.expected_upstream_index);

    // Send response
    if (!tp.response_body.empty()) {
      std::string multipart_body = absl::StrCat(body_prefix, tp.response_body, body_suffix);
      tp.response_headers.addCopy(Http::LowerCaseString("content-length"),
                               std::to_string(multipart_body.length()));
      tp.response_headers.addCopy(Http::LowerCaseString("content-type"), content_type);
      upstream_request_->encodeHeaders(tp.response_headers, false);
      Buffer::OwnedImpl response_data(multipart_body);
      upstream_request_->encodeData(response_data, true);
    } else {
      // No body -> no multipart
      upstream_request_->encodeHeaders(tp.response_headers, true);
    }

    ASSERT_TRUE(response->waitForEndStream());

    for (std::map<std::string, std::string>::const_iterator itr = tp.expected_request_headers.begin();
         itr != tp.expected_request_headers.end(); ++itr) {
      EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(itr->first, itr->second));
    }

    if (!tp.expected_query_params.empty()) {
      const auto request_query_params = Http::Utility::QueryParamsMulti::parseQueryString(
          upstream_request_->headers()
              .get(Http::LowerCaseString(":path"))[0]
              ->value()
              .getStringView());
      for (const auto& expected_query_param : tp.expected_query_params) {
        const auto query_param = request_query_params.getFirstValue(expected_query_param.first);
        if (query_param.has_value()) {
          EXPECT_EQ(expected_query_param.second, query_param.value());
        }
      }
    }

    if (!tp.expected_request_body.empty()) {
      Body req_body(&(upstream_request_->body()), content_type);
      EXPECT_EQ(tp.expected_request_body, *(req_body.getBodyAsJson()));
    }

    for (std::map<std::string, std::string>::const_iterator itr = tp.expected_response_headers.begin();
         itr != tp.expected_response_headers.end(); ++itr) {
      EXPECT_THAT(response->headers(), Http::HeaderValueOf(itr->first, itr->second));
    }

    if (!tp.expected_response_body.empty()) {
      Body resp_body;
      resp_body.setBodyFromString(response->body(), content_type);
      EXPECT_EQ(tp.expected_response_body, *(resp_body.getBodyAsJson()));
    }

    ENVOY_LOG(trace, printCounters(test_server_, "http.ingress.n8e.g3p.topology_hiding"));

    for (const auto& counter : tp.expected_counters) {
      EXPECT_EQ(counter.second, test_server_->counter(counter.first)->value());
    }

    codec_client_->close();
  }

  void testThServiceProfileMPSCDS1738(TestParameters tp) {

    initConfig(tp.filter_configs, tp.cluster_config);

    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response;

    const std::string content_type{"multipart/related; boundary=MultipartDataListBoundary"};

    std::string multipart_body = "\x2d\x2d\x4d\x75\x6c\x74\x69\x70\x61\x72\x74\x44\x61\x74\x61\x4c" \
"\x69\x73\x74\x42\x6f\x75\x6e\x64\x61\x72\x79\x0d\x0a\x43\x6f\x6e" \
"\x74\x65\x6e\x74\x2d\x54\x79\x70\x65\x3a\x20\x61\x70\x70\x6c\x69" \
"\x63\x61\x74\x69\x6f\x6e\x2f\x6a\x73\x6f\x6e\x0d\x0a\x43\x6f\x6e" \
"\x74\x65\x6e\x74\x2d\x49\x44\x3a\x20\x6a\x73\x6f\x6e\x0d\x0a\x43" \
"\x6f\x6e\x74\x65\x6e\x74\x2d\x54\x72\x61\x6e\x73\x66\x65\x72\x2d" \
"\x45\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20\x73\x74\x72\x69\x6e\x67" \
"\x0d\x0a\x0d\x0a\x7b\x22\x73\x75\x70\x69\x22\x3a\x22\x69\x6d\x73" \
"\x69\x2d\x32\x36\x32\x38\x30\x30\x30\x30\x30\x30\x30\x32\x31\x34" \
"\x37\x22\x2c\x22\x70\x65\x69\x22\x3a\x22\x69\x6d\x65\x69\x73\x76" \
"\x2d\x31\x32\x33\x34\x30\x30\x30\x30\x30\x30\x32\x31\x34\x37\x30" \
"\x31\x22\x2c\x22\x70\x64\x75\x53\x65\x73\x73\x69\x6f\x6e\x49\x64" \
"\x22\x3a\x35\x2c\x22\x64\x6e\x6e\x22\x3a\x22\x69\x6e\x74\x65\x72" \
"\x6e\x65\x74\x2e\x73\x6d\x66\x33\x31\x38\x2e\x6d\x6e\x63\x30\x38" \
"\x30\x2e\x6d\x63\x63\x32\x36\x32\x2e\x67\x70\x72\x73\x22\x2c\x22" \
"\x73\x4e\x73\x73\x61\x69\x22\x3a\x7b\x22\x73\x73\x74\x22\x3a\x31" \
"\x7d\x2c\x22\x76\x73\x6d\x66\x49\x64\x22\x3a\x22\x30\x35\x33\x63" \
"\x39\x63\x62\x66\x2d\x61\x63\x32\x39\x2d\x34\x62\x63\x66\x2d\x39" \
"\x66\x35\x31\x2d\x36\x39\x36\x32\x64\x64\x39\x36\x36\x61\x65\x63" \
"\x22\x2c\x22\x73\x65\x72\x76\x69\x6e\x67\x4e\x65\x74\x77\x6f\x72" \
"\x6b\x22\x3a\x7b\x22\x6d\x63\x63\x22\x3a\x22\x37\x32\x34\x22\x2c" \
"\x22\x6d\x6e\x63\x22\x3a\x22\x38\x30\x22\x7d\x2c\x22\x72\x65\x71" \
"\x75\x65\x73\x74\x54\x79\x70\x65\x22\x3a\x22\x49\x4e\x49\x54\x49" \
"\x41\x4c\x5f\x52\x45\x51\x55\x45\x53\x54\x22\x2c\x22\x76\x73\x6d" \
"\x66\x50\x64\x75\x53\x65\x73\x73\x69\x6f\x6e\x55\x72\x69\x22\x3a" \
"\x22\x68\x74\x74\x70\x3a\x2f\x2f\x73\x6d\x66\x33\x30\x32\x2d\x6e" \
"\x6f\x74\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x2e\x35\x67\x63\x2e" \
"\x6d\x6e\x63\x30\x38\x30\x2e\x6d\x63\x63\x37\x32\x34\x2e\x33\x67" \
"\x70\x70\x6e\x65\x74\x77\x6f\x72\x6b\x2e\x6f\x72\x67\x3a\x33\x30" \
"\x33\x30\x2f\x6e\x6f\x74\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x73" \
"\x2f\x76\x73\x6d\x66\x2f\x6e\x73\x6d\x66\x2d\x70\x64\x75\x73\x65" \
"\x73\x73\x69\x6f\x6e\x2f\x76\x31\x2f\x72\x65\x66\x65\x72\x65\x6e" \
"\x63\x65\x69\x64\x2f\x35\x37\x39\x33\x33\x38\x33\x35\x32\x22\x2c" \
"\x22\x76\x63\x6e\x54\x75\x6e\x6e\x65\x6c\x49\x6e\x66\x6f\x22\x3a" \
"\x7b\x22\x69\x70\x76\x34\x41\x64\x64\x72\x22\x3a\x22\x31\x30\x2e" \
"\x34\x33\x2e\x32\x30\x32\x2e\x32\x31\x38\x22\x2c\x22\x67\x74\x70" \
"\x54\x65\x69\x64\x22\x3a\x22\x37\x42\x43\x34\x30\x30\x32\x31\x22" \
"\x7d\x2c\x22\x61\x6e\x54\x79\x70\x65\x22\x3a\x22\x33\x47\x50\x50" \
"\x5f\x41\x43\x43\x45\x53\x53\x22\x2c\x22\x72\x61\x74\x54\x79\x70" \
"\x65\x22\x3a\x22\x4e\x52\x22\x2c\x22\x75\x65\x4c\x6f\x63\x61\x74" \
"\x69\x6f\x6e\x22\x3a\x7b\x22\x6e\x72\x4c\x6f\x63\x61\x74\x69\x6f" \
"\x6e\x22\x3a\x7b\x22\x74\x61\x69\x22\x3a\x7b\x22\x70\x6c\x6d\x6e" \
"\x49\x64\x22\x3a\x7b\x22\x6d\x63\x63\x22\x3a\x22\x37\x32\x34\x22" \
"\x2c\x22\x6d\x6e\x63\x22\x3a\x22\x38\x30\x22\x7d\x2c\x22\x74\x61" \
"\x63\x22\x3a\x22\x30\x30\x34\x32\x38\x65\x22\x7d\x2c\x22\x6e\x63" \
"\x67\x69\x22\x3a\x7b\x22\x70\x6c\x6d\x6e\x49\x64\x22\x3a\x7b\x22" \
"\x6d\x63\x63\x22\x3a\x22\x37\x32\x34\x22\x2c\x22\x6d\x6e\x63\x22" \
"\x3a\x22\x38\x30\x22\x7d\x2c\x22\x6e\x72\x43\x65\x6c\x6c\x49\x64" \
"\x22\x3a\x22\x30\x30\x39\x37\x35\x30\x30\x30\x30\x22\x7d\x2c\x22" \
"\x75\x65\x4c\x6f\x63\x61\x74\x69\x6f\x6e\x54\x69\x6d\x65\x73\x74" \
"\x61\x6d\x70\x22\x3a\x22\x32\x30\x32\x34\x2d\x30\x35\x2d\x32\x30" \
"\x54\x30\x35\x3a\x30\x31\x3a\x32\x38\x5a\x22\x7d\x7d\x2c\x22\x75" \
"\x65\x54\x69\x6d\x65\x5a\x6f\x6e\x65\x22\x3a\x22\x2b\x30\x32\x3a" \
"\x30\x30\x2b\x31\x22\x2c\x22\x67\x70\x73\x69\x22\x3a\x22\x6d\x73" \
"\x69\x73\x64\x6e\x2d\x34\x39\x31\x36\x35\x30\x30\x30\x30\x30\x32" \
"\x31\x34\x37\x22\x2c\x22\x6e\x31\x53\x6d\x49\x6e\x66\x6f\x46\x72" \
"\x6f\x6d\x55\x65\x22\x3a\x7b\x22\x63\x6f\x6e\x74\x65\x6e\x74\x49" \
"\x64\x22\x3a\x22\x50\x64\x75\x53\x65\x73\x73\x69\x6f\x6e\x45\x73" \
"\x74\x61\x62\x6c\x69\x73\x68\x6d\x65\x6e\x74\x52\x65\x71\x75\x65" \
"\x73\x74\x22\x7d\x2c\x22\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x46" \
"\x65\x61\x74\x75\x72\x65\x73\x22\x3a\x22\x32\x34\x22\x2c\x22\x73" \
"\x65\x6c\x4d\x6f\x64\x65\x22\x3a\x22\x56\x45\x52\x49\x46\x49\x45" \
"\x44\x22\x2c\x22\x75\x64\x6d\x47\x72\x6f\x75\x70\x49\x64\x22\x3a" \
"\x22\x31\x22\x2c\x22\x72\x6f\x75\x74\x69\x6e\x67\x49\x6e\x64\x69" \
"\x63\x61\x74\x6f\x72\x22\x3a\x22\x30\x30\x30\x30\x22\x2c\x22\x65" \
"\x70\x73\x49\x6e\x74\x65\x72\x77\x6f\x72\x6b\x69\x6e\x67\x49\x6e" \
"\x64\x22\x3a\x22\x57\x49\x54\x48\x5f\x4e\x32\x36\x22\x2c\x22\x76" \
"\x53\x6d\x66\x53\x65\x72\x76\x69\x63\x65\x49\x6e\x73\x74\x61\x6e" \
"\x63\x65\x49\x64\x22\x3a\x22\x6e\x73\x6d\x66\x2d\x70\x64\x75\x73" \
"\x65\x73\x73\x69\x6f\x6e\x2e\x30\x35\x33\x63\x39\x63\x62\x66\x2d" \
"\x61\x63\x32\x39\x2d\x34\x62\x63\x66\x2d\x39\x66\x35\x31\x2d\x36" \
"\x39\x36\x32\x64\x64\x39\x36\x36\x61\x65\x63\x22\x2c\x22\x63\x68" \
"\x61\x72\x67\x69\x6e\x67\x49\x64\x22\x3a\x22\x31\x33\x34\x32\x32" \
"\x30\x38\x31\x36\x32\x22\x2c\x22\x61\x6d\x66\x4e\x66\x49\x64\x22" \
"\x3a\x22\x35\x37\x32\x37\x36\x61\x39\x34\x2d\x66\x30\x64\x32\x2d" \
"\x34\x39\x31\x39\x2d\x62\x66\x61\x30\x2d\x62\x39\x64\x31\x34\x61" \
"\x36\x62\x30\x61\x33\x31\x22\x2c\x22\x67\x75\x61\x6d\x69\x22\x3a" \
"\x7b\x22\x70\x6c\x6d\x6e\x49\x64\x22\x3a\x7b\x22\x6d\x63\x63\x22" \
"\x3a\x22\x37\x32\x34\x22\x2c\x22\x6d\x6e\x63\x22\x3a\x22\x38\x30" \
"\x22\x7d\x2c\x22\x61\x6d\x66\x49\x64\x22\x3a\x22\x38\x32\x37\x38" \
"\x30\x31\x22\x7d\x2c\x22\x6d\x61\x78\x49\x6e\x74\x65\x67\x72\x69" \
"\x74\x79\x50\x72\x6f\x74\x65\x63\x74\x65\x64\x44\x61\x74\x61\x52" \
"\x61\x74\x65\x55\x6c\x22\x3a\x22\x36\x34\x5f\x4b\x42\x50\x53\x22" \
"\x2c\x22\x6d\x61\x78\x49\x6e\x74\x65\x67\x72\x69\x74\x79\x50\x72" \
"\x6f\x74\x65\x63\x74\x65\x64\x44\x61\x74\x61\x52\x61\x74\x65\x44" \
"\x6c\x22\x3a\x22\x36\x34\x5f\x4b\x42\x50\x53\x22\x7d\x0d\x0a\x2d" \
"\x2d\x4d\x75\x6c\x74\x69\x70\x61\x72\x74\x44\x61\x74\x61\x4c\x69" \
"\x73\x74\x42\x6f\x75\x6e\x64\x61\x72\x79\x0d\x0a\x43\x6f\x6e\x74" \
"\x65\x6e\x74\x2d\x54\x79\x70\x65\x3a\x20\x61\x70\x70\x6c\x69\x63" \
"\x61\x74\x69\x6f\x6e\x2f\x76\x6e\x64\x2e\x33\x67\x70\x70\x2e\x35" \
"\x67\x6e\x61\x73\x0d\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x49\x44" \
"\x3a\x20\x50\x64\x75\x53\x65\x73\x73\x69\x6f\x6e\x45\x73\x74\x61" \
"\x62\x6c\x69\x73\x68\x6d\x65\x6e\x74\x52\x65\x71\x75\x65\x73\x74" \
"\x0d\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x54\x72\x61\x6e\x73\x66" \
"\x65\x72\x2d\x45\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20\x62\x69\x6e" \
"\x61\x72\x79\x0d\x0a\x0d\x0a\xc1\x91\xa1\x0d\x0a\x2d\x2d\x4d\x75" \
"\x6c\x74\x69\x70\x61\x72\x74\x44\x61\x74\x61\x4c\x69\x73\x74\x42" \
"\x6f\x75\x6e\x64\x61\x72\x79\x2d\x2d"
;
    tp.request_headers.addCopy(Http::LowerCaseString("content-length"),
                            std::to_string(multipart_body.length()));
    tp.request_headers.addCopy(Http::LowerCaseString("content-type"), content_type);
    response = codec_client_->makeRequestWithBody(tp.request_headers, multipart_body);

    waitForNextUpstreamRequest(tp.expected_upstream_index);

    // Send response
    upstream_request_->encodeHeaders(tp.response_headers, true);

    ASSERT_TRUE(response->waitForEndStream());

    for (std::map<std::string, std::string>::const_iterator itr = tp.expected_request_headers.begin();
         itr != tp.expected_request_headers.end(); ++itr) {
      EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(itr->first, itr->second));
    }

    for (std::map<std::string, std::string>::const_iterator itr = tp.expected_response_headers.begin();
         itr != tp.expected_response_headers.end(); ++itr) {
      EXPECT_THAT(response->headers(), Http::HeaderValueOf(itr->first, itr->second));
    }

    ENVOY_LOG(trace, printCounters(test_server_, "http.ingress.n8e.g3p.topology_hiding"));

    for (const auto& counter : tp.expected_counters) {
      EXPECT_EQ(counter.second, test_server_->counter(counter.first)->value());
    }

    codec_client_->close();
  }

  TestParameters intToExtMappingSuccess1Params() {
    TestParameters tp;
    tp.cluster_config =
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

    tp.filter_configs = {config_int_to_ext};

    tp.request_headers = {
        {":method", "GET"},
        {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                  "nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
        {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
        {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
        {"callback-uri", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

    tp.response_headers = {
        {":status", "200"},
        {"location", "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
        {"x-response-origin", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"}};

    tp.request_body = "";

    // Fake response body
    Json response_json_body = Json::parse(nf_disc_resp_body);
    response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
        "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
    response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
        "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
    response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
        "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
    tp.response_body = response_json_body.dump();

    tp.expected_upstream_index = 0;

    tp.expected_request_headers = {
        {"x-cluster", "sepp_pool_1"},
        {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                  "fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
        {"callback-uri", "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

    tp.expected_response_headers = {
        {":status", "200"},
        {"location", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
        {"x-response-origin", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"}};

    tp.expected_query_params = {
        {"hnrf-uri", "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

    const Json expected_request_body = nullptr;

    Json expected_response_json_body = Json::parse(nf_disc_resp_body);
    expected_response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
        "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
    expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
        "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
    expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
        "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
    tp.expected_response_body = expected_response_json_body;

    tp.expected_counters = {{"http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nnrf_disc."
                             "o4n.internal.th_fqdn_mapping_req_map_success_total",
                             1UL},
                            {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nnrf_disc."
                             "o4n.internal.th_fqdn_mapping_resp_demap_success_total",
                             1UL}};
    return tp;
  }

TestParameters intToExtMappingError1Params() {
  TestParameters tp;
  tp.cluster_config =
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

  tp.filter_configs = {config_int_to_ext};

  tp.request_headers = {
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "nrf3.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"callback-uri", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.response_headers = {
      {":status", "200"},
      {"location", "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"}};

  tp.request_body = "";

  // Fake response body
  Json response_json_body = Json::parse(nf_disc_resp_body);
  response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://fakenrf3.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.response_body = response_json_body.dump();

  tp.expected_upstream_index = 0;

  tp.expected_request_headers = {
      {"x-cluster", "sepp_pool_1"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "nrf3.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
      {"callback-uri", "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.expected_response_headers = {
      {":status", "200"},
      {"location", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"}};

  tp.expected_query_params = {
      {"hnrf-uri", "http://nrf3.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.expected_request_body = nullptr;

  Json expected_response_json_body = Json::parse(nf_disc_resp_body);
  expected_response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://fakenrf3.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.expected_response_body = expected_response_json_body;

  tp.expected_counters = {
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nnrf_disc."
       "o4n.internal.th_fqdn_mapping_req_map_success_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nnrf_disc."
       "o4n.internal.th_fqdn_mapping_req_forwarded_unmodified_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nnrf_disc."
       "o4n.internal.th_fqdn_mapping_resp_demap_failure_total",
       1UL}};
  return tp;
}

TestParameters intToExtMappingSuccessMultipleScParams() {
  TestParameters tp;
  tp.cluster_config =
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

  tp.filter_configs = {config_int_to_ext_multiple_sc};

  tp.request_headers = {
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"callback-uri", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.response_headers = {
      {":status", "200"},
      {"location", "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"}};

  tp.request_body = "";

  // Fake response body
  Json response_json_body = Json::parse(nf_disc_resp_body);
  response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.response_body = response_json_body.dump();

  tp.expected_upstream_index = 0;

  tp.expected_request_headers = {
      {"x-cluster", "sepp_pool_1"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
      {"callback-uri", "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.expected_response_headers = {
      {":status", "200"},
      {"location", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"}};

  tp.expected_query_params = {
      {"hnrf-uri", "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.expected_request_body = nullptr;

  Json expected_response_json_body = Json::parse(nf_disc_resp_body);
  expected_response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.expected_response_body = expected_response_json_body;

  tp.expected_counters = {
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nnrf_disc."
       "o4n.internal.th_fqdn_mapping_req_map_success_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nnrf_disc."
       "o4n.internal.th_fqdn_mapping_resp_demap_success_total",
       1UL}};

  return tp;
}

TestParameters intToExtMappingErrorMultipleScParams() {
  TestParameters tp;

  tp.cluster_config =
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

  tp.filter_configs = {config_int_to_ext_multiple_sc};

  tp.request_headers = {
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "nrf3.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"callback-uri", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.response_headers = {
      {":status", "200"},
      {"location", "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"}};

  tp.request_body = "";

  // Fake response body
  Json response_json_body = Json::parse(nf_disc_resp_body);
  response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://fakenrf3.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.response_body = response_json_body.dump();

  tp.expected_upstream_index = 0;

  tp.expected_request_headers = {
      {"x-cluster", "sepp_pool_1"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "nrf3.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
      {"callback-uri", "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.expected_response_headers = {
      {":status", "200"},
      {"location", "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"}};

  tp.expected_query_params = {
      {"hnrf-uri", "http://nrf3.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.expected_request_body = nullptr;

  Json expected_response_json_body = Json::parse(nf_disc_resp_body);
  expected_response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://fakenrf3.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.expected_response_body = expected_response_json_body;

  tp.expected_counters = {
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nnrf_disc."
       "o4n.internal.th_fqdn_mapping_req_map_success_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nnrf_disc."
       "o4n.internal.th_fqdn_mapping_req_forwarded_unmodified_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nnrf_disc."
       "o4n.internal.th_fqdn_mapping_resp_demap_failure_total",
       1UL}};

  return tp;
}

TestParameters intToExtScramblingSuccess1Params() {
  TestParameters tp;
  tp.cluster_config =
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

  tp.filter_configs = {config_int_to_ext};

  tp.request_headers = {
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "nrf1.nrf.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"},
      {"callback-uri", "http://nrf1.5Gc.mnc123.mcc456.3GPPnetwork.org:80"}};

  tp.response_headers = {
      {":status", "200"},
      {"location", "http://Ab101D5dSBfXgMIp5O.5Gc.mnc123.mcc456.3GPPnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.request_body = "";

  // Fake response body
  Json response_json_body = Json::parse(nf_disc_resp_body);
  response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.response_body = response_json_body.dump();

  tp.expected_upstream_index = 1;

  tp.expected_request_headers = {
      {"x-cluster", "sepp_pool_2"},
      {":path",
       "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
       "AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
      {"callback-uri", "http://AB101D5DSBFXGMIP5O.5Gc.mnc123.mcc456.3GPPnetwork.org:80"}};

  tp.expected_response_headers = {
      {":status", "200"},
      {"location", "http://nrf1.5Gc.mnc123.mcc456.3GPPnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.expected_query_params = {
      {"hnrf-uri", "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.expected_request_body = nullptr;

  Json expected_response_json_body = Json::parse(nf_disc_resp_body);
  expected_response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://nrf1.nrf.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.expected_response_body = expected_response_json_body;

  tp.expected_counters = {
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_req_scramble_success_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_resp_descramble_success_total",
       1UL}};

  return tp;
}

TestParameters intToExtScamblingError1Params() {
  TestParameters tp;
  tp.cluster_config =
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

  tp.filter_configs = {config_int_to_ext};

  tp.request_headers = {
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "nrf1.nrf.5gc.mnc123.mcc456.org:80&target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"},
      {"callback-uri", "http://nrf1.5Gc.mnc123.mcc456.3GPPnetwork.org:80"}};

  tp.response_headers = {
      {":status", "200"},
      {"location", "http://10.10.10.10:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.request_body = "";

  // Fake response body
  Json response_json_body = Json::parse(nf_disc_resp_body);
  response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.response_body = response_json_body.dump();

  tp.expected_upstream_index = 1;

  tp.expected_request_headers = {
      {"x-cluster", "sepp_pool_2"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "nrf1.nrf.5gc.mnc123.mcc456.org:80&target-nf-type=SMF"},
      {"callback-uri", "http://AB101D5DSBFXGMIP5O.5Gc.mnc123.mcc456.3GPPnetwork.org:80"}};

  tp.expected_response_headers = {
      {":status", "200"},
      {"location", "http://10.10.10.10:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.expected_query_params = {
      {"hnrf-uri", "http://nrf1.nrf.5gc.mnc123.mcc456.org:80"}};

  tp.expected_request_body = nullptr;

  Json expected_response_json_body = Json::parse(nf_disc_resp_body);
  expected_response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://nrf1.nrf.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.expected_response_body = expected_response_json_body;

  tp.expected_counters = {
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_req_scramble_invalid_fqdn_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_req_forwarded_unmodified_fqdn_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_req_scramble_success_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.unknown_id.th_fqdn_scrambling_resp_forwarded_unmodified_ip_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_resp_descramble_success_total",
       1UL}};

  return tp;
}

TestParameters intToExtScramblingError2Params() {
  TestParameters tp;
  tp.cluster_config =
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

  tp.filter_configs = {config_int_to_ext};

  tp.request_headers = {
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://10.10.10.10:80&target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"},
      {"callback-uri", "http://nrf1.5Gc.mnc123.mcc456.3GPPnetwork.org:80"}};

  tp.response_headers = {
      {":status", "200"},
      {"location", "http://10.10.10.10:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.request_body = "";

  // Fake response body
  Json response_json_body = Json::parse(nf_disc_resp_body);
  response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://AC101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.response_body = response_json_body.dump();

  tp.expected_upstream_index = 1;

  tp.expected_request_headers = {
      {"x-cluster", "sepp_pool_2"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://10.10.10.10:80&target-nf-type=SMF"},
      {"callback-uri", "http://AB101D5DSBFXGMIP5O.5Gc.mnc123.mcc456.3GPPnetwork.org:80"}};

  tp.expected_response_headers = {
      {":status", "200"},
      {"location", "http://10.10.10.10:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.expected_query_params = {
      {"hnrf-uri", "http://10.10.10.10:80"}};

  tp.expected_request_body = nullptr;

  Json expected_response_json_body = Json::parse(nf_disc_resp_body);
  expected_response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://AC101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.expected_response_body = expected_response_json_body;

  tp.expected_counters = {
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_req_forwarded_unmodified_ip_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_req_scramble_success_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.unknown_id.th_fqdn_scrambling_resp_descramble_encryption_id_not_found_"
       "total",
       1UL}};

  return tp;
}

TestParameters intToExtScramblingError3Params() {
  TestParameters tp;
  tp.cluster_config =
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

  tp.filter_configs = {config_int_to_ext};

  tp.request_headers = {
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "nrf1.nrf.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"},
      {"callback-uri", "http://nrf1.5Gc.mnc123.mcc456.org:80"}};

  tp.response_headers = {
      {":status", "200"},
      {"location", "http://Ab101D5dSBfXgMIp5O.5Gc.mnc123.mcc456.3GPPnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.request_body = "";

  // Fake response body
  Json response_json_body = Json::parse(nf_disc_resp_body);
  response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://AA101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.response_body = response_json_body.dump();

  tp.expected_upstream_index = 1;

  tp.expected_request_headers = {
      {"x-cluster", "sepp_pool_2"},
      {":path",
       "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
       "AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
      {"callback-uri", "http://nrf1.5Gc.mnc123.mcc456.org:80"}};

  tp.expected_response_headers = {
      {":status", "200"},
      {"location", "http://nrf1.5Gc.mnc123.mcc456.3GPPnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.expected_query_params = {
      {"hnrf-uri", "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.expected_request_body = nullptr;

  Json expected_response_json_body = Json::parse(nf_disc_resp_body);
  expected_response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://AA101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.expected_response_body = expected_response_json_body;

  tp.expected_counters = {
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_req_scramble_invalid_fqdn_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.A101.th_fqdn_scrambling_resp_descramble_incorrect_encryption_id_total",
       1UL}};

  return tp;
}

TestParameters intToExtScramblingErrors4Params() {
  TestParameters tp;
  tp.cluster_config =
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

  tp.filter_configs = {config_int_to_ext};

  tp.request_headers = {
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "nrf1.nrf.5gc.mnc123.mcc456.org:80&target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"},
      {"callback-uri", "http://nrf1.5Gc.mnc123.mcc456.3GPPnetwork.org:80"}};

  tp.response_headers = {
      {":status", "200"},
      {"location", "http://nrf1:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.request_body = "";

  // Fake response body
  Json response_json_body = Json::parse(nf_disc_resp_body);
  response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.response_body = response_json_body.dump();

  tp.expected_upstream_index = 1;

  tp.expected_request_headers = {
      {"x-cluster", "sepp_pool_2"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "nrf1.nrf.5gc.mnc123.mcc456.org:80&target-nf-type=SMF"},
      {"callback-uri", "http://AB101D5DSBFXGMIP5O.5Gc.mnc123.mcc456.3GPPnetwork.org:80"}};

  tp.expected_response_headers = {
      {":status", "200"},
      {"location", "http://nrf1:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.expected_query_params = {
      {"hnrf-uri", "http://nrf1.nrf.5gc.mnc123.mcc456.org:80"}};

  tp.expected_request_body = nullptr;

  Json expected_response_json_body = Json::parse(nf_disc_resp_body);
  expected_response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.expected_response_body = expected_response_json_body;

  tp.expected_counters = {
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_req_scramble_invalid_fqdn_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_req_forwarded_unmodified_fqdn_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_req_scramble_success_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.unknown_id.th_fqdn_scrambling_resp_descramble_invalid_fqdn_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_resp_descramble_incorrect_encryption_id_total",
       1UL}};

  return tp;
}

TestParameters intToExtScramblingError5Params() {
  TestParameters tp;
  tp.cluster_config =
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

  tp.filter_configs = {config_int_to_ext};

  tp.request_headers = {
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "nrf1.nrf.5gc.mnc123.mcc456.org:80&target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"},
      {"callback-uri", "http://nrf1.5Gc.mnc123.mcc456.org:80"}};

  tp.response_headers = {
      {":status", "200"},
      {"location", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.request_body = "";

  // Fake response body
  Json response_json_body = Json::parse(nf_disc_resp_body);
  response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://nrf1000.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.response_body = response_json_body.dump();

  tp.expected_upstream_index = 1;

  tp.expected_request_headers = {
      {"x-cluster", "sepp_pool_2"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "nrf1.nrf.5gc.mnc123.mcc456.org:80&target-nf-type=SMF"},
      {"callback-uri", "http://nrf1.5Gc.mnc123.mcc456.org:80"}};

  tp.expected_response_headers = {
      {":status", "200"},
      {"location", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.expected_query_params = {
      {"hnrf-uri", "http://nrf1.nrf.5gc.mnc123.mcc456.org:80"}};

  tp.expected_request_body = nullptr;

  Json expected_response_json_body = Json::parse(nf_disc_resp_body);
  expected_response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://nrf1000.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.expected_response_body = expected_response_json_body;

  tp.expected_counters = {
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_req_scramble_invalid_fqdn_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.unknown_id.th_fqdn_scrambling_resp_descramble_encryption_id_not_found_"
       "total",
       1UL}};

  return tp;
}

TestParameters intToExtScramblingSuccessMultipleScParams() {
  TestParameters tp;
  tp.cluster_config =
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

  tp.filter_configs = {config_int_to_ext_multiple_sc};

  tp.request_headers = {
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "nrf1.nrf.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"},
      {"callback-uri", "http://nrf1.5Gc.mnc123.mcc456.3GPPnetwork.org:80"}};

  tp.response_headers = {
      {":status", "200"},
      {"location", "http://Ab101D5dSBfXgMIp5O.5Gc.mnc123.mcc456.3GPPnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.request_body = "";

  // Fake response body
  Json response_json_body = Json::parse(nf_disc_resp_body);
  response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.response_body = response_json_body.dump();

  tp.expected_upstream_index = 1;

  tp.expected_request_headers = {
      {"x-cluster", "sepp_pool_2"},
      {":path",
       "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
       "AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
      {"callback-uri", "http://AB101D5DSBFXGMIP5O.5Gc.mnc123.mcc456.3GPPnetwork.org:80"}};

  tp.expected_response_headers = {
      {":status", "200"},
      {"location", "http://nrf1.5Gc.mnc123.mcc456.3GPPnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.expected_query_params = {
      {"hnrf-uri", "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.expected_request_body = nullptr;

  Json expected_response_json_body = Json::parse(nf_disc_resp_body);
  expected_response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://nrf1.nrf.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.expected_response_body = expected_response_json_body;

  tp.expected_counters = {
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_req_scramble_success_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_resp_descramble_success_total",
       1UL}};


  return tp;
}

TestParameters intToExtScramblingErrorMultipleScParams() {
  TestParameters tp;
  tp.cluster_config =
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

  tp.filter_configs = {config_int_to_ext_multiple_sc};

  tp.request_headers = {
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
                "nrf1.nrf.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"},
      {"callback-uri", "http://nrf1.5Gc.mnc123.mcc456.org:80"}};

  tp.response_headers = {
      {":status", "200"},
      {"location", "http://Ab101D5dSBfXgMIp5O.5Gc.mnc123.mcc456.3GPPnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.request_body = "";

  // Fake response body
  Json response_json_body = Json::parse(nf_disc_resp_body);
  response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80";
  response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://AA101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.response_body = response_json_body.dump();

  tp.expected_upstream_index = 1;

  tp.expected_request_headers = {
      {"x-cluster", "sepp_pool_2"},
      {":path",
       "/nnrf-disc/v1/nf-instances?hnrf-uri=http://"
       "AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80&target-nf-type=SMF"},
      {"callback-uri", "http://nrf1.5Gc.mnc123.mcc456.org:80"}};

  tp.expected_response_headers = {
      {":status", "200"},
      {"location", "http://Ab101D5dSBfXgMIp5O.5Gc.mnc123.mcc456.3GPPnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc456.mcc456.3gppnetwork.org:80"}};

  tp.expected_query_params = {
      {"hnrf-uri", "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.expected_request_body = nullptr;

  Json expected_response_json_body = Json::parse(nf_disc_resp_body);
  expected_response_json_body.at("nfInstances").at(0).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(0).at("callbackUri") =
      "http://AB101D5DSBFXGMIP5O.D5DSANAKHJVQ.5gc.mnc123.mcc456.3gppnetwork.org:80";
  expected_response_json_body.at("nfInstances").at(1).at("nfServices").at(1).at("callbackUri") =
      "http://AA101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80";
  tp.expected_response_body = expected_response_json_body;

  tp.expected_counters = {
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.B101.th_fqdn_scrambling_req_scramble_invalid_fqdn_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.internal.e10d.A101.th_fqdn_scrambling_resp_descramble_incorrect_encryption_id_total",
       1UL}};

  return tp;
}

TestParameters extToIntMappingSuccess1Params() {
  TestParameters tp;
  tp.cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("nrf_pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}}))
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}})));
  tp.filter_configs = {config_header_to_metadata, config_ext_to_int};

  tp.request_headers = {
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"callback-uri", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"x-eric-sepp-test-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc123.mcc123.3gppnetwork.org"}};

  tp.response_headers = {
      {":status", "200"},
      {"location", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.request_body = "";
  tp.response_body = "";
  tp.expected_upstream_index = 0;
  tp.expected_request_headers = {
      {"x-cluster", "nrf_pool"},
      {"callback-uri", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"}};
  tp.expected_response_headers = {
      {":status", "200"},
      {"location", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"x-response-origin", "http://fakenrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"}};
  tp.expected_query_params = {{}};
  tp.expected_request_body = nullptr;
  tp.expected_response_body = nullptr;

  tp.expected_counters = {
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nnrf_disc."
       "o4n.external.th_fqdn_mapping_req_demap_success_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nnrf_disc."
       "o4n.external.th_fqdn_mapping_resp_map_success_total",
       1UL}};

  return tp;
}

TestParameters extToIntScramblingSuccess1Params() {
  TestParameters tp;
  tp.cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("nrf_pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}}))
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}})));
  tp.filter_configs = {config_header_to_metadata, config_ext_to_int};

  tp.request_headers = {
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"callback-uri", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"x-eric-sepp-test-rp-name", "rp_2"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc456.mcc456.3gppnetwork.org"}};

  tp.response_headers = {
      {":status", "200"},
      {"location", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.request_body = "";
  tp.response_body = "";
  tp.expected_upstream_index = 0;
  tp.expected_request_headers = {
      {"x-cluster", "nrf_pool"},
      {"callback-uri", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"}};
  tp.expected_response_headers = {
      {":status", "200"},
      {"location", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"x-response-origin", "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80"}};
  tp.expected_query_params = {{}};
  tp.expected_request_body = nullptr;
  tp.expected_response_body = nullptr;

  tp.expected_counters = {
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.external.e10d.B101.th_fqdn_scrambling_req_descramble_success_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.external.e10d.B101.th_fqdn_scrambling_resp_scramble_success_total",
       1UL}};

  return tp;
}

TestParameters extToIntScramblingDifferentRoamingPartnerNamesParams() {
  TestParameters tp;
  tp.cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("nrf_pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}}))
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}})));
  tp.filter_configs = {config_header_to_metadata,
                                                   config_ext_to_int_differentRoamingPartnerNames};

  tp.request_headers = {
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"callback-uri", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"x-eric-sepp-test-rp-name", "rp_2"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc456.mcc456.3gppnetwork.org"}};

  tp.response_headers = {
      {":status", "200"},
      {"location", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.request_body = "";
  tp.response_body = "";
  tp.expected_upstream_index = 0;
  tp.expected_request_headers = {
      {"x-cluster", "nrf_pool"},
      {"callback-uri", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"}};
  tp.expected_response_headers = {
      {":status", "200"},
      {"location", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"x-response-origin", "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80"}};
  tp.expected_query_params = {{}};
  tp.expected_request_body = nullptr;
  tp.expected_response_body = nullptr;

  tp.expected_counters = {
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.external.e10d.B101.th_fqdn_scrambling_req_descramble_success_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.external.e10d.B101.th_fqdn_scrambling_resp_scramble_success_total",
       1UL}};

  return tp;
}


TestParameters extToIntScramblingScds1738() {
  TestParameters tp;
  tp.cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("nrf_pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}}))
              .withEndpoint(EndpointBuilder()
                                .withHostName("nrf2.5gc.mnc123.mcc456.3gppnetwork.org:80")
                                .withHostMd({{"support", {"NF"}}})));
  tp.filter_configs = {config_header_to_metadata, config_ext_to_int_scds_1738};

  tp.request_headers = {
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.5gc.mnc123.mcc456.3gppnetwork.org"},
      {"3gpp-Sbi-target-apiRoot", "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80"},
      {"callback-uri", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"x-eric-sepp-test-rp-name", "rp_2"},
      {"x-eric-sepp-test-san", "sepp.5gc.mnc456.mcc456.3gppnetwork.org"}};

  tp.response_headers = {
      {":status", "200"},
      {"location", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"x-response-origin", "http://nrf1.5gc.mnc123.mcc456.3gppnetwork.org:80"}};

  tp.request_body = "";
  tp.response_body = "";
  tp.expected_upstream_index = 0;
  tp.expected_request_headers = {
      {"x-cluster", "nrf_pool"},
      {"callback-uri", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"}};
  tp.expected_response_headers = {
      {":status", "200"},
      {"location", "http://nrf1.5gc.mnc123.mcc123.3gppnetwork.org:80"},
      {"x-response-origin", "http://AB101D5DSBFXGMIP5O.5gc.mnc123.mcc456.3gppnetwork.org:80"}};
  tp.expected_query_params = {{}};
  tp.expected_request_body = nullptr;
  tp.expected_response_body = nullptr;

  tp.expected_counters = {
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.external.e10d.B101.th_fqdn_scrambling_req_descramble_success_total",
       1UL},
      {"http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.s5e.nnrf_disc."
       "o4n.external.e10d.B101.th_fqdn_scrambling_resp_scramble_success_total",
       1UL}};

  return tp;
}

};

//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------
INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterSeppThFqdnScramblingTest,
                         testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest())));

//----------------- Begin SEPP Int-to-Ext Traffic Tests ------------------

// Mapping: Success Case 1
// 2 RP's and NF Discovery request
// from internal network to rp_1
// RP1: Sepp edge screening enabled with:
//      Request, Topology Hiding, FQDN mapping:
//      - modify-query-param: hnrf-uri
//        do_nothing: true
//      - modify-header: callback-uri
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: success
//      Response, Topology Unhiding, FQDN demapping:
//      - modify-header: location
//        do_nothing: true
//      - modify-json-body: "/nfInstances/*/nfServices/*/callbackUri"
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: success
// Expect to map fqdn in request to RP1 and
// to demap fqdn in response from RP1
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Mapping_Success1) {
  testThServiceProfile(intToExtMappingSuccess1Params());
}
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Mapping_Success1_MP) {
  testThServiceProfileMP(intToExtMappingSuccess1Params());
}

// Mapping: Error Case 1
// 2 RP's and NF Discovery request
// from internal network to rp_1
// RP1: Sepp edge screening enabled with:
//      Request, Topology Hiding, FQDN mapping:
//      - modify-query-param: hnrf-uri (fqdn not present in table)
//        do_nothing: true
//      - modify-header: callback-uri (fqdn present in table)
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: success, forwarded unmodified
//      Response, Topology Unhiding, FQDN demapping:
//      - modify-header: location (fqdn present in table)
//        do_nothing: true
//      - modify-json-body: "/nfInstances/*/nfServices/*/callbackUri" (fqdn not present in table)
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: failure
// Expect to map fqdn in request to RP1 and
// to demap fqdn in response from RP1
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Mapping_Error1) {
  testThServiceProfile(intToExtMappingError1Params());
}
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Mapping_Error1_MP) {
  testThServiceProfileMP(intToExtMappingError1Params());
}

// Mapping: Success Case Multiple Matching Service Cases
// 2 RP's and NF Discovery request
// from internal network to rp_1
// RP1: Sepp edge screening enabled with:
//      Request, Topology Hiding, FQDN mapping:
//      - service_case: sc_1
//        modify-query-param: hnrf-uri
//        do_nothing: true
//      - service_case: sc_3
//        modify-header: callback-uri
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: success
//      Response, Topology Unhiding, FQDN demapping:
//      - service_case: sc_1
//        modify-json-body: "/nfInstances/*/nfServices/*/callbackUri"
//        fc_unsuccessful_operation: fc_failover_1
//      - service_case: sc_3
//        modify-header: location
//        do_nothing: true
//      - counters: success
// Expect to map fqdn in request to RP1 and
// to demap fqdn in response from RP1
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Mapping_Success_Multiple_Sc) {
  testThServiceProfile(intToExtMappingSuccessMultipleScParams());
}
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Mapping_Success_Multiple_Sc_MP) {
  testThServiceProfileMP(intToExtMappingSuccessMultipleScParams());
}

// Mapping: Error Case Multiple Matching Service Cases
// 2 RP's and NF Discovery request
// from internal network to rp_1
// RP1: Sepp edge screening enabled with:
//      Request, Topology Hiding, FQDN mapping:
//      - service_case: sc_1
//        modify-query-param: hnrf-uri (fqdn not present in table)
//        do_nothing: true
//      - service_case: sc_3
//        modify-header: callback-uri (fqdn present in table)
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: success, forwarded unmodified
//      Response, Topology Unhiding, FQDN demapping:
//      - service_case: sc_1
//        modify-json-body: "/nfInstances/*/nfServices/*/callbackUri" (fqdn not present in table)
//        fc_unsuccessful_operation: fc_failover_1
//      - service_case: sc_3
//        modify-header: location (fqdn present in table)
//        do_nothing: true
//      - counters: failure
// Expect to map fqdn in request to RP1 and
// to demap fqdn in response from RP1
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Mapping_Error_Multiple_Sc) {
  testThServiceProfile(intToExtMappingErrorMultipleScParams());
}
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Mapping_Error_Multiple_Sc_MP) {
  testThServiceProfileMP(intToExtMappingErrorMultipleScParams());
}

// Scrambling: Success Case 1
// 2 RP's and NF Discovery request
// from internal network to rp_2
// RP2: Sepp edge screening enabled with:
//      Request, Topology Hiding, FQDN scrambling:
//      - modify-query-param: hnrf-uri
//        do_nothing: true
//      - modify-header: callback-uri
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: success
//      Response, Topology Unhiding, FQDN descrambling:
//      - modify-header: location
//        do_nothing: true
//      - modify-json-body: "/nfInstances/*/nfServices/*/callbackUri"
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: success
// Expect to scramble fqdn in request to RP2 and
// to descramble fqdn in response from RP2
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Success1) {
  testThServiceProfile(intToExtScramblingSuccess1Params());
}
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Success1_MP) {
  testThServiceProfileMP(intToExtScramblingSuccess1Params());
}

// Scrambling: Error Case 1
// 2 RP's and NF Discovery request
// from internal network to rp_2
// RP2: Sepp edge screening enabled with:
//      Request, Topology Hiding, FQDN scrambling:
//      - modify-query-param: hnrf-uri (invalid fqdn)
//        do_nothing: true
//      - modify-header: callback-uri (valid original fqdn)
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: invalid fqdn, forwarded unmodified fqdn, success
//      Response, Topology Unhiding, FQDN descrambling:
//      - modify-header: location (ip present)
//        do_nothing: true
//      - modify-json-body: "/nfInstances/*/nfServices/*/callbackUri" (valid scrambled fqdn)
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: forwarded unmodified ip, success
// Expect to scramble fqdn in request to RP2 and
// to descramble fqdn in response from RP2
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Error1) {
  testThServiceProfile(intToExtScamblingError1Params());
}
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Error1_MP) {
  testThServiceProfileMP(intToExtScamblingError1Params());
}

// Scrambling: Error Case 2
// 2 RP's and NF Discovery request
// from internal network to rp_2
// RP2: Sepp edge screening enabled with:
//      Request, Topology Hiding, FQDN scrambling:
//      - modify-query-param: hnrf-uri (ip present)
//        do_nothing: true
//      - modify-header: callback-uri (valid original fqdn)
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: forwarded unmodified ip, success
//      Response, Topology Unhiding, FQDN descrambling:
//      - modify-header: location (ip present)
//        do_nothing: true
//      - modify-json-body: "/nfInstances/*/nfServices/*/callbackUri" (unknown encryption id
//      present)
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: encryption id not found
// Expect to scramble fqdn in request to RP2 and
// to descramble fqdn in response from RP2
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Error2) {
  testThServiceProfile(intToExtScramblingError2Params());
}
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Error2_MP) {
  testThServiceProfileMP(intToExtScramblingError2Params());
}

// Scrambling: Error Case 3
// 2 RP's and NF Discovery request
// from internal network to rp_2
// RP2: Sepp edge screening enabled with:
//      Request, Topology Hiding, FQDN scrambling:
//      - modify-query-param: hnrf-uri (valid original fqdn)
//        do_nothing: true
//      - modify-header: callback-uri (invalid fqdn)
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: invalid fqdn
//      Response, Topology Unhiding, FQDN descrambling:
//      - modify-header: location (valid scrambled fqdn)
//        do_nothing: true
//      - modify-json-body: "/nfInstances/*/nfServices/*/callbackUri" (incorrect encryption id
//      present)
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: incorrect encryption id
// Expect to scramble fqdn in request to RP2 and
// to descramble fqdn in response from RP2
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Error3) {
  testThServiceProfile(intToExtScramblingError3Params());
}
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Error3_MP) {
  testThServiceProfileMP(intToExtScramblingError3Params());
}

// Scrambling: Error Case 4
// 2 RP's and NF Discovery request
// from internal network to rp_2
// RP2: Sepp edge screening enabled with:
//      Request, Topology Hiding, FQDN scrambling:
//      - modify-query-param: hnrf-uri (invalid fqdn)
//        do_nothing: true
//      - modify-header: callback-uri (valid original fqdn)
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: invalid fqdn, forwarded unmodified fqdn, success
//      Response, Topology Unhiding, FQDN descrambling:
//      - modify-header: location (invalid fqdn)
//        do_nothing: true
//      - modify-json-body: "/nfInstances/*/nfServices/*/callbackUri" (incorrect scrambled fqdn)
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: invalid fqdn, incorrect encryption id
// Expect to scramble fqdn in request to RP2 and
// to descramble fqdn in response from RP2
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Error4) {
  testThServiceProfile(intToExtScramblingErrors4Params());
}
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Error4_MP) {
  testThServiceProfileMP(intToExtScramblingErrors4Params());
}

// Scrambling: Error Case 5
// 2 RP's and NF Discovery request
// from internal network to rp_2
// RP2: Sepp edge screening enabled with:
//      Request, Topology Hiding, FQDN scrambling:
//      - modify-query-param: hnrf-uri (invalid fqdn)
//        do_nothing: true
//      - modify-header: callback-uri (invalid fqdn)
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: invalid fqdn
//      Response, Topology Unhiding, FQDN descrambling:
//      - modify-header: location (valid original fqdn)
//        do_nothing: true
//      - modify-json-body: "/nfInstances/*/nfServices/*/callbackUri" (valid original fqdn)
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: encryption id not found
// Expect to scramble fqdn in request to RP2 and
// to descramble fqdn in response from RP2
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Error5) {
  testThServiceProfile(intToExtScramblingError5Params());
}
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Error5_MP) {
  testThServiceProfileMP(intToExtScramblingError5Params());
}

// Scrambling: Success Case Multiple Matching Service Cases
// 2 RP's and NF Discovery request
// from internal network to rp_2
// RP2: Sepp edge screening enabled with:
//      Request, Topology Hiding, FQDN scrambling:
//      - service_case: sc_1
//        modify-query-param: hnrf-uri
//        do_nothing: true
//      - service_case: sc_3
//        modify-header: callback-uri
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: success
//      Response, Topology Unhiding, FQDN descrambling:
//      - service_case: sc_1
//        modify-json-body: "/nfInstances/*/nfServices/*/callbackUri"
//        fc_unsuccessful_operation: fc_failover_1
//      - service_case: sc_3
//        modify-header: location
//        do_nothing: true
//      - counters: success
// Expect to scramble fqdn in request to RP2 and
// to descramble fqdn in response from RP2
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Success_Multiple_Sc) {
  testThServiceProfile(intToExtScramblingSuccessMultipleScParams());
}
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Success_Multiple_Sc_MP) {
  testThServiceProfileMP(intToExtScramblingSuccessMultipleScParams());
}

// Scrambling: Error Case Multiple Matching Service Cases
// 2 RP's and NF Discovery request
// from internal network to rp_2
// RP2: Sepp edge screening enabled with:
//      Request, Topology Hiding, FQDN scrambling:
//      - service_case: sc_1
//        modify-query-param: hnrf-uri (valid original fqdn)
//        do_nothing: true
//      - service_case: sc_3
//        modify-header: callback-uri (invalid fqdn)
//        fc_unsuccessful_operation: fc_failover_1
//      - counters: invalid fqdn
//      Response, Topology Unhiding, FQDN descrambling:
//      - service_case: sc_1
//        modify-json-body: "/nfInstances/*/nfServices/*/callbackUri" (incorrect encryption id
//        present) fc_unsuccessful_operation: fc_failover_1
//      - service_case: sc_3
//        modify-header: location (valid scrambled fqdn)
//        do_nothing: true
//      - counters: incorrect encryption id
// Expect to scramble fqdn in request to RP2 and
// to descramble fqdn in response from RP2
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Error_Multiple_Sc) {
  testThServiceProfile(intToExtScramblingErrorMultipleScParams());
}
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, IntToExt_Scrambling_Error_Multiple_Sc_MP) {
  testThServiceProfileMP(intToExtScramblingErrorMultipleScParams());
}

//------------------ End SEPP Int-to-Ext Traffic Tests -------------------

//----------------- Begin SEPP Ext-to-Int Traffic Tests ------------------

// Mapping: Success Case 1
// 2 RP's and NF Discovery request
// from rp_1 to internal network
// RP1: Sepp edge screening enabled with:
//      Request, Topology Unhiding, FQDN demapping:
//      - modify-header: 3gpp-Sbi-target-apiRoot
//        do_nothing: true
//      - counters: success
//      Response, Topology Hiding, FQDN mapping:
//      - modify-header: x-response-origin
//        do_nothing: true
//      - counters: success
// Expect to demap fqdn in request from RP1
// and to map fqdn in response to RP1
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, ExtToInt_Mapping_Success1) {
  testThServiceProfile(extToIntMappingSuccess1Params());
}
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, ExtToInt_Mapping_Success1_MP) {
  testThServiceProfileMP(extToIntMappingSuccess1Params());
}

// Scrambling: Success Case 1
// 2 RP's and NF Discovery request
// from rp_2 to internal network
// RP2: Sepp edge screening enabled with:
//      Request, Topology Unhiding, FQDN descrambling:
//      - modify-header: 3gpp-Sbi-target-apiRoot
//        do_nothing: true
//      - counters: success
//      Response, Topology Hiding, FQDN scrambling:
//      - modify-header: x-response-origin
//        do_nothing: true
//      - counters: success
// Expect to descramble fqdn in request from RP2
// and to scramble fqdn in response to RP2
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, ExtToInt_Scrambling_Success1) {
  testThServiceProfile(extToIntScramblingSuccess1Params());
}
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, ExtToInt_Scrambling_Success1_MP) {
  testThServiceProfileMP(extToIntScramblingSuccess1Params());
}

// Scrambling: Different Roaming Partner Names
// 2 RP's and NF Discovery request
// from rp_2 to internal network
// RP2: Sepp edge screening enabled with:
//      Request, Topology Unhiding, FQDN descrambling:
//      - modify-header: 3gpp-Sbi-target-apiRoot
//        do_nothing: true
//      - counters: success
//      Response, Topology Hiding, FQDN scrambling:
//      - modify-header: x-response-origin
//        do_nothing: true
//      - counters: success
// Expect to descramble fqdn in request from RP2
// and to scramble fqdn in response to RP2
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, ExtToInt_Scrambling_differentRoamingPartnerNames) {
  testThServiceProfile(extToIntScramblingDifferentRoamingPartnerNamesParams());
}
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, ExtToInt_Scrambling_differentRoamingPartnerNames_MP) {
  testThServiceProfileMP(extToIntScramblingDifferentRoamingPartnerNamesParams());
}

//------------------ End SEPP Ext-to-Int Traffic Tests -------------------

//------------------ Begin DND/SCDS Specific Tests -----------------------
// SCDS-1738: Multipart body leads to error when descrambling.
// Ext-to-int
TEST_P(EricProxyFilterSeppThFqdnScramblingTest, Scds1738MPbody) {
  testThServiceProfileMPSCDS1738(extToIntScramblingScds1738());
}
//------------------ End DND/SCDS Specific Tests -----------------------


} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
