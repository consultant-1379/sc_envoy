#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "test/integration/http_integration.h"
#include <ostream>

#include "config_utils/pluggable_configurator.h"
#include "config_utils/basic_cluster_configurator.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

// using ClusterDefinition = std::vector<std::pair<std::string, std::vector<std::string>>>;

class EricProxyFilterIntegrationTest : public PluggableConfigurator {
public:
  // given a metadata key, asserts that value is the expected one
  bool assertMetadata(FakeStreamPtr& request_stream, const std::string& metadata_key,
                      const std::string& expected_md_val) {
    const auto& request_metadata = request_stream->streamInfo().dynamicMetadata().filter_metadata();
    const auto filter_it = request_metadata.find("eric_proxy");
    std::unique_ptr<Router::MetadataMatchCriteriaImpl> eric_proxy_metadata;
    if (filter_it != request_metadata.end()) {
      eric_proxy_metadata = std::make_unique<Router::MetadataMatchCriteriaImpl>(filter_it->second);
    }

    if (eric_proxy_metadata) {
      const auto& md_val =
          eric_proxy_metadata->filterMatchCriteria(std::set<std::string>{metadata_key});
      // if routing_behaviour is there, the md are appended by eric proxy and is a string value
      return (md_val && !md_val->metadataMatchCriteria().empty() &&
              md_val->metadataMatchCriteria()[0]->value().value().string_value() ==
                  expected_md_val);
    }
    return false;
  }
  // Configuration for basic positive tests
  const std::string config_basic = R"EOF(
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
        extractor_regex: (?i)eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      - name: apiRoot_header
        header: 3gpp-Sbi-target-apiRoot
        variable_name:  apiRoot_hdr
      - name: chfsim_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: (?i)eric-(?P<chfsim>chfsim-\d+?)-.+
      filter_rules:
      - name: csepp_to_rp_A
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
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
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: psepp_to_pref
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: occ
            routing_behaviour: PREFERRED
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

 // Configuration for basic positive tests
  const std::string config_basic_phase_1_2_3_4_6 = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  own_internal_port: 80
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - sc_ph1
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
    out_request_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          cluster_K: sc_K_3
          universal_pool: sc_ph3
  response_filter_cases:
    in_response_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          universal_pool: sc_ph4
          cluster_K: sc_K_4
    out_response_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - sc_ph6

  filter_cases:
    - name: sc_ph1
      filter_rules:
      - name: dummy_ph1
        condition:
           term_boolean: true
        actions:
        - action_add_header:
            name: x-it-header-name-added
            value:
              term_string: x-it-header-value-added-screening_ph1
            if_exists: NO_ACTION
    - name: sc_ph6
      filter_rules:
      - name: dummy_ph6
        condition:
           term_boolean: true
        actions:
        - action_add_header:
            name: x-added-by-response_ph6
            value:
              term_string: x-it-header-value-added-screening_ph6
            if_exists: NO_ACTION
    - name: default_routing
      filter_data:
      - name: apiRoot_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: (?i)eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      - name: apiRoot_header
        header: 3gpp-Sbi-target-apiRoot
        variable_name:  apiRoot_hdr
      - name: chfsim_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: (?i)eric-(?P<chfsim>chfsim-\d+?)-.+
      filter_rules:
      - name: csepp_to_rp_A
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
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
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: psepp_to_pref
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: occ
            routing_behaviour: PREFERRED
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
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
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  // Configuration for basic positive tests
  const std::string config_basic_phase_2_3_4_6 = R"EOF(
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
    out_request_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          universal_pool: sc_ph3
  response_filter_cases:
    in_response_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          universal_pool: sc_ph4
    out_response_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - sc_ph6
  filter_cases:
    - name: default_routing
      filter_data:
      - name: apiRoot_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: (?i)eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      - name: apiRoot_header
        header: 3gpp-Sbi-target-apiRoot
        variable_name:  apiRoot_hdr
      - name: chfsim_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: (?i)eric-(?P<chfsim>chfsim-\d+?)-.+
      filter_rules:
      - name: csepp_to_rp_A
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
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
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: psepp_to_pref
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: occ
            routing_behaviour: PREFERRED
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
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
    - name: sc_ph6
      filter_rules:
      - name: dummy_ph6
        condition:
           term_boolean: true
        actions:
        - action_add_header:
            name: x-added-by-response_ph6
            value:
              term_string: x-it-header-value-added-screening_ph6
            if_exists: NO_ACTION
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";


  // Configuration to test "preferred_target" in action_route_to_pool and
  // action_route_to_roaming_partner
  const std::string config_preferred_target = R"EOF(
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
        extractor_regex: eric-(?P<target>chfsim-\d+?)-.+
      filter_rules:
      - name: "Hdr2Pool: preferred host from header, route to pool1"
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'Hdr2Pool'}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: pool1
            routing_behaviour: PREFERRED
            preserve_if_indirect: TARGET_API_ROOT

      - name: "Hdr2RP: preferred host from header, route to roaming-partner rp_A (pool sepp_rp_A)"
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'Hdr2RP'}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT

      - name: "Var2Pool: preferred host from var, route to pool2"
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'Var2Pool'}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: pool2
            routing_behaviour: PREFERRED
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_var: "target"

      - name: "Var2RP: preferred host from var, route to roaming-partner rp_B (pool sepp_rp_B)"
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'Var2RP'}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_B
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT


      - name: "Str2Pool: preferred host from string constant, route to pool3"
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'Str2Pool'}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: pool3
            routing_behaviour: PREFERRED
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_string: "fixed_target"

      - name: "Str2RP: preferred host from string constant, route to roaming-partner rp_C (pool sepp_rp_C)"
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'Str2RP'}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_C
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT


      - name: "Hdr2PoolPreservePath: preferred host from header, route to pool1, preserve absolute path"
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'Hdr2PoolPreservePath'}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: pool1
            routing_behaviour: PREFERRED
            preserve_if_indirect: ABSOLUTE_PATH
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"

      - name: "Hdr2RPPreservePath: preferred host from header, route to roaming-partner rp_A (pool sepp_rp_A), preserve abs. path"
        condition:
          op_equals:
            typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: 'tc'}
            typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'Hdr2RPPreservePath'}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: ABSOLUTE_PATH


      - name: "fall-through"
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
    - name: rp_B
      pool_name: sepp_rp_B
    - name: rp_C
      pool_name: sepp_rp_C
)EOF";

  // Configuration to reproduce DND-24977
  const std::string config_dnd24977 = R"EOF(
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
      - name: routing_binding_data
        header: 3gpp-Sbi-Routing-Binding
        extractor_regex: ^\s*bl=nf-set;\s*nfset=(?P<setid>.+)$
      - name: setID_data
        header: 3gpp-Sbi-Discovery-nf-set-id
        variable_name: setid
      filter_rules:
      - name: pSepp_to_ownPLMN_NfAmf_set1_to_fw
        condition: {
                    "op_or": {
                     "arg1": {
                      "op_equals": {
                       "typed_config1": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                        "term_var": "setid"
                       },
                       "typed_config2": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                        "term_string": "set1.amfset.5gc.mnc073.mcc262"
                       }
                      }
                     },
                     "arg2": {
                      "op_equals": {
                       "typed_config1": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                        "term_var": "setidrb"
                       },
                       "typed_config2": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                        "term_string": "set1.amfset.5gc.mnc073.mcc262"
                       }
                      }
                     }
                    }
                   }
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: set1
            routing_behaviour: ROUND_ROBIN
      - name: pSepp_to_ownPLMN_NfAmf_set2_to_tt
        condition:  {
                    "op_or": {
                     "arg1": {
                      "op_equals": {
                       "typed_config1": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                        "term_var": "setid"
                       },
                       "typed_config2": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                        "term_string": "set2.amfset.5gc.mnc073.mcc262"
                       }
                      }
                     },
                     "arg2": {
                      "op_and": {
                       "arg1": {
                        "op_equals": {
                         "typed_config1": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_var": "setidrb"
                         },
                         "typed_config2": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_string": "set2.amfset.5gc.mnc073.mcc262"
                         }
                        }
                       },
                       "arg2": {
                        "op_exists": {
                         "arg1": {
                          "term_reqheader": "3gpp-sbi-target-apiRoot"
                         }
                        }
                       }
                      }
                     }
                    }
                   }
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: set2
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: fallthrough
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";

  // Configuration to test "req.header["abc"] exists"
  // No filter data that refers to this header (DND26150)
  const std::string config_header_exists = R"EOF(
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
      filter_rules:
      - name: headerIsPresent
        condition: { "op_exists": { "arg1": { "term_reqheader": "3gpp-sbi-target-apiroot" } } }
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: headerExists
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT

      - name: headerIsNotPresent
        condition: { op_not: { arg1: { "op_exists": { "arg1": { "term_reqheader": "3gpp-sbi-target-apiroot" } } } } }
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: headerDoesNotExist
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: fallthrough
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";

  // Configuration to test "not var.a exists" when the extractor-regex doesn't match
  // (because the variable is set to the empty string)
  const std::string config_var_not_exists = R"EOF(
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
      - name: mnc_mcc
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      filter_rules:
      - name: varMncExists
        condition: {"op_not": {"arg1": {"op_exists": { "arg1": { "term_var": "mnc" } } } } }
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: varMncNotExists
            routing_behaviour: ROUND_ROBIN
      - name: fallthrough
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";

  // Configuration to test "var.a == '' " when the extractor-regex doesn't match
  // Source is a header
  const std::string config_header_var_is_empty_string = R"EOF(
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
      - name: mnc_mcc
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      filter_rules:
      - name: varMccIsEqualEmptyString
        condition: {
                     "op_equals": {
                       "typed_config1": {
                       "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                       "term_var": "mnc"
                       },
                       "typed_config2": {
                       "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                       "term_string": ""
                       }
                     }
                   }
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: varMccIsEqualEmptyString
            routing_behaviour: ROUND_ROBIN
      - name: fallthrough
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";

  // Configuration to test "query.param["name"] is empty"
  const std::string config_query_param_is_empty = R"EOF(
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
      filter_rules:
      - name: queryParamIsEmpty
        condition: { "op_isempty": { "arg1": { "term_queryparam": "target-nf-type" } } }
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: queryParamIsEmpty
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: queryParamIsNotEmpty
        condition: { op_not: { arg1: { "op_isempty": { "arg1": { "term_queryparam": "target-nf-type" } } } } }
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: queryParamIsNotEmpty
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: fallthrough
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";

  const std::string config_apicontext_name = R"EOF(
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
    out_request_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          apiContextNameEqualsNnrf: sc_ph3
  response_filter_cases:
    in_response_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          apiContextNameEqualsNnrf: sc_ph4
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: apiContextNameIsEmpty
        condition:
          op_isempty: { arg1: { term_apicontext: API_NAME } }
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: apiContextNameIsEmpty
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
      - name: apiContextNameEquals
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_apicontext: API_NAME}, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'nnrf-disc'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: apiContextNameEqualsNnrf
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT

      - name: apiContextNameEqualsCase
        condition:
          op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_apicontext: API_NAME}, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'nnrf-disc'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: apiContextNameEqualsNnrfCaseIns
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
    - name: sc_ph3
      filter_rules:
      - name: api_name_nnrf_disc
        condition:
          op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_apicontext: API_NAME}, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'nnrf-disc'}}
        actions:
        - action_add_header:
            name: x-it-header-api-context-name
            value:
              term_string: x-nnrf-disc_ph3
            if_exists: NO_ACTION
    - name: sc_ph4
      filter_rules:
      - name: dummy_ph4
        condition:
          op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_apicontext: API_NAME}, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'nnrf-disc'}}
        actions:
        - action_add_header:
            name:  x-it-header-api-context-name
            value:
              term_string: x-nnrf-disc_ph4
            if_exists: NO_ACTION

)EOF";

  // Configuration to test isInSubnet
  const std::string config_is_in_subnet = R"EOF(
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
      - name: address
        header: target-address
        variable_name: addr
      filter_rules:
      - name: routeViaStringHeaderIPv4
        condition: { "op_isinsubnet": { "arg1": { "term_reqheader": "address-header" }, arg2: "10.0.0.0/24" } }
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: headerIPv4
            routing_behaviour: ROUND_ROBIN
      - name: routeViaStringVarIPv4
        condition: { "op_isinsubnet": { "arg1": { "term_var": "addr" }, arg2: "10.0.0.0/24" } }
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: varIPv4
            routing_behaviour: ROUND_ROBIN
      - name: routeViaStringHeaderIPv6
        condition: { "op_isinsubnet": { "arg1": { "term_reqheader": "address-header" }, arg2: "fe80::c88d:edff:fee8:acd8/64" } }
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: headerIPv6
            routing_behaviour: ROUND_ROBIN
      - name: routeViaStringVarIPv6
        condition: { "op_isinsubnet": { "arg1": { "term_var": "addr" }, arg2: "fe80::c88d:edff:fee8:acd8/64" } }
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: varIPv6
            routing_behaviour: ROUND_ROBIN
      - name: fallthrough
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";

  // Common configuration that sets the start-routingcase
  std::string ericProxyHttpProxyConfig() {
    return fmt::format(R"EOF(
admin:
  access_log_path: /dev/null
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 0
static_resources:
  clusters:
  - name: occ
    connect_timeout: 15s
    load_assignment:
      cluster_name: occ
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 0
            hostname: host:80
  - name: universal_pool
    connect_timeout: 15s
    load_assignment:
      cluster_name: universal_pool
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 0
            hostname: eric-chfsim-6-mnc-456-mcc-456:3777

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
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - name: catch_all
                match:
                  prefix: "/"
                  headers:
                    - name: x-eric-proxy
                      present_match: true
                      invert_match: true
                route:
                  cluster_header: not_used
              - name: route1
                match:
                  prefix: "/"
                  headers:
                    - name: x-cluster
                      string_match:
                        exact: occ
                route:
                  cluster: occ
              - name: route2
                match:
                  prefix: "/"
                  headers:
                    - name: x-cluster
                      string_match:
                        exact: universal_pool
                route:
                  cluster: universal_pool
  )EOF",
                       Platform::null_device_path);
  }

  // Configuration to test DND-64820, action_route_to_pool
  // Validate that headers required by an action are loaded into the run-context
  const std::string config_dnd_68420_route_to_pool = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: "strict to pool"
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: target_pool
            routing_behaviour: STRICT
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: "add tar header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "3gpp-sbi-target-apiroot"
      - name: "wrong pool"
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";


  // Configuration to test DND-64820, action_route_to_roaming_partner
  // Validate that headers required by an action are loaded into the run-context
  const std::string config_dnd_68420_route_to_roaming_partner = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: "strict to roaming partner"
        condition:
          term_boolean: true
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: STRICT
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: "add tar header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "3gpp-sbi-target-apiroot"
      - name: "wrong pool"
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


  // Configuration to test DND-64820, action_add_header
  // Validate that headers required by an action are loaded into the run-context
  const std::string config_dnd_68420_add_header = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: "strict to pool"
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: test_out
            value:
              term_header: test_in
        - action_route_to_pool:
            pool_name:
              term_string: target_pool
            routing_behaviour: STRICT
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: "add tar header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "3gpp-sbi-target-apiroot"
      - name: "add test_in header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_in"
      - name: "wrong pool"
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";


  // Configuration to test DND-64820, action_modify_header
  // Validate that headers required by an action are loaded into the run-context
  const std::string config_dnd_68420_modify_header = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: "strict to pool"
        condition:
          term_boolean: true
        actions:
        - action_modify_header:
            name: test_in
            replace_value:
              term_header: test_replace
        - action_modify_header:
            name: test_in
            prepend_value:
              term_header: test_prepend
        - action_modify_header:
            name: test_in
            append_value:
              term_header: test_append
        - action_route_to_pool:
            pool_name:
              term_string: target_pool
            routing_behaviour: STRICT
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: "add tar header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "3gpp-sbi-target-apiroot"
      - name: "add test_in header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_in"
      - name: "add test_replace header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_replace"
      - name: "add test_prepend header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_prepend"
      - name: "add test_append header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_append"
      - name: "wrong pool"
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";

  // Configuration to test DND-64820, action_modify_header with string-modifiers
  // append and prepend.
  // Validate that headers required by an action are loaded into the run-context
  const std::string config_dnd_68420_string_modify_header = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: "strict to pool"
        condition:
          term_boolean: true
        actions:
        - action_modify_header:
            name: test_in
            use_string_modifiers:
              string_modifiers:
              - append:
                  term_header: test_append
              - prepend:
                  term_header: test_prepend
        - action_route_to_pool:
            pool_name:
              term_string: target_pool
            routing_behaviour: STRICT
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: "add tar header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "3gpp-sbi-target-apiroot"
      - name: "add test_in header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_in"
      - name: "add test_prepend header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_prepend"
      - name: "add test_append header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_append"
      - name: "wrong pool"
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";


  // Configuration to test DND-64820, action_modify_header with string-modifier
  // search and replace
  // Validate that headers required by an action are loaded into the run-context
  const std::string config_dnd_68420_string_sar_modify_header = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: "strict to pool"
        condition:
          term_boolean: true
        actions:
        - action_modify_header:
            name: test_in
            use_string_modifiers:
              string_modifiers:
              - search_and_replace:
                  search_value:
                    term_header: test_search
                  replace_value:
                    term_header: test_replace
        - action_route_to_pool:
            pool_name:
              term_string: target_pool
            routing_behaviour: STRICT
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: "add tar header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "3gpp-sbi-target-apiroot"
      - name: "add test_in header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_in"
      - name: "add test_search header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_search"
      - name: "add test_replace header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_replace"
      - name: "wrong pool"
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";


  // Configuration to test DND-64820, action_modify_query_param with replace_value
  // Validate that headers required by an action are loaded into the run-context
  const std::string config_dnd_68420_modify_replace_query_param = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: "strict to pool"
        condition:
          term_boolean: true
        actions:
        - action_modify_query_param:
            key_name: test_in
            replace_value:
              term_header: test_replace
        - action_route_to_pool:
            pool_name:
              term_string: target_pool
            routing_behaviour: STRICT
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: "add tar header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "3gpp-sbi-target-apiroot"
      - name: "add test_replace header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_replace"
      - name: "wrong pool"
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";


  // Configuration to test DND-64820, action_modify_query_param with replace_value
  // Validate that headers required by an action are loaded into the run-context
  const std::string config_dnd_68420_modify_stringactions_query_param = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: "strict to pool"
        condition:
          term_boolean: true
        actions:
        - action_modify_query_param:
            key_name: test_in
            use_string_modifiers:
              string_modifiers:
              - search_and_replace:
                  search_value:
                    term_header: test_search
                  replace_value:
                    term_header: test_replace
              - append:
                  term_header: test_append
              - prepend:
                  term_header: test_prepend
        - action_route_to_pool:
            pool_name:
              term_string: target_pool
            routing_behaviour: STRICT
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: "add tar header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "3gpp-sbi-target-apiroot"
      - name: "add test_append header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_append"
      - name: "add test_prepend header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_prepend"
      - name: "add test_search header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_search"
      - name: "add test_replace header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_replace"
      - name: "wrong pool"
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";

  // Configuration to test DND-64820, action_modify_variable with table-lookup
  // Validate that headers required by an action are loaded into the run-context
  const std::string config_dnd_68420_modify_variable_kvt = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp
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
      - name: test_var
        header: test_in
        variable_name: test_var
      filter_rules:
      - name: "strict to pool"
        condition:
          term_boolean: true
        actions:
        - action_modify_variable:
            name: test_var
            table_lookup:
              table_name: mapping
              key:
                term_header: test_key
        - action_add_header:
            name: test_out
            value:
              term_var: test_var
        - action_route_to_pool:
            pool_name:
              term_string: target_pool
            routing_behaviour: STRICT
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: "add tar header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "3gpp-sbi-target-apiroot"
      - name: "add test_in header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_in"
      - name: "add test_key header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_key"
      - name: "wrong pool"
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
  key_value_tables:
   - name: mapping
     entries:
       - key: key_A
         value: val_A
       - key: key_B
         value: val_B
       - key: key_C
         value: val_c
)EOF";


  // Configuration to test DND-64820, action_modify_json_body with string_modifiers
  // Validate that headers required by an action are loaded into the run-context
  const std::string config_dnd_68420_modify_stringactions_json_body = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: "strict to pool"
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            json_operation:
              modify_json_value:
                json_pointer:
                  term_string: "/subscriberIdentifier"
                string_modifiers:
                - search_and_replace:
                    search_value:
                      term_header: test_search
                    replace_value:
                      term_header: test_replace
                - append:
                    term_header: test_append
                - prepend:
                    term_header: test_prepend
        - action_route_to_pool:
            pool_name:
              term_string: target_pool
            routing_behaviour: STRICT
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: "add tar header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "3gpp-sbi-target-apiroot"
      - name: "add test_append header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_append"
      - name: "add test_prepend header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_prepend"
      - name: "add test_search header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_search"
      - name: "add test_replace header to root_ctx"
        condition:
          op_exists:
            arg1:
              term_reqheader: "test_replace"
      - name: "wrong pool"
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";



  // Common function for preferred_host tests
  void testPreferredHost(
    const std::string& testcase,
    const std::string& header_name, const std::string& header_value,
    const std::string& expected_cluster, const std::string& expected_host
  ) {
    BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{expected_cluster, {expected_host}}})
    );
    initConfig(config_preferred_target, cluster_config);

    Http::TestRequestHeaderMapImpl headers{
        {":method", "GET"},
        {":path", "/"},
        {":authority", "host"},
        {"tc", testcase},
        {header_name, header_value},
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
    EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", expected_cluster));
    // EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-host", expected_host));
    EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));

    codec_client->close();
  }

  // Common function for preserve_path_tests
  void testPreservePath(
    const std::string& testcase, const std::string& expected_authority,
    const std::string& path, const std::string& expected_path,
    const std::string& header_name, const std::string& header_value,
    const std::string& expected_cluster, const std::string& expected_host
  ) {
    BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{expected_cluster, {expected_host}}})
    );
    initConfig(config_preferred_target, cluster_config);
    Http::TestRequestHeaderMapImpl headers{
        {":method", "GET"},
        {":path", path},
        {":authority", "host"},
        {"tc", testcase},
        {header_name, header_value},
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

    EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":path", expected_path));
    EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
    EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", expected_cluster));
    // EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-host", expected_host));
    EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", expected_authority));

    codec_client->close();
  }

  // Common function to test varIsEmptyString tests
  void testVarIsEmptyString(const Http::RequestHeaderMap& headers, const std::string& config) {
    BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"varMccIsEqualEmptyString", {"host.abc.com"}}})
    );
    initConfig(config, cluster_config);
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

    EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "varMccIsEqualEmptyString"));

    codec_client->close();
  }

  // Common function for all isInSubnet() tests
  void testIsInSubnet( const std::string& header_name, const std::string& address,
      const std::string& expected_cluster) {
    BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{expected_cluster, {"host.abc.com"}}})
    );
    initConfig(config_is_in_subnet, cluster_config);
    Http::TestRequestHeaderMapImpl headers{
        {":method", "POST"},
        {":path", "/"},
        {":authority", "host"},
        {header_name, address},
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

    EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", expected_cluster));

    codec_client->close();
  }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterIntegrationTest,
                         testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest())));

//------ Basic Positive Tests ---------------------------------------------
//ROUND ROBIN
TEST_P(EricProxyFilterIntegrationTest, TestRoundRobin) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"sepp_rp_A", {"host.abc.com"}}})
  ); // sepp_rp_A cluster containing one host with hostname 'host.abc.com'
  initConfig(config_basic, cluster_config); // config_basic is the eric proxy config

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"}
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));

  codec_client->close();
}


//PSEPP TO PREF
TEST_P(EricProxyFilterIntegrationTest, TestPreferredRouting) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"occ", {"eric-chfsim-1-mnc-456-mcc-456:443"}}})
  );
  initConfig(config_basic, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-chfsim-1-mnc-456-mcc-456:443"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "occ"));
  // EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-host",
  //"eric-chfsim-1-mnc-456-mcc-456:443"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));

  codec_client->close();
}

//PSEPP TO PREF (DND-32220)
TEST_P(EricProxyFilterIntegrationTest, TestPreferredRouting_DND_32220) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"occ", {"eric-chfsim-1-mnc-456-mcc-456:443"}}})
  );
  initConfig(config_basic, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-Chfsim-1-mnc-456-mcc-456:443"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "occ"));
  // EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-host",
  // "eric-chfsim-1-mnc-456-mcc-456:443"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));

  codec_client->close();
}

// STRICT BEHAVIOR
TEST_P(EricProxyFilterIntegrationTest, TestStrictRouting) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"universal_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}})
  );
  initConfig(config_basic, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "universal_pool"));
  // EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-host",
  // "eric-chfsim-6-mnc-456-mcc-456:3777"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));

  codec_client->close();
}

// STRICT BEHAVIOR  (DFW)
// malformed TaR (without scheme)
// should return 400 error
TEST_P(EricProxyFilterIntegrationTest, TestStrictRoutingMalformedTarNoScheme) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"universal_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}})
  );
  initConfig(config_basic, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "eric-chfsim-6-mnc-456-mcc-456:3777"},
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ(
      R"({"status": 400, "title": "Bad Request", "cause": "MANDATORY_IE_INCORRECT", "detail": "3gpp-sbi-target-apiroot_header_malformed"})",
      response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());

  codec_client_->close();
}

// STRICT BEHAVIOR
// malformed TaR (wrong syntax)
// should return 400 error
TEST_P(EricProxyFilterIntegrationTest, TestStrictRoutingMalformedTarWrongSyntax) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"universal_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}})
  );
  initConfig(config_basic, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777!"},
      };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ(
      R"({"status": 400, "title": "Bad Request", "cause": "MANDATORY_IE_INCORRECT", "detail": "3gpp-sbi-target-apiroot_header_malformed"})",
      response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());

  codec_client_->close();
}

// A BASIC TEST, STRICT BEHAVIOR, with a (dummy) screening filter before/after routing (DND-26598)
TEST_P(EricProxyFilterIntegrationTest, TestStrictRoutingAfterScreening) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"universal_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}})
  );
  initConfig(config_basic_phase_1_2_3_4_6, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "universal_pool"));
  // EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-host",
  // "eric-chfsim-6-mnc-456-mcc-456:3777"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-it-header-name-added", "x-it-header-value-added-screening_ph1"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-added-by-response_ph4", "x-it-header-value-added-screening_ph4"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-added-by-response_ph6", "x-it-header-value-added-screening_ph6"));
  codec_client->close();
}

// A BASIC TEST, STRICT BEHAVIOR  (DFW), with a (dummy) screening filter after routing (DND-26598)
TEST_P(EricProxyFilterIntegrationTest, TestStrictRoutingBeforeScreening) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"universal_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}})
  );
  initConfig(config_basic_phase_1_2_3_4_6, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "universal_pool"));
  // EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-host",
  // "eric-chfsim-6-mnc-456-mcc-456:3777"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-added-by-response_ph4", "x-it-header-value-added-screening_ph4"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-added-by-response_ph6", "x-it-header-value-added-screening_ph6"));
  codec_client->close();
}

//------Test "preferred_host" ------------------------------------------------------------------
// Hdr2Pool: preferred host from header, route to pool1
TEST_P(EricProxyFilterIntegrationTest, TestPreferredHdr2Pool) {
  testPreferredHost("Hdr2Pool", "3gpp-Sbi-target-apiRoot",
                    "http://eric-chfsim-6-mnc-456-mcc-456:3777", "pool1",
                    "eric-chfsim-6-mnc-456-mcc-456:3777");
}

// Hdr2RP: preferred host from header, route to roaming-partner rp_A (pool sepp_rp_A)
TEST_P(EricProxyFilterIntegrationTest, TestPreferredHdr2RP) {
  // !!! FIXME(eedala): This test only passes when the node_type is not SEPP in the configuration.
  // !!!                However, we route to a roaming-partner, which is a SEPP function.
  testPreferredHost("Hdr2RP", "target",
                    "http://eric-chfsim-6-mnc-456-mcc-456:3777/path/that/should/not/matter?at=all",
                    "sepp_rp_A", "eric-chfsim-6-mnc-456-mcc-456:3777");
}

// Var2Pool: preferred host from var, route to pool2
TEST_P(EricProxyFilterIntegrationTest, TestPreferredVar2Pool) {
 testPreferredHost("Var2Pool",
     "3gpp-sbi-target-apiroot", "http://eric-chfsim-6-mnc-456-mcc-456:3777/path/that/should/not/matter?at=all",
     "pool2", "chfsim-6:80");
}

// Var2RP: preferred host from var, route to roaming-partner rp_B (pool sepp_rp_B)
TEST_P(EricProxyFilterIntegrationTest, TestPreferredVar2RP) {
 testPreferredHost("Var2RP",
     "3gpp-sbi-target-apiroot", "http://eric-chfsim-6-mnc-456-mcc-456:3777/path/that/should/not/matter?at=all",
     "sepp_rp_B", "chfsim-6:80");
}

// Str2Pool: preferred host from string constant, route to pool3
TEST_P(EricProxyFilterIntegrationTest, TestPreferredStr2Pool) {
 testPreferredHost("Str2Pool",
     "ignored", "also ignored",
     "pool3", "fixed_target:80");
}

// Str2RP: preferred host from string constant, route to roaming-partner rp_C (pool sepp_rp_C)
TEST_P(EricProxyFilterIntegrationTest, TestPreferredStr2RP) {
 testPreferredHost("Str2RP",
     "dummy", "",
     "sepp_rp_C", "target:80");
}

//-------Test "preserve_if_indirect"-----------------------------------------------------------------
// No automatic check of metadata of outgoing requests. Check manually that TestPreferredHdr2Pool
// and TestPreferredVar2RP both send out metadata for target-api-root processing.
// The two testcases here shall send metadata with absolute and relative paths.
TEST_P(EricProxyFilterIntegrationTest, TestPreserveIfIndirectPathPool) {
  testPreservePath("Hdr2PoolPreservePath", "cg2.operator.com:443",
      "http://cg2.operator.com:443/path/to/resource?arg=val&arg2=val2", "/path/to/resource?arg=val&arg2=val2",
      "3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777",
      "pool1", "eric-chfsim-6-mnc-456-mcc-456:3777");
}
TEST_P(EricProxyFilterIntegrationTest, TestPreserveIfIndirectPathRP) {
  testPreservePath("Hdr2RPPreservePath", "[fe80:ab::cd]:443",
      "https://[fe80:ab::cd]:443/path/to/resource?arg=val&arg2=val2", "/path/to/resource?arg=val&arg2=val2",
      "target", "http://eric-chfsim-6-mnc-456-mcc-456:3777",
      "sepp_rp_A", "eric-chfsim-6-mnc-456-mcc-456:3777");
}


//-------DND-24977 Coredump ------------------------------------------------------
TEST_P(EricProxyFilterIntegrationTest, Test_DND24977_pass) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"set1", {"host.abc.com"}}})
  );
  initConfig(config_dnd24977, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-Discovery-nf-set-id", "set1.amfset.5gc.mnc073.mcc262"},
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

  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "set1"));

  codec_client->close();
}

TEST_P(EricProxyFilterIntegrationTest, Test_DND24977_crash) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"set2", {"host.abc.com"}}})
  );
  initConfig(config_dnd24977, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-Discovery-nf-set-id", "set2.amfset.5gc.mnc073.mcc262"},
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

  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "set2"));

  codec_client->close();
}

//------- DND-26150 Test "req.header["3gpp-sbi-target-apiRoot"] exists" ------------
// (Header is not referenced in a filter-data rule)
// Header is present in the request:
TEST_P(EricProxyFilterIntegrationTest, Test_DND26150_header_exists_present) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"headerExists", {"host.abc.com"}}})
  );
  initConfig(config_header_exists, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://set1.amfset.5gc.mnc073.mcc262"},
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

  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "headerExists"));

  codec_client->close();
}

// Header is not present in the request (DND-26150)
TEST_P(EricProxyFilterIntegrationTest, Test_DND26150_header_exists_not_present) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"headerDoesNotExist", {"host.abc.com"}}})
  );
  initConfig(config_header_exists, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
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

  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "headerDoesNotExist"));

  codec_client->close();
}

//----- Test non-matching extractor-regex vs. empty string and "exist" ------
// Test the "exists" operator on a non-matched var -> expected to not match
// because the variable will get an empty string as its value = it does exists
TEST_P(EricProxyFilterIntegrationTest, TestVarExists) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"varMncNotExists", {"host.abc.com"}}})
  );
  initConfig(config_var_not_exists, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://set1.amfset.5gc"},
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

  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "varMncNotExists"));

  codec_client->close();
}

// Test the comparison of a non-matched var with the empty string. Is expected to match.
TEST_P(EricProxyFilterIntegrationTest, TestCompareVarEmptyString) {
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-3"},
      };
  testVarIsEmptyString(headers, config_header_var_is_empty_string);
}


// Test the comparison of a non-matched var with the empty string. The variable
// is extracted from a non-existing header.
// The comparison is expected to match because the variable(s) are set to the empty string.
TEST_P(EricProxyFilterIntegrationTest, TestCompareVarEmptyString2) {
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      };
  testVarIsEmptyString(headers, config_header_var_is_empty_string);
}

//------- Test "query.param["name"] is empty" ------------
// Query parameter does not exist in the request:
TEST_P(EricProxyFilterIntegrationTest, query_param_does_not_exist) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"queryParamIsEmpty", {"host.abc.com"}}})
  );
  initConfig(config_query_param_is_empty, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://set1.amfset.5gc.mnc073.mcc262"},
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

  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "queryParamIsEmpty"));

  codec_client->close();
}

// Query parameter has value in the request:
TEST_P(EricProxyFilterIntegrationTest, query_param_has_value) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"queryParamIsNotEmpty", {"host.abc.com"}}})
  );
  initConfig(config_query_param_is_empty, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://set1.amfset.5gc.mnc073.mcc262"},
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

  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "queryParamIsNotEmpty"));

  codec_client->close();
}

//------- Test "api_context related conditions" ------------
// api name equals nnrf-disc:
TEST_P(EricProxyFilterIntegrationTest, api_context_nnrf_disc) {
  BasicClusterConfigurator cluster_config =
      BasicClusterConfigurator(ClusterDefinition({{"apiContextNameEqualsNnrf", {"host.abc.com"}},
                                                  {"apiContextNameIsEmpty", {"host.abc.com"}}}));
  initConfig(config_apicontext_name, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances"},
      {":authority", "host"},
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

  EXPECT_THAT(request_stream->headers(),
              Http::HeaderValueOf("x-cluster", "apiContextNameEqualsNnrf"));
  EXPECT_THAT(request_stream->headers(),
              Http::HeaderValueOf("x-it-header-api-context-name", "x-nnrf-disc_ph3"));
  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("x-it-header-api-context-name", "x-nnrf-disc_ph4"));

  codec_client->close();
}

//--------- Test the "isInSubnet" operator --------------------------------
// Header with the target address inside the IPv4 subnet is 10.0.0.0/24
TEST_P(EricProxyFilterIntegrationTest, Test_isInSubnetHeaderIPv4Inside) {
  testIsInSubnet("address-header", std::string("10.0.0.4"), std::string("headerIPv4"));
}

// Variable with the target address inside the IPv4 subnet 10.0.0.0/24
TEST_P(EricProxyFilterIntegrationTest, Test_isInSubnetVarIPv4Inside) {
  testIsInSubnet("target-address", std::string("10.0.0.4"), std::string("varIPv4"));
}

// Header with the target address not inside the IPv4 subnet is 10.0.0.0/24
TEST_P(EricProxyFilterIntegrationTest, Test_isInSubnetHeaderIPv4Outside) {
  testIsInSubnet("address-header", std::string("10.0.33.4"), std::string("wrong_pool"));
}

// Variable with the target address not inside the IPv4 subnet 10.0.0.0/24
TEST_P(EricProxyFilterIntegrationTest, Test_isInSubnetVarIPv4Outside) {
  testIsInSubnet("target-address", std::string("10.44.0.4"), std::string("wrong_pool"));
}

// Header with the target address inside the IPv6 subnet is fe80::c88d:edff:fee8:acd8/64
TEST_P(EricProxyFilterIntegrationTest, Test_isInSubnetHeaderIPv6Inside) {
  testIsInSubnet("address-header", std::string("fe80::c88d:edff:fee8:acd8"), std::string("headerIPv6"));
}

// Variable with the target address inside the IPv6 subnet fe80::c88d:edff:fee8:acd8/64
TEST_P(EricProxyFilterIntegrationTest, Test_isInSubnetVarIPv6Inside) {
  testIsInSubnet("target-address", std::string("fe80::c88d:edff:fee8:AAAA"), std::string("varIPv6"));
}

// Header with the target address not inside the IPv6 subnet is fe80::c88d:edff:fee8:acd8/64
TEST_P(EricProxyFilterIntegrationTest, Test_isInSubnetHeaderIPv6Outside) {
  testIsInSubnet("address-header", std::string("fe80:3::c88d:edff:fee8:acd8"), std::string("wrong_pool"));
}

// Variable with the target address not inside the IPv6 subnet fe80::c88d:edff:fee8:acd8/64
TEST_P(EricProxyFilterIntegrationTest, Test_isInSubnetVarIPv6Outside) {
  testIsInSubnet("target-address", std::string("fe33::c88d:edff:fee8:acd8"), std::string("wrong_pool"));
}

//------------------------------------------------------------------------------------------------

// DND 68420 / SCDS-1702: action_route_to_pool with strict routing
// failed because the TaR header was "empty" when reading the preferred
// host from it although the request contained the correct host in TaR.
// Reason was that the header was not marked as required for the routing-case.
TEST_P(EricProxyFilterIntegrationTest, TestDND68420RouteToPool) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"target_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}})
  );
  initConfig(config_dnd_68420_route_to_pool, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "target_pool"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));

  codec_client->close();
}

// DND 68420 / SCDS-1702: action_route_to_roaming_partner with strict routing
// failed because the TaR header was "empty" when reading the preferred
// host from it although the request contained the correct host in TaR.
// Reason was that the header was not marked as required for the routing-case.
TEST_P(EricProxyFilterIntegrationTest, TestDND68420RouteToRoaming_partner) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"sepp_rp_A", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}})
  );
  initConfig(config_dnd_68420_route_to_roaming_partner, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));

  codec_client->close();
}



// DND 68420 / SCDS-1702: action_add_header with strict routing
TEST_P(EricProxyFilterIntegrationTest, TestDND68420AddHeader) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"target_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}})
  );
  initConfig(config_dnd_68420_add_header, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"test_in", "test_val"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "target_pool"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("test_in", "test_val"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("test_out", "test_val"));

  codec_client->close();
}

// DND 68420 / SCDS-1702: action_modify_header with strict routing
TEST_P(EricProxyFilterIntegrationTest, TestDND68420ModifyHeader) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"target_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}})
  );
  initConfig(config_dnd_68420_modify_header, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"test_in", "test_val"},
      {"test_replace", "Replacement"},
      {"test_prepend", "Prefix"},
      {"test_append", "Suffix"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "target_pool"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("test_in", "PrefixReplacementSuffix"));

  codec_client->close();
}

// DND 68420 / SCDS-1702: action_modify_header with string-modifiers (append
// and prepend) and strict routing
TEST_P(EricProxyFilterIntegrationTest, TestDND68420StringModifyHeader) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"target_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}})
  );
  initConfig(config_dnd_68420_string_modify_header, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"test_in", "Test_val"},
      {"test_prepend", "Prefix"},
      {"test_append", "Suffix"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "target_pool"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("test_in", "PrefixTest_valSuffix"));

  codec_client->close();
}

// DND 68420 / SCDS-1702: action_modify_header with string-modifiers (search
// and replace) and strict routing
TEST_P(EricProxyFilterIntegrationTest, TestDND68420StringSaRModifyHeader) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"target_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}})
  );
  initConfig(config_dnd_68420_string_sar_modify_header, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"test_in", "Test_val"},
      {"test_search", "st_v"},
      {"test_replace", "rmin"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "target_pool"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("test_in", "Terminal"));

  codec_client->close();
}

// DND 68420 / SCDS-1702: action_modify_query_param with replace =and strict routing
TEST_P(EricProxyFilterIntegrationTest, TestDND68420ModifyReplaceQueryParam) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"target_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}})
  );
  initConfig(config_dnd_68420_modify_replace_query_param, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/?eric=son&test_in=telecom&euro=lab"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"test_replace", "REPLACED"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":path", "/?eric=son&euro=lab&test_in=REPLACED"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "target_pool"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));

  codec_client->close();
}


// DND 68420 / SCDS-1702: action_modify_query_param with string actions and strict routing
// First search&replace, then prepend, then append
TEST_P(EricProxyFilterIntegrationTest, TestDND68420StringActionsModifyQueryParam) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"target_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}})
  );
  initConfig(config_dnd_68420_modify_stringactions_query_param, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/?eric=son&test_in=telecom&euro=lab"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"test_search", "telecom"},
      {"test_replace", "REPLACED"},
      {"test_prepend", "Prefix"},
      {"test_append", "Suffix"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":path", "/?eric=son&euro=lab&test_in=PrefixREPLACEDSuffix"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "target_pool"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));

  codec_client->close();
}

// DND 68420 / SCDS-1702: action_modify_variable with kvt-lookup and strict routing
// First search&replace, then prepend, then append
TEST_P(EricProxyFilterIntegrationTest, TestDND68420ModifyVariableKvt) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"target_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}})
  );
  initConfig(config_dnd_68420_modify_variable_kvt, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/?eric=son&test_in=telecom&euro=lab"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"test_in", "this is a test"},
      {"test_key", "key_B"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "target_pool"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("test_out", "val_B"));

  codec_client->close();
}


// DND 68420 / SCDS-1702: action_modify_json_body with string actions and strict routing
// First search&replace, then prepend, then append
TEST_P(EricProxyFilterIntegrationTest, TestDND68420StringActionsModifyJsonBody) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
    ClusterDefinition({{"target_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}})
  );
  initConfig(config_dnd_68420_modify_stringactions_json_body, cluster_config);
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/?eric=son&test_in=telecom&euro=lab"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"test_search", "46000"},
      {"test_replace", "REPLACED"},
      {"test_prepend", "Prefix"},
      {"test_append", "Suffix"},
      };

  std::string body{R"(
{
  "subscriberIdentifier": "imsi-460001357924610",
  "nfConsumerIdentification": {
    "nfName": "123e-e8b-1d3-a46-421",
    "nfIPv4Address": "192.168.0.1",
    "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348"
  }
})"};
 std::string expected_body{R"(
{
  "subscriberIdentifier": "Prefiximsi-REPLACED1357924610Suffix",
  "nfConsumerIdentification": {
    "nfName": "123e-e8b-1d3-a46-421",
    "nfIPv4Address": "192.168.0.1",
    "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348"
  }
})"};

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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "target_pool"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf(":authority", "host"));
  EXPECT_EQ(Json::parse(expected_body), Json::parse(request_stream->body().toString()));

  codec_client->close();
}


} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
