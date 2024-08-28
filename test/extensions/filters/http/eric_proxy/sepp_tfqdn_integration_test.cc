#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/extensions/filters/http/eric_proxy/tfqdn_codec.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"
#include "include/nlohmann/json.hpp"

#include "config_utils/pluggable_configurator.h"
#include "config_utils/basic_cluster_configurator.h"
#include "config_utils/endpoint_md_cluster_md_configurator.h"

#include <iostream>
#include <ostream>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

using json = nlohmann::json;

enum Scope {ALL, SOME, FEW, NONE};

// Configuration for C-SEPP for external to internal routing:
std::string config_basic_ext_to_int = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.ownplmn.com
  own_external_port: 9090
  rp_name_table : rp_san_to_name
  request_filter_cases:
    routing:
      ext_nw:
        name: ext_network
        ext_nw_fc_config_list:
        - per_rp_fc_config:
            rp_to_fc_map:
              rp_A: default_routing
  key_value_tables:
    - name: rp_san_to_name
      entries:
        - key: 'smf1.external_plmn.com'
          value: rp_A
  callback_uri_klv_table: callback_uris
  key_list_value_tables:
    - name: callback_uris
      entries:
        - key: test_api_name_1/v1
          value:
            - /nfInstances/*/nfServices/*/test_api_1_cb_uri_1
            - /nfInstances/*/nfServices/*/test_api_1_cb_uri_2
        - key: test_api_name_2/v1
          value:
            - /nfInstances/*/nfServices/*/test_api_2_cb_uri_1
            - /nfInstances/*/nfServices/*/test_api_2_cb_uri_2
        - key: nchf-convergedcharging/v2
          value:
            - /notifyUri
  nf_types_requiring_t_fqdn:
    - SMF
    - PCF
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
      filter_rules:
      - name: c_no_tar_pool
        condition:
          op_not:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: c_no_tar_pool
            routing_behaviour: STRICT
      - name: c_tar_nf1_other_plmn
        condition:
          op_and:
            arg1:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nf1.other-plmn.com:5678'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':authority'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'sepp.ownplmn.com:80'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: c_tar_nf1_other_plmn
            routing_behaviour: ROUND_ROBIN
      - name: csepp_to_rp_A
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc },
                           typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc },
                           typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: psepp_to_dfw
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc },
                           typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456'}}
            arg2:
              op_and:
                arg1:
                  op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc },
                               typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
                arg2:
                  op_or:
                    arg1:
                      op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim },
                                   typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-6'}}
                    arg2:
                      op_or:
                        arg1:
                          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim },
                                       typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-7'}}
                        arg2:
                          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim },
                                       typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-8'}}
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
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc },
                           typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc },
                           typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
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

std::string config_basic = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.ownplmn.com
  own_internal_port: 80
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  callback_uri_klv_table: callback_uris
  key_list_value_tables:
    - name: callback_uris
      entries:
        - key: test_api_name_1/v1
          value:
            - /nfInstances/*/nfServices/*/test_api_1_cb_uri_1
            - /nfInstances/*/nfServices/*/test_api_1_cb_uri_2
        - key: test_api_name_2/v1
          value:
            - /nfInstances/*/nfServices/*/test_api_2_cb_uri_1
            - /nfInstances/*/nfServices/*/test_api_2_cb_uri_2
        - key: nchf-convergedcharging/v2
          value:
            - /notifyUri
  nf_types_requiring_t_fqdn:
    - SMF
    - PCF
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
      filter_rules:
      - name: c_no_tar_pool
        condition:
          op_not:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: c_no_tar_pool
            routing_behaviour: ROUND_ROBIN
      - name: c_tar_nf1_other_plmn
        condition:
          op_and:
            arg1:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nf1.other-plmn.com:5678'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':authority'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'sepp.ownplmn.com:80'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: c_tar_nf1_other_plmn
            routing_behaviour: ROUND_ROBIN
      - name: csepp_to_rp_A
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc },
                           typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc },
                           typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: csepp_to_rp_A2
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: '3gpp-sbi-target-apiroot'},
                       typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'http://prod.plmnb.com:1234' }}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: psepp_to_dfw
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc },
                           typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456'}}
            arg2:
              op_and:
                arg1:
                  op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc },
                               typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
                arg2:
                  op_or:
                    arg1:
                      op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim },
                                   typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-6'}}
                    arg2:
                      op_or:
                        arg1:
                          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim },
                                       typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-7'}}
                        arg2:
                          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim },
                                       typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-8'}}
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
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc },
                           typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc },
                           typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
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

// Configuration for P-SEPP
std::string config_basic_p_sepp = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.ownplmn.com
  own_external_port: 9090
  rp_name_table : rp_san_to_name
  request_filter_cases:
    routing:
      ext_nw:
        name: "external network"
        ext_nw_fc_config_list:
        - per_rp_fc_config:
            rp_to_fc_map:
              rp_A: rp_A_routing
            default_fc_for_rp_not_found: default_routing
  key_value_tables:
    - name: rp_san_to_name
      entries:
        - key: '*.ext-plmn.com'
          value: rp_A
  callback_uri_klv_table: callback_uris
  key_list_value_tables:
    - name: callback_uris
      entries:
        - key: test_api_name_1/v1
          value:
            - /nfInstances/*/nfServices/*/test_api_1_cb_uri_1
            - /nfInstances/*/nfServices/*/test_api_1_cb_uri_2
        - key: test_api_name_2/v1
          value:
            - /nfInstances/*/nfServices/*/test_api_2_cb_uri_1
            - /nfInstances/*/nfServices/*/test_api_2_cb_uri_2
        - key: nchf-convergedcharging/v2
          value:
            - /notifyUri
  nf_types_requiring_t_fqdn:
    - SMF
    - PCF
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: psepp_to_pref
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: occ
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
    - name: rp_A_routing
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
      filter_rules:
      - name: no_tar_header
        condition:
          op_not:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: no_tar_pool
            routing_behaviour: ROUND_ROBIN
      - name: PAuthOtherFqdn
        condition:
          op_and:
            arg1:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nf.ownplmn.com:9090'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':authority'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'sepp.ownplmn.com:9090'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: tar_is_nf_ext_pool
            routing_behaviour: STRICT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: TestPAuthTaR
        condition:
          op_and:
            arg1:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nf.ownplmn.com:80'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':authority'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'sepp.ownplmn.com:9090'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: tar_is_nf_int_pool
            routing_behaviour: STRICT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: csepp_to_rp_A
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc },
                           typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc },
                           typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
      - name: psepp_to_dfw
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc },
                           typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456'}}
            arg2:
              op_and:
                arg1:
                  op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc },
                               typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
                arg2:
                  op_or:
                    arg1:
                      op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim },
                                   typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-6'}}
                    arg2:
                      op_or:
                        arg1:
                          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim },
                                       typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-7'}}
                        arg2:
                          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim },
                                       typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-8'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: universal_pool
            routing_behaviour: STRICT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: psepp_to_pref
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc },
                           typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc },
                           typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: occ
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

//  request_fc_table : rp_to_fc
//  request_fc_kvt_key: ROUTING
//  key_value_tables:
//   - name: rp_to_fc
//     entries:
//       - key: ROUTING
//         value: default_routing
//       - key: '*.ext-plmn.com'
//         value: rp_A_routing
// Configuration for P-SEPP (DND-28889) no CB-URIs configured
std::string config_basic_p_sepp_no_cburi = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.ownplmn.com
  own_external_port: 9090
  rp_name_table : rp_san_to_name
  request_filter_cases:
    routing:
      ext_nw:
        name: "external network"
        ext_nw_fc_config_list:
        - per_rp_fc_config:
            rp_to_fc_map:
              rp_A: rp_A_routing
            default_fc_for_rp_not_found: default_routing
  key_value_tables:
    - name: rp_san_to_name
      entries:
        - key: '*.ext-plmn.com'
          value: rp_A
  nf_types_requiring_t_fqdn:
    - SMF
    - PCF
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: psepp_to_pref
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: occ
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
    - name: rp_A_routing
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
      filter_rules:
      - name: no_tar_header
        condition:
          op_not:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: no_tar_pool
            routing_behaviour: ROUND_ROBIN
      - name: PAuthOtherFqdn
        condition:
          op_and:
            arg1:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nf.ownplmn.com:9090'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':authority'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'sepp.ownplmn.com:9090'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: tar_is_nf_ext_pool
            routing_behaviour: STRICT
      - name: TestPAuthTaR
        condition:
          op_and:
            arg1:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nf.ownplmn.com:80'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':authority'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'sepp.ownplmn.com:9090'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: tar_is_nf_int_pool
            routing_behaviour: STRICT
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
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

//------------------------------------------------------------------------
// Configuration to reproduce DND-28882, Envoy crashes in tcmalloc with a crazy big size
const std::string config_dnd_28882 = R"EOF(
  "name": "envoy.filters.http.cdn_loop"
  "typed_config":
    "@type": "type.googleapis.com/envoy.extensions.filters.http.cdn_loop.v3.CdnLoopConfig"
    "cdn_id": "2.0 sepp.mnc.567.mcc.765.ericsson.de"
  "name": "envoy.filters.http.eric-proxy"
  "typed_config": {
    "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig",
    "filter_cases": [
      {
        "filter_data": [
          {
            "extractor_regex": "^(http(s?)://)?(?P<nf>.+?)\\..+?\\.(?P<mnc>.+?)\\..+?\\.(?P<mcc>.+?)\\..*",
            "header": "3gpp-Sbi-target-apiRoot",
            "name": "apiRoot_data"
          }
        ],
        "filter_rules": [
          {
            "actions": [
              {
                "action_add_header": {
                  "if_exists": "REPLACE",
                  "name": "x-eric-fop",
                  "value": {
                    "term_string": "fob_default"
                  }
                }
              },
              {
                "action_route_to_roaming_partner": {
                  "preserve_if_indirect": "TARGET_API_ROOT",
                  "roaming_partner_name": "RP_1",
                  "routing_behaviour": "ROUND_ROBIN"
                }
              }
            ],
            "name": "csepp_to_RP-1",
            "condition": {
              "op_and": {
                "arg1": {
                  "op_equals": {
                    "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "mnc"
                    },
                    "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "012"
                    }
                  }
                },
                "arg2": {
                  "op_equals": {
                    "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "mcc"
                    },
                    "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "210"
                    }
                  }
                }
              }
            }
          },
          {
            "actions": [
              {
                "action_add_header": {
                  "if_exists": "REPLACE",
                  "name": "x-eric-fop",
                  "value": {
                    "term_string": "fob_default"
                  }
                }
              },
              {
                "action_route_to_roaming_partner": {
                  "preserve_if_indirect": "TARGET_API_ROOT",
                  "roaming_partner_name": "RP_2",
                  "routing_behaviour": "ROUND_ROBIN"
                }
              }
            ],
            "name": "csepp_to_RP-2",
            "condition": {
              "op_and": {
                "arg1": {
                  "op_equals": {
                    "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "mnc"
                    },
                    "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "123"
                    }
                  }
                },
                "arg2": {
                  "op_equals": {
                    "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "mcc"
                    },
                    "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "321"
                    }
                  }
                }
              }
            }
          },
          {
            "actions": [
              {
                "action_add_header": {
                  "if_exists": "REPLACE",
                  "name": "x-eric-fop",
                  "value": {
                    "term_string": "fob_default"
                  }
                }
              },
              {
                "action_route_to_roaming_partner": {
                  "preserve_if_indirect": "TARGET_API_ROOT",
                  "roaming_partner_name": "RP_3",
                  "routing_behaviour": "ROUND_ROBIN"
                }
              }
            ],
            "name": "csepp_to_RP-3",
            "condition": {
              "op_and": {
                "arg1": {
                  "op_equals": {
                    "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "mnc"
                    },
                    "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "234"
                    }
                  }
                },
                "arg2": {
                  "op_equals": {
                    "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "mcc"
                    },
                    "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "432"
                    }
                  }
                }
              }
            }
          },
          {
            "actions": [
              {
                "action_add_header": {
                  "if_exists": "REPLACE",
                  "name": "x-eric-fop",
                  "value": {
                    "term_string": "fob_default"
                  }
                }
              },
              {
                "action_route_to_pool": {
                  "pool_name": {
                    "term_string": "universal_pool#!_#subset_sr:"
                  },
                  "preferred_target": {
                    "term_header": "3gpp-Sbi-target-apiRoot"
                  },
                  "preserve_if_indirect": "TARGET_API_ROOT",
                  "routing_behaviour": "ROUND_ROBIN"
                }
              }
            ],
            "name": "pSepp_to_ownPLMN_NRF_universal",
            "condition": {
              "op_and": {
                "arg1": {
                  "op_and": {
                    "arg1": {
                      "op_equals": {
                        "typed_config1": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_var": "nf"
                        },
                        "typed_config2": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_string": "nfNrf1"
                        }
                      }
                    },
                    "arg2": {
                      "op_equals": {
                        "typed_config1": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_var": "mnc"
                        },
                        "typed_config2": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_string": "567"
                        }
                      }
                    }
                  }
                },
                "arg2": {
                  "op_equals": {
                    "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "mcc"
                    },
                    "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "765"
                    }
                  }
                }
              }
            }
          },
          {
            "actions": [
              {
                "action_add_header": {
                  "if_exists": "REPLACE",
                  "name": "x-eric-fop",
                  "value": {
                    "term_string": "fob_default"
                  }
                }
              },
              {
                "action_route_to_pool": {
                  "pool_name": {
                    "term_string": "universal_pool#!_#subset_sr:"
                  },
                  "preferred_target": {
                    "term_header": "3gpp-Sbi-target-apiRoot"
                  },
                  "preserve_if_indirect": "TARGET_API_ROOT",
                  "routing_behaviour": "ROUND_ROBIN"
                }
              }
            ],
            "name": "default_universal",
            "condition": {
              "op_equals": {
                "typed_config1": {
                  "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                  "term_var": "nf"
                },
                "typed_config2": {
                  "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                  "term_string": ""
                }
              }
            }
          },
          {
            "actions": [
              {
                "action_add_header": {
                  "if_exists": "REPLACE",
                  "name": "x-eric-fop",
                  "value": {
                    "term_string": "fob_default"
                  }
                }
              },
              {
                "action_route_to_pool": {
                  "pool_name": {
                    "term_string": "Pool_NfAmf#!_#aggr:"
                  },
                  "preferred_target": {
                    "term_header": "3gpp-Sbi-target-apiRoot"
                  },
                  "preserve_if_indirect": "TARGET_API_ROOT",
                  "routing_behaviour": "ROUND_ROBIN"
                }
              }
            ],
            "name": "pSepp_to_ownPLMN_static_NfAmf",
            "condition": {
              "op_and": {
                "arg1": {
                  "op_and": {
                    "arg1": {
                      "op_or": {
                        "arg1": {
                          "op_equals": {
                            "typed_config1": {
                              "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                              "term_var": "nf"
                            },
                            "typed_config2": {
                              "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                              "term_string": "nfAmf1"
                            }
                          }
                        },
                        "arg2": {
                          "op_equals": {
                            "typed_config1": {
                              "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                              "term_var": "nf"
                            },
                            "typed_config2": {
                              "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                              "term_string": "nfAmf2"
                            }
                          }
                        }
                      }
                    },
                    "arg2": {
                      "op_equals": {
                        "typed_config1": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_var": "mnc"
                        },
                        "typed_config2": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_string": "567"
                        }
                      }
                    }
                  }
                },
                "arg2": {
                  "op_equals": {
                    "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "mcc"
                    },
                    "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "765"
                    }
                  }
                }
              }
            }
          },
          {
            "actions": [
              {
                "action_add_header": {
                  "if_exists": "REPLACE",
                  "name": "x-eric-fop",
                  "value": {
                    "term_string": "fob_default"
                  }
                }
              },
              {
                "action_route_to_pool": {
                  "pool_name": {
                    "term_string": "Pool_NfAusf#!_#aggr:"
                  },
                  "preferred_target": {
                    "term_header": "3gpp-Sbi-target-apiRoot"
                  },
                  "preserve_if_indirect": "TARGET_API_ROOT",
                  "routing_behaviour": "ROUND_ROBIN"
                }
              }
            ],
            "name": "pSepp_to_ownPLMN_static_NfAusf",
            "condition": {
              "op_and": {
                "arg1": {
                  "op_and": {
                    "arg1": {
                      "op_equals": {
                        "typed_config1": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_var": "nf"
                        },
                        "typed_config2": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_string": "nfAusf1"
                        }
                      }
                    },
                    "arg2": {
                      "op_equals": {
                        "typed_config1": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_var": "mnc"
                        },
                        "typed_config2": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_string": "567"
                        }
                      }
                    }
                  }
                },
                "arg2": {
                  "op_equals": {
                    "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "mcc"
                    },
                    "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "765"
                    }
                  }
                }
              }
            }
          },
          {
            "actions": [
              {
                "action_add_header": {
                  "if_exists": "REPLACE",
                  "name": "x-eric-fop",
                  "value": {
                    "term_string": "fob_default"
                  }
                }
              },
              {
                "action_route_to_pool": {
                  "pool_name": {
                    "term_string": "Pool_NfUdm#!_#aggr:"
                  },
                  "preferred_target": {
                    "term_header": "3gpp-Sbi-target-apiRoot"
                  },
                  "preserve_if_indirect": "TARGET_API_ROOT",
                  "routing_behaviour": "ROUND_ROBIN"
                }
              }
            ],
            "name": "pSepp_to_ownPLMN_static_NfUdm",
            "condition": {
              "op_and": {
                "arg1": {
                  "op_and": {
                    "arg1": {
                      "op_or": {
                        "arg1": {
                          "op_or": {
                            "arg1": {
                              "op_or": {
                                "arg1": {
                                  "op_or": {
                                    "arg1": {
                                      "op_equals": {
                                        "typed_config1": {
                                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                                          "term_var": "nf"
                                        },
                                        "typed_config2": {
                                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                                          "term_string": "nfUdm1"
                                        }
                                      }
                                    },
                                    "arg2": {
                                      "op_equals": {
                                        "typed_config1": {
                                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                                          "term_var": "nf"
                                        },
                                        "typed_config2": {
                                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                                          "term_string": "nfUdm2"
                                        }
                                      }
                                    }
                                  }
                                },
                                "arg2": {
                                  "op_equals": {
                                    "typed_config1": {
                                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                                      "term_var": "nf"
                                    },
                                    "typed_config2": {
                                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                                      "term_string": "nfUdm3"
                                    }
                                  }
                                }
                              }
                            },
                            "arg2": {
                              "op_equals": {
                                "typed_config1": {
                                  "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                                  "term_var": "nf"
                                },
                                "typed_config2": {
                                  "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                                  "term_string": "nfUdm4"
                                }
                              }
                            }
                          }
                        },
                        "arg2": {
                          "op_equals": {
                            "typed_config1": {
                              "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                              "term_var": "nf"
                            },
                            "typed_config2": {
                              "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                              "term_string": "nfUdm99"
                            }
                          }
                        }
                      }
                    },
                    "arg2": {
                      "op_equals": {
                        "typed_config1": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_var": "mnc"
                        },
                        "typed_config2": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_string": "567"
                        }
                      }
                    }
                  }
                },
                "arg2": {
                  "op_equals": {
                    "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "mcc"
                    },
                    "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "765"
                    }
                  }
                }
              }
            }
          },
          {
            "actions": [
              {
                "action_add_header": {
                  "if_exists": "REPLACE",
                  "name": "x-eric-fop",
                  "value": {
                    "term_string": "fob_strict"
                  }
                }
              },
              {
                "action_route_to_pool": {
                  "pool_name": {
                    "term_string": "Universal_Pool_NfUdm#!_#subset_sr:"
                  },
                  "preferred_target": {
                    "term_header": "3gpp-Sbi-target-apiRoot"
                  },
                  "preserve_if_indirect": "TARGET_API_ROOT",
                  "routing_behaviour": "ROUND_ROBIN"
                }
              }
            ],
            "name": "pSepp_to_ownPLMN_strict_static_NfUdm",
            "condition": {
              "op_and": {
                "arg1": {
                  "op_and": {
                    "arg1": {
                      "op_or": {
                        "arg1": {
                          "op_equals": {
                            "typed_config1": {
                              "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                              "term_var": "nf"
                            },
                            "typed_config2": {
                              "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                              "term_string": "nfUdm7"
                            }
                          }
                        },
                        "arg2": {
                          "op_equals": {
                            "typed_config1": {
                              "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                              "term_var": "nf"
                            },
                            "typed_config2": {
                              "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                              "term_string": "nfUdm8"
                            }
                          }
                        }
                      }
                    },
                    "arg2": {
                      "op_equals": {
                        "typed_config1": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_var": "mnc"
                        },
                        "typed_config2": {
                          "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                          "term_string": "567"
                        }
                      }
                    }
                  }
                },
                "arg2": {
                  "op_equals": {
                    "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "mcc"
                    },
                    "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "765"
                    }
                  }
                }
              }
            }
          },
          {
            "actions": [
              {
                "action_add_header": {
                  "if_exists": "REPLACE",
                  "name": "x-eric-fop",
                  "value": {
                    "term_string": "fob_default"
                  }
                }
              },
              {
                "action_route_to_pool": {
                  "pool_name": {
                    "term_string": "universal_pool#!_#subset_sr:"
                  },
                  "preferred_target": {
                    "term_header": "3gpp-Sbi-target-apiRoot"
                  },
                  "preserve_if_indirect": "TARGET_API_ROOT",
                  "routing_behaviour": "ROUND_ROBIN"
                }
              }
            ],
            "name": "pSepp_to_ownPLMN_universal",
            "condition": {
              "op_and": {
                "arg1": {
                  "op_equals": {
                    "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "mnc"
                    },
                    "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "567"
                    }
                  }
                },
                "arg2": {
                  "op_equals": {
                    "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "mcc"
                    },
                    "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "765"
                    }
                  }
                }
              }
            }
          }
        ],
        "name": "default_routing"
      }
    ],
    "key_value_tables": [
      {
        "entries": [
          {
            "key": "pSepp11.mnc.012.mcc.210.ericsson.se",
            "value": "RP_1"
          },
          {
            "key": "pSepp21.mnc.123.mcc.321.ericsson.se",
            "value": "RP_2"
          },
          {
            "key": "pSepp22.mnc.123.mcc.321.ericsson.se",
            "value": "RP_2"
          },
          {
            "key": "pSepp12.mnc.012.mcc.210.ericsson.se",
            "value": "RP_1"
          },
          {
            "key": "pSepp13.mnc.012.mcc.210.ericsson.se",
            "value": "RP_1"
          },
          {
            "key": "pSepp31.mnc.234.mcc.432.ericsson.se",
            "value": "RP_3"
          }
        ],
        "name": "domain_names_to_roaming_partners"
      },
    ],
    "name": "sepp_routing",
    "node_type": "SEPP",
    "own_external_port": 31090,
    "own_fqdn": "sepp.mnc.567.mcc.765.ericsson.de",
    "rp_name_table" : "domain_names_to_roaming_partners",
    "request_filter_cases": {
      "routing": {
        "ext_nw": {
          "name": "external network",
          "ext_nw_fc_config_list": [
            "per_rp_fc_config": {
              "rp_to_fc_map": {
                "pSepp11.mnc.012.mcc.210.ericsson.se": "default_routing",
                "pSepp21.mnc.123.mcc.321.ericsson.se": "default_routing",
                "pSepp22.mnc.123.mcc.321.ericsson.se": "default_routing",
                "pSepp12.mnc.012.mcc.210.ericsson.se": "default_routing",
                "pSepp13.mnc.012.mcc.210.ericsson.se": "default_routing",
                "pSepp31.mnc.234.mcc.432.ericsson.se": "default_routing",
              },
              "default_fc_for_rp_not_found": "default_routing"
            }
          ]
        }
      }
    },
    "roaming_partners": [
      {
        "name": "RP_1",
        "pool_name": "Pool_PSEPP1"
      },
      {
        "name": "RP_2",
        "pool_name": "Pool_PSEPP2"
      },
      {
        "name": "RP_3",
        "pool_name": "Pool_PSEPP3"
      }
    ]
  }
)EOF";

//------------------------------------------------------------------------
// Configuration for DND-28053 Don't copy authority to TaR if :authority only contains own FQDN
// This configuration works by routing differently depending on the TaR header being present or not
const std::string config_authority_tar = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.ownplmn.com
  own_internal_port: 8888
  request_filter_cases:
      routing:
        own_nw:
          name: own_network
          start_fc_list:
          - default_routing
  callback_uri_klv_table: callback_uris
  key_list_value_tables:
    - name: callback_uris
      entries:
        - key: test_api_name_1
          value:
            - /nfInstances/*/nfServices/*/test_api_1_cb_uri_1
            - /nfInstances/*/nfServices/*/test_api_1_cb_uri_2
        - key: test_api_name_2
          value:
            - /nfInstances/*/nfServices/*/test_api_2_cb_uri_1
            - /nfInstances/*/nfServices/*/test_api_2_cb_uri_2
  nf_types_requiring_t_fqdn:
    - SMF
    - PCF
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: tar_present
        condition:
          op_and:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
            arg2:
              op_equals:
                typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_reqheader: '3gpp-Sbi-target-apiRoot'}
                typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'http://eric-chfsim-6-mnc-456-mcc-456:3777'}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_tar
            routing_behaviour: ROUND_ROBIN
      - name: tar_absent
        condition:
          term_boolean: true
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_no_tar
            routing_behaviour: ROUND_ROBIN
  roaming_partners:
    - name: rp_tar
      pool_name: sepp_rp_tar
    - name: rp_no_tar
      pool_name: sepp_rp_no_tar
)EOF";

std::string config_basic_p_sepp_egress_scr = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.ownplmn.com
  own_external_port: 9090
  rp_name_table : rp_san_to_name
  request_filter_cases:
    routing:
      ext_nw:
        name: "external network"
        ext_nw_fc_config_list:
        - per_rp_fc_config:
            rp_to_fc_map:
              rp_A: rp_A_routing
            default_fc_for_rp_not_found: default_routing
    out_request_screening:
      cluster_fc_config_list:
        - cluster_to_fc_map:
            no_tar_pool: out_req_screening

  key_value_tables:
    - name: rp_san_to_name
      entries:
        - key: '*.ext-plmn.com'
          value: rp_A
  callback_uri_klv_table: callback_uris
  key_list_value_tables:
    - name: callback_uris
      entries:
        - key: test_api_name_1/v1
          value:
            - /nfInstances/*/nfServices/*/test_api_1_cb_uri_1
            - /nfInstances/*/nfServices/*/test_api_1_cb_uri_2
        - key: test_api_name_2/v1
          value:
            - /nfInstances/*/nfServices/*/test_api_2_cb_uri_1
            - /nfInstances/*/nfServices/*/test_api_2_cb_uri_2
        - key: nchf-convergedcharging/v2
          value:
            - /notifyUri
  nf_types_requiring_t_fqdn:
    - SMF
    - PCF
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: psepp_to_pref
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: occ
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
    - name: rp_A_routing
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
      filter_rules:
      - name: no_tar_header
        condition:
          op_not:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: no_tar_pool
            routing_behaviour: ROUND_ROBIN
      - name: PAuthOtherFqdn
        condition:
          op_and:
            arg1:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nf.ownplmn.com:9090'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':authority'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'sepp.ownplmn.com:9090'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: tar_is_nf_ext_pool
            routing_behaviour: STRICT
      - name: TestPAuthTaR
        condition:
          op_and:
            arg1:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nf.ownplmn.com:80'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':authority'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'sepp.ownplmn.com:9090'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: tar_is_nf_int_pool
            routing_behaviour: STRICT
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
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
    - name: out_req_screening
      filter_data:
      - name: locality_header
        header: locality
        variable_name: locality
      filter_rules:
      - name: egress_rule1
        condition:
          term_boolean: true
        actions:
        - action_modify_json_body:
            name: "test modify (tfqdn-)request body egress"
            json_operation:
              add_to_json:
                value:
                  term_string: '"supi-added"'
                json_pointer:
                  term_string: "/subscriberIdentifier1"
                if_path_not_exists:  CREATE
                if_element_exists:  REPLACE
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";


//------------------------------------------------------------------------
// Configuration for the Envoy Header-to-Metadata filter. Useful to inject Metadata
// into test-cases. This filter is not present in official deployments.
const std::string config_header_to_metadata = R"EOF(
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

)EOF";

//------------------------------------------------------------------------
// NF Discovery response body, with fqdn everywhere
const std::string nf_disc_resp_body{R"(
{
    "validityPeriod": 60,
    "nfInstances": [{
        "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "nfInstanceName": "nfInstanceName_1",
        "nfType": "AUSF",
        "fqdn": "FQDN_0_0.example1.com",
        "nfServices": [{
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "https",
            "nfServiceStatus": "REGISTERED",
            "fqdn": "FQDN.example1.com",
            "test_api_1_cb_uri_1": "FQDN_0_1.example1.com",
            "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP",
                "port": 9091
            }]
        }]
    }, {
        "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce101",
        "nfInstanceName": "nfInstanceName_2",
        "nfType": "AUSF",
        "fqdn": "FQDN_1_0.example1.com",
        "nfServices": [{
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "https",
            "nfServiceStatus": "REGISTERED",
            "fqdn": "FQDN1.example2.com",
            "test_api_1_cb_uri_1": "FQDN1.example2.com",
            "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP",
                "port": 9092
            }]
          }, {
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "fqdn": "FQDN2.example2.com",
            "test_api_1_cb_uri_1": "FQDN1.example2.com",
            "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP",
                "port": 9093
            }]
        }]
    }],
    "searchId": null,
    "numNfInstComplete": null,
    "preferredSearch": null,
    "nrfSupportedFeatures": "nausf-auth"
}
  )"};

const std::string nf_disc_resp_body_nf_service_list{R"(
{
    "validityPeriod": 60,
    "nfInstances": [{
        "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "nfInstanceName": "nfInstanceName_1",
        "nfType": "AUSF",
        "fqdn": "FQDN_0_0.example1.com",
        "nfServiceList": {
            "serviceInstanceId_1": {
              "serviceInstanceId": "serviceInstanceId_1",
              "serviceName": "nausf-auth",
              "versions": [],
              "scheme": "https",
              "nfServiceStatus": "REGISTERED",
              "fqdn": "FQDN.example1.com",
              "test_api_1_cb_uri_1": "FQDN_0_1.example1.com",
              "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
              "ipEndPoints": [{
                  "ipv4Address": "10.11.12.253",
                  "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                  "transport": "TCP",
                  "port": 9091
              }]
            } 
        },            
        "nfServices": [{
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "https",
            "nfServiceStatus": "REGISTERED",
            "fqdn": "FQDN.example1.com",
            "test_api_1_cb_uri_1": "FQDN_0_1.example1.com",
            "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP",
                "port": 9091
            }]
        }]
    }, {
        "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce101",
        "nfInstanceName": "nfInstanceName_2",
        "nfType": "AUSF",
        "fqdn": "FQDN_1_0.example1.com",
        "nfServiceList": {
          "serviceInstanceId_1": {  
              "serviceInstanceId": "serviceInstanceId_1",
              "serviceName": "nausf-auth",
              "versions": [],
              "scheme": "https",
              "nfServiceStatus": "REGISTERED",
              "fqdn": "FQDN1.example2.com",
              "test_api_1_cb_uri_1": "FQDN1.example2.com",
              "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
              "ipEndPoints": [{
                  "ipv4Address": "10.11.12.253",
                  "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                  "transport": "TCP",
                  "port": 9092
              }]
          }, 
          "serviceInstanceId_2": {  
              "serviceInstanceId": "serviceInstanceId_2",
              "serviceName": "nausf-auth",
              "versions": [],
              "scheme": "http",
              "nfServiceStatus": "REGISTERED",
              "fqdn": "FQDN2.example2.com",
              "test_api_1_cb_uri_1": "FQDN1.example2.com",
              "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
              "ipEndPoints": [{
                  "ipv4Address": "10.11.12.253",
                  "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                  "transport": "TCP",
                  "port": 9093
              }]
          }    
        }
    }],
    "searchId": null,
    "numNfInstComplete": null,
    "preferredSearch": null,
    "nrfSupportedFeatures": "nausf-auth"
}
  )"};


// Converged-Charging Create Request Body (shortened)
const std::string cc_create_req_body{R"(
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
    },
    "invocationTimeStamp": "2019-03-28T14:30:50Z",
    "invocationSequenceNumber": 0,
    "notifyUri": "http://192.168.0.2:8080/rar",
    "multipleUnitUsage": [{
        "ratingGroup": 100,
        "requestedUnit": {
            "time": 123,
            "totalVolume": 211,
            "uplinkVolume": 123,
            "downlinkVolume": 1234,
            "serviceSpecificUnits": 6543
        },
        "uPFID": "123e-e8b-1d3-a46-421"
    }],
    "pDUSessionChargingInformation": {
        "chargingId": 123,
        "userInformation": {
            "servedGPSI": "msisdn-77117777",
            "servedPEI": "imei-234567891098765",
            "unauthenticatedFlag": true,
            "roamerInOut": "OUT_BOUND"
        },
        "userLocationTime": "2019-03-28T14:30:50Z",
        "uetimeZone": "+05:30",
        "unitCountInactivityTimer": 125
    }
}
  )"};

// Converged-Charging Create Response Body (shortened)
const std::string cc_create_resp_body{R"(
{
  "invocationSequenceNumber": 1,
  "invocationTimeStamp": "2019-03-28T14:30:51.888+0100",
  "multipleUnitInformation": [
    {
      "quotaHoldingTime": 82400,
      "uPFID": "123e-e8b-1d3-a46-421",
      "validityTime": "2019-03-29T13:24:11.885+0100",
      "grantedUnit": {
        "totalVolume": 211
      },
      "ratingGroup": 100,
      "resultCode": "SUCCESS",
      "volumeQuotaThreshold": 104857
    }
  ],
  "pDUSessionChargingInformation": {
    "chargingId": 123,
    "userInformation": {
      "servedGPSI": "msisdn-77117777",
      "servedPEI": "imei-234567891098765",
      "unauthenticatedFlag": true,
      "roamerInOut": "OUT_BOUND"
    },
    "userLocationinfo": {
      "nrLocation": {
        "tai": {
          "plmnId": {
            "mcc": "374",
            "mnc": "645"
          },
          "tac": "ab01"
        },
        "ncgi": {
          "plmnId": {
            "mcc": "374",
            "mnc": "645"
          },
          "nrCellId": "ABCabc123"
        },
        "ageOfLocationInformation": 1,
        "ueLocationTimestamp": "2019-03-28T14:30:51Z",
        "geographicalInformation": "AB12334765498F12",
        "geodeticInformation": "AB12334765498F12ACBF",
        "globalGnbId": {
          "plmnId": {
            "mcc": "374",
            "mnc": "645"
          },
          "n3IwfId": "ABCD123",
          "ngRanNodeId": "MacroNGeNB-abc92"
        }
      },
      "ratType": "EUTRA",
      "dnnId": "DN-AAA",
      "chargingCharacteristics": "AB",
      "startTime": "2019-03-28T14:30:50Z"
    },
    "unitCountInactivityTimer": 180
  }
}
  )"};


//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------
// P-SEPP: Cluster config is here so that we can define our own endpoint-metadata
class EricProxyFilterPSeppTFqdnIntegrationTest : public PluggableConfigurator {
public:
  EricProxyFilterPSeppTFqdnIntegrationTest() = default;
};

//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------
// C-SEPP
class EricProxyFilterSeppTFqdnIntegrationTest : public PluggableConfigurator {
public:
  EricProxyFilterSeppTFqdnIntegrationTest() = default;

  // Helper-function to test that a NF Discovery response is modified (to TFQDN)
  // for an NF-Type that is configured to require T-FQDN
  void testNfDiscRespModificationForConfiguredNfType(const std::string nftype, const std::string& body,
      Scope test_scope) {
    BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
        ClusterDefinition({{"sepp_rp_A", {"eric-chfsim-1-mnc-123-mcc-123:80"}}}));
    initConfig(config_basic, cluster_config);

    Http::TestRequestHeaderMapImpl request_headers{
        {":method", "POST"},
        {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=" + nftype},
        {":authority", "sepp.ownplmn.com:80"},
        {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
    };

    Http::TestResponseHeaderMapImpl response_headers{
        {":status", "200"},
        {"content-length", std::to_string(body.length())},
        {"content-type", "application/json"},
        {"location", "https://abc.def.com"}
    };
    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
    waitForNextUpstreamRequest();

    // Send response:
    upstream_request_->encodeHeaders(response_headers, false);
    Buffer::OwnedImpl response_data(body);
    upstream_request_->encodeData(response_data, true);
    ASSERT_TRUE(response->waitForEndStream());

    Buffer::InstancePtr data(new Buffer::OwnedImpl(response->body()));    
    Body body_obj(data.get(), "application/json");

    // Location header must not be modified
    EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "https://abc.def.com"));
    verifyModificationsInNfDiscResponse(test_scope, body_obj); 
  }

  void verifyModificationsInNfDiscResponse(const Scope& test_scope, Body& body_obj)  {
    // Tests for all fqdn values to be converted to T-FQDN correctly:
    if (test_scope == ALL || test_scope == SOME || test_scope == FEW) {
      auto tfqdn = body_obj.readWithPointer("/nfInstances/0/fqdn");
      EXPECT_TRUE(tfqdn.ok());
      // The nfInstance fqdn should not be changed to T-FQDN
      EXPECT_EQ(*tfqdn, "FQDN_0_0.example1.com");
    }
    auto json_body = body_obj.getBodyAsJson();
    if (test_scope == ALL) {
      if (json_body->at("nfInstances").at(0).contains("nfServices")) {
        auto tfqdn = body_obj.readWithPointer("/nfInstances/0/nfServices/0/fqdn");
        EXPECT_TRUE(tfqdn.ok());
        EXPECT_EQ(*tfqdn,
                  TfqdnCodec::encode("https://FQDN.example1.com:9091") + ".sepp.ownplmn.com");
      }
      if (json_body->at("nfInstances").at(0).contains("nfServiceList")) {
        auto tfqdn = body_obj.readWithPointer("/nfInstances/0/nfServiceList/serviceInstanceId_1/fqdn");
        EXPECT_TRUE(tfqdn.ok());
        EXPECT_EQ(*tfqdn,
                  TfqdnCodec::encode("https://FQDN.example1.com:9091") + ".sepp.ownplmn.com");
      }      
    }
    if (test_scope == ALL) {
      auto tfqdn = body_obj.readWithPointer("/nfInstances/1/fqdn");
      EXPECT_TRUE(tfqdn.ok());
      // The nfInstance fqdn should not be changed to T-FQDN
      EXPECT_EQ(*tfqdn, "FQDN_1_0.example1.com");
    }
    if (test_scope == ALL || test_scope == SOME) {
      if (json_body->at("nfInstances").at(1).contains("nfServices")) {
        auto tfqdn = body_obj.readWithPointer("/nfInstances/1/nfServices/0/fqdn");
        EXPECT_TRUE(tfqdn.ok());
        EXPECT_EQ(*tfqdn,
                  TfqdnCodec::encode("https://FQDN1.example2.com:9092") + ".sepp.ownplmn.com");
      }
    }
    if (test_scope == ALL || test_scope == SOME || test_scope == FEW) {
      if (json_body->at("nfInstances").at(1).contains("nfServices")) {
        auto tfqdn = body_obj.readWithPointer("/nfInstances/1/nfServices/1/fqdn");
        EXPECT_TRUE(tfqdn.ok());
        EXPECT_EQ(*tfqdn,
                  TfqdnCodec::encode("http://FQDN2.example2.com:9093") + ".sepp.ownplmn.com");
      }
    }

    // Test that other places of the body are not modified:
    {
      auto value = body_obj.readWithPointer("/validityPeriod");
      EXPECT_TRUE(value.ok());
      EXPECT_EQ(*value, 60);
    }
    if (test_scope == ALL || test_scope == SOME) {
      auto value = body_obj.readWithPointer("/nfInstances/0/nfType");
      EXPECT_TRUE(value.ok());
      EXPECT_EQ(*value, "AUSF");
    }
    if (test_scope == ALL || test_scope == SOME) {
      if (json_body->at("nfInstances").at(1).contains("nfServices")) {
        auto value = body_obj.readWithPointer("/nfInstances/1/nfServices/1/ipEndPoints/0/port");
        EXPECT_TRUE(value.ok());
        EXPECT_EQ(*value, 9093);
      }
    }
  }

  // Helper function for location-header modification tests
  void testLocationHeaderModification(const Http::TestRequestHeaderMapImpl& request_headers,
    const std::string& location_in, const std::string& expected_location_out) {
    BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
        ClusterDefinition({{"sepp_rp_A", {"eric-chfsim-1-mnc-123-mcc-123:80"}}}));
    initConfig(config_basic, cluster_config);

    Http::TestResponseHeaderMapImpl response_headers{
        {":status", "200"},
        {"content-length", std::to_string(cc_create_resp_body.length())},
        {"content-type", "application/json"},
        {"location", location_in}
    };
    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
    waitForNextUpstreamRequest();

    // Send response:
    upstream_request_->encodeHeaders(response_headers, false);
    Buffer::OwnedImpl response_data(cc_create_resp_body);
    upstream_request_->encodeData(response_data, true);
    ASSERT_TRUE(response->waitForEndStream());

    // Location header has been converted correctly:
    EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", expected_location_out));

    // Body is unmodified
    EXPECT_EQ(response->body(), cc_create_resp_body);
  }

};


//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------
INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterSeppTFqdnIntegrationTest,
                         testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest())));

TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestStrictRoutingExtToInt) {

  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"universal_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}}));
  initConfig({config_header_to_metadata, config_basic_ext_to_int}, cluster_config);

  // A short fake body is good enough for this test
  std::string body{R"({"validityPeriod": 60})"};
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1"},
      {":authority", "eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"x-eric-sepp-test-san", "smf1.external-plmn.com"},
      {"x-eric-sepp-rp-name", "rp_A"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "universal_pool"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-host", "eric-chfsim-6-mnc-456-mcc-456:3777"));

  codec_client->close();
}

// DND-36939 SEPP-TFQDN: Envoy crashes when a request with malformed JSON body is received
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestStrictRoutingExtToInt_MalformedJsonBody) {

  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"universal_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}}));
  initConfig({config_header_to_metadata, config_basic_ext_to_int}, cluster_config);

  // Send fake downstream request with fake malformed JSON body
  // The fake body is a malformed JSON: last closing } is missing
  std::string body{R"({"validityPeriod": 60)"};
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1"},
      {":authority", "eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"x-eric-sepp-test-san", "smf1.external-plmn.com"},
      {"x-eric-sepp-rp-name", "rp_A"},
      {"content-type", "application/json"},
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
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "universal_pool"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-host", "eric-chfsim-6-mnc-456-mcc-456:3777"));

  codec_client->close();
}

TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestStrictRoutingFromIntNoTarTFqdnInAuthority) {

  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"universal_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}}));
  initConfig(config_basic, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", TfqdnCodec::encode("http://eric-chfsim-6-mnc-456-mcc-456:3777") + ".sepp.ownplmn.com:80"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(headers,0, default_response_headers_,0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "universal_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "eric-chfsim-6-mnc-456-mcc-456:3777"));

  codec_client_->close();
}


// DND-28053 Don't copy authority to TaR if :authority only contains own FQDN
// The :authority header is unmodified
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestRoutingFromIntNoTarOwnFqdnInAuthority) {
  BasicClusterConfigurator cluster_config =
      BasicClusterConfigurator(ClusterDefinition({{"sepp_rp_no_tar", {"sepp.ownplmn.com:8888"}}}));
  initConfig(config_authority_tar, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "sepp.ownplmn.com:8888"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  // The "1" at the end is the number of the cluster that is expected to get the request
  // (2nd cluster in the configuration)
  auto response = sendRequestAndWaitForResponse(headers,0, default_response_headers_,0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_no_tar"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "sepp.ownplmn.com:8888"));

  codec_client_->close();
}


// DND-28053 Don't copy authority to TaR if :authority only contains own FQDN
// The :authority header is unmodified
// Same test as before, but the :authority is all uppercase
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestRoutingFromIntNoTarOwnFqdnInAuthority2) {
  BasicClusterConfigurator cluster_config =
      BasicClusterConfigurator(ClusterDefinition({{"sepp_rp_no_tar", {"sepp.ownplmn.com:8888"}}}));

  initConfig(config_authority_tar, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "SEPP.OWNPLMN.COM:8888"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(headers,0, default_response_headers_,0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_no_tar"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "SEPP.OWNPLMN.COM:8888"));

  codec_client_->close();
}


// DND-28053 Do copy authority to TaR if :authority does not contain only the own FQDN
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestRoutingFromIntNoTarOwnFqdnNotInAuthority) {
  BasicClusterConfigurator cluster_config =
      BasicClusterConfigurator(ClusterDefinition({{"sepp_rp_tar", {"sepp.ownplmn.com:8888"}}}));
  initConfig(config_authority_tar, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", TfqdnCodec::encode("http://eric-chfsim-6-mnc-456-mcc-456:3777") + ".sepp.ownplmn.com:80"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(headers,0, default_response_headers_,0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_tar"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "sepp.ownplmn.com:8888"));
  // Cannot test for the 3gpp-Sbi-target-apiRoot header here because it's removed because next
  // hop is an NF

  codec_client_->close();
}

TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestStrictRoutingFromIntNfDiscTarWoTFqdn) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"sepp_rp_A", {"eric-chfsim-1-mnc-123-mcc-123:80"}}}));
  initConfig({config_header_to_metadata, config_basic}, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
      {":authority", "eric-chfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"x-eric-sepp-test-san", "smf1.ownplmn.com"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(headers,0, default_response_headers_,0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "sepp_rp_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "eric-chfsim-1-mnc-123-mcc-123:80"));
  codec_client_->close();
}

// NF Discovery request sent from a requester-nf-type that
// is **not** configured to require T-FQDN processing of the NF Discovery
// response.
// Expected Result:
// - Received body is the same as the fake response body (= response body
//   is not modified)
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestSeppRoutingFromIntNfDiscTarWoTFqdn_NoModResponseBody) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"sepp_rp_A", {"eric-chfsim-1-mnc-123-mcc-123:80"}}}));
  initConfig(config_basic, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=CHF"},
      {":authority", "eric-chfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body.length())},
      {"content-type", "application/json"}
  };
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ(nf_disc_resp_body, response->body());
}

//------------------------------------------------------------------------
//------ T-FQDN INGRESS TESTS PART 1  (C-SEPP) ---------------------------
//--- These tests are implemented so that the routing decision is taken --
//--- based on the headers present or not, and their values. Then the ----
//--- message is routed to a different cluster for each test case, and ---
//--- the x-cluster header is used to check in the test-case if the test -
//--- was successful. (The 404-tests with invalid T-FQDN are different) --
//------------------------------------------------------------------------
// Name: CAuthTFqdn
// Description: Request from int. NW with only authority=TFQDN of foreign FQDN, no TaR
// Expected Result: (same as TestCAuthForeignFqdn, TestCAuthTarForeignFqdn, TestCAuthTarTFqdn,
// see below)
// - Authority is own FQDN:Int-port
// - TaR is decoded producer-label = foreign-FQDN
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCAuthTFqdn) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"c_tar_nf1_other_plmn", {"eric-chfsim-1-mnc-123-mcc-123:80"}}}));
  initConfig(config_basic, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", TfqdnCodec::encode("http://nf1.other-plmn.com:5678") + ".sepp.ownplmn.com:80"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(headers,0, default_response_headers_,0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  // We went through our filter:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  // If no TaR header was present, we get routed to the "c_tar_nf1_other_plmn" cluster:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "c_tar_nf1_other_plmn"));

  codec_client_->close();
}

//------------------------------------------------------------------------
// Name: CAuthFaultyTFqdn
// Description: Request from int. NW with only authority=TFQDN, no TaR, TFQDN is not a valid string:
// - Illegal characters
// - A single 'q' at the end
// Expected Result:
// - Direct response 404
// - No routing-case is processed
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCAuthFaultyTFqdn) {

  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"c_tar_nf1_other_plmn", {"eric-chfsim-1-mnc-123-mcc-123:80"}}}));
  initConfig(config_basic, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "abcq.sepp.ownplmn.com"},
  };

  IntegrationCodecClientPtr codec_client = makeHttpConnection(lookupPort("http"));
  IntegrationStreamDecoderPtr response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ(R"({"status": 400, "title": "Bad Request", "cause": "MANDATORY_IE_INCORRECT", "detail": "decoding_error_tfqdn_invalid"})", response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()), response->headers().getContentLengthValue());

  codec_client->close();
}

//------------------------------------------------------------------------
// Name: CAuthForeignFqdn
// Description: Request from int. NW with only authority=foreign-FQDN, no TaR
// Expected Result: (same as TestCAuthTFqdn, TestCAuthTarForeignFqdn, TestCAuthTarTFqdn
// because we sent already the foreign-FQDN, it does not have to be decoded
// -> result is the same)
// - Authority is own FQDN:int-port
// - TaR is foreign-FQDN
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCAuthForeignFqdn) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"c_tar_nf1_other_plmn", {"nf1.other-plmn.com:5678"}}}));
  initConfig(config_basic, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "nf1.other-plmn.com:5678"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(headers,0, default_response_headers_,0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  // We went through our filter:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  // If no TaR header was present, we get routed to the "c_tar_nf1_other_plmn" cluster:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "c_tar_nf1_other_plmn"));

  codec_client_->close();
}

//------------------------------------------------------------------------
// Name: CAuthOwnFqdn
// Description: Request from internal NW with only authority=own-FQDN, no TaR
// Expected Result:
// - Request is unmodified
// - No TaR header
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCAuthOwnFqdn) {
  BasicClusterConfigurator cluster_config =
      BasicClusterConfigurator(ClusterDefinition({{"c_no_tar_pool", {"dummy.ownplmn.com:80"}}}));
  initConfig(config_basic, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "sepp.ownplmn.com:80"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(headers,0, default_response_headers_,0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  // We went through our filter:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  // If no TaR header was present, we get routed to the "c_no_tar_pool" cluster:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "c_no_tar_pool"));

  codec_client_->close();
}

//------------------------------------------------------------------------
// Name: CAuthTarForeignFqdn
// Description: Request from int. NW with authority=own-FQDN, TaR=foreign-FQDN
// Expected Result: (same as TestCAuthTFqdn, TestCAuthForeignFqdn, TestCAuthTarTFqdn)
// - Request is unmodified:
//    - authority=own-FQDN
//    - TaR=foreign-FQDN
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCAuthTarForeignFqdn) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"c_tar_nf1_other_plmn", {"dummy.ownplmn.com:80"}}}));
  initConfig(config_basic, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "sepp.ownplmn.com:80"},
      {"3gpp-sbi-Target-APIROOT", "http://nf1.other-plmn.com:5678"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(headers,0, default_response_headers_,0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  // We went through our filter:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  // If no TaR header was present, we get routed to the "c_tar_nf1_other_plmn" cluster:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "c_tar_nf1_other_plmn"));

  codec_client_->close();
}

//------------------------------------------------------------------------
// Name: CAuthTarTFqdn
// Description: Request from int. NW with authority=own-FQDN, TaR=T-FQDN of foreign FQDN
// Expected Result: (same as TestCAuthTFqdn and TestCAuthForeignFqdn, TestCAuthTarForeignFqdn)
// - Authority is unmodified
// - TaR is decoded producer-label = foreign FQDN
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCAuthTarTFqdn) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"c_tar_nf1_other_plmn", {"dummy.ownplmn.com:80"}}}));
  initConfig(config_basic, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "sepp.ownplmn.com:80"},
      {"3GPP-SBI-tARGET-APIROOT", "http://" + TfqdnCodec::encode("http://nf1.other-plmn.com:5678") + ".sepp.ownplmn.com:80"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(headers,0, default_response_headers_,0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  // We went through our filter:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  // If no TaR header was present, we get routed to the "c_tar_nf1_other_plmn" cluster:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "c_tar_nf1_other_plmn"));

  codec_client_->close();
}

//------------------------------------------------------------------------
// Name: CAuthTarFaultyTFqdn
// Description: Request from int. NW with authority=own-FQDN, TaR=faulty TFQDN (illegal characters)
// Expected Result:
// - Direct response 404
// - No routing case is processed
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCAuthTarFaultyTFqdn) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"c_tar_nf1_other_plmn", {"dummy.ownplmn.com:80"}}}));
  initConfig(config_basic, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "sepp.ownplmn.com:80"},
      {"3gpp-Sbi-Target-apiRoot", "http://smf1Q5123Q###m456Q3.sepp.ownplmn.com"},
  };

  IntegrationCodecClientPtr codec_client = makeHttpConnection(lookupPort("http"));
  IntegrationStreamDecoderPtr response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ(R"({"status": 400, "title": "Bad Request", "cause": "MANDATORY_IE_INCORRECT", "detail": "decoding_error_tfqdn_invalid"})", response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()), response->headers().getContentLengthValue());

  codec_client->close();
}


//------------------------------------------------------------------------
//------ T-FQDN DISCOVERY RESPONSE MODIFICATION TESTS --------------------
//------------------------------------------------------------------------
// Name: CNfDiscNoTFqdn
// Description: Unmodified NF Discovery Response to an NF that does not
// need T-FQDN (R16 NF with TaR)
// - NF Discovery Request from int. network
// - authority=own-FQDN
// - TaR=foreign-FQDN
// - query-string not matching any configured NF-type that does needs T-FQDN
// Expected Result:
// - Request and response are not modified (check headers and body)
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCNfDiscNoTFqdn) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"sepp_rp_A", {"eric-chfsim-1-mnc-123-mcc-123:80"}}}));
  initConfig(config_basic, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=CHF"},
      {":authority", "sepp.ownplmn.com:80"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com"}};
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Location header must not be modified
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "https://abc.def.com"));

  // Body is unmodified
  EXPECT_EQ(response->body(), nf_disc_resp_body);
  }

//------------------------------------------------------------------------
// Name: CNfDiscTFqdn
// Description: Modified NF Discovery Response to an NF that needs T-FQDN
// (i.e. R15 NF without TaR)
// - NF Discovery Request from int. network
// - authority=own-FQDN
// - TaR=foreign-FQDN
// - query-string matching a configured NF-type that needs T-FQDN
// Expected Result:
// - Request is not modified
// - Response body is modified: FQDN -> T-FQDN
// - Response body has "fqdn" attribute on both nfInstances and nfServices level
// - Response body has multiple nfInstances and multiple nfServices
// - Rest of the body is unchanged (check 3 samples of data)
// - Location header is not modified
// Variants:
// - NF-type in upper and lower case
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCNfDisTFqdn1) {
  testNfDiscRespModificationForConfiguredNfType("SMF", nf_disc_resp_body, Scope::ALL);
}
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCNfDisTFqdn2) {
  testNfDiscRespModificationForConfiguredNfType("smf", nf_disc_resp_body, Scope::ALL);
}
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCNfDisTFqdn3) {
  testNfDiscRespModificationForConfiguredNfType("PcF", nf_disc_resp_body, Scope::ALL);
}

//DND-44546 T-FQDN encoding is not done for nfServiceList
//------------------------------------------------------------------------
// Name: CNfDiscTFqdn_nfServiceList
// Description: Modified NF Discovery Response to an NF that needs T-FQDN
// (i.e. R15 NF without TaR)
// - NF Discovery Request from int. network
// - authority=own-FQDN
// - TaR=foreign-FQDN
// - query-string matching a configured NF-type that needs T-FQDN
// Expected Result:
// - Request is not modified
// - Response body is modified: FQDN -> T-FQDN
// - Response body has "fqdn" attribute on both nfInstances and nfServices level
// - Response body has multiple nfInstances and multiple nfServices
// - Rest of the body is unchanged (check 3 samples of data)
// - Location header is not modified
// Variants:
// - NF-type in upper and lower case
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCNfDisTFqdn1_nfServiceList) {
  testNfDiscRespModificationForConfiguredNfType("SMF", nf_disc_resp_body_nf_service_list, Scope::ALL);
}
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCNfDisTFqdn2_nfServiceList) {
  testNfDiscRespModificationForConfiguredNfType("smf", nf_disc_resp_body_nf_service_list, Scope::ALL);
}
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCNfDisTFqdn3_nfServiceList) {
  testNfDiscRespModificationForConfiguredNfType("PcF", nf_disc_resp_body_nf_service_list, Scope::ALL);
}


//------------------------------------------------------------------------
// Name: CNfDiscTFqdnNoFqdnInResp
// Description: Unmodified NF Discovery Response without 'fqdn' to an NF
// that needs T-FQDN (R15 NF without TaR)
// - NF Discovery Request from int. NW
// - authority=own-FQDN
// - TaR=foreign-FQDN
// - query-string matching a configured NF-type that needs T-FQDN
// - Response body does not contain "fqdn" in one nfInstance but in the
//   nfServices below, and in another nfInstance there is an fqdn but in
//   the nfServices below there are no fqdn
// Expected Result:
// - Request is not modified
// - Response body is not modified
// - Response body has no "fqdn" attribute on neither nfInstances nor nfServices level
// - Response body has multiple nfInstances and multiple nfServices
// - Location header is not modified
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCNfDiscTFqdnNoFqdnInResp) {
  // NF Discovery response body, with no fqdn in the nfServices of the first
  // nfInstance, and no fqdn in the second nfInstance but in the nfServices below it
  const std::string nf_disc_resp_body_no_fqdn{R"(
  {
    "validityPeriod": 60,
    "nfInstances": [{
        "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "nfInstanceName": "nfInstanceName_1",
        "nfType": "AUSF",
        "fqdn": "FQDN_0_0.example1.com",
        "nfServices": [{
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "https",
            "nfServiceStatus": "REGISTERED",
            "test_api_1_cb_uri_1": "FQDN_0_1.example1.com",
            "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP",
                "port": 9091
            }]
        }]
    }, {
        "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce101",
        "nfInstanceName": "nfInstanceName_2",
        "nfType": "AUSF",
        "nfServices": [{
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "https",
            "nfServiceStatus": "REGISTERED",
            "fqdn": "FQDN1.example2.com",
            "test_api_1_cb_uri_1": "FQDN1.example2.com",
            "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP",
                "port": 9092
            }]
          }, {
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "fqdn": "FQDN2.example2.com",
            "test_api_1_cb_uri_1": "FQDN1.example2.com",
            "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP",
                "port": 9093
            }]
        }]
    }],
    "searchId": null,
    "numNfInstComplete": null,
    "preferredSearch": null,
    "nrfSupportedFeatures": "nausf-auth"
  }
  )"};

  testNfDiscRespModificationForConfiguredNfType("SMF", nf_disc_resp_body_no_fqdn, Scope::SOME);
}

// Same as TestCNfDiscTFqdnNoFqdnInResp but the first nfService
// of the second nfInstance does not have an FQDN (DND-32662)
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCNfDiscTFqdnNoFqdnInResp2) {
  // NF Discovery response body, with no fqdn in the nfServices of the first
  // nfInstance, and no fqdn in the second nfInstance but in the nfServices below it
  const std::string nf_disc_resp_body_no_fqdn{R"(
  {
    "validityPeriod": 60,
    "nfInstances": [{
        "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "nfInstanceName": "nfInstanceName_1",
        "nfType": "AUSF",
        "fqdn": "FQDN_0_0.example1.com",
        "nfServices": [{
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "https",
            "nfServiceStatus": "REGISTERED",
            "test_api_1_cb_uri_1": "FQDN_0_1.example1.com",
            "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP",
                "port": 9091
            }]
        }]
    }, {
        "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce101",
        "nfInstanceName": "nfInstanceName_2",
        "nfType": "AUSF",
        "nfServices": [{
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "https",
            "nfServiceStatus": "REGISTERED",
            "test_api_1_cb_uri_1": "FQDN1.example2.com",
            "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP",
                "port": 9092
            }]
          }, {
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "fqdn": "FQDN2.example2.com",
            "test_api_1_cb_uri_1": "FQDN1.example2.com",
            "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP",
                "port": 9093
            }]
        }]
    }],
    "searchId": null,
    "numNfInstComplete": null,
    "preferredSearch": null,
    "nrfSupportedFeatures": "nausf-auth"
  }
  )"};

  testNfDiscRespModificationForConfiguredNfType("SMF", nf_disc_resp_body_no_fqdn, Scope::FEW);
}

//------------------------------------------------------------------------
// Name: CNfDiscTFqdnNoNfServiceFqdnInResp
// Description: Modified NF Discovery Response with 'fqdn' to an NF
// that needs T-FQDN (R15 NF without TaR)
// - NF Discovery Request from int. NW
// - authority=own-FQDN
// - TaR=foreign-FQDN
// - query-string matching a configured NF-type that needs T-FQDN
// 
// - Response body does 
//  - in the nfInstance there is an fqdn but in the nfServices below there are no fqdn
//
//    - exp. Result: the T-FQDN label should be the encoded scheme from NfService
//                   + the FQDN from NfInstance + Port from first EP 
//
//  - another NfInnt. does not contain "fqdn" in, but in the nfServices below and
//      has no port in the first IpEndPoint
//
//      - exp. Result: the T-FQDN label should be the encoded scheme from NfService
//                   + the FQDN from NfService + default Port depending on the NfService scheme 
//                      (80/443) 
//
//  - in another nfInstance/nfServices the are no IpEndPoints defined
//
//      - exp. Result: the T-FQDN label should be the encoded scheme from NfService
//                     + the FQDN from NfService + default Port depending on the NfService scheme 
//                        (80/443) 
// - Location header is not modified
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCNfDiscTFqdnNoNfServiceFqdnInResp) {
  const std::string nf_disc_resp_body{R"(
  {
    "validityPeriod": 60,
    "nfInstances": [{
        "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "nfInstanceName": "nfInstanceName_1",
        "nfType": "AUSF",
        "fqdn": "FQDN_0_0.example1.com",
        "nfServices": [{
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "https",
            "nfServiceStatus": "REGISTERED",
            "test_api_1_cb_uri_1": "FQDN_0_1.example1.com",
            "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP",
                "port": 9091
            }]
        }]
    }, {
        "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce101",
        "nfInstanceName": "nfInstanceName_2",
        "nfType": "AUSF",
        "nfServices": [{
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "https",
            "nfServiceStatus": "REGISTERED",
            "fqdn": "FQDN1.example2.com",
            "test_api_1_cb_uri_1": "FQDN1.example2.com",
            "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP"
            }]
          }, {
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "fqdn": "FQDN2.example2.com",
            "test_api_1_cb_uri_1": "FQDN1.example2.com",
            "test_api_1_cb_uri_2": "FQDN_0_2.example1.com"
        }]
    }, {
       "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce102",
        "nfInstanceName": "nfInstanceName_3",
        "nfType": "AUSF",
        "nfServices": [{
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "https",
            "nfServiceStatus": "REGISTERED",
            "test_api_1_cb_uri_1": "FQDN_0_1.example1.com",
            "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP",
                "port": 9091
            }]
        }]
    }],
    "searchId": null,
    "numNfInstComplete": null,
    "preferredSearch": null,
    "nrfSupportedFeatures": "nausf-auth"
  }
  )"};

  const std::string nftype = "SMF";
  const std::string& body = nf_disc_resp_body;

  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"sepp_rp_A", {"eric-chfsim-1-mnc-123-mcc-123:80"}}}));
  initConfig(config_basic, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=" + nftype},
      {":authority", "sepp.ownplmn.com:80"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com"}
  };
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Location header must not be modified
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "https://abc.def.com"));

  Buffer::InstancePtr data(new Buffer::OwnedImpl(response->body()));
  Body body_obj(data.get(), "application/json");

  // Tests for all fqdn values to be converted to T-FQDN correctly:
  {
    auto tfqdn = body_obj.readWithPointer("/nfInstances/0/fqdn");
    EXPECT_TRUE(tfqdn.ok());
    // The nfInstance fqdn should not be changed to T-FQDN
    EXPECT_EQ(*tfqdn, "FQDN_0_0.example1.com");
  }
  {
    auto tfqdn = body_obj.readWithPointer("/nfInstances/0/nfServices/0/fqdn");
    EXPECT_TRUE(tfqdn.ok());
    EXPECT_EQ(*tfqdn, TfqdnCodec::encode("https://FQDN_0_0.example1.com:9091")+".sepp.ownplmn.com");
  }
  {
    auto tfqdn = body_obj.readWithPointer("/nfInstances/1/nfServices/0/fqdn");
    EXPECT_TRUE(tfqdn.ok());
    EXPECT_EQ(*tfqdn, TfqdnCodec::encode("https://FQDN1.example2.com:443") + ".sepp.ownplmn.com");
  }
  {
    auto tfqdn = body_obj.readWithPointer("/nfInstances/1/nfServices/1/fqdn");
    EXPECT_TRUE(tfqdn.ok());
    EXPECT_EQ(*tfqdn, TfqdnCodec::encode("http://FQDN2.example2.com:80") + ".sepp.ownplmn.com");
  }
  // no input fqdn on nfInst or nfService
  {
    auto tfqdn = body_obj.readWithPointer("/nfInstances/2/nfServices/0/fqdn");
    // no T-FQDN expected for the service
    EXPECT_TRUE(tfqdn.ok());
    EXPECT_EQ(*tfqdn, Json());
  }

  // Test that other places of the body are not modified:
  {
    auto value = body_obj.readWithPointer("/validityPeriod");
    EXPECT_TRUE(value.ok());
    EXPECT_EQ(*value, 60);
  }
  {
    auto value = body_obj.readWithPointer("/nfInstances/0/nfType");
    EXPECT_TRUE(value.ok());
    EXPECT_EQ(*value, "AUSF");
  }
}

//------------------------------------------------------------------------
// Name: CNfDiscTFqdnEmptyResult
// Description: Unmodified empty NF Discovery Response for an NF that needs T-FQDN (R15 NF without TaR)
// - NF Discovery Request from int. NW
// - authority=own-FQDN
// - TaR=foreign-FQDN
// - query-string matching a configured NF-type that needs T-FQDN
// - Response body contains an empty search result (but is not empty)
// Expected Result:
// - Request is not modified
// - Response body is not modified
// - Location header is not modified
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCNfDiscTFqdnEmptyResult) {
  // NF Discovery response body with an empty search result
  const std::string nf_disc_resp_body_empty_search{R"(
  {
    "validityPeriod": 60,
    "nfInstances": [],
    "searchId": null,
    "numNfInstComplete": null,
    "preferredSearch": null,
    "nrfSupportedFeatures": "nausf-auth"
  }
  )"};

  testNfDiscRespModificationForConfiguredNfType("SMF", nf_disc_resp_body_empty_search, Scope::NONE);
}

//------------------------------------------------------------------------
// Name: CReqTFqdn
// Description: Request other than NF Discovery Request from an NF that needs T-FQDN (R15 NF)
// - Converged-Charging CREATE request from int. NW
// - authority=own-FQDN,
// - TaR=foreign-FQDN
// - query-string matching a configured NF-type that needs T-FQDN
// Expected Result:
// - Request and response are not modified (check headers and body)
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCReqTFqdn) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"sepp_rp_A", {"eric-chfsim-1-mnc-123-mcc-123:80"}}}));
  initConfig(config_basic, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=CHF"},
      {":authority", "sepp.ownplmn.com:80"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Location header must not be modified
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location",
        "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"));

  // Body is unmodified
  EXPECT_EQ(response->body(), cc_create_resp_body);
}

//------------------------------------------------------------------------
//----- T-FQDN LOCATION HEADER MODIFICATION TESTS ------------------------
//------------------------------------------------------------------------
// Name: CAuthTFqdnLocMod
// Description: Location response header is modified when the request
// contains a T-FQDN in :authority.
// - Converged-charging CREATE request from int. NW
// - authority has T-FQDN
// - no TaR
// - Loation header is originally "http://prod.plmnB.com:1234/nchf-convergedcharging/v2/chargingdata/89asd8-asd"
// Expected Result:
// - Location header is converted from FQDN to T-FQDN:
// http://ENCODED.own-fqdn:own-port/nchf-convergedcharging/v2/chargingdata/89asd8-asd
// - Body is not modified
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCAuthTFqdnLocMod1) {
    // The authority-header contains a T-FQDN to trigger the conversion of a Location header
    // in the response:
    Http::TestRequestHeaderMapImpl request_headers{
        {":method", "POST"},
        {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
        {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.ownplmn.com:80"},
    };

    // Verify correct encoding of location header (http://prod.plmnB.com:1234):
    testLocationHeaderModification(request_headers,
        "http://prod.plmnB.com:1234/nchf-convergedcharging/v2/chargingdata/89asd8-asd",
        "http://" + TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.ownplmn.com/nchf-convergedcharging/v2/chargingdata/89asd8-asd");
}

// Same test but https in the location header:
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCAuthTFqdnLocMod2) {
    // The authority-header contains a T-FQDN to trigger the conversion of a Location header
    // in the response:
    Http::TestRequestHeaderMapImpl request_headers{
        {":method", "POST"},
        {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
        {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.ownplmn.com:80"},
    };
    // Verify correct encoding of location header (http://prod.plmnB.com:1234):
    testLocationHeaderModification(request_headers,
        "https://prod.plmnB.com:1234/nchf-convergedcharging/v2/chargingdata/89asd8-asd",
        "https://" + TfqdnCodec::encode("https://prod.plmnB.com:1234") + ".sepp.ownplmn.com/nchf-convergedcharging/v2/chargingdata/89asd8-asd");
}

//------------------------------------------------------------------------
// Name: CTarTFqdnLocMod
// Description: Location response header is modified when the request
// contains a T-FQDN in TaR header
// - Converged-charging CREATE request from int. NW
// - authority=own-FQDN
// - TaR=TFQDN
// - Loation header is originally "http://prod.plmnB.com:1234/nchf-convergedcharging/v2/chargingdata/89asd8-asd"
// Expected Result
// - Location header is converted from FQDN to T-FQDN:
// http://ENCODED.own-fqdn:own-port/nchf-convergedcharging/v2/chargingdata/89asd8-asd
// - Body is not modified
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCTarTFqdnLocMod1) {
    // The TaR-header contains a T-FQDN to trigger the conversion of a Location header
    // in the response:
    Http::TestRequestHeaderMapImpl request_headers{
        {":method", "POST"},
        {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=smf"},
        {":authority", "sepp.ownplmn.com:80"},
        {"3gpp-Sbi-target-apiRoot", "http://" + TfqdnCodec::encode("eric-chfsim-1-mnc-123-mcc-123:80") + ".sepp.ownplmn.com:80"},
    };
    // eric-chfsim-1-mnc-123-mcc-123:80

    // Verify correct encoding of location header (prod.plmnB.com:1234):
    testLocationHeaderModification(request_headers,
      "http://prod.plmnB.com:1234/nchf-convergedcharging/v2/chargingdata/89asd8-asd",
      "http://" + TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.ownplmn.com/nchf-convergedcharging/v2/chargingdata/89asd8-asd");
}

// Same test but https in the location header:
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCTarTFqdnLocMod) {
    // The TaR-header contains a T-FQDN to trigger the conversion of a Location header
    // in the response:
    Http::TestRequestHeaderMapImpl request_headers{
        {":method", "POST"},
        {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=smf"},
        {":authority", "sepp.ownplmn.com:80"},
        {"3gpp-Sbi-target-apiRoot", "http://" + TfqdnCodec::encode("eric-chfsim-1-mnc-123-mcc-123:80") + ".sepp.ownplmn.com:80"},
    };
    // Verify correct encoding of location header (https://prod.plmnB.com:1234):
    testLocationHeaderModification(request_headers,
      "https://prod.plmnB.com:1234/nchf-convergedcharging/v2/chargingdata/89asd8-asd",
      "https://" + TfqdnCodec::encode("https://prod.plmnB.com:1234") + ".sepp.ownplmn.com/nchf-convergedcharging/v2/chargingdata/89asd8-asd");
}

//------------------------------------------------------------------------
// Name: CNoTFqdnLocNodMod
// Description: Location response header is not modified when the request
// didn't contain a T-FQDN in neither TaR nor authority header
// - Converged-Charging CREATE request from int. NW
// - authority=own-FQDN
// - TaR=foreign-FQDN
// Expected Result:
// - Location header is not modified
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCNoTFqdnLocNodMod) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"sepp_rp_A", {"eric-chfsim-1-mnc-123-mcc-123:80"}}}));
  initConfig(config_basic, cluster_config);

  // No T-FQDN in order to not trigger Location-header conversion:
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=smf"},
      {":authority", "sepp.ownplmn.com:80"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
  };
  std::string location{"https://prod.plmnB.com:1234/nchf-convergedcharging/v2/chargingdata/89asd8-asd"};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", location}
  };
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Location header is not modified:
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", location));

  // Body is unmodified (ignore whitespace and the order of fields in the JSON):
  nlohmann::basic_json received_body = json::parse(response->body());
  nlohmann::basic_json reference_body = json::parse(cc_create_resp_body);
  auto diff = json::diff(received_body, reference_body);
  EXPECT_EQ(diff.dump(), "[]");
}

//------------------------------------------------------------------------
//---- T-FQDN CALLBACK URI MODIFICATION TESTS PART 1 (C-SEPP) ------------
//------------------------------------------------------------------------
// Name: CCallbackNotMod
// Description: Callback-URI is not modified in a request from int. NW
// - Converged-Charging CREATE request from int. NW
// - authority=own-FQDN
// - TaR=foreign-FQDN
// - Body has a callback URI at a configured path
// Expected Result:
// - Headers and Body are not changed
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestCCallbackNotMod) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"sepp_rp_A", {"eric-chfsim-1-mnc-123-mcc-123:80"}}}));
  initConfig(config_basic, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=CHF"},
      {":authority", "sepp.ownplmn.com:80"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Request body is not modified
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);

  // Request header is not modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"));

  // (we don't care for a response)
  codec_client_->close();
}

//------------------------------------------------------------------------
//--- OLDER TESTS --------------------------------------------------------
//------------------------------------------------------------------------
// Request:
// - from internal network
// - no TaR header present
// - but :authority header contains a TFQDN
// Response:
// - has a location header without TFQDN
// Expected:
// - location header in response is converted to TFQDN
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestSeppRoutingFromIntNoTarTFqdnInAuthorityResponsePath) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"universal_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}}));
  initConfig(config_basic, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", TfqdnCodec::encode("http://eric-chfsim-6-mnc-456-mcc-456:3777") + ".sepp.ownplmn.com"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));

  default_response_headers_.setCopy(Http::LowerCaseString("location"),"http://eric-chfsim-6-mnc-456-mcc-456:3777");

  auto response = sendRequestAndWaitForResponse(headers,0, default_response_headers_,0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "universal_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "eric-chfsim-6-mnc-456-mcc-456:3777"));

  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "http://" + TfqdnCodec::encode("http://eric-chfsim-6-mnc-456-mcc-456:3777") + ".sepp.ownplmn.com"));

  codec_client_->close();
}

// Request:
// - from internal network
// - TaR header present with TFQDN
// Response:
// - has a location header without TFQDN
// Expected:
// - location header in response is converted to TFQDN
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, TestSeppRoutingFromIntTFqdnInTarResponsePath) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"universal_pool", {"eric-chfsim-6-mnc-456-mcc-456:3777"}}}));
  initConfig(config_basic, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://" + TfqdnCodec::encode("http://eric-chfsim-6-mnc-456-mcc-456:3777") + ".sepp.ownplmn.com:80"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));

  default_response_headers_.setCopy(Http::LowerCaseString("location"),"http://eric-chfsim-6-mnc-456-mcc-456:3777");

  auto response = sendRequestAndWaitForResponse(headers,0, default_response_headers_,0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "universal_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "eric-chfsim-6-mnc-456-mcc-456:3777"));

  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "http://" + TfqdnCodec::encode("http://eric-chfsim-6-mnc-456-mcc-456:3777") + ".sepp.ownplmn.com"));

  codec_client_->close();
}

//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------
INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterPSeppTFqdnIntegrationTest,
                         testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest())));

//------------------------------------------------------------------------
//------ T-FQDN INGRESS TESTS PART 2  (P-SEPP) ---------------------------
//--- These tests are implemented so that the routing decision is taken --
//--- based on the headers present or not, and their values. Then the ----
//--- message is routed to a different cluster for each test case, and ---
//--- the x-cluster header is used to check in the test-case if the test -
//--- was successful. ----------------------------------------------------
//------------------------------------------------------------------------
// Name: PAuthOwnFqdn
// Description: Request from ext. NW with only authority=own-FQDN, no TaR
// Expected Result:
// - Request is unmodified
// - No TaR header
TEST_P(EricProxyFilterPSeppTFqdnIntegrationTest, TestPAuthOwnFqdn) {
  BasicClusterConfigurator cluster_config =
      BasicClusterConfigurator(ClusterDefinition({{"no_tar_pool", {"dummy:80"}}}));
  initConfig({config_header_to_metadata, config_basic_p_sepp}, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "sepp.ownplmn.com:80"},
      {"x-eric-sepp-test-san", "stranger.ext-plmn.com"},
      {"x-eric-sepp-rp-name", "rp_A"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(headers,0, default_response_headers_,0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  // We went through our filter:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  // If no TaR header was present, we get routed to the "no_tar_pool" cluster:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "no_tar_pool"));

  codec_client_->close();
}

//------------------------------------------------------------------------
// Name: PAuthOtherFqdn
// Description: Request from ext. NW with only authority=other-FQDN, no TaR
// Expected Result:
// - TaR header is added
// - TaR header is other-FQDN
// - Authority is own-FQDN:ext-port
TEST_P(EricProxyFilterPSeppTFqdnIntegrationTest, TestPAuthOtherFqdn) {
  BasicClusterConfigurator cluster_config = BasicClusterConfigurator(
      ClusterDefinition({{"tar_is_nf_ext_pool", {"nf.ownplmn.com:9090"}}}));
  initConfig({config_header_to_metadata, config_basic_p_sepp}, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "nf.ownplmn.com:9090"},
      {"x-eric-sepp-test-san", "stranger.ext-plmn.com"},
      {"x-eric-sepp-rp-name", "rp_A"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(headers,0, default_response_headers_,0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  // We went through our filter:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  // If TaR header and :authority are correct, we get routed to the "tar_is_ext_nf_pool" cluster:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "tar_is_nf_ext_pool"));

  codec_client_->close();
}

//------------------------------------------------------------------------
// Name: PAuthTaR
// Description: Request from ext. NW with authority=own-FQDN and TaR=other-FQDN
// Expected Result:
// - Request is unmodified
TEST_P(EricProxyFilterPSeppTFqdnIntegrationTest, TestPAuthTaR) {
  BasicClusterConfigurator cluster_config =
      BasicClusterConfigurator(ClusterDefinition({{"tar_is_nf_int_pool", {"nf.ownplmn.com:80"}}}));
  initConfig({config_header_to_metadata, config_basic_p_sepp}, cluster_config);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "sepp.ownplmn.com:9090"},
      {"3gpp-Sbi-target-apiroot", "http://nf.ownplmn.com:80"},
      {"x-eric-sepp-test-san", "stranger.ext-plmn.com"},
      {"x-eric-sepp-rp-name", "rp_A"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(headers,0, default_response_headers_,0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  // We went through our filter:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  // If TaR header and :authority are correct, we get routed to the "tar_is_nf_int_pool" cluster:
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "tar_is_nf_int_pool"));

  codec_client_->close();
}

//------------------------------------------------------------------------
//---- T-FQDN CALLBACK URI MODIFICATION TESTS PART 2  (P-SEPP) -----------
//------------------------------------------------------------------------
// Name: PCallbackMod
// Description: Callback-URI is modified in a request from ext. NW (TaR/R16)
// - Converged-Charging CREATE request from ext. NW
// - authority=own-FQDN
// - TaR=other-FQDN
// - Body has a callback URI at a configured path
// - Target host has endpoint-metadata "supports: TFQDN"
// Expected Result:
// - Callback URI in the request body is translated to T-FQDN
// - Rest of the body is unchanged
TEST_P(EricProxyFilterPSeppTFqdnIntegrationTest, TestPCallbackMod) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("no_tar_pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("nf.ownplmn.com:80")
                                .withHostMd({{"support", {"TFQDN"}}})));

  initConfig({config_header_to_metadata, config_basic_p_sepp}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "sepp.ownplmn.com:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-eric-sepp-test-san", "stranger.ext-plmn.com"},
      {"x-eric-sepp-rp-name", "rp_A"},
      {"test-apiroot", "nf.ownplmn.com:80"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();
  EXPECT_TRUE(upstream_request_->complete());


  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  Body body_obj(&upstream_request_->body(), "application/json");

  // Request body has modified notifyUri:
  // http://192.168.0.2:8080/rar -> http://NB2HI4B2F4XTCOJSFYYTMOBOGAXDEORYGA4DA.sepp.own-fqdn.com/rar"
  auto value = body_obj.readWithPointer("/notifyUri");
  EXPECT_TRUE(value.ok());
  EXPECT_EQ(*value, "http://" + TfqdnCodec::encode("http://192.168.0.2:8080") + ".sepp.ownplmn.com/rar");

  // TaR header is removed (because we send to an NF (with TFQDN, but that doesn't matter))
  EXPECT_TRUE(
        upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());

}
//------------------------------------------------------------------------
// DND-28882 Envoy crashes on a request with a tcmalloc "failed to allocate"
// error.
TEST_P(EricProxyFilterPSeppTFqdnIntegrationTest, TestDnd28882) {
  BasicClusterConfigurator cluster_config =
      BasicClusterConfigurator(ClusterDefinition({{"Pool_NfUdm#!_#aggr:", {"nf.ownplmn.com:80"}}}));
  initConfig({config_header_to_metadata, config_dnd_28882}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/dummy-uri"},
      {":authority", "sepp.mnc.567.mcc.765.ericsson.de:31772"},
      {"3gpp-Sbi-target-apiRoot", "http://nfUdm1.mnc.567.mcc.765.ericsson.de:8292"},
      {"via", "http/2 seroiuvd08419.sero.gic.ericsson.se,2.0 sepp.mnc.567.mcc.765.ericsson.de"},
      {"content-type", "application/json"},
      {"content-length", "18"},
      {"x-forwarded-proto", "https"},
      {"x-request-id", "ab5125e3-cf25-48a6-9c30-0c64a0db865e"},
      {"x-eric-sepp-test-san", "pSepp11.mnc.012.mcc.210.ericsson.se"},
      {"x-eric-sepp-rp-name", "rp_A"},
  };

  const std::string request_body{"{\"notifyItems\":[]}"};
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, request_body);
  waitForNextUpstreamRequest();
  EXPECT_TRUE(upstream_request_->complete());
  codec_client_->close();
}


// Name: DND-28833
// Description: Callback-URI is not modified in a request from ext. NW (TaR/R16) if T-FQDN is not configured
// - Converged-Charging CREATE request from ext. NW
// - authority=own-FQDN
// - TaR=other-FQDN
// - Body has a callback URI at a configured path
// - Target host has endpoint-metadata "supports: TFQDN"
// Expected Result:
// - Callback URI in the request body is the body is unchanged
TEST_P(EricProxyFilterPSeppTFqdnIntegrationTest, TestPCallbackModNoTFqdnConfigured) {
  BasicClusterConfigurator cluster_config =
      BasicClusterConfigurator(ClusterDefinition({{"no_tar_pool", {"dummy.ownplmn.com:80"}}}));
  initConfig({config_header_to_metadata, config_basic_p_sepp_no_cburi}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "sepp.ownplmn.com:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-eric-sepp-test-san", "stranger.ext-plmn.com"},
      {"x-eric-sepp-rp-name", "rp_A"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();
  EXPECT_TRUE(upstream_request_->complete());


  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Request body is not modified
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);

  // TaR header is removed (because we send to an NF (with TFQDN, but that doesn't matter))
  EXPECT_TRUE(
        upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());

}

// Name: TestPCallbackMod_EgressScreeningBodyMod
// Description: Callback-URI is modified in a request from ext. NW (TaR/R16)
// - Converged-Charging CREATE request from ext. NW
// - authority=own-FQDN
// - TaR=other-FQDN
// - Body has a callback URI at a configured path
// - Target host has endpoint-metadata "supports: TFQDN"
//
// - Egress Msg. Screening is configured with action-modify-json-body 
//
// Expected Result:
// - Callback URI in the request body is translated to T-FQDN
// - Rest of the body is unchanged
// - action-modify-json-body is applied to the "original-body" (buffer) and the T-FQDN
//   modified body in dynamic Metadata 
//
TEST_P(EricProxyFilterPSeppTFqdnIntegrationTest, TestPCallbackMod_EgressScreeningBodyMod) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("no_tar_pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("nf.ownplmn.com:80")
                                .withHostMd({{"support", {"TFQDN"}}})));

  initConfig({config_header_to_metadata, config_basic_p_sepp_egress_scr}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "sepp.ownplmn.com:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-eric-sepp-test-san", "stranger.ext-plmn.com"},
      {"x-eric-sepp-rp-name", "rp_A"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();
  EXPECT_TRUE(upstream_request_->complete());


  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  Body body_obj(&upstream_request_->body(), "application/json");

  // Request body has modified notifyUri:
  // http://192.168.0.2:8080/rar -> http://NB2HI4B2F4XTCOJSFYYTMOBOGAXDEORYGA4DA.sepp.own-fqdn.com/rar"
  auto value = body_obj.readWithPointer("/notifyUri");
  EXPECT_TRUE(value.ok());
  EXPECT_EQ(*value, "http://" + TfqdnCodec::encode("http://192.168.0.2:8080") + ".sepp.ownplmn.com/rar");

  value = body_obj.readWithPointer("/subscriberIdentifier1");
  EXPECT_TRUE(value.ok());
  EXPECT_EQ(*value, "supi-added");

  // TaR header is removed (because we send to an NF (with TFQDN, but that doesn't matter))
  EXPECT_TRUE(
        upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());

}


} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
