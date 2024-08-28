#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "base_integration_test.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "config_utils/pluggable_configurator.h"
#include "config_utils/endpoint_md_cluster_md_configurator.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterEgressScreeningTest : public PluggableConfigurator{

public :
  EricProxyFilterEgressScreeningTest() = default;
  void SetUp() override { }
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  /*
    Manager adds suffix #!_#LRP: and #!_#aggr: in case of round-robin routing and preferred routing
    to x-cluster having last resort pool, so comparison with kvt should not fail as kvt values
    don't have these suffixes in request screening
  */
  const std::string config_phase_2_3 = R"EOF(
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
          'correct-pool': out_req_screening_cp
          'wrong-pool': out_req_screening_wp
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: correct_route_rr
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: routing-behaviour }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'ROUND_ROBIN' }}
        actions:
          - action_route_to_pool:
              pool_name:
                term_string: 'correct-pool#!_#LRP:correct-lrp-pool#!_#aggr:'
              routing_behaviour: ROUND_ROBIN
      - name: correct_route_pr
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: routing-behaviour }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'PREFERRED' }}
        actions:
          - action_route_to_pool:
              pool_name:
                term_string: 'correct-pool#!_#LRP:correct-lrp-pool#!_#aggr:'
              routing_behaviour: PREFERRED
              preserve_if_indirect: TARGET_API_ROOT
              preferred_target:
                term_header: "3gpp-Sbi-target-apiRoot"
      - name: correct_route_sr
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: routing-behaviour }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'STRICT' }}
        actions:
          - action_route_to_pool:
              pool_name:
                term_string: 'correct-pool'
              routing_behaviour: STRICT
              preserve_if_indirect: TARGET_API_ROOT
              preferred_target:
                term_header: "3gpp-Sbi-target-apiRoot"
      - name: fall_through
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: 'wrong-pool'
            routing_behaviour: ROUND_ROBIN
    - name: out_req_screening_cp
      filter_data:
      - name: locality_header
        header: locality
        variable_name: locality
      filter_rules:
      - name: loc1
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: locality }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'datacenter0' }}
        actions:
        - action_modify_header:
            name: locality
            replace_value:
              term_string: datacenter1
        - action_add_header:
            name: x-loc
            value:
              term_string: "locality 1 rule executed"
    - name: out_req_screening_wp
      filter_data:
      - name: locality_header
        header: locality
        variable_name: locality
      filter_rules:
      - name: loc2
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: locality }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'datacenter0' }}
        actions:
        - action_modify_header:
            name: locality
            replace_value:
              term_string: datacenter2
        - action_add_header:
            name: x-loc
            value:
              term_string: "locality 2 rule executed"

  )EOF";

  const std::string config_phase_2_4 = R"EOF(
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
  response_filter_cases:
    in_response_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          'correct-pool': in_resp_screening_cp
          'wrong-pool': in_resp_screening_wp
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: correct_route_rr
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: routing-behaviour }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'ROUND_ROBIN' }}
        actions:
          - action_route_to_pool:
              pool_name:
                term_string: 'correct-pool#!_#LRP:correct-lrp-pool#!_#aggr:'
              routing_behaviour: ROUND_ROBIN
      - name: correct_route_pr
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: routing-behaviour }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'PREFERRED' }}
        actions:
          - action_route_to_pool:
              pool_name:
                term_string: 'correct-pool#!_#LRP:correct-lrp-pool#!_#aggr:'
              routing_behaviour: PREFERRED
              preserve_if_indirect: TARGET_API_ROOT
              preferred_target:
                term_header: "3gpp-Sbi-target-apiRoot"
      - name: correct_route_sr
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: routing-behaviour }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'STRICT' }}
        actions:
          - action_route_to_pool:
              pool_name:
                term_string: 'correct-pool'
              routing_behaviour: STRICT
              preserve_if_indirect: TARGET_API_ROOT
              preferred_target:
                term_header: "3gpp-Sbi-target-apiRoot"
      - name: fall_through
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: 'wrong-pool'
            routing_behaviour: ROUND_ROBIN
    - name: in_resp_screening_cp
      filter_data:
      - name: locality_header
        header: resp-locality
        variable_name: locality
      filter_rules:
      - name: loc1
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: locality }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'datacenter0' }}
        actions:
        - action_modify_header:
            name: resp-locality
            replace_value:
              term_string: datacenter1
        - action_add_header:
            name: x-loc
            value:
              term_string: "resp locality 1 rule executed"
    - name: in_resp_screening_wp
      filter_data:
      - name: locality_header
        header: resp-locality
        variable_name: locality
      filter_rules:
      - name: loc2
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: locality }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'datacenter0' }}
        actions:
        - action_modify_header:
            name: resp-locality
            replace_value:
              term_string: datacenter2
        - action_add_header:
            name: x-loc
            value:
              term_string: "resp locality 2 rule executed"
  )EOF";

  /*
    Bug (segfault due to missing x-cluster): When routing stage fails no egress screening 
    should be invoked
  */
  const std::string config_route_fail_phase_2_3 = R"EOF(
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
          correct-pool: out_req_screening_cp
          wrong-pool: out_req_screening_wp
  filter_cases:
    - name: default_routing
      filter_data:
      - name: amf-mcc-ex
        path: true
        extractor_regex: /namf-comm/v1/ue-contexts/imsi-(?P<mcc>\d\d\d)(?P<mnc>\d\d\d)\d+/
      - name: udm-mcc-ex
        path: true
        extractor_regex: /nudm-uecm/v1/imsi-(?P<mcc>\d\d\d)(?P<mnc>\d\d\d)\d+/registrations
      filter_rules:
      - name: correct_route
        condition:
          op_and:
            arg1:
              op_equals: 
                typed_config1: 
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_var: mcc 
                typed_config2: 
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_string: '206' 
            arg2:
              op_equals: 
                typed_config1: 
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_var: mnc 
                typed_config2: 
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_string: '033' 
        actions:
          - action_route_to_pool:
              pool_name:
                term_string: correct-pool
              routing_behaviour: ROUND_ROBIN
      - name: alt_route
        condition:
          op_and:
            arg1:
              op_equals: 
                typed_config1: 
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_var: mcc 
                typed_config2: 
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_string: '210' 
            arg2:
              op_equals: 
                typed_config1: 
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_var: mnc 
                typed_config2: 
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_string: '036' 
        actions:
          - action_route_to_pool:
              pool_name:
                term_string: wrong-pool
              routing_behaviour: ROUND_ROBIN
    - name: out_req_screening_cp
      filter_data:
      - name: locality_header
        header: locality
        variable_name: locality
      filter_rules:
      - name: loc1
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: locality }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'datacenter0' }}
        actions:
        - action_modify_header:
            name: locality
            replace_value:
              term_string: datacenter1
        - action_add_header:
            name: x-loc
            value:
              term_string: "locality 1 rule executed"
    - name: out_req_screening_wp
      filter_data:
      - name: locality_header
        header: locality
        variable_name: locality
      filter_rules:
      - name: loc2
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: locality }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'datacenter0' }}
        actions:
        - action_modify_header:
            name: locality
            replace_value:
              term_string: datacenter2
        - action_add_header:
            name: x-loc
            value:
              term_string: "locality 2 rule executed"

  )EOF";

  /*
    Action Route to Roaming Partner -> Egress Screening //start
  */
  const std::string config_route_to_rp_phase_2_3 = R"EOF(
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
          sepp_rp_tar: out_req_screening_tar
          sepp_rp_no_tar: out_req_screening_no_tar
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
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 8888
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
                typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-Sbi-target-apiRoot'}
                typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://eric-chfsim-6-mnc-456-mcc-456:3777'}
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
    - name: out_req_screening_tar
      filter_data:
      - name: locality_header
        header: locality
        variable_name: locality
      filter_rules:
      - name: loc1
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: locality }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'datacenter0' }}
        actions:
        - action_modify_header:
            name: locality
            replace_value:
              term_string: datacenter1
        - action_add_header:
            name: x-loc
            value:
              term_string: "locality 1 rule executed"
    - name: out_req_screening_no_tar
      filter_data:
      - name: locality_header
        header: locality
        variable_name: locality
      filter_rules:
      - name: loc2
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: locality }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'datacenter0' }}
        actions:
        - action_modify_header:
            name: locality
            replace_value:
              term_string: datacenter2
        - action_add_header:
            name: x-loc
            value:
              term_string: "locality 2 rule executed"
  roaming_partners:
    - name: rp_tar
      pool_name: sepp_rp_tar
    - name: rp_no_tar
      pool_name: sepp_rp_no_tar
)EOF";

const std::string config_route_to_rp_phase_2_3_alter_tar = R"EOF(
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
          sepp_rp_tar: out_req_screening_tar
          sepp_rp_no_tar: out_req_screening_no_tar
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 8888
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
                typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-Sbi-target-apiRoot'}
                typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://eric-chfsim-6-mnc-456-mcc-456:3777'}
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_tar
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: tar_absent
        condition:
          term_boolean: true
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_no_tar
            routing_behaviour: ROUND_ROBIN
    - name: out_req_screening_tar
      filter_rules:
      - name: modify_tar
        condition:
          term_boolean: true
        actions:
        - action_modify_header:
            name: 3gpp-sbi-target-apiroot
            replace_value:
              term_string: 'https://eric-chfsim-6-mnc-456-mcc-456:3777'
        - action_add_header:
            name: x-loc
            value:
              term_string: "TaR 1 rule executed"
    - name: out_req_screening_no_tar
      filter_data:
      - name: locality_header
        header: locality
        variable_name: locality
      filter_rules:
      - name: loc2
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: locality }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'datacenter0' }}
        actions:
        - action_modify_header:
            name: locality
            replace_value:
              term_string: datacenter2
        - action_add_header:
            name: x-loc
            value:
              term_string: "locality 2 rule executed"
  roaming_partners:
    - name: rp_tar
      pool_name: sepp_rp_tar
    - name: rp_no_tar
      pool_name: sepp_rp_no_tar
)EOF";

const std::string config_route_to_rp_phase_2_3_alter_tar_scp = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp_router
  node_type: SCP
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
          tar_scp_pool: out_req_screening_tar
          no_tar_scp_pool: out_req_screening_no_tar
  own_fqdn: scp.own_plmn.com
  own_internal_port: 8888
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
                typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-Sbi-target-apiRoot'}
                typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://eric-chfsim-6-mnc-456-mcc-456:3777'}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: tar_scp_pool
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: tar_absent
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool: 
            pool_name: 
              term_string: no_tar_scp_pool
            routing_behaviour: ROUND_ROBIN
    - name: out_req_screening_tar
      filter_rules:
      - name: modify_tar
        condition:
          term_boolean: true
        actions:
        - action_modify_header:
            name: 3gpp-sbi-target-apiroot
            replace_value:
              term_string: 'https://eric-chfsim-6-mnc-456-mcc-456:3777'
        - action_add_header:
            name: x-loc
            value:
              term_string: "TaR 1 rule executed"
    - name: out_req_screening_no_tar
      filter_data:
      - name: locality_header
        header: locality
        variable_name: locality
      filter_rules:
      - name: loc2
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: locality }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'datacenter0' }}
        actions:
        - action_modify_header:
            name: locality
            replace_value:
              term_string: datacenter2
        - action_add_header:
            name: x-loc
            value:
              term_string: "locality 2 rule executed"
)EOF";


  /*
    Action Route to Roaming Partner -> Egress Screening //end
  */

  // Common function for request path egress screening tests with different routing behaviours
  void testRequestPathEgressScreening(const std::string& routing_behaviour,
    const std::string& expected_cluster, const std::string& expected_locality,
    const std::string& expected_xloc) {
    EndpointMetadataClusterConfigurator cluster_config =
        EndpointMetadataClusterConfigurator()
            .withClusterBuilder(ClusterBuilder()
                                    .withName("correct-pool")
                                    .withEndpoint(EndpointBuilder()
                                                      .withHostName("chf1.ericsson.com:80")
                                                      .withHostMd({{"support", {"NF"}}})))
            .withClusterBuilder(ClusterBuilder()
                                    .withName("correct-lrp-pool")
                                    .withEndpoint(EndpointBuilder()
                                                      .withHostName("chf2.ericsson.com:80")
                                                      .withHostMd({{"support", {"NF"}}})))
            .withClusterBuilder(ClusterBuilder()
                                    .withName("wrong-pool")
                                    .withEndpoint(EndpointBuilder()
                                                      .withHostName("chf3.ericsson.com:80")
                                                      .withHostMd({{"support", {"NF"}}})))
            .withAggregateCluster({"correct-pool#!_#LRP:correct-lrp-pool#!_#aggr:", "correct-pool",
                                   "correct-lrp-pool"});

    initConfig(config_phase_2_3, cluster_config);

    IntegrationCodecClientPtr codec_client;
    FakeHttpConnectionPtr fake_upstream_connection;
    FakeStreamPtr request_stream;

    codec_client = makeHttpConnection(lookupPort("http"));

    Http::TestRequestHeaderMapImpl req_headers {
      {":method", "GET"},
      {":authority", "host"},
      {":path", "/nudm-uecm/v1/imsi-2060330007487/registrations"},
      {"3gpp-Sbi-target-apiRoot", "http://chf1.ericsson.com:80"},
      {"routing-behaviour", routing_behaviour},
      {"locality", "datacenter0"}
    };
    auto response = codec_client->makeHeaderOnlyRequest(req_headers);

    if (
      expected_cluster == "correct-pool#!_#LRP:correct-lrp-pool#!_#aggr:" ||
      expected_cluster == "correct-pool"
    ) {
      ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
    }    
    if (expected_cluster == "wrong-pool") {
      ASSERT_TRUE(fake_upstreams_[2]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
    }
    ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
    ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

    // Send fake upstream response:
    Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};
    request_stream->encodeHeaders(response_headers, true);

    ASSERT_TRUE(response->waitForEndStream());
    ASSERT_TRUE(fake_upstream_connection->close());
    
    // Verify upstream request
    EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("x-cluster", expected_cluster));
    EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("locality", expected_locality));
    EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("x-loc", expected_xloc));

    // Verify downstream response
    EXPECT_THAT(response->headers().get(Http::LowerCaseString(":status"))[0]->value().getStringView(), "200");

    codec_client->close();
  }

  // Common function for response path egress screening tests with different routing behaviours
  void testResponsePathEgressScreening(const std::string& routing_behaviour,
    const std::string& expected_cluster, const std::string& expected_locality,
    const std::string& expected_xloc, const std::string& expected_resp_locality) {
    EndpointMetadataClusterConfigurator cluster_config =
        EndpointMetadataClusterConfigurator()
            .withClusterBuilder(ClusterBuilder()
                                    .withName("correct-pool")
                                    .withEndpoint(EndpointBuilder()
                                                      .withHostName("chf1.ericsson.com:80")
                                                      .withHostMd({{"support", {"NF"}}})))
            .withClusterBuilder(ClusterBuilder()
                                    .withName("correct-lrp-pool")
                                    .withEndpoint(EndpointBuilder()
                                                      .withHostName("chf2.ericsson.com:80")
                                                      .withHostMd({{"support", {"NF"}}})))
            .withClusterBuilder(ClusterBuilder()
                                    .withName("wrong-pool")
                                    .withEndpoint(EndpointBuilder()
                                                      .withHostName("chf3.ericsson.com:80")
                                                      .withHostMd({{"support", {"NF"}}})))
            .withAggregateCluster({"correct-pool#!_#LRP:correct-lrp-pool#!_#aggr:", "correct-pool",
                                   "correct-lrp-pool"});
    initConfig(config_phase_2_4, cluster_config);

    IntegrationCodecClientPtr codec_client;
    FakeHttpConnectionPtr fake_upstream_connection;
    FakeStreamPtr request_stream;

    codec_client = makeHttpConnection(lookupPort("http"));

    Http::TestRequestHeaderMapImpl req_headers {
      {":method", "GET"},
      {":authority", "host"},
      {":path", "/nudm-uecm/v1/imsi-2060330007487/registrations"},
      {"3gpp-Sbi-target-apiRoot", "http://chf1.ericsson.com:80"},
      {"routing-behaviour", routing_behaviour},
      {"locality", "datacenter0"},
    };
    auto response = codec_client->makeHeaderOnlyRequest(req_headers);

    if (
      expected_cluster == "correct-pool#!_#LRP:correct-lrp-pool#!_#aggr:" ||
      expected_cluster == "correct-pool"
    ) {
      ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
    }    
    if (expected_cluster == "wrong-pool") {
      ASSERT_TRUE(fake_upstreams_[2]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
    }
    ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
    ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

    // Send fake upstream response:
    Http::TestResponseHeaderMapImpl response_headers{
        {":status", "200"},
        {"resp-locality", "datacenter0"}
    };  
    request_stream->encodeHeaders(response_headers, true);

    ASSERT_TRUE(response->waitForEndStream());
    ASSERT_TRUE(fake_upstream_connection->close());

    // Verify upstream request
    EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("x-cluster", expected_cluster));
    EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("locality", expected_locality));

    // Verify downstream response
    EXPECT_THAT(response->headers().get(Http::LowerCaseString(":status"))[0]->value().getStringView(), "200");
    EXPECT_THAT(response->headers().get(Http::LowerCaseString("x-loc"))[0]->value().getStringView(), expected_xloc);
    EXPECT_THAT(response->headers().get(Http::LowerCaseString("resp-locality"))[0]->value().getStringView(), expected_resp_locality);

    codec_client->close();
  }

};
// End Initializer Class

//------------------------------------------------------------------------
//-------------BEGIN TEST SUITES---------------------
//------------------------------------------------------------------------
INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterEgressScreeningTest,
                         testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest())));


// Basic test Check Only Phase 3 SCREENING

TEST_P(EricProxyFilterEgressScreeningTest, TestEgressScreening_req_rr)
{
  testRequestPathEgressScreening(
    "ROUND_ROBIN", "correct-pool#!_#LRP:correct-lrp-pool#!_#aggr:",
    "datacenter1", "locality 1 rule executed"
  );
}

TEST_P(EricProxyFilterEgressScreeningTest, TestEgressScreening_req_pr)
{
  testRequestPathEgressScreening(
    "PREFERRED", "correct-pool#!_#LRP:correct-lrp-pool#!_#aggr:",
    "datacenter1", "locality 1 rule executed"
  );
}

TEST_P(EricProxyFilterEgressScreeningTest, TestEgressScreening_req_sr)
{
  testRequestPathEgressScreening(
    "STRICT", "correct-pool", "datacenter1", "locality 1 rule executed"
  );
}

TEST_P(EricProxyFilterEgressScreeningTest, TestEgressScreening_req_no_rb)
{
  testRequestPathEgressScreening(
    "", "wrong-pool", "datacenter2", "locality 2 rule executed"
  );
}

// Basic test Check Only Phase 4 SCREENING

TEST_P(EricProxyFilterEgressScreeningTest, TestEgressScreening_resp_rr)
{
  testResponsePathEgressScreening(
    "ROUND_ROBIN", "correct-pool#!_#LRP:correct-lrp-pool#!_#aggr:",
    "datacenter0", "resp locality 1 rule executed", "datacenter1"
  );
}

TEST_P(EricProxyFilterEgressScreeningTest, TestEgressScreening_resp_pr)
{
  testResponsePathEgressScreening(
    "PREFERRED", "correct-pool#!_#LRP:correct-lrp-pool#!_#aggr:",
    "datacenter0", "resp locality 1 rule executed", "datacenter1"
  );
}

TEST_P(EricProxyFilterEgressScreeningTest, TestEgressScreening_resp_sr)
{
  testResponsePathEgressScreening(
    "STRICT", "correct-pool", "datacenter0", "resp locality 1 rule executed", "datacenter1"
  );
}

TEST_P(EricProxyFilterEgressScreeningTest, TestEgressScreening_resp_no_rb)
{
  testResponsePathEgressScreening(
    "", "wrong-pool", "datacenter0", "resp locality 2 rule executed", "datacenter2"
  );
}

// Bugfix (segfault): When routing stage cannot find a pool to route to because of failure
// x-cluster would be empty and filter-chain should not proceed with egress screening
// should respond with 404
TEST_P(EricProxyFilterEgressScreeningTest, TestEgressScreening_route_fail)
{
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator()
          .withClusterBuilder(ClusterBuilder()
                                  .withName("correct-pool")
                                  .withEndpoint(EndpointBuilder()
                                                    .withHostName("chf1.ericsson.com:80")
                                                    .withHostMd({{"support", {"NF"}}})))

          .withClusterBuilder(ClusterBuilder()
                                  .withName("wrong-pool")
                                  .withEndpoint(EndpointBuilder()
                                                    .withHostName("chf3.ericsson.com:80")
                                                    .withHostMd({{"support", {"NF"}}})));

  initConfig(config_route_fail_phase_2_3, cluster_config);

  IntegrationCodecClientPtr codec_client;
  codec_client = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/nudm-uecm/v1/imsi-2161330007487/registrations"},
    {"locality", "datacenter0"},
  };
  auto response = codec_client->makeHeaderOnlyRequest(req_headers);
  ASSERT_TRUE(response->waitForEndStream());

  // Verify downstream response
  ASSERT_TRUE(
    response->headers().get(Http::LowerCaseString(":status"))[0]->value().getStringView() == "404" ||
    response->headers().get(Http::LowerCaseString(":status"))[0]->value().getStringView() == "503"
  );

  codec_client->close();
}

// Check action_route_to_rp integration with egress req Message Screening
TEST_P(EricProxyFilterEgressScreeningTest, TestEgressScreening_route_to_rp)
{

  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator()
          .withClusterBuilder(ClusterBuilder()
                                  .withName("sepp_rp_tar")
                                  .withEndpoint(EndpointBuilder()
                                                    .withHostName("sepp1.rp_tar.com:80")
                                                    .withHostMd({{"support", {"Indirect"}}})))
          .withClusterBuilder(ClusterBuilder()
                                  .withName("sepp_rp_no_tar")
                                  .withEndpoint(EndpointBuilder()
                                                    .withHostName("sepp1.rp_no_tar.com:80")
                                                    .withHostMd({{"support", {"Indirect"}}})));

  initConfig(config_route_to_rp_phase_2_3, cluster_config);

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":path", "/test_api_name_1/v1/"},
    {":authority", "sepp.own_plmn.com:8888"},
    {"locality", "datacenter0"},
  };
  auto response = codec_client->makeHeaderOnlyRequest(req_headers);
  
  ASSERT_TRUE(fake_upstreams_[1]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

  // Send fake upstream response:
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};
  request_stream->encodeHeaders(response_headers, true);

  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection->close());
  
  // Verify upstream request
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("x-cluster","sepp_rp_no_tar"));
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("locality","datacenter2"));
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("x-loc", "locality 2 rule executed"));

  // Verify downstream response
  EXPECT_THAT(response->headers().get(Http::LowerCaseString(":status"))[0]->value().getStringView(), "200");

  codec_client->close();
}

const std::string config_basic = R"EOF(
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
    
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 8888
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: tar_present
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: foo
            routing_behaviour: STRICT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
)EOF";

// Check action_route_to_rp integration with egress req Message Screening
TEST_P(EricProxyFilterEgressScreeningTest, interplmn_fqdn_test) {

  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("foo")
              .withClusterMd({{"nfudm7.mnc567.mcc765.3gppnetwork.org:80",
                               {{{"fqdn", "nfudm7.mnc.567.mcc.765.ericsson.de:80"},
                                 {"ip", "192.168.1.1:80"}}}}})
              .withEndpoint(EndpointBuilder()
                                .withHostName("nfudm7.mnc.567.mcc.765.ericsson.de:80")
                                .withHostMd({{"support", {"NF", "TFQDN"}},
                                             {"interplmn_fqdn",
                                              {"nfudm7.mnc567.mcc765.3gppnetwork.org:80"}}})));

  initConfig(config_basic, cluster_config);
    IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));
    Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "sepp.own_plmn.com:8888"},
      {"3gpp-Sbi-target-apiRoot", "http://nfudm7.mnc567.mcc765.3gppnetwork.org:80"},
  };
  auto response = codec_client->makeHeaderOnlyRequest(req_headers);
    ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

  // Send fake upstream response:
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};
  request_stream->encodeHeaders(response_headers, true);

  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection->close());
    // Verify upstream request
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "foo"));
  EXPECT_THAT(request_stream->headers(),
              Http::HeaderValueOf(":authority", "nfudm7.mnc567.mcc765.3gppnetwork.org:80"));

  // Verify downstream response
  EXPECT_THAT(response->headers().get(Http::LowerCaseString(":status"))[0]->value().getStringView(),
              "200");
  codec_client->close();
}
// DND 50654 Stale value of TaR header after egress screening modifies scheme or path attributes
// of it
// Check action_route_to_rp integration with egress req Message Screening
TEST_P(EricProxyFilterEgressScreeningTest, TestEgressScreening_route_to_rp2)
{
// R"EOF(
// metadata:
//   filter_metadata:
//     envoy.eric_proxy.cluster:
//       eric-chfsim-6-mnc-456-mcc-456:3777:
//       - fqdn: 'sepp1.rp_tar.com:80'
//         ip: '10.10.10.1:443'
//       - fqdn: 'scp2.ericsson.se:443'
//         ip: '10.10.10.2:443'
//       chf2.ericsson.se:443:
//       - fqdn: 'sepp1.rp_no_tar.com:80'
//         ip: '10.10.10.3:443'
// )EOF";

    EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("sepp_rp_tar")
              .withClusterMd({{"eric-chfsim-6-mnc-456-mcc-456:3777",
                               {{{"fqdn", "sepp1.rp_tar.com:80"},
                                 {"ip", "10.10.10.1:443"}}}},
                                 {"chf2.ericsson.se:443",
                               {{{"fqdn", "sepp1.rp_no_tar.com:80"},
                                 {"ip", "10.10.10.3:443"}}}}
                                 })
              .withEndpoint(EndpointBuilder()
                                .withHostName("sepp1.rp_tar.com:80")
                                .withHostMd({{"support", {"Indirect"}}})))
.withClusterBuilder(
          ClusterBuilder()
              .withName("sepp_rp_no_tar")
              .withClusterMd({{"eric-chfsim-6-mnc-456-mcc-456:3777",
                               {{{"fqdn", "sepp1.rp_tar.com:80"},
                                 {"ip", "10.10.10.1:443"}}}},
                                 {"chf2.ericsson.se:443",
                               {{{"fqdn", "sepp1.rp_no_tar.com:80"},
                                 {"ip", "10.10.10.3:443"}}}}
                                 })
              .withEndpoint(EndpointBuilder()
                                .withHostName("sepp1.rp_no_tar.com:80")
                                .withHostMd({{"support", {"Indirect"}}})));
  initConfig(config_route_to_rp_phase_2_3_alter_tar, cluster_config);

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":path", "/test_api_name_1/v1/"},
    {":authority", "sepp.own_plmn.com:8888"},
    {"3gpp-sbi-target-apiroot","http://eric-chfsim-6-mnc-456-mcc-456:3777"},
    {"locality", "datacenter0"},
  };
  auto response = codec_client->makeHeaderOnlyRequest(req_headers);
  
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

  // Send fake upstream response:
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};
  request_stream->encodeHeaders(response_headers, true);

  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection->close());
  
  // Verify upstream request
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("x-cluster","sepp_rp_tar"));
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("3gpp-sbi-target-apiroot","https://eric-chfsim-6-mnc-456-mcc-456:3777"));
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("locality","datacenter0"));
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("x-loc", "TaR 1 rule executed"));

  // Verify downstream response
  EXPECT_THAT(response->headers().get(Http::LowerCaseString(":status"))[0]->value().getStringView(), "200");

  codec_client->close();
}

TEST_P(EricProxyFilterEgressScreeningTest, TestEgressScreening_route_to_rp2_scp)
{

      EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("tar_scp_pool")
              .withClusterMd({{"eric-chfsim-6-mnc-456-mcc-456:3777",
                               {{{"fqdn", "sepp1.rp_tar.com:80"},
                                 {"ip", "10.10.10.1:443"}}}},
                                 {"chf2.ericsson.se:443",
                               {{{"fqdn", "sepp1.rp_no_tar.com:80"},
                                 {"ip", "10.10.10.3:443"}}}}
                                 })
              .withEndpoint(EndpointBuilder()
                                .withHostName("sepp1.rp_tar.com:80")
                                .withHostMd({{"support", {"Indirect"}}})))
.withClusterBuilder(
          ClusterBuilder()
              .withName("no_tar_scp_pool")
              .withClusterMd({{"eric-chfsim-6-mnc-456-mcc-456:3777",
                               {{{"fqdn", "sepp1.rp_tar.com:80"},
                                 {"ip", "10.10.10.1:443"}}}},
                                 {"chf2.ericsson.se:443",
                               {{{"fqdn", "sepp1.rp_no_tar.com:80"},
                                 {"ip", "10.10.10.3:443"}}}}
                                 })
              .withEndpoint(EndpointBuilder()
                                .withHostName("sepp1.rp_no_tar.com:80")
                                .withHostMd({{"support", {"Indirect"}}})));
  initConfig(config_route_to_rp_phase_2_3_alter_tar_scp, cluster_config);

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":path", "/test_api_name_1/v1/"},
    {":authority", "scp.own_plmn.com:8888"},
    {"3gpp-sbi-target-apiroot","http://eric-chfsim-6-mnc-456-mcc-456:3777"},
    {"locality", "datacenter0"},
  };
  auto response = codec_client->makeHeaderOnlyRequest(req_headers);
  
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

  // Send fake upstream response:
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};
  request_stream->encodeHeaders(response_headers, true);

  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(fake_upstream_connection->close());
  
  // Verify upstream request
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("x-cluster","tar_scp_pool"));
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("3gpp-sbi-target-apiroot","https://eric-chfsim-6-mnc-456-mcc-456:3777"));
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("locality","datacenter0"));
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("x-loc", "TaR 1 rule executed"));

  // Verify downstream response
  EXPECT_THAT(response->headers().get(Http::LowerCaseString(":status"))[0]->value().getStringView(), "200");

  codec_client->close();
}


} //namespace
} //EricProxy
} //HttpFilters
} //Extensions
} //Envoy 
