#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "base_integration_test.h"

#include "config_utils/pluggable_configurator.h"
#include "config_utils/basic_cluster_configurator.h"
#include "config_utils/endpoint_md_cluster_md_configurator.h"

#include "test/integration/utility.h"
#include "include/nlohmann/json.hpp"
#include <iostream>
#include <ostream>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

using Json = nlohmann::json;

enum Scope { ALL, SOME, NONE };

// Configuration to test "preferred_target" in action_route_to_pool and
const std::string config_preferred_target{R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.own_plmn.com
  own_external_port: 80
  request_filter_cases:
    routing:
      ext_nw:
        name: "external network"
        ext_nw_fc_config_list:
        - per_rp_fc_config:
            rp_to_fc_map:
              rp_1: rp_1_routing
              rp_2: rp_2_routing
              rp_3: rp_3_routing
              rp_4: rp_4_routing
            default_fc_for_rp_not_found: rp_1_routing
  callback_uri_klv_table: callback_uris
  rp_name_table : rp_san_to_name
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
  key_value_tables:
    - name: rp_san_to_name
      entries:
        - key: rpa.extplmn.com
          value: rp_1
        - key: rpb.extplmn.com
          value: rp_2
        - key: rpc.extplmn.com
          value: rp_3
        - key: rpd.extplmn.com
          value: rp_4
  filter_cases:
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
    - name: rp_1_routing
      filter_data:
      - name: nudm
        path: true
        extractor_regex: (?P<nudm>/nudm-*)
      - name: nausf
        path: true
        extractor_regex: (?P<nausf>/nausf-*)
      filter_rules:
      - name: nausf_to_ausf1pool
        condition:
          op_and:
            arg1:
              op_exists: {arg1: {term_var: 'nausf'}}
            arg2:
              op_not: {arg1: {op_isempty: {arg1: {term_var: 'nausf'}}}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: ausf1pool
            routing_behaviour: STRICT
      - name: nudm_to_rp1pool
        condition:
          op_and:
            arg1:
              op_exists: {arg1: {term_var: 'nudm'}}
            arg2:
              op_not: {arg1: {op_isempty: {arg1: {term_var: 'nudm'}}}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: rp1pool
            routing_behaviour: ROUND_ROBIN
    - name: rp_2_routing
      filter_data:
      - name: apiRoot_header
        header: 3gpp-Sbi-target-apiRoot
        variable_name: apiRoot_hdr
      filter_rules:
      - name: to_udm2pool
        condition:
          op_and:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://udm2.com'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: udm2pool
            routing_behaviour: ROUND_ROBIN
      - name: to_ausf2pool
        condition:
          op_and:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://ausfx.com'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: ausf2pool
            routing_behaviour: STRICT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: to_unknownPool
        condition:
          op_and:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
            arg2:
              op_or:
                arg1: 
                  op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                              typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://udm3.com'}}
                arg2:
                  op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                              typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://ausf3.com'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: unknownPool
            routing_behaviour: STRICT
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
      - name: to_rp2pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: rp2pool
            routing_behaviour: STRICT
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
    - name: rp_3_routing
      filter_data:
      - name: apiRoot_header
        header: 3gpp-Sbi-target-apiRoot
        variable_name: apiRoot_hdr
      filter_rules:
      - name: to_udm3pool
        condition:
          op_and:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://udm3.com'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: udm3pool
            routing_behaviour: ROUND_ROBIN
      - name: to_udm2_reject
        condition:
          op_and:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://udm2.com'}}
        actions:
        - action_reject_message:
                status: 404
                title: "not possible in SEPP for a user?!"
                message_format: PLAIN_TEXT
      - name: to_ausf3pool
        condition:
          op_and:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://ausfx.com'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: ausf3pool
            routing_behaviour: STRICT
            preferred_target:
              term_header: 3gpp-Sbi-target-apiRoot
      - name: ausf3_reject
        condition:
          op_and:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://ausf3.com'}}
        actions:
        - action_reject_message:
                status: 404
                title: "not possible in SEPP for a user?!"
                message_format: PLAIN_TEXT
      - name: to_rp3pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: rp3pool
            routing_behaviour: STRICT
    - name: rp_4_routing
      filter_data:
      - name: apiRoot_header
        header: 3gpp-Sbi-target-apiRoot
        variable_name: apiRoot_hdr
      filter_rules:
      - name: to_udm4pool
        condition:
          op_and:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'udm4'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: udm4pool
            routing_behaviour: ROUND_ROBIN
  roaming_partners:
    - name: rp_1
      pool_name: sepp_rp_1
    - name: rp_2
      pool_name: sepp_rp_2
      topology_hiding:
        pseudo_profiles:
          - nf_type: UDM
            pseudo_profile: "pseudo_profile_json_udm2"
          - nf_type: AUSF
            pseudo_profile: "pseudo_profile_json_ausf2"
        pseudo_fqdn:
          - uDm2
          - ausf2
    - name: rp_3
      pool_name: sepp_rp_3
      topology_hiding:
        pseudo_profiles:
          - nf_type: UDM
            pseudo_profile: "pseudo_profile_json_udm3"
          - nf_type: AUSF
            pseudo_profile: "pseudo_profile_json_ausf3"
        pseudo_fqdn:
          - udM3
          - ausf3
    - name: rp_4
      pool_name: sepp_rp_4
      topology_hiding:
        pseudo_profiles:
          - nf_type: UDM
            pseudo_profile: "pseudo_profile_json_udm4"
          - nf_type: AUSF
            pseudo_profile: "pseudo_profile_json_ausf4"
        pseudo_fqdn:
          - udm4
          - ausf4
)EOF"};

const std::string test_config{R"EOF(
name: envoy.filters.http.eric-proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_routing
  node_type: SEPP
  own_fqdn: sepp.ericsson.com
  own_external_port: 32262
  request_filter_cases:
    routing:
      ext_nw:
        name: "external network"
        ext_nw_fc_config_list:
        - per_rp_fc_config:
            rp_to_fc_map:
              RP_A: default_routing
  rp_name_table : rp_san_to_name
  key_value_tables:
    - name: rp_san_to_name
      entries:
        - key: rc
          value: RP_A

  callback_uri_klv_table: ___callback_uris
  filter_cases:
  - name: default_routing
    filter_data:
    - name: apiRoot_data
      header: 3gpp-Sbi-target-apiRoot
      extractor_regex: eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
    - name: chfsim_data
      header: 3gpp-Sbi-target-apiRoot
      extractor_regex: eric-(?P<chfsim>chfsim-\d+?)-.+
    filter_rules:
    - name: csepp_to_rp_A
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
      - action_add_header:
          name: x-eric-fop
          value:
            term_string: fop1
          if_exists: REPLACE
      - action_route_to_roaming_partner:
          roaming_partner_name: RP_A
          routing_behaviour: ROUND_ROBIN
          preserve_if_indirect: TARGET_API_ROOT
    - name: psepp_to_dfw
      condition:
        op_and:
          arg1:
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
          arg2:
            op_or:
              arg1:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_var: chfsim
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: chfsim-6
              arg2:
                op_equals:
                  typed_config1:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_var: chfsim
                  typed_config2:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                    term_string: chfsim-7
      actions:
      - action_add_header:
          name: x-eric-fop
          value:
            term_string: fop1
          if_exists: REPLACE
      - action_route_to_pool:
          pool_name:
            term_string: 'universal_pool#!_#subset_sr:'
          routing_behaviour: ROUND_ROBIN
          preserve_if_indirect: TARGET_API_ROOT
          preferred_target:
            term_header: 3gpp-Sbi-target-apiRoot
    - name: psepp_topo_hide
      condition:
        op_or:
          arg1:
            op_equals:
              typed_config1:
                "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                term_var: chfsim
              typed_config2:
                "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                term_string: chfsim-1000
          arg2:
            op_equals:
              typed_config1:
                "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                term_var: chfsim
              typed_config2:
                "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
                term_string: chfsim-2000
      actions:
      - action_add_header:
          name: x-eric-fop
          value:
            term_string: fop1
          if_exists: REPLACE
      - action_route_to_pool:
          pool_name:
            term_string: occ
          routing_behaviour: ROUND_ROBIN
          preserve_if_indirect: TARGET_API_ROOT  
  roaming_partners:
  - name: RP_A
    pool_name: sepp_rp_A
    topology_hiding:
      pseudo_profiles:
      - nf_type: AUSF
        pseudo_profile: '{"validityPeriod":120,"nfInstances":[{"nfInstanceId":"50b36ee6-7cb9-4db5-9190-b35b7e385dc2","nfType":"AUSF","nfStatus":"REGISTERED","fqdn":"eric-chfsim-2000-ausfX","nfServicePersistence":false,"lcHSupportInd":false,"olcHSupportInd":false}]}'
      - nf_type: UDM
        pseudo_profile: '{"validityPeriod":120,"nfInstances":[{"nfInstanceId":"3a0e28ff-6920-4e03-b63f-2d3806022743","nfType":"UDM","nfStatus":"REGISTERED","fqdn":"eric-chfsim-1000-udmX","nfServicePersistence":false,"lcHSupportInd":false,"olcHSupportInd":false}]}'
      pseudo_fqdn:
      - eric-chfsim-2000-ausfX
      - eric-chfsim-1000-udmX
  key_list_value_tables:
  - name: ___callback_uris
    entries:
    - key: nudm-niddau/v1
      value:
      - "/authUpdateCallbackUri"
    - key: nudm-uecm/v1
      value:
      - "/deregCallbackUri"
      - "/pcscfRestorationCallbackUri"
    - key: nlmf-loc/v1
      value:
      - "/hgmlcCallBackURI"
    - key: namf-loc/v1
      value:
      - "/locationNotificationUri"
    - key: nsmf-pdusession/v1
      value:
      - "/smContextStatusUri"
      - "/vsmfPduSessionUri"
      - "/ismfPduSessionUri"
    - key: nchf-convergedcharging/v3
      value:
      - "/notifyUri"
    - key: nchf-spendinglimitcontrol/v1
      value:
      - "/notifUri"
    - key: nnrf-nfm/v1
      value:
      - "/nfStatusNotificationUri"
    - key: npcf-smpolicycontrol/v1
      value:
      - "/notificationUri"
    - key: nnwdaf-eventssubscription/v1
      value:
      - "/notificationURI"
    - key: nchf-convergedcharging/v2
      value:
      - "/n2NotifyUri"
    - key: nudm-sdm/v2
      value:
      - "/callbackReference"
    - key: nudm-ee/v1
      value:
      - "/callbackReference"
    - key: naf-eventexposure/v1
      value:
      - "/notifUri"
    - key: nlmf-broadcast/v1
      value:
      - "/amfCallBackURI"
    - key: namf-evts/v1
      value:
      - "/subscription/eventNotifyUri"
      - "/subscription/subsChangeNotifyUri"
    - key: nnssf-nssaiavailability/v1
      value:
      - "/nfNssaiAvailabilityUri"
    - key: namf-comm/v1
      value:
      - "/n2NotifyUri"
      - "/n1n2FailureTxfNotifURI"
      - "/n1NotifyCallbackUri"
      - "/n2NotifyCallbackUri"
      - "/amfStatusUri"  
  nf_types_requiring_t_fqdn:
  - chf
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
    - header: x-eric-sepp-rp-name
      on_header_present:
        metadata_namespace: eric.proxy.test
        key: test_rp_name
        type: STRING
)EOF"};

const std::string fake_body{R"({"validityPeriod":60})"};

class EricProxyFilterSeppTopologyHidingTest : public PluggableConfigurator {
public:
  EricProxyFilterSeppTopologyHidingTest() : PluggableConfigurator(ericProxyHttpProxyConfig()) {}

  std::string ericProxyHttpProxyConfig() {
    return fmt::format(R"EOF(
admin:
  access_log:
  - name: envoy.access_loggers.file
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
      path: "{}"
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
          server_header_transformation: APPEND_IF_ABSENT
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
              - name: matches_on_x_cluster
                match:
                  prefix: "/"
                route:
                  cluster_header: x-cluster
  )EOF",
                       Platform::null_device_path, Platform::null_device_path,
                       Platform::null_device_path);
  };
};

//------------------------------------------------------------------------
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
INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterSeppTopologyHidingTest,
                         testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest())));

// Name: NfDiscNoTphRp1
// Description: NF-Discovery request for “nftype=UDM” from RP1 which does not have topology-hiding
// Expected Result: The NF-Discovery request is forwarded by the SEPP without modification
TEST_P(EricProxyFilterSeppTopologyHidingTest, NfDiscNoTphRp1) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder().withName("rp1pool").withEndpoint(
              EndpointBuilder()
                  .withHostName("rpa.extplmn.com")
                  .withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, config_preferred_target}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nudm-disc/v1/nf-instances?target-nf-type=UDM"},
      {":authority", "rpa.extplmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rpa.extplmn.com"},
      {"content-length", std::to_string(cc_create_req_body.length())}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "location"},
      {"server", "secret.internal.fqdn.com"},
  };

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nudm-disc/v1/nf-instances?target-nf-type=UDM"));

  // location and server headers are not modified:
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "location"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));

  codec_client_->close();
}

// Name: NfDiscTphRp2Udm
// Description: NF-Discovery request for “nftype=UDM” from RP2
// Expected Result:
// - SEPP does not forward the request.
// - Instead, it sends a NF-Discovery response with data configured by the user.
// - The response contains the p-FQDN “udm2” and the configured status “REGISTERED”
TEST_P(EricProxyFilterSeppTopologyHidingTest, NfDiscTphRp2Udm) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder().withName("rp1pool").withEndpoint(
              EndpointBuilder()
                  .withHostName("rpa.extplmn.com")
                  .withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, config_preferred_target}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=UDM"},
      {":authority", "rpa.extplmn.com"},
      {"x-eric-sepp-rp-name", "rp_2"},
      {"3gpp-Sbi-target-apiRoot", "http://udm2.com"},
      {"x-eric-sepp-test-san", "rpb.extplmn.com"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
  };
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  // waitForNextUpstreamRequest(0);

  EXPECT_TRUE(upstream_request_ == nullptr);

  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_EQ("pseudo_profile_json_udm2", response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString(":authority")).empty());
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.t8e."
                               "UDM.s5e.nf_discovery.th_pseudo_search_result_total")
                     ->value());

  codec_client_->close();
}

// Name: NfDiscTphRp3Udm
// Description: NF-Discovery request for “nftype=UDM” from RP3
// Expected Result:
// - SEPP does not forward the request.
// - Instead, it sends a NF-Discovery response with data configured by the user.
// - The response contains the p-FQDN “udm3” and the configured status “SUSPENDED”
TEST_P(EricProxyFilterSeppTopologyHidingTest, NfDiscTphRp3Udm) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder().withName("rp1pool").withEndpoint(
              EndpointBuilder()
                  .withHostName("rpa.extplmn.com")
                  .withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, config_preferred_target}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=UDM"},
      {":authority", "rpc.extplmn.com"},
      {"x-eric-sepp-rp-name", "rp_3"},
      {"3gpp-Sbi-target-apiRoot", "http://udm3.com"},
      {"x-eric-sepp-test-san", "rpc.extplmn.com"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
  };
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  // waitForNextUpstreamRequest(0);

  EXPECT_TRUE(upstream_request_ == nullptr);

  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_EQ("pseudo_profile_json_udm3", response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString(":authority")).empty());
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_3.t8e.UDM.s5e.nf_"
                               "discovery.th_pseudo_search_result_total")
                     ->value());

  codec_client_->close();
}

// Name: NfDiscTphRp2Chf
// Description: NF-Discovery request for “nftype=CHF” from RP2
// Expected Result:
// - The NF-Discovery request is forwarded by the SEPP without modification
TEST_P(EricProxyFilterSeppTopologyHidingTest, NfDiscTphRp2Chf) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder().withName("rp2pool").withEndpoint(
              EndpointBuilder()
                  .withHostName("rpb.extplmn.com:80")
                  .withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, config_preferred_target}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=CHF"},
      {":authority", "rpb.extplmn.com"},
      {"x-eric-sepp-rp-name", "rp_2"},
      {"x-eric-sepp-test-san", "rpb.extplmn.com"},
      {"content-length", std::to_string(fake_body.length())}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, fake_body);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "location"}};

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("content-length", std::to_string(fake_body.length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp2pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "rpb.extplmn.com:80"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=CHF"));

  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "location"));

  codec_client_->close();
}

// Name: ServReqNoTphRp1
// Description: Service request to UDM (/nudm-sdm/v2/shared-data) from RP1 which does not have
// topology-hiding Expected Result:
// - Service request is forwarded by the SEPP unmodified
TEST_P(EricProxyFilterSeppTopologyHidingTest, ServReqNoTphRp1) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder().withName("rp1pool").withEndpoint(
              EndpointBuilder()
                  .withHostName("rpa.extplmn.com")
                  .withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, config_preferred_target}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nudm-sdm/v2/shared-data"},
      {":authority", "rpa.extplmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_1.extplmn.com"},
      {"content-length", std::to_string(fake_body.length())}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, fake_body);
  waitForNextUpstreamRequest(0);

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("content-length", std::to_string(fake_body.length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nudm-sdm/v2/shared-data"));

  codec_client_->close();
}

// Name: ServReqTphRp2Udm
// Description: Service request to UDM (/nudm-sdm/v2/shared-data) from RP2, with correct p-FQDN
// “udm2” Expected Result:
// - The request is routed to the cluster “udm2pool”.
// - The header 3gpp-Sbi-Target-apiRoot is present in routing, but absent when the request leaves
// the filter.
// - No preferred host (x-host) is set.
// - The server-header's original value is removed because of topology-hiding
TEST_P(EricProxyFilterSeppTopologyHidingTest, ServReqTphRp2Udm) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("udm2pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("host.abc.com")
                                .withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, config_preferred_target}, cluster_config);

  std::string fake_body{R"({"validityPeriod":60})"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nudm-sdm/v2/shared-data"},
      {"3gpp-Sbi-target-apiRoot", "http://udm2.com"},
      {":authority", "rp_B.ext_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_2"},
      {"x-eric-sepp-test-san", "rpb.extplmn.com"},
      {"content-length", std::to_string(fake_body.length())}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, fake_body);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "location"},
      {"server", "secret.internal.fqdn.com"},
  };

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("content-length", std::to_string(fake_body.length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "udm2pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nudm-sdm/v2/shared-data"));

  EXPECT_TRUE(
      upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("x-host")).empty());

  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "://uDm2"));
  // Topo-hiding deleted the server header
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString("server")).empty());

  codec_client_->close();
}

// Name: ServReqTphRp3Udm
// Description: Service request to UDM (/nudm-sdm/v2/shared-data) from RP3, with correct p-FQDN
// “udm3” Expected Result:
// - The request is routed to the cluster “udm3pool”.
// - The header 3gpp-Sbi-Target-apiRoot is present in routing, but absent when the request leaves
// the filter.
// - No preferred host (x-host) is set.
TEST_P(EricProxyFilterSeppTopologyHidingTest, ServReqTphRp3Udm) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("udm3pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("host.abc.com")
                                .withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, config_preferred_target}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nudm-sdm/v2/shared-data"},
      {"3gpp-Sbi-target-apiRoot", "http://udm3.com"},
      {":authority", "rpc.extplmn.com"},
      {"x-eric-sepp-rp-name", "rp_3"},
      {"x-eric-sepp-test-san", "rpc.extplmn.com"},
      {"content-length", std::to_string(fake_body.length())}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, fake_body);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "location"},
      {"server", "secret.internal.fqdn.com"},
  };

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("content-length", std::to_string(fake_body.length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "udm3pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nudm-sdm/v2/shared-data"));

  EXPECT_TRUE(
      upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("x-host")).empty());

  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "://udM3"));
  // Topo-hiding deleted the server header
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString("server")).empty());

  codec_client_->close();
}

// Name: ServReqTphRp2UdmUnknownPfqdn
// Description: Service request from RP2 to UDM (/nudm-sdm/v2/shared-data), with incorrect p-FQDN
// “udm3” Expected Result:
// - The request is routed to the cluster “unknownPool”
// - The 3gpp-Sbi-Target-apiRoot header is still present when the request leaves the filter
// - Preferred host “x-host” is set to udm3…
TEST_P(EricProxyFilterSeppTopologyHidingTest, ServReqTphRp2UdmUnknownPfqdn) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("unknownPool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("udm3.com:80")
                                .withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, config_preferred_target}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nudm-sdm/v2/shared-data"},
      {"3gpp-Sbi-target-apiRoot", "http://udm3.com"},
      {":authority", "sepp.own_plmn.com:80"},
      {"x-eric-sepp-rp-name", "rp_2"},
      {"x-eric-sepp-test-san", "rpb.extplmn.com"},
      {"content-length", std::to_string(fake_body.length())}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, fake_body);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "location"},
      {"server", "secret.internal.fqdn.com"},
  };

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("content-length", std::to_string(fake_body.length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "unknownPool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nudm-sdm/v2/shared-data"));
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-Sbi-target-apiRoot",
  // "udm3"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "udm3.com:80"));

  // location and server headers are not modified:
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "location"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));

  codec_client_->close();
}

// Name: ServReqTphRp3UdmUnknownPfqdn
// Description: Service request from RP3 to UDM (/nudm-sdm/v2/shared-data), with incorrect p-FQDN
// “udm2” Expected Result:
// - The request is replied with a direct response 404.
TEST_P(EricProxyFilterSeppTopologyHidingTest, ServReqTphRp3UdmUnknownPfqdn) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("does_not_matter")
              .withEndpoint(EndpointBuilder()
                                .withHostName("host.abc.com")
                                .withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, config_preferred_target}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nudm-sdm/v2/shared-data"},
      {"3gpp-Sbi-target-apiRoot", "http://udm2.com"},
      {":authority", "sepp.own_plmn.com:80"},
      {"x-eric-sepp-rp-name", "rp_3"},
      {"x-eric-sepp-test-san", "rpc.extplmn.com"},
      {"content-length", std::to_string(fake_body.length())}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, fake_body);

  EXPECT_TRUE(upstream_request_ == nullptr);

  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("404", response->headers().getStatusValue());
  EXPECT_EQ("text/plain", response->headers().getContentTypeValue());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());

  codec_client_->close();
}

// Name: ServReqTphRp2Ausf
// Description: Service request from RP2 to AUSF (/nausf-auth/v1/rg-authentications) with correct
// p-FQDN “ausfx” Expected Result:
// - The request is routed to the cluster “ausf2pool”
// - The header 3gpp-Sbi-Target-apiRoot is present in routing, but absent when the request leaves
// the filter.
TEST_P(EricProxyFilterSeppTopologyHidingTest, ServReqTphRp2Ausf) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("ausf2pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("ausfx.com:80")
                                .withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, config_preferred_target}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nausf-auth/v1/rg-authentications"},
      {"3gpp-Sbi-target-apiRoot", "http://ausfx.com"},
      {":authority", "sepp.own_plmn.com:80"},
      {"x-eric-sepp-rp-name", "rp_2"},
      {"x-eric-sepp-test-san", "rpb.extplmn.com"},
      {"content-length", std::to_string(fake_body.length())}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, fake_body);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "location"},
      {"server", "secret.internal.fqdn.com"},
  };

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("content-length", std::to_string(fake_body.length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "ausf2pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nausf-auth/v1/rg-authentications"));
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "ausfx:80"));

  EXPECT_TRUE(
      upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  // location and server headers are not modified:
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "location"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));

  codec_client_->close();
}

// Name: ServReqTphRp3Ausf
// Description: Service request from RP3 to AUSF (/nausf-auth/v1/rg-authentications) with correct
// p-FQDN “ausfx” Expected Result:
// - The request is routed to the cluster “ausf3pool”
// - The header 3gpp-Sbi-Target-apiRoot is present in routing, but absent when the request leaves
// the filter.
TEST_P(EricProxyFilterSeppTopologyHidingTest, ServReqTphRp3Ausf) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("ausf3pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("ausfx.com:80")
                                .withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, config_preferred_target}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nausf-auth/v1/rg-authentications"},
      {"3gpp-Sbi-target-apiRoot", "http://ausfx.com"},
      {":authority", "sepp.own_plmn.com:80"},
      {"x-eric-sepp-rp-name", "rp_3"},
      {"x-eric-sepp-test-san", "rpc.extplmn.com"},
      {"content-length", std::to_string(fake_body.length())}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, fake_body);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "location"},
      {"server", "secret.internal.fqdn.com"},
  };

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("content-length", std::to_string(fake_body.length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "ausf3pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nausf-auth/v1/rg-authentications"));
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "ausfx:80"));

  EXPECT_TRUE(
      upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  // location and server headers are not modified:
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "location"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));

  codec_client_->close();
}

// Name: ServRespNoTphRp1
// Description: Valid service request from RP1 to UDM, no topology hiding, response contains a
// Location header with value “udmPrivate1” Expected Result:
// - The Location header is forwarded un-modified with the value “udmPrivate1”
TEST_P(EricProxyFilterSeppTopologyHidingTest, ServRespNoTphRp1) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder().withName("rp1pool").withEndpoint(
              EndpointBuilder().withHostName("host.abc.com").withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, config_preferred_target}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nudm-disc/v1/nf-instances?target-nf-type=UDM"},
      {":authority", "sepp.own_plmn.com:80"},
      {"3gpp-Sbi-target-apiRoot", "http://udmPrivate1.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rpa.extplmn.com"},
      {"content-length", std::to_string(fake_body.length())}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, fake_body);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "udmPrivate1"},
      {"server", "secret.internal.fqdn.com"},
  };

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("content-length", std::to_string(fake_body.length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1pool"));
  // location and server headers are not modified:
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "udmPrivate1"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));

  codec_client_->close();
}

// Name: ServRespTphRp2Udm
// Description: Valid service request from RP2 to UDM, response contains a Location header with
// value “udmPrivate2”. Expected Result:
// - The Location header in a service response from a UDM is translated from “udmPrivate2” to the
// configured p-FQDN “udm2”
// - The rest of the location header is not modified
TEST_P(EricProxyFilterSeppTopologyHidingTest, ServRespTphRp2Udm) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder()
              .withName("udm2pool")
              .withEndpoint(EndpointBuilder()
                                .withHostName("host.abc.com")
                                .withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, config_preferred_target}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nudm-disc/v1/nf-instances?target-nf-type=UDM"},
      {":authority", "sepp.own_plmn.com:80"},
      {"3gpp-Sbi-target-apiRoot", "http://udm2.com"},
      {"x-eric-sepp-rp-name", "rp_2"},
      {"x-eric-sepp-test-san", "rpb.extplmn.com"},
      {"content-length", std::to_string(fake_body.length())}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, fake_body);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "udmPrivate2"}};

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("content-length", std::to_string(fake_body.length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "udm2pool"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "://uDm2"));
  // Topo-hiding deleted the server header
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString("server")).empty());

  codec_client_->close();
}

// Name: ServRespTphRp2Chf
// Description: Valid service request from RP2 to CHF, response contains a location header
// “udmPrivate2” Expected Result:
// - The Location header is not modified.
TEST_P(EricProxyFilterSeppTopologyHidingTest, ServRespTphRp2Chf) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder().withName("rp2pool").withEndpoint(
              EndpointBuilder().withHostName("chf.com:80").withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, config_preferred_target}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nudm-disc/v1/nf-instances?target-nf-type=CHF"},
      {":authority", "sepp.own_plmn.com:80"},
      {"3gpp-Sbi-target-apiRoot", "http://chf.com"},
      {"x-eric-sepp-rp-name", "rp_2"},
      {"x-eric-sepp-test-san", "rpb.extplmn.com"},
      {"content-length", std::to_string(fake_body.length())}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, fake_body);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_resp_body.length())},
      {"content-type", "application/json"},
      {"location", "udmPrivate2"},
      {"server", "secret.internal.fqdn.com"},
  };

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("content-length", std::to_string(fake_body.length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp2pool"));
  // location and server headers are not modified:
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("location", "udmPrivate2"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));

  codec_client_->close();
}

// Name: TopoHidingTestBla
// Description: test config from Konstantins
// Expected Result:
// - working topo hiding
TEST_P(EricProxyFilterSeppTopologyHidingTest, TopoHidingTestBla) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder().withName("occ").withEndpoint(
              EndpointBuilder().withHostName("host.abc.com").withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, test_config}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/blabla"},
      {":authority", "rpA.sepp.ericsson.com:32677"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1000-udmX.com"},
      {"x-eric-sepp-rp-name", "RP_A"},
      {"x-eric-sepp-test-san", "rc"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest();

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-sepp-rp-name", "RP_A"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-sepp-test-san", "rc"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-fop", "fop1"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "occ"));

  codec_client_->close();
}

// Name: TopoHidingTestDiscovery
// Description: test config from Konstantins
// Expected Result:
// - working topo hiding
TEST_P(EricProxyFilterSeppTopologyHidingTest, TopoHidingTestDiscovery) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder().withName("occ").withEndpoint(
              EndpointBuilder().withHostName("host.abc.com").withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, test_config}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=UDM"},
      {":authority", "rpA.sepp.ericsson.com:32677"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1000-udmX.com"},
      {"x-eric-sepp-rp-name", "RP_A"},
      {"x-eric-sepp-test-san", "rc"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);

  EXPECT_TRUE(upstream_request_ == nullptr);

  const std::string expected_body{
      R"({"validityPeriod":120,"nfInstances":[{"nfInstanceId":"3a0e28ff-6920-4e03-b63f-2d3806022743","nfType":"UDM","nfStatus":"REGISTERED","fqdn":"eric-chfsim-1000-udmX","nfServicePersistence":false,"lcHSupportInd":false,"olcHSupportInd":false}]})"};

  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_EQ(expected_body, response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()), std::to_string(expected_body.length()));
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString(":authority")).empty());

  codec_client_->close();
}

// Name: SpecialCharactersReplacement
// Description: DND-30192 incorrectly handling non-alphanumeric characters in the RP names
// Expected Result:
// - should work for special characters
TEST_P(EricProxyFilterSeppTopologyHidingTest, SpecialCharactersReplacement) {
  EndpointMetadataClusterConfigurator cluster_config =
      EndpointMetadataClusterConfigurator().withClusterBuilder(
          ClusterBuilder().withName("occ").withEndpoint(
              EndpointBuilder().withHostName("host.abc.com").withHostMd({{"support", {"TFQDN"}}})));
  initConfig({config_header_to_metadata, config_preferred_target}, cluster_config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=UDM"},
      {":authority", "rpd.extplmn.com"},
      {"x-eric-sepp-rp-name", "rp_4"},
      {"3gpp-Sbi-target-apiRoot", "http://udm4.com"},
      {"x-eric-sepp-test-san", "rpd.extplmn.com"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);

  EXPECT_TRUE(upstream_request_ == nullptr);

  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_EQ("pseudo_profile_json_udm4", response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());
  EXPECT_TRUE(response->headers().get(Http::LowerCaseString(":authority")).empty());
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_4.t8e.UDM.s5e.nf_"
                               "discovery.th_pseudo_search_result_total")
                     ->value());

  codec_client_->close();
}

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
