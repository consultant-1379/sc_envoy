#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "base_integration_test.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"
#include "include/nlohmann/json.hpp"
#include "source/extensions/filters/http/eric_proxy/proxy_filter_config.h"
#include "source/extensions/filters/http/eric_proxy/wrappers.h"
#include "source/extensions/filters/http/eric_proxy/config.h"
#include <cstddef>
#include <ostream>
#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

using EricProxyFilterProtoConfig =
    envoy::extensions::filters::http::eric_proxy::v3::EricProxyConfig;

enum BodyContentType {APPLICATION_JSON, MULTIPART_RELATED};

class EricProxyFilterSeppThNrfFqdnMappingTest
    : public EricProxyIntegrationTestBase,
      public testing::TestWithParam<std::tuple<Network::Address::IpVersion, BodyContentType>> {
public:
  EricProxyFilterSeppThNrfFqdnMappingTest()
      : EricProxyIntegrationTestBase(
            Http::CodecClient::Type::HTTP1, std::get<0>(GetParam()),
            EricProxyFilterSeppThNrfFqdnMappingTest::ericProxyHttpBaseConfig()) {
    setUpstreamCount(1);
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

  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  BodyContentType getBodyContentType() const { return std::get<1>(GetParam()); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);

    HttpIntegrationTest::initialize();
  }

  // Common base configuration
  std::string ericProxyHttpBaseConfig() {
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
  clusters:
    name: cluster_0
    load_assignment:
      cluster_name: cluster_0
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 0
          metadata:
            filter_metadata:
              envoy.eric_proxy:
                pernfcounter: true
                nfInstanceId:
                - "2ec8ac0b-265e-4165-86e9-e0735e6ce309"
                support:
                - TFQDN
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
              - name: route2
                match:
                  prefix: "/"
                  headers:
                    - name: x-eric-proxy
                route:
                  cluster: cluster_0
              - name: route1
                match:
                  prefix: "/"
                route:
                  cluster: cluster_0
  )EOF",
                       Platform::null_device_path, Platform::null_device_path,
                       Platform::null_device_path);
  };

  // DND-45306 demapping heder then non existing uri
  const std::string dnd_45306_config{R"EOF(
      topology_hiding:
        service_profile:
          topology_hiding_service_cases:
          - service_case_name: service_1
            service_type:
              api_name: nsmf-pduinit
              api_version: v1
              direction: REQUEST
              http_method: POST
            filter_case:
              name: fc_1
              filter_rules:
              - name: fr_1
                condition: { "op_exists": { "arg1": { "term_reqheader": "x-modify-hdr" } } }
                actions:
                - action_modify_header:
                    name: x-modify-hdr
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: map_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_query_param:
                    key_name: hnrf-uri
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: map_table
                          fc_unsuccessful_operation: fc-fail-2
              - name: fr_2
                condition: {"op_not": {"arg1": {"op_exists": { "arg1": { "term_reqheader": "x-modify-hdr" } } } } }
                actions:
                - action_modify_query_param:
                    key_name: hnrf-uri
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: map_table
                          fc_unsuccessful_operation: fc-fail-2
          unsuccessful_operation_filter_cases:
            - name: fc-fail-1
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nudm
                    detail: fc-fail-detail
                    cause: FC_FAIL
                    message_format: JSON
            - name: fc-fail-2
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nsmf
                    detail: fc-fail-detail
                    cause: FC_FAIL
)EOF"};

  //------------------------------------------------------------------------
  // Configuration to test TH IP hiding NF Discovery
  const std::string config_eric_proxy_base{R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.own_plmn.com
  <listener-type>: 80
  request_filter_cases:
    routing:
      <routing>
  rp_name_table : rp_san_to_name
  key_value_tables:
    - name: rp_san_to_name
      entries:
        - key: rp_A.ext_plmn.com
          value: rp_1
        - key: rp_B.ext_plmn.com
          value: rp_2
    - name: map_table
      entries:
        - key: nrf1.mcc123.mnc456.ericsson.se
          value: fakenrf1.mcc123.mnc456.ericsson.se
        - key: nrf2.mcc123.mnc456.ericsson.se
          value: fakenrf2.mcc123.mnc456.ericsson.se
    - name: demap_table
      entries:
        - value: nrf1.mcc123.mnc456.ericsson.se
          key: fakenrf1.mcc123.mnc456.ericsson.se
        - value: nrf2.mcc123.mnc456.ericsson.se
          key: fakenrf2.mcc123.mnc456.ericsson.se
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: nrf_pool
        condition:
          op_equals:
            typed_config1:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_reqheader: 3gpp-sbi-target-apiroot
            typed_config2:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_string: nrf.own_plmn.com
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: nrf_pool
            routing_behaviour: ROUND_ROBIN
      - name: rp_A_pool
        condition:
          op_equals:
            typed_config1:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_reqheader: 3gpp-sbi-target-apiroot
            typed_config2:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_string: rp_A.ext_plmn.com 
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_1
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
      - name: rp_B_pool
        condition:
          op_equals:
            typed_config1:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_reqheader: 3gpp-sbi-target-apiroot
            typed_config2:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_string: rp_B.ext_plmn.com 
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_2
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
  

  roaming_partners:
    - name: rp_1
      pool_name: rp1_pool
      <rp1-topo-hiding>
    - name: rp_2
      pool_name: rp2_pool
      <rp2-topo-hiding>    
)EOF"};

  // Basic config for internal listener
  const std::string config_test_rp_th_int{R"EOF(
      topology_hiding:
        service_profile:
          topology_hiding_service_cases:
            service_case_name: service_1
            service_type:
              api_name: nnrf-disc
              api_version: v1
              direction: REQUEST
            filter_case:
              name: fc_1
              filter_rules:
              - name: fr_1
                condition: 
                  term_boolean: true
                actions:
                - action_modify_header:
                    name: x-modify-hdr
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: map_table
                          do_nothing: true
          unsuccessful_operation_filter_cases:
            - name: failover_1
              filter_rules:
              - name: failover_fr1
                condition:
                  term_boolean: true
                actions:
                - action_add_header:
                    name: x-failover-1
                    value:
                      term_string: x-failover-1-val
)EOF"};

  // Basic config for external listener
  const std::string config_test_rp_th{R"EOF(
      topology_hiding:
        service_profile:
          topology_unhiding_service_cases:
            service_case_name: service_1
            service_type:
              api_name: nnrf-disc
              api_version: v1
              direction: REQUEST
            filter_case:
              name: fc_1
              filter_rules:
              - name: fr_1
                condition: 
                  term_boolean: true
                actions:
                - action_modify_header:
                    name: x-modify-hdr
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          do_nothing: true
          unsuccessful_operation_filter_cases:
            - name: failover_1
              filter_rules:
              - name: failover_fr1
                condition:
                  term_boolean: true
                actions:
                - action_add_header:
                    name: x-failover-1
                    value:
                      term_string: x-failover-1-val
)EOF"};

  // Service Case for an external listener
  // Topology  Info Unhide for requests and Topology Info
  // hide for responses.
  const std::string service_case1{R"EOF(
      topology_hiding:
        service_profile:
          topology_unhiding_service_cases:
          - service_case_name: service_1
            service_type:
              api_name: nsmf-pduinit
              api_version: v1
              direction: REQUEST
              http_method: POST
            filter_case:
              name: fc_1
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_modify_header:
                    name: x-modify-hdr
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_query_param:
                    key_name: hnrf-uri
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_json_body:
                    name: json_body
                    json_operation:
                      modify_json_value:
                        string_modifiers:
                        - table_lookup:
                            lookup_table_name: demap_table
                            fc_unsuccessful_operation: fc-fail-2
                        json_pointer:
                          term_string: "/nfConsumerIdentification/nfPLMNID/fqdn"
                        enable_exception_handling: true
          - service_case_name: service_2
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
                - action_modify_header:
                    name: 3gpp-sbi-target-apiroot-dummy
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_header:
                    name: 3gpp-sbi-target-apiroot-dummy2
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_header:
                    name: 3gpp-sbi-target-apiroot-dummy3
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
          topology_hiding_service_cases:
          - service_case_name: service_3
            service_type:
              api_name: nudm-uecm
              api_version: v1
              direction: RESPONSE
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
                      term_string: '308'
                actions:
                - action_modify_header:
                    name: location
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: map_table
                          fc_unsuccessful_operation: fc-fail-1
                - action_modify_header:
                    name: x-modify-resp
                    replace_value:
                      term_string: x-modify-resp-val
          unsuccessful_operation_filter_cases:
            - name: fc-fail-1
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nudm
                    detail: fc-fail-detail
                    cause: FC_FAIL
                    message_format: JSON
            - name: fc-fail-2
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nsmf
                    detail: fc-fail-detail
                    cause: FC_FAIL
)EOF"};

  // Service Case for an external listener
  // Only Topology Info Unhide for requests.
  const std::string service_case1_NoTopoHiding{R"EOF(
      topology_hiding:
        service_profile:
          topology_unhiding_service_cases:
          - service_case_name: service_1
            service_type:
              api_name: nsmf-pduinit
              api_version: v1
              direction: REQUEST
              http_method: POST
            filter_case:
              name: fc_1
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_modify_header:
                    name: x-modify-hdr
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_query_param:
                    key_name: hnrf-uri
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_json_body:
                    name: json_body
                    json_operation:
                      modify_json_value:
                        string_modifiers:
                        - table_lookup:
                            lookup_table_name: demap_table
                            fc_unsuccessful_operation: fc-fail-2
                        json_pointer:
                          term_string: "/nfConsumerIdentification/nfPLMNID/fqdn"
                        enable_exception_handling: true
          - service_case_name: service_2
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
                - action_modify_header:
                    name: 3gpp-sbi-target-apiroot-dummy
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_header:
                    name: 3gpp-sbi-target-apiroot-dummy2
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_header:
                    name: 3gpp-sbi-target-apiroot-dummy3
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
          unsuccessful_operation_filter_cases:
            - name: fc-fail-1
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nudm
                    detail: fc-fail-detail
                    cause: FC_FAIL
                    message_format: JSON
            - name: fc-fail-2
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nsmf
                    detail: fc-fail-detail
                    cause: FC_FAIL
)EOF"};

  // Service Case for an internal listener
  // Topology  Info Hide for requests and Topology Info
  // unhide for responses.
  const std::string service_case2{R"EOF(
      topology_hiding:
        service_profile:
          topology_hiding_service_cases:
          - service_case_name: service_1
            service_type:
              api_name: nsmf-pduinit
              api_version: v1
              direction: REQUEST
              http_method: POST
            filter_case:
              name: fc_1
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_modify_header:
                    name: x-modify-hdr
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: map_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_query_param:
                    key_name: hnrf-uri
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: map_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_json_body:
                    name: json_body
                    json_operation:
                      modify_json_value:
                        string_modifiers:
                        - table_lookup:
                            lookup_table_name: map_table
                            fc_unsuccessful_operation: fc-fail-2
                        json_pointer:
                          term_string: "/nfConsumerIdentification/nfPLMNID/fqdn"
                        enable_exception_handling: true
          topology_unhiding_service_cases:
          - service_case_name: service_3
            service_type:
              api_name: nudm-uecm
              api_version: v1
              direction: RESPONSE
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
                      term_string: '308'
                actions:
                - action_modify_header:
                    name: location
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-1
                - action_modify_header:
                    name: x-modify-resp
                    replace_value:
                      term_string: x-modify-resp-val
          unsuccessful_operation_filter_cases:
            - name: fc-fail-1
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nudm
                    detail: fc-fail-detail
                    cause: FC_FAIL
                    message_format: JSON
            - name: fc-fail-2
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nsmf
                    detail: fc-fail-detail
                    cause: FC_FAIL
)EOF"};

  // Service Case for an internal listener
  // Only Topology Info unhide for responses.
  const std::string service_case2_noTopoHiding{R"EOF(
      topology_hiding:
        service_profile:
          topology_unhiding_service_cases:
          - service_case_name: service_3
            service_type:
              api_name: nudm-uecm
              api_version: v1
              direction: RESPONSE
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
                      term_string: '308'
                actions:
                - action_modify_header:
                    name: location
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-1
                - action_modify_header:
                    name: x-modify-resp
                    replace_value:
                      term_string: x-modify-resp-val
          unsuccessful_operation_filter_cases:
            - name: fc-fail-1
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nudm
                    detail: fc-fail-detail
                    cause: FC_FAIL
                    message_format: JSON
            - name: fc-fail-2
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nsmf
                    detail: fc-fail-detail
                    cause: FC_FAIL
)EOF"};

  // Service Case for an external listener
  // Topology  Info Unhide for requests and Topology Info
  // hide for responses.
  const std::string service_case_misc{R"EOF(
      topology_hiding:
        service_profile:
          topology_unhiding_service_cases:
          - service_case_name: service_1
            service_type:
              api_name: nsmf-pduinit
              api_version: v1
              direction: REQUEST
              http_method: POST
              resource_matcher : /some/fixed/resource
            filter_case:
              name: fc_1
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_modify_header:
                    name: x-modify-hdr
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_query_param:
                    key_name: hnrf-uri
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_json_body:
                    name: json_body
                    json_operation:
                      modify_json_value:
                        string_modifiers:
                        - table_lookup:
                            lookup_table_name: demap_table
                            fc_unsuccessful_operation: fc-fail-2
                        json_pointer:
                          term_string: "/nfConsumerIdentification/nfPLMNID/fqdn"
                        enable_exception_handling: true
          - service_case_name: service_2
            service_type:
              api_name: nsmf-pduinit
              api_version: v1
              direction: REQUEST
              is_notification: false
              resource_matcher: /?[aA-zZ0-9]?.*/nf-instances/?[aA-zZ0-9]?.*
              http_method: POST
            filter_case:
              name: fc_1
              filter_rules:
              - name: fr_1
                condition: 
                  term_boolean: true
                actions:
                - action_modify_header:
                    name: x-modify-hdr
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_query_param:
                    key_name: hnrf-uri
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_json_body:
                    name: json_body
                    json_operation:
                      modify_json_value:
                        string_modifiers:
                        - table_lookup:
                            lookup_table_name: demap_table
                            fc_unsuccessful_operation: fc-fail-2
                        json_pointer:
                          term_string: "/nfConsumerIdentification/nfPLMNID/fqdn"
                        enable_exception_handling: true
          topology_hiding_service_cases:
          - service_case_name: service_3
            service_type:
              api_name: nudm-uecm
              api_version: v1
              direction: RESPONSE
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
                      term_string: '308'
                actions:
                - action_modify_header:
                    name: location
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: map_table
                          fc_unsuccessful_operation: fc-fail-1
                - action_modify_header:
                    name: x-modify-resp
                    replace_value:
                      term_string: x-modify-resp-val
          unsuccessful_operation_filter_cases:
            - name: fc-fail-1
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nudm
                    detail: fc-fail-detail
                    cause: FC_FAIL
                    message_format: JSON
            - name: fc-fail-2
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nsmf
                    detail: fc-fail-detail
                    cause: FC_FAIL
)EOF"};

  const std::string service_case_bootstrap_oauth{R"EOF(
      topology_hiding:
        service_profile:
          topology_unhiding_service_cases:
          - service_case_name: service_1
            service_type:
              api_name: bootstrapping
              direction: REQUEST
              http_method: POST
              resource_matcher : /some/fixed/resource
            filter_case:
              name: fc_1
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_add_header:
                    name: x-svc-ctx-hdr
                    value:
                      term_string: "bootstrapping-service"
          - service_case_name: service_2
            service_type:
              api_name: oauth2
              direction: REQUEST
              is_notification: false
              resource_matcher: /some/fixed/resource
              http_method: POST
            filter_case:
              name: fc_1
              filter_rules:
              - name: fr_1
                condition: 
                  term_boolean: true
                actions:
                - action_add_header:
                    name: x-svc-ctx-hdr
                    value:
                      term_string: "oauth2-service"
          topology_hiding_service_cases:
          - service_case_name: service_3
            service_type:
              api_name: nudm-uecm
              api_version: v1
              direction: RESPONSE
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
                      term_string: '308'
                actions:
                - action_modify_header:
                    name: location
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: map_table
                          fc_unsuccessful_operation: fc-fail-1
                - action_modify_header:
                    name: x-modify-resp
                    replace_value:
                      term_string: x-modify-resp-val
          unsuccessful_operation_filter_cases:
            - name: fc-fail-1
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nudm
                    detail: fc-fail-detail
                    cause: FC_FAIL
                    message_format: JSON
            - name: fc-fail-2
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nsmf
                    detail: fc-fail-detail
                    cause: FC_FAIL
)EOF"};

  // Only for demoing the problem with
  // header mapping as shown in service_2
  // for notification handling
  const std::string service_case1_demo{R"EOF(
      topology_hiding:
        service_profile:
          topology_unhiding_service_cases:
          - service_case_name: service_1
            service_type:
              api_name: nsmf-pduinit
              api_version: v1
              direction: REQUEST
              http_method: POST
            filter_case:
              name: fc_1
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_modify_header:
                    name: x-modify-hdr
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_query_param:
                    key_name: hnrf-uri
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          fc_unsuccessful_operation: fc-fail-2
                - action_modify_json_body:
                    name: json_body
                    json_operation:
                      modify_json_value:
                        string_modifiers:
                        - table_lookup:
                            lookup_table_name: demap_table
                            fc_unsuccessful_operation: fc-fail-2
                        json_pointer:
                          term_string: "/nfConsumerIdentification/nfPLMNID/fqdn"
                        enable_exception_handling: true
          - service_case_name: service_2
            service_type:
              api_name: Nnrf_NFManagement_NFStatusNotify
              api_version: v1
              direction: REQUEST
              is_notification: true
              http_method: POST
            filter_case:
              name: fc_1
              filter_data:
              - name: apiRoot-data
                header: 3gpp-sbi-target-apiroot-dummy
                extractor_regex: (?P<scheme>https?://)(?P<fqdn>[aA-zZ.0-9]*):(?P<port>\d+)
              filter_rules:
              - name: fr_1
                condition: 
                  op_exists:
                    arg1: 
                      term_var: scheme
                actions:
                - action_modify_variable:
                    name: fqdn
                    table_lookup:
                      table_name: demap_table
                      key: 
                        term_var: fqdn
                - action_remove_header:
                    name: 3gpp-sbi-target-apiroot-dummy
                - action_add_header:
                    name: 3gpp-sbi-target-apiroot-dummy
                    value:
                      term_var: scheme
                - action_modify_header:
                    name: 3gpp-sbi-target-apiroot-dummy
                    append_value: 
                      term_var: fqdn
                - action_modify_header:
                    name: 3gpp-sbi-target-apiroot-dummy
                    append_value:
                      term_string: ":"
                - action_modify_header:
                    name: 3gpp-sbi-target-apiroot-dummy
                    append_value:
                      term_var: port
          topology_hiding_service_cases:
          - service_case_name: service_3
            service_type:
              api_name: nudm-uecm
              api_version: v1
              direction: RESPONSE
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
                      term_string: '308'
                actions:
                - action_modify_header:
                    name: location
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: map_table
                          fc_unsuccessful_operation: fc-fail-1
                - action_modify_header:
                    name: x-modify-resp
                    replace_value:
                      term_string: x-modify-resp-val
          unsuccessful_operation_filter_cases:
            - name: fc-fail-1
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nudm
                    detail: fc-fail-detail
                    cause: FC_FAIL
                    message_format: JSON
            - name: fc-fail-2
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nsmf
                    detail: fc-fail-detail
                    cause: FC_FAIL
)EOF"};

  std::string makeConfigInternal(std::string base, const std::string rp1, const std::string rp2) {

    auto yaml = R"EOF(  
      own_nw:     
        name: "own network"
        start_fc_list:
        - default_routing
            )EOF";
    auto routing = std::regex_replace(base, std::regex("<routing>*"), fmt::format("{}", yaml));
    auto listener_type = std::regex_replace(routing, std::regex("<listener-type>*"),
                                            fmt::format("{}", "own_internal_port"));

    auto rp1_temp =
        std::regex_replace(listener_type, std::regex("<rp1-topo-hiding>*"), fmt::format("{}", rp1));
    return std::regex_replace(rp1_temp, std::regex("<rp2-topo-hiding>*"), fmt::format("{}", rp2));
  }
  std::string makeConfigExternal(std::string base, const std::string rp1, const std::string rp2) {
    auto yaml = R"EOF(  
      ext_nw:     
        name: "external network"
        ext_nw_fc_config_list:
        - per_rp_fc_config:
            rp_to_fc_map:
              rp_1: default_routing
              rp_2: default_routing
            default_fc_for_rp_not_found: default_routing
            )EOF";
    auto routing = std::regex_replace(base, std::regex("<routing>*"), fmt::format("{}", yaml));
    auto listener_type = std::regex_replace(routing, std::regex("<listener-type>*"),
                                            fmt::format("{}", "own_external_port"));

    auto rp1_temp =
        std::regex_replace(listener_type, std::regex("<rp1-topo-hiding>*"), fmt::format("{}", rp1));
    return std::regex_replace(rp1_temp, std::regex("<rp2-topo-hiding>*"), fmt::format("{}", rp2));
  }

std::string logHeaders(Http::RequestOrResponseHeaderMap& headers)
{
  std::string log_message = "\n  ";
  headers.iterate([&](const Http::HeaderEntry& entry) -> Http::HeaderMap::Iterate {
    absl::StrAppend(&log_message, entry.key().getStringView(), ": ", entry.value().getStringView(),
                    "\n  ");
    return Http::HeaderMap::Iterate::Continue;
  });
  return log_message;
}

  // Common function for all test cases
  void runTest(Http::TestRequestHeaderMapImpl& req_hdr, Http::TestResponseHeaderMapImpl& resp_hdr,
               const std::string& req_body, const std::string& resp_body,
               std::map<std::string, std::string> expected_req_headers,
               std::map<std::string, std::string> expected_resp_headers,
               const std::map<std::string, std::string> expected_query_param,
               const Json& expected_rq_body, const Json& expected_resp_body,
               bool adapt_expected_headers_to_multipart = true) {
    HttpIntegrationTest::initialize();

    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response;
    if (!req_body.empty()) {
      if (getBodyContentType() == BodyContentType::MULTIPART_RELATED) {
        // Create multipart request body and set headers
        std::string multipart_request_body = absl::StrCat(body_prefix, req_body, body_suffix);
        req_hdr.removeContentLength();
        req_hdr.removeContentType();
        req_hdr.addCopy(Http::LowerCaseString("content-length"),
                        std::to_string(multipart_request_body.length()));
        req_hdr.addCopy(Http::LowerCaseString("content-type"), content_type);
        // Send request
        response = codec_client_->makeRequestWithBody(req_hdr, multipart_request_body);
      } else {
        // Send non-multipart body request
        req_hdr.addCopy(Http::LowerCaseString("content-length"), std::to_string(req_body.length()));
        req_hdr.addCopy(Http::LowerCaseString("content-type"), "application/json");
        response = codec_client_->makeRequestWithBody(req_hdr, req_body);
      }
    } else { // no body
      response = codec_client_->makeHeaderOnlyRequest(req_hdr);
    }
    if (!expected_req_headers.empty()) {
      waitForNextUpstreamRequest(0);
      // Send response
      if (!resp_body.empty()) {
        if (getBodyContentType() == BodyContentType::MULTIPART_RELATED) {
          // Create multipart response body and set headers
          resp_hdr.removeContentLength();
          resp_hdr.removeContentType();
          std::string multipart_response_body = absl::StrCat(body_prefix, resp_body, body_suffix);
          resp_hdr.addCopy(Http::LowerCaseString("content-length"),
                           std::to_string(multipart_response_body.length()));
          resp_hdr.addCopy(Http::LowerCaseString("content-type"), content_type);
          upstream_request_->encodeHeaders(resp_hdr, false);
          Buffer::OwnedImpl response_data(multipart_response_body);
          upstream_request_->encodeData(response_data, true);
        } else { // Non-multipart body
          resp_hdr.addCopy(Http::LowerCaseString("content-length"),
                           std::to_string(req_body.length()));
          resp_hdr.addCopy(Http::LowerCaseString("content-type"), "application/json");
          upstream_request_->encodeHeaders(resp_hdr, false);
          Buffer::OwnedImpl response_data(resp_body);
          upstream_request_->encodeData(response_data, true);
        }
      } else { // no body
        upstream_request_->encodeHeaders(resp_hdr, true);
      }
    }

    ASSERT_TRUE(response->waitForEndStream());

    if (getBodyContentType() == BodyContentType::MULTIPART_RELATED && adapt_expected_headers_to_multipart && !expected_rq_body.empty()) {
      expected_req_headers.erase("content-length");
      expected_req_headers.erase("content-type");
      // Commented out because the length of the expected body depends on the JSON formatting
      // expected_req_headers.insert({std::string("content-length"),
      //                              std::to_string(expected_rq_body.dump().length() + mp_overhead)});
      expected_req_headers.insert({std::string("content-type"), content_type});
    }

    for (std::map<std::string, std::string>::const_iterator itr = expected_req_headers.begin();
         itr != expected_req_headers.end(); ++itr) {
      EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(itr->first, itr->second));
    }

    if (!expected_query_param.empty()) {
      const auto req_query_params = Http::Utility::QueryParamsMulti::parseQueryString(
          upstream_request_->headers()
              .get(Http::LowerCaseString(":path"))[0]
              ->value()
              .getStringView());
      for (std::map<std::string, std::string>::const_iterator itr = expected_query_param.begin();
           itr != expected_query_param.end(); ++itr) {
        const auto query_param = req_query_params.getFirstValue(itr->first);
        if (query_param.has_value()) {
          EXPECT_EQ(itr->second, query_param.value());
        }
      }
    }

    if (!expected_rq_body.empty()) {
      if (getBodyContentType() == BodyContentType::MULTIPART_RELATED) {
        Body req_body(&(upstream_request_->body()), content_type);
        EXPECT_EQ(expected_rq_body, *(req_body.getBodyAsJson()));
      } else { // Non-multipart
        EXPECT_EQ(expected_rq_body, Json::parse(upstream_request_->body().toString()));
      }
    }
    if (getBodyContentType() == BodyContentType::MULTIPART_RELATED) {
      // Adapt expected headers to multipart (size and content-type).
      // This is usually wanted, but if we expect a direct (=error) response,
      // it's not desired.
      if (adapt_expected_headers_to_multipart && !expected_resp_body.empty()) {
        expected_resp_headers.erase("content-length");
        expected_resp_headers.erase("content-type");
        expected_resp_headers.insert({std::string("content-length"),
                                      std::to_string(expected_resp_body.dump().length() + mp_overhead)});
        expected_resp_headers.insert({std::string("content-type"), content_type});
      }
    }
    for (std::map<std::string, std::string>::const_iterator itr = expected_resp_headers.begin();
         itr != expected_resp_headers.end(); ++itr) {
      EXPECT_THAT(response->headers(), Http::HeaderValueOf(itr->first, itr->second));
    }

    if (!expected_resp_body.empty()) {
      if (getBodyContentType() == BodyContentType::MULTIPART_RELATED) {
        Body resp_body;
        resp_body.setBodyFromString(response->body(), content_type);
        EXPECT_EQ(expected_resp_body, *(resp_body.getBodyAsJson()));
      } else { // Non-multipart
        EXPECT_EQ(expected_resp_body, Json::parse(response->body()));
      }
    }

    ENVOY_LOG(trace, printCounters(test_server_, "http.ingress.n8e.g3p.topology_hiding"));

    codec_client_->close();
  }

  //------------------------------------------------------------------------
  // Configuration to test TH IP hiding NF Status Notify
  const std::string config_th_ip_hiding_nf_status_notify{R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.own_plmn.com
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
        extractor_regex: mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
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
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
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
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
  roaming_partners:
    - name: rp_1
      pool_name: rp1_pool
      topology_hiding:    
    - name: rp_2
      pool_name: rp2_pool
  service_profile:
    targets:
      - api_name: nnrf-disc
        direction: REQUEST
        headers:
          - 3gpp-Sbi-target-apiRoot
        query_params:
          - target-nrf-fqdn-2
          - target-nrf-fqdn-3
        json_pointers:
            ptr_value: /some/json-pointer/*/fqdn
            matching_regex: .*
            ptr_value: /some/json-pointer/*/fqdn1
      - api_name: nnrf-disc
        api_version: v1
        direction: REQUEST
        headers:
          - some-other-header-v1
        query_params:
          - target-nrf-fqdn
      - api_name: nnrf-disc
        api_version: v2
        direction: REQUEST
        headers:
          - some-other-header-v2
        query_params:
          - target-nrf-fqdn
        json_pointers:
            ptr_value: /some/json-pointer/*/fqdn
            matching_regex: .*
            ptr_value: /some/json-pointer/*/fqdn1
    ext_to_int_fqdn_map:
      nrf1_ext.plmna.com: nrf.own_plmn.com
      nrf2_ext.plmnb.com: nrf2_int.hplmn.de
      nrf3_ext.plmnc.com: nrf3_int.hplmn.de
      nrf4_ext.plmnc.com: nrf4_int.hplmn.de 
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

  //------------------------------------------------------------------------
  // NF Discovery response body (NF Instances), with fqdn everywhere
  // (SearchResult -> nfInstances)
  const std::string nf_disc_resp_body{R"(
{
  "validityPeriod": 60,
  "nfInstances": [
    {
      "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
      "nfInstanceName": "nfInstanceName_1",
      "nfType": "AUSF",
      "fqdn": "FQDN_0_0.example1.com",
      "ipv4Addresses": ["10.11.12.253","10.11.12.254"],
      "ipv6Addresses": ["2001:1b70:8230:5501:4401:3301:2201:1101","::0"],        
      "nfServices": [
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce100",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "nfServiceStatus": "REGISTERED",
          "fqdn": "FQDN.example1.com",
          "test_api_1_cb_uri_1": "FQDN_0_1.example1.com",
          "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
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
      "nfType": "AUSF",
      "fqdn": "FQDN_1_0.example1.com",
      "nfServices": [
        {
          "serviceInstanceId": "4ec8ac0b-265e-4165-86e9-e0735e6ce100",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "nfServiceStatus": "REGISTERED",
          "fqdn": "FQDN1.example2.com",
          "test_api_1_cb_uri_1": "FQDN1.example2.com",
          "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9092
            }
          ]
        },
        {
          "serviceInstanceId": "5ec8ac0b-265e-4165-86e9-e0735e6ce100",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "http",
          "nfServiceStatus": "REGISTERED",
          "fqdn": "FQDN2.example2.com",
          "test_api_1_cb_uri_1": "FQDN1.example2.com",
          "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9093
            },
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
  "nrfSupportedFeatures": "nausf-auth"
}
)"};

  //------------------------------------------------------------------------
  // NF Status Notify request body (NF Profile), with fqdn everywhere
  // (NotificationData -> nfProfile)
  const std::string nf_status_notify_req_body_nf_profile{R"(
{
  "event": "NF_REGISTERED",
  "nfInstanceUri": "nfInstanceUri_1",
  "nfProfile": {
    "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
    "nfInstanceName": "nfInstanceName_1",
    "nfType": "AUSF",
    "fqdn": "FQDN_0_0.example1.com",
    "ipv4Addresses": ["10.11.12.253","10.11.12.254"],
    "ipv6Addresses": ["2001:1b70:8230:5501:4401:3301:2201:1101","::0"],
    "nfServices": [
      {
        "serviceInstanceId": "4ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "serviceName": "nausf-auth",
        "versions": [],
        "scheme": "https",
        "nfServiceStatus": "REGISTERED",
        "fqdn": "FQDN1.example2.com",
        "test_api_1_cb_uri_1": "FQDN1.example2.com",
        "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
        "ipEndPoints": [
          {
            "ipv4Address": "10.11.12.253",
            "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
            "transport": "TCP",
            "port": 9092
          }
        ]
      },
      {
        "serviceInstanceId": "5ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "serviceName": "nausf-auth",
        "versions": [],
        "scheme": "http",
        "nfServiceStatus": "REGISTERED",
        "fqdn": "FQDN2.example2.com",
        "test_api_1_cb_uri_1": "FQDN1.example2.com",
        "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
        "ipEndPoints": [
          {
            "ipv4Address": "10.11.12.253",
            "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
            "transport": "TCP",
            "port": 9093
          },
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
}
)"};

  //------------------------------------------------------------------------
  // NF Status Notify request body (NF Profile), with fqdn everywhere
  // (NotificationData -> nfProfile)
  const std::string some_api_req_body_nf_profile{R"(
{
  "event": "NF_REGISTERED",
  "nfInstanceUri": "nfInstanceUri_1",
  "nfProfile": {
    "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
    "nfInstanceName": "nfInstanceName_1",
    "nfType": "AUSF",
    "fqdn": "nrf1_ext.plmna.com",
    "ipv4Addresses": ["10.11.12.253","10.11.12.254"],
    "ipv6Addresses": ["2001:1b70:8230:5501:4401:3301:2201:1101","::0"],
    "nfServices": [
      {
        "serviceInstanceId": "4ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "serviceName": "nausf-auth",
        "versions": [],
        "scheme": "https",
        "nfServiceStatus": "REGISTERED",
        "fqdn": "FQDN1.example2.com",
        "test_api_1_cb_uri_1": "FQDN1.example2.com",
        "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
        "ipEndPoints": [
          {
            "ipv4Address": "10.11.12.253",
            "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
            "transport": "TCP",
            "port": 9092
          }
        ]
      },
      {
        "serviceInstanceId": "5ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "serviceName": "nausf-auth",
        "versions": [],
        "scheme": "http",
        "nfServiceStatus": "REGISTERED",
        "fqdn": "FQDN2.example2.com",
        "test_api_1_cb_uri_1": "FQDN1.example2.com",
        "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
        "ipEndPoints": [
          {
            "ipv4Address": "10.11.12.253",
            "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
            "transport": "TCP",
            "port": 9093
          },
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
}
)"};
};

//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------
INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterSeppThNrfFqdnMappingTest,
                         testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         testing::Values(BodyContentType::APPLICATION_JSON,
                                         BodyContentType::MULTIPART_RELATED)));

//--------------- Begin Config Tests -------------------------------------
// Config Test: Check if the config time SEPP Edge processing
// filter cases are populated correctly. Sanity checking the
// proxy_filter_config functions
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, FilterConfigTest1) {
  auto yaml = R"EOF(
  node_type: SEPP
  own_external_port: 80
  roaming_partners:
    - name: rp_1
      pool_name: rp1_pool
      <rp1-topo-hiding>
    - name: rp_2
      pool_name: rp2_pool
      <rp2-topo-hiding>
)EOF";
  auto config1 = makeConfigExternal(yaml, config_test_rp_th, config_test_rp_th);

  EricProxyFilterProtoConfig proto_config;
  Upstream::MockClusterManager cluster_manager_;
  TestUtility::loadFromYamlAndValidate(config1, proto_config);

  auto config = std::make_shared<EricProxyFilterConfig>(proto_config, cluster_manager_);
  auto fcWrapper =
      config->getFilterCaseByNameForServiceCaseForRP("rp_1", "service_1", "fc_1", true, false);
  EXPECT_EQ(config->getThReqServiceCases()["rp_1"].size(), 0);
  EXPECT_EQ(config->getThRespServiceCases()["rp_1"].size(), 0);
  EXPECT_EQ(config->getTuhReqServiceCases()["rp_1"].size(), 1);
  EXPECT_EQ(config->getTuhRespServiceCases()["rp_1"].size(), 0);
  EXPECT_EQ(fcWrapper->filterRules().size(), 1);
  // 2 filter cases in service-case service_1: 1 fc + 1 fail-case fc
  EXPECT_EQ(config->getTuhReqServiceCases()["rp_1"]["service_1"].size(), 2);
  // Check if ServiceContext is present for both RP's
  EXPECT_EQ(config->getTuhReqServiceCtx()["rp_1"].size(), 1);
  EXPECT_EQ(config->getTuhReqServiceCtx()["rp_2"].size(), 1);
}

//------------- Begin SEPP Int-to-Ext traffic Tests ----------------------
// Case1: 2 RP's
//  RP1 : Sepp edge screening disabled
//  RP2 : Sepp edge screening enabled with:
//         - modify-header : x-modify-hdr
// Expect request to RP2 to map x-modify-hdr value
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, IntToExt1) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_th_ip_hiding_nf_discovery =
      makeConfigInternal(config_eric_proxy_base, "", config_test_rp_th_int);
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/some/path/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "rp_B.ext_plmn.com"},
      {"x-modify-hdr", "nrf1.mcc123.mnc456.ericsson.se"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"}, {"server", "secret.internal.fqdn.com"}, {"via", "location"}};

  runTest(request_headers, response_headers, "", "",
          {{"x-cluster", "rp2_pool"}, {"x-modify-hdr", "fakenrf1.mcc123.mnc456.ericsson.se"}},
          {{":status", "200"}}, {{}}, nullptr, nullptr, false);
  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.t8e.nrf.s5e.nnrf_disc."
                          "o4n.internal.th_fqdn_mapping_req_map_success_total")
                ->value());
}
// Case2: 2 RP's
//  RP1 : Sepp edge screening disabled
//  RP2 : Sepp edge screening enabled with:
//         - modify-header : x-modify-hdr
// Expect request to RP1 to be unaffected
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, IntToExt2) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_th_ip_hiding_nf_discovery =
      makeConfigInternal(config_eric_proxy_base, "", config_test_rp_th_int);
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "rp_A.ext_plmn.com"},
      {"x-modify-hdr", "nrf1.mcc123.mnc456.ericsson.se"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"}, {"server", "secret.internal.fqdn.com"}, {"via", "location"}};

  runTest(request_headers, response_headers, "", "",
          {{"x-cluster", "rp1_pool"}, {"x-modify-hdr", "nrf1.mcc123.mnc456.ericsson.se"}},
          {{":status", "200"}}, {{}}, nullptr, nullptr, false);

  for (const auto& c : test_server_->counters()) {
    if (c->name().rfind("http.ingress.n8e.g3p.topology_hiding", 0) == 0) {
      EXPECT_TRUE(false);
    } else {
      continue;
    }
  }
}

// DND-45306
// For request path:
//        map x-modify-hdr
//        map hnrf-uri query-param -> skip
// should count 1 modified request
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, IntToExtBug) {
  auto config = makeConfigInternal(config_eric_proxy_base, dnd_45306_config, dnd_45306_config);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nsmf-pduinit/v1/arget-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "rp_A.ext_plmn.com"},
      {"x-modify-hdr", "nrf2.mcc123.mnc456.ericsson.se"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"}, {"server", "secret.internal.fqdn.com"}, {"via", "location"}};

  std::string req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "nrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Json expected_req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "nrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};
  runTest(request_headers, response_headers, req_body, "",
          {{"x-cluster", "rp1_pool"}, {"x-modify-hdr", "fakenrf2.mcc123.mnc456.ericsson.se"}},
          {{":status", "200"}}, {{"hnrf-uri", "fakenrf1.mcc123.mnc456.ericsson.se"}},
          expected_req_body, nullptr);

  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nsmf_pduinit."
                          "o4n.internal.th_fqdn_mapping_req_map_success_total")
                ->value());
}

TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, IntToExtBug2) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_udm_service_case =
      makeConfigInternal(config_eric_proxy_base, dnd_45306_config, dnd_45306_config);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_udm_service_case);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nsmf-pduinit/v1/arget-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "rp_A.ext_plmn.com"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"}, {"server", "secret.internal.fqdn.com"}, {"via", "location"}};

  std::string req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "nrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Json expected_req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "nrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};
  runTest(request_headers, response_headers, req_body, "",
          {
              {"x-cluster", "rp1_pool"},
          },
          {{":status", "200"}}, {{"hnrf-uri", "fakenrf1.mcc123.mnc456.ericsson.se"}},
          expected_req_body, nullptr);

  for (const auto& c : test_server_->counters()) {
    if (c->name().rfind("http.ingress.n8e.g3p.topology_hiding", 0) == 0) {
      EXPECT_TRUE(false);
    } else {
      continue;
    }
  }
}

// Case3 : 2 RP's
// RP1 & RP2 Sepp Edge Screening enabled
// Topology Information Hide for requests and
// Topology information unhide for responses.
// Mapping mode active for both RP's
// For an Nsmf request to a Roaming Partner
// For request path:
//        map x-modify-hdr
//        map hnrf-uri query-param
//        map json-body @ /nfConsumerIdentification/nfPLMNID/fqdn
// For response path:
//        :status 200
//        Unmapped location header
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, IntToExt3) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_udm_service_case =
      makeConfigInternal(config_eric_proxy_base, service_case2, service_case2);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_udm_service_case);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/some/apiroot/nsmf-pduinit/v1/"
                "create?hnrf-uri=nrf1.mcc123.mnc456.ericsson.se&target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "rp_A.ext_plmn.com"},
      {"x-modify-hdr", "nrf2.mcc123.mnc456.ericsson.se"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"}, {"server", "secret.internal.fqdn.com"}, {"via", "location"}};

  std::string req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "nrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Json expected_req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};
  runTest(request_headers, response_headers, req_body, "",
          {{"x-cluster", "rp1_pool"}, {"x-modify-hdr", "fakenrf2.mcc123.mnc456.ericsson.se"}},
          {{":status", "200"}}, {{"hnrf-uri", "fakenrf1.mcc123.mnc456.ericsson.se"}},
          expected_req_body, nullptr);

  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nsmf_pduinit."
                          "o4n.internal.th_fqdn_mapping_req_map_success_total")
                ->value());
}

// Case4 : 2 RP's
// RP1 & RP2 Sepp Edge Screening enabled
// Topology Information hide for requests and
// Topology information unhide for responses.
// Mapping mode inactive for both RP's
// For an Nsmf request to a Roaming Partner
// For request path:
//        no impact x-modify-hdr
//        no impact hnrf-uri query-param
//        no impact json-body @ /nfConsumerIdentification/nfPLMNID/fqdn
// For response path:
//        :status 200
//        Demapping only happens when service is nudm-uecm
//        Unimpacted location header
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, IntToExt4) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_udm_service_case = makeConfigInternal(
      config_eric_proxy_base, service_case2_noTopoHiding, service_case2_noTopoHiding);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_udm_service_case);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/some/path/apiroot/nsmf-pduinit/v1/create/"
                "pdu-ctx-123?hnrf-uri=nrf1.mcc123.mnc456.ericsson.se&target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "rp_A.ext_plmn.com"},
      {"x-modify-hdr", "nrf2.mcc123.mnc456.ericsson.se"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"},
      {"location", "fakenrf2.mcc123.mnc456.ericsson.se"}};

  std::string req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "nrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Json expected_req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "nrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};
  runTest(request_headers, response_headers, req_body, "",
          {{"x-cluster", "rp1_pool"}, {"x-modify-hdr", "nrf2.mcc123.mnc456.ericsson.se"}},
          {{":status", "200"}}, {{"hnrf-uri", "nrf1.mcc123.mnc456.ericsson.se"}}, expected_req_body,
          nullptr);

  for (const auto& c : test_server_->counters()) {
    if (c->name().rfind("http.ingress.n8e.g3p.topology_hiding", 0) == 0) {
      EXPECT_TRUE(false);
    } else {
      continue;
    }
  }
}

// Case5 : 2 RP's
// RP1 & RP2 Sepp Edge Screening enabled
// Topology Information Hide for requests and
// Topology information unhide for responses.
// Mapping mode inactive for both RP's
// For an nudm-uecm request to a Roaming Partner
// For request path: -
//        No mapping as no service cases
//        defined for nudm-uecm
// For response path:
//        :status 200
//        Unimpacted location header because demapping only done if :status = 308
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, IntToExt5) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_udm_service_case =
      makeConfigInternal(config_eric_proxy_base, service_case2, service_case2);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_udm_service_case);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nudm-uecm/v1/create/"
                "ue-ctx-123?hnrf-uri=nrf1.mcc123.mnc456.ericsson.se&target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "rp_A.ext_plmn.com"},
      {"x-modify-hdr", "nrf2.mcc123.mnc456.ericsson.se"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"server", "secret.internal.fqdn.com"},
      {"location", "fakenrf2.mcc123.mnc456.ericsson.se"},
      {"x-modify-resp", "x-modify-orig-val"},
      {"via", "location"}};

  std::string req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "nrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Json expected_req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "nrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};
  runTest(request_headers, response_headers, req_body, "",
          {{"x-cluster", "rp1_pool"}, {"x-modify-hdr", "nrf2.mcc123.mnc456.ericsson.se"}},
          {{":status", "200"},
           {"location", "fakenrf2.mcc123.mnc456.ericsson.se"},
           {"x-modify-resp", "x-modify-orig-val"}},
          {{"hnrf-uri", "nrf1.mcc123.mnc456.ericsson.se"}}, expected_req_body, nullptr);

  for (const auto& c : test_server_->counters()) {
    if (c->name().rfind("http.ingress.n8e.g3p.topology_hiding", 0) == 0) {
      EXPECT_TRUE(false);
    } else {
      continue;
    }
  }
}

// Case6 : 2 RP's
// RP1 & RP2 Sepp Edge Screening enabled
// Topology Information Hide for requests and
// Topology information unhide for responses.
// Mapping mode inactive for both RP's
// For an nudm-uecm request to a Roaming Partner
// For request path: -
//        No mapping as no service cases
//        defined for nudm-uecm
// For response path:
//        :status 308
//        Demapped location header because in passive mode
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, IntToExt6) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_udm_service_case =
      makeConfigInternal(config_eric_proxy_base, service_case2, service_case2);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_udm_service_case);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/some/path/to/root/nudm-uecm/v1/create/"
                "ue-ctx-123?hnrf-uri=nrf1.mcc123.mnc456.ericsson.se&target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "rp_A.ext_plmn.com"},
      {"x-modify-hdr", "nrf2.mcc123.mnc456.ericsson.se"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "308"},
      {"server", "secret.internal.fqdn.com"},
      {"location", "fakenrf2.mcc123.mnc456.ericsson.se"},
      {"x-modify-resp", "x-modify-orig-val"},
      {"via", "location"}};

  std::string req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "nrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Json expected_req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "nrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};
  runTest(request_headers, response_headers, req_body, "",
          {{"x-cluster", "rp1_pool"}, {"x-modify-hdr", "nrf2.mcc123.mnc456.ericsson.se"}},
          {{":status", "308"},
           {"location", "nrf2.mcc123.mnc456.ericsson.se"},
           {"x-modify-resp", "x-modify-resp-val"}},
          {{"hnrf-uri", "nrf1.mcc123.mnc456.ericsson.se"}}, expected_req_body, nullptr);

  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nudm_uecm."
                          "o4n.internal.th_fqdn_mapping_resp_demap_success_total")
                ->value());
}

// Case8 : 2 RP's
// RP1 & RP2 Sepp Edge Screening enabled
// Topology Information Hide for requests and
// Topology information unhide for responses.
// Mapping mode inactive for both RP's
// For an nudm-uecm request to a Roaming Partner
// For request path: -
//        No mapping as no service cases
//        defined for nudm-uecm
// For response path:
//        :status 308
//        location header map failure in active mode
//        Returns a local reply with status 502 and title fc-fail-nudm
// CHECK : If action-reject has to be modified such that if local reply is invoked on
// a response path you just forward the message
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, IntToExt8) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_udm_service_case =
      makeConfigInternal(config_eric_proxy_base, service_case2, service_case2);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_udm_service_case);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nudm-uecm/v1/create/"
                "ue-ctx-123?hnrf-uri=nrf1.mcc123.mnc456.ericsson.se&target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "rp_A.ext_plmn.com"},
      {"x-modify-hdr", "nrf2.mcc123.mnc456.ericsson.se"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "308"},
      {"server", "secret.internal.fqdn.com"},
      {"location", "fakenrf23.mcc123.mnc456.ericsson.se"},
      {"x-modify-resp", "x-modify-orig-val"},
      {"via", "location"}};

  std::string req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Json expected_req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};
  Json expected_resp_body{R"(
    {
      "status":502,
      "title":"fc-fail-nudm",
      "detail":"fc-fail-detail",
      "cause":"FC_FAIL"
    }
  )"_json};
  runTest(request_headers, response_headers, req_body, "",
          {{"x-cluster", "rp1_pool"}, {"x-modify-hdr", "nrf2.mcc123.mnc456.ericsson.se"}},
          {{":status", "502"}}, {{"hnrf-uri", "nrf1.mcc123.mnc456.ericsson.se"}}, expected_req_body,
          expected_resp_body, false);

  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nudm_uecm."
                          "o4n.internal.th_fqdn_mapping_resp_demap_failure_total")
                ->value());
}

// Case9 : 2 RP's
// RP1 & RP2 Sepp Edge Screening enabled
// Topology Information Hide for requests and
// Topology information Unhide for responses.
// Mapping mode inactive for both RP's
// For an nsmf-pduinit request to a Roaming Partner
// For request path: -
//        Map header x-modify-hdr
//        Map attempted on query param and fails
//        Returns a local reply with status 502 and title fc-fail-nsmf
// For response path:
//        NA
// CHECK : If action-reject has to be modified such that if local reply is invoked on
// a response path you just forward the message
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, IntToExt9) {
  auto config_smf_udm_service_case =
      makeConfigInternal(config_eric_proxy_base, service_case2, service_case2);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_udm_service_case);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nsmf-pduinit/v1/create/"
                "ue-ctx-123?hnrf-uri=nrf12.mcc123.mnc456.ericsson.se&target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "rp_A.ext_plmn.com"},
      {"x-modify-hdr", "nrf2.mcc123.mnc456.ericsson.se"}};

  Http::TestResponseHeaderMapImpl response_headers{};

  std::string req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Json expected_resp_body{R"(
    {
      "status":502,
      "title":"fc-fail-nsmf",
      "detail":"fc-fail-detail",
      "cause":"FC_FAIL"
    }
  )"_json};
  runTest(request_headers, response_headers, req_body, "", {}, {{":status", "502"}}, {}, nullptr,
          expected_resp_body, false);

  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nsmf_pduinit."
                          "o4n.internal.th_fqdn_mapping_req_map_failure_total")
                ->value());
}

//------------- Begin SEPP Ext-to-Int traffic Tests ----------------------
// Case1: 2 RP's
//  RP1 : Sepp edge screening disabled
//  RP2 : Sepp edge screening enabled with:
//         - modify-header : x-modify-hdr
// Expect request from RP2 to demap x-modify-hdr value
// request demap ?internal
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToInt1) {
  auto config_th_ip_hiding_nf_discovery =
      makeConfigExternal(config_eric_proxy_base, "", config_test_rp_th);
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-modify-hdr", "fakenrf1.mcc123.mnc456.ericsson.se"},
      {"x-eric-sepp-rp-name", "rp_2"},
      {"x-eric-sepp-test-san", "rp_B.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"}, {"server", "secret.internal.fqdn.com"}, {"via", "location"}};

  runTest(request_headers, response_headers, "", "",
          {{"x-cluster", "nrf_pool"}, {"x-modify-hdr", "nrf1.mcc123.mnc456.ericsson.se"}},
          {{":status", "200"}}, {{}}, nullptr, nullptr, false);

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.t8e.nrf.s5e.nnrf_"
                               "disc.o4n.external.th_fqdn_mapping_req_demap_success_total")
                     ->value());
}

TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToInt1_Do_Nothing) {
  auto config_th_ip_hiding_nf_discovery =
      makeConfigExternal(config_eric_proxy_base, "", config_test_rp_th);
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-modify-hdr", "fakenrf157.mcc123.mnc456.ericsson.se"},
      {"x-eric-sepp-rp-name", "rp_2"},
      {"x-eric-sepp-test-san", "rp_B.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"}, {"server", "secret.internal.fqdn.com"}, {"via", "location"}};

  runTest(request_headers, response_headers, "", "",
          {{"x-cluster", "nrf_pool"}, {"x-modify-hdr", "fakenrf157.mcc123.mnc456.ericsson.se"}},
          {{":status", "200"}}, {{}}, nullptr, nullptr, false);

  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.t8e.nrf.s5e.nnrf_disc."
                          "o4n.external.th_fqdn_mapping_req_forwarded_unmodified_total")
                ->value());
}

// DND-45412
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToInt2_Success_Do_Nothing) {
  const std::string conf_bug{R"EOF(
      topology_hiding:
        service_profile:
          topology_unhiding_service_cases:
            service_case_name: service_1
            service_type:
              api_name: nnrf-disc
              api_version: v1
              direction: REQUEST
            filter_case:
              name: fc_1
              filter_rules:
              - name: fr_1
                condition: 
                  term_boolean: true
                actions:
                - action_modify_header:
                    name: x-modify-hdr
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          do_nothing: true
                - action_modify_header:
                    name: x-modify-hdr2
                    use_string_modifiers:
                      string_modifiers:
                      - table_lookup:
                          lookup_table_name: demap_table
                          do_nothing: true
          unsuccessful_operation_filter_cases:
            - name: failover_1
              filter_rules:
              - name: failover_fr1
                condition:
                  term_boolean: true
                actions:
                - action_add_header:
                    name: x-failover-1
                    value:
                      term_string: x-failover-1-val
)EOF"};
  auto config_th_ip_hiding_nf_discovery = makeConfigExternal(config_eric_proxy_base, "", conf_bug);
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-modify-hdr", "fakenrf157.mcc123.mnc456.ericsson.se"},
      {"x-modify-hdr2", "fakenrf1.mcc123.mnc456.ericsson.se"},
      {"x-eric-sepp-rp-name", "rp_2"},
      {"x-eric-sepp-test-san", "rp_B.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"}, {"server", "secret.internal.fqdn.com"}, {"via", "location"}};

  runTest(request_headers, response_headers, "", "",
          {{"x-cluster", "nrf_pool"}, {"x-modify-hdr", "fakenrf157.mcc123.mnc456.ericsson.se"}},
          {{":status", "200"}}, {{}}, nullptr, nullptr, false);

  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.t8e.nrf.s5e.nnrf_disc."
                          "o4n.external.th_fqdn_mapping_req_forwarded_unmodified_total")
                ->value());
  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.t8e.nrf.s5e.nnrf_disc."
                          "o4n.external.th_fqdn_mapping_req_demap_success_total")
                ->value());
}

// DND-45673
// Test modify json with asterisk
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToInt2_ModifyJsonWithAsterisk) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  const std::string conf_bug{R"EOF(
      topology_hiding:
        service_profile:
          topology_unhiding_service_cases:
            service_case_name: service_1
            service_type:
              api_name: nnrf-disc
              api_version: v1
              direction: REQUEST
            filter_case:
              name: fc_1
              filter_rules:
              - name: fr_1
                condition: 
                  term_boolean: true
                actions:
                - action_modify_json_body:
                    name: json_body
                    json_operation:
                      modify_json_value:
                        string_modifiers:
                        - table_lookup:
                            lookup_table_name: demap_table
                            fc_unsuccessful_operation: fc-fail-2
                        json_pointer:
                          term_string: "/nfInstances/*/nfServices/0/fqdn"
                        enable_exception_handling: true
          unsuccessful_operation_filter_cases:
            - name: fc-fail-2
              filter_rules:
              - name: fr_1
                condition:
                  term_boolean: true
                actions:
                - action_reject_message:
                    status: 502
                    title: fc-fail-nsmf
                    detail: fc-fail-detail
                    cause: FC_FAIL
)EOF"};

  auto config_th_ip_hiding_nf_discovery =
      makeConfigExternal(config_eric_proxy_base, conf_bug, conf_bug);
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_2"},
      {"x-eric-sepp-test-san", "rp_B.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"server", "secret.internal.fqdn.com"},
      {"location", "fakenrf2.mcc123.mnc456.ericsson.se"},
      {"via", "location"}};

  std::string req_body{R"(
    {
    "nfInstances":
        [
            {
            "nfInstanceId": "a341960f-8bf2-4285-8591-1ecbf5057c15",
            "nfStatus": "REGISTERED",
            "nfType": "NRF"
            },
            {
            "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce104",
            "nfServices":
                [
                    {
                    "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se",
                    "nfServiceStatus": null,
                    "scheme": "http",
                    "serviceInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce104",
                    "serviceName": "nnrf-nfm",
                    "versions":
                        [
                            {
                            "apiFullVersion": "1",
                            "apiVersionInUri": "v1"
                            }
                        ]
                    }
                ],
            "nfStatus": "REGISTERED",
            "nfType": "NRF"
            }
        ],
    "subscriberIdentifier": "imsi-460001357924610"
    }
  )"};

  Json expected_req_body{R"(
    {
    "nfInstances":
        [
            {
            "nfInstanceId": "a341960f-8bf2-4285-8591-1ecbf5057c15",
            "nfStatus": "REGISTERED",
            "nfType": "NRF"
            },
            {
            "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce104",
            "nfServices":
                [
                    {
                    "fqdn": "nrf2.mcc123.mnc456.ericsson.se",
                    "nfServiceStatus": null,
                    "scheme": "http",
                    "serviceInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce104",
                    "serviceName": "nnrf-nfm",
                    "versions":
                        [
                            {
                            "apiFullVersion": "1",
                            "apiVersionInUri": "v1"
                            }
                        ]
                    }
                ],
            "nfStatus": "REGISTERED",
            "nfType": "NRF"
            }
        ],
    "subscriberIdentifier": "imsi-460001357924610"
    }
  )"_json};

  runTest(request_headers, response_headers, req_body, "",
          {{"x-cluster", "nrf_pool"}}, // expected_req_headers
          {{":status", "200"}},        // expected_resp_headers
          {{"hnrf-uri", "nrf1.mcc123.mnc456.ericsson.se"}}, expected_req_body, nullptr);

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_2.t8e.nrf.s5e.nnrf_"
                               "disc.o4n.external.th_fqdn_mapping_req_demap_success_total")
                     ->value());
}

// Case2: 2 RP's
//  RP1 : Sepp edge screening disabled
//  RP2 : Sepp edge screening enabled with:
//         - modify-header : x-modify-hdr
// Expect request from RP1 to be unaffected
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToInt2) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_th_ip_hiding_nf_discovery =
      makeConfigExternal(config_eric_proxy_base, "", config_test_rp_th);
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-modify-hdr", "fakenrf1.mcc123.mnc456.ericsson.se"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"}, {"server", "secret.internal.fqdn.com"}, {"via", "location"}};

  runTest(request_headers, response_headers, "", "",
          {{"x-cluster", "nrf_pool"}, {"x-modify-hdr", "fakenrf1.mcc123.mnc456.ericsson.se"}},
          {{":status", "200"}}, {{}}, nullptr, nullptr, false);

  for (const auto& c : test_server_->counters()) {
    if (c->name().rfind("http.ingress.n8e.g3p.topology_hiding", 0) == 0) {
      EXPECT_TRUE(false);
    } else {
      continue;
    }
  }
}

// Case3 : 2 RP's
// RP1 & RP2 Sepp Edge Screening enabled
// Topology Information Unhide for requests and
// Topology information hide for responses.
// Mapping mode active for both RP's
// For an Nsmf request from a Roaming Partner
// For request path:
//        demap x-modify-hdr
//        demap hnrf-uri query-param
//        demap json-body @ /nfConsumerIdentification/nfPLMNID/fqdn
// For response path:
//        :status 200
//        Unmapped location header
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToInt3) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_udm_service_case =
      makeConfigExternal(config_eric_proxy_base, service_case1, service_case1);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_udm_service_case);
  config_helper_.addFilter(config_header_to_metadata);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path",
       "/nsmf-pduinit/v1/create?hnrf-uri=fakenrf1.mcc123.mnc456.ericsson.se&target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-modify-hdr", "fakenrf2.mcc123.mnc456.ericsson.se"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"}, {"server", "secret.internal.fqdn.com"}, {"via", "location"}};

  std::string req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Json expected_req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "nrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};
  runTest(request_headers, response_headers, req_body, "",
          {{"x-cluster", "nrf_pool"}, {"x-modify-hdr", "nrf2.mcc123.mnc456.ericsson.se"}},
          {{":status", "200"}}, {{"hnrf-uri", "nrf1.mcc123.mnc456.ericsson.se"}}, expected_req_body,
          nullptr);

  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nsmf_pduinit."
                          "o4n.external.th_fqdn_mapping_req_demap_success_total")
                ->value());
}

// Case4 : 2 RP's
// RP1 & RP2 Sepp Edge Screening enabled
// Topology Information Unhide for requests and
// Topology information hide for responses.
// Mapping mode inactive for both RP's
// For an Nsmf request from a Roaming Partner
// For request path:
//        demap x-modify-hdr
//        demap hnrf-uri query-param
//        demap json-body @ /nfConsumerIdentification/nfPLMNID/fqdn
// For response path:
//        :status 200
//        Unmapped location header
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToInt4) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_udm_service_case =
      makeConfigExternal(config_eric_proxy_base, service_case1, service_case1);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_udm_service_case);
  config_helper_.addFilter(config_header_to_metadata);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nsmf-pduinit/v1/create/"
                "pdu-ctx-123?hnrf-uri=fakenrf1.mcc123.mnc456.ericsson.se&target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-modify-hdr", "fakenrf2.mcc123.mnc456.ericsson.se"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"}, {"server", "secret.internal.fqdn.com"}, {"via", "location"}};

  std::string req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Json expected_req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "nrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};
  runTest(request_headers, response_headers, req_body, "",
          {{"x-cluster", "nrf_pool"}, {"x-modify-hdr", "nrf2.mcc123.mnc456.ericsson.se"}},
          {{":status", "200"}}, {{"hnrf-uri", "nrf1.mcc123.mnc456.ericsson.se"}}, expected_req_body,
          nullptr);

  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nsmf_pduinit."
                          "o4n.external.th_fqdn_mapping_req_demap_success_total")
                ->value());
}

// Case5 : 2 RP's
// RP1 & RP2 Sepp Edge Screening enabled
// Topology Information Unhide for requests and
// Topology information hide for responses.
// Mapping mode inactive for both RP's
// For an nudm-uecm request from a Roaming Partner
// For request path: -
//        No demapping as no service cases
//        defined for nudm-uecm
// For response path:
//        :status 200
//        Unmapped location header because mapping only done if :status = 308
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToInt5) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_udm_service_case =
      makeConfigExternal(config_eric_proxy_base, service_case1, service_case1);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_udm_service_case);
  config_helper_.addFilter(config_header_to_metadata);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nudm-uecm/v1/create/"
                "ue-ctx-123?hnrf-uri=fakenrf1.mcc123.mnc456.ericsson.se&target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-modify-hdr", "fakenrf2.mcc123.mnc456.ericsson.se"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"server", "secret.internal.fqdn.com"},
      {"location", "fakenrf2.mcc123.mnc456.ericsson.se"},
      {"x-modify-resp", "x-modify-orig-val"},
      {"via", "location"}};

  std::string req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Json expected_req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};
  runTest(request_headers, response_headers, req_body, "",
          {{"x-cluster", "nrf_pool"}, {"x-modify-hdr", "fakenrf2.mcc123.mnc456.ericsson.se"}},
          {{":status", "200"},
           {"location", "fakenrf2.mcc123.mnc456.ericsson.se"},
           {"x-modify-resp", "x-modify-orig-val"}},
          {{"hnrf-uri", "fakenrf1.mcc123.mnc456.ericsson.se"}}, expected_req_body, nullptr);

  for (const auto& c : test_server_->counters()) {
    if (c->name().rfind("http.ingress.n8e.g3p.topology_hiding", 0) == 0) {
      EXPECT_TRUE(false);
    } else {
      continue;
    }
  }
}

// Case6 : 2 RP's
// RP1 & RP2 Sepp Edge Screening enabled
// Topology Information Unhide for requests and
// Topology information hide for responses.
// Mapping mode inactive for both RP's
// For an nudm-uecm request from a Roaming Partner
// For request path: -
//        No demapping as no service cases
//        defined for nudm-uecm
// For response path:
//        :status 308
//        Unmapped location header because in passive mode
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToInt6) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_udm_service_case = makeConfigExternal(
      config_eric_proxy_base, service_case1_NoTopoHiding, service_case1_NoTopoHiding);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_udm_service_case);
  config_helper_.addFilter(config_header_to_metadata);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nudm-uecm/v1/create/"
                "ue-ctx-123?hnrf-uri=fakenrf1.mcc123.mnc456.ericsson.se&target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-modify-hdr", "fakenrf2.mcc123.mnc456.ericsson.se"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{{":status", "308"},
                                                   {"server", "secret.internal.fqdn.com"},
                                                   {"location", "nrf2.mcc123.mnc456.ericsson.se"},
                                                   {"x-modify-resp", "x-modify-orig-val"},
                                                   {"via", "location"}};

  std::string req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Json expected_req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};
  runTest(request_headers, response_headers, req_body, "",
          {{"x-cluster", "nrf_pool"}, {"x-modify-hdr", "fakenrf2.mcc123.mnc456.ericsson.se"}},
          {{":status", "308"},
           {"location", "nrf2.mcc123.mnc456.ericsson.se"},
           {"x-modify-resp", "x-modify-orig-val"}},
          {{"hnrf-uri", "fakenrf1.mcc123.mnc456.ericsson.se"}}, expected_req_body, nullptr);

  for (const auto& c : test_server_->counters()) {
    if (c->name().rfind("http.ingress.n8e.g3p.topology_hiding", 0) == 0) {
      EXPECT_TRUE(false);
    } else {
      continue;
    }
  }
}

// Case7 : 2 RP's
// RP1 & RP2 Sepp Edge Screening enabled
// Topology Information Unhide for requests and
// Topology information hide for responses.
// Mapping mode inactive for both RP's
// For an nudm-uecm request from a Roaming Partner
// For request path: -
//        No demapping as no service cases
//        defined for nudm-uecm
// For response path:
//        :status 308
//        location header mapped in active mode
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToInt7) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_udm_service_case =
      makeConfigExternal(config_eric_proxy_base, service_case1, service_case1);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_udm_service_case);
  config_helper_.addFilter(config_header_to_metadata);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nudm-uecm/v1/create/"
                "ue-ctx-123?hnrf-uri=fakenrf1.mcc123.mnc456.ericsson.se&target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-modify-hdr", "fakenrf2.mcc123.mnc456.ericsson.se"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{{":status", "308"},
                                                   {"server", "secret.internal.fqdn.com"},
                                                   {"location", "nrf2.mcc123.mnc456.ericsson.se"},
                                                   {"x-modify-resp", "x-modify-orig-val"},
                                                   {"via", "location"}};

  std::string req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Json expected_req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};
  runTest(request_headers, response_headers, req_body, "",
          {{"x-cluster", "nrf_pool"}, {"x-modify-hdr", "fakenrf2.mcc123.mnc456.ericsson.se"}},
          {{":status", "308"},
           {"location", "fakenrf2.mcc123.mnc456.ericsson.se"},
           {"x-modify-resp", "x-modify-resp-val"}},
          {{"hnrf-uri", "fakenrf1.mcc123.mnc456.ericsson.se"}}, expected_req_body, nullptr);

  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nudm_uecm."
                          "o4n.external.th_fqdn_mapping_resp_map_success_total")
                ->value());
}

// Case8 : 2 RP's
// RP1 & RP2 Sepp Edge Screening enabled
// Topology Information Unhide for requests and
// Topology information hide for responses.
// Mapping mode inactive for both RP's
// For an nudm-uecm request from a Roaming Partner
// For request path: -
//        No demapping as no service cases
//        defined for nudm-uecm
// For response path:
//        :status 308
//        location header map failure in active mode
//        Returns a local reply with status 502 and title fc-fail-nudm
// CHECK : If action-reject has to be modified such that if local reply is invoked on
// a response path you just forward the message
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToInt8) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_udm_service_case =
      makeConfigExternal(config_eric_proxy_base, service_case1, service_case1);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_udm_service_case);
  config_helper_.addFilter(config_header_to_metadata);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nudm-uecm/v1/create/"
                "ue-ctx-123?hnrf-uri=fakenrf1.mcc123.mnc456.ericsson.se&target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-modify-hdr", "fakenrf2.mcc123.mnc456.ericsson.se"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{{":status", "308"},
                                                   {"server", "secret.internal.fqdn.com"},
                                                   {"location", "nrf23.mcc123.mnc456.ericsson.se"},
                                                   {"x-modify-resp", "x-modify-orig-val"},
                                                   {"via", "location"}};

  std::string req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Json expected_req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"_json};
  Json expected_resp_body{R"(
    {
      "status":502,
      "title":"fc-fail-nudm",
      "detail":"fc-fail-detail",
      "cause":"FC_FAIL"
    }
  )"_json};
  runTest(request_headers, response_headers, req_body, "",
          {{"x-cluster", "nrf_pool"}, {"x-modify-hdr", "fakenrf2.mcc123.mnc456.ericsson.se"}},
          {{":status", "502"}}, {{"hnrf-uri", "fakenrf1.mcc123.mnc456.ericsson.se"}},
          expected_req_body, expected_resp_body, false);

  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nudm_uecm."
                          "o4n.external.th_fqdn_mapping_resp_map_failure_total")
                ->value());
}

// Case9 : 2 RP's
// RP1 & RP2 Sepp Edge Screening enabled
// Topology Information Unhide for requests and
// Topology information hide for responses.
// Mapping mode inactive for both RP's
// For an nsmf-pduinit request from a Roaming Partner
// For request path: -
//        Demap header x-modify-hdr
//        Demapping attempted on query param and fails
//        Returns a local reply with status 502 and title fc-fail-nsmf
// For response path:
//        NA
// CHECK : If action-reject has to be modified such that if local reply is invoked on
// a response path you just forward the message
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToInt9) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_udm_service_case =
      makeConfigExternal(config_eric_proxy_base, service_case1, service_case1);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_udm_service_case);
  config_helper_.addFilter(config_header_to_metadata);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nsmf-pduinit/v1/create/"
                "ue-ctx-123?hnrf-uri=fakenrf12.mcc123.mnc456.ericsson.se&target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-modify-hdr", "fakenrf2.mcc123.mnc456.ericsson.se"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{};

  std::string req_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
          "nfName": "123e-e8b-1d3-a46-421",
          "nfIPv4Address": "192.168.0.1",
          "nfIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
          "nfPLMNID": {
              "mcc": "311",
              "mnc": 280,
              "fqdn": "fakenrf2.mcc123.mnc456.ericsson.se"
          },
          "nodeFunctionality": "SMF"
        }
      }
  )"};
  Json expected_resp_body{R"(
    {
      "status":502,
      "title":"fc-fail-nsmf",
      "detail":"fc-fail-detail",
      "cause":"FC_FAIL"
    }
  )"_json};
  runTest(request_headers, response_headers, req_body, "", {}, {{":status", "502"}}, {}, nullptr,
          expected_resp_body, false);

  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nsmf_pduinit."
                          "o4n.external.th_fqdn_mapping_req_demap_failure_total")
                ->value());
}

// Case10 : 2 RP's
// RP1 & RP2 Sepp Edge Screening enabled
// Topology Information Unhide for requests and
// Topology information hide for responses.
// Mapping mode inactive for both RP's
// For an Nnrf_NFManagement_NFStatusNotify  request from a Roaming Partner
// Notification from RP to own n/w for a previous subscription from own n/w NF to RP
// 3gpp-sbi-callback = Nnrf_NFManagementNFSStatusNotify (No apiVersion entry)
// For request path: -
//        Demap header 3gpp-sbi-target-apiroot-dummy Since real TaR would be
//        removed by router so the prefix uri to the callback is kept in this dumy TaR
//        Returns 200 Ok
// For response path:
//        No actions required
TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToInt10) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_udm_service_case =
      makeConfigExternal(config_eric_proxy_base, service_case1, service_case1);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_udm_service_case);
  config_helper_.addFilter(config_header_to_metadata);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/some/path/to/callback/uri"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"3gpp-sbi-callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"3gpp-sbi-target-apiroot-dummy",
       "http://fakenrf2.mcc123.mnc456.ericsson.se:30982/some/path"},
      {"3gpp-sbi-target-apiroot-dummy2", "http://fakenrf2.mcc123.mnc456.ericsson.se:30982"},
      {"3gpp-sbi-target-apiroot-dummy3", "http://fakenrf2.mcc123.mnc456.ericsson.se/some/path"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"},
                                                   {"server", "secret.internal.fqdn.com"},
                                                   {"x-modify-resp", "x-modify-orig-val"},
                                                   {"via", "location"}};

  std::string req_body{R"(
{
  "event": "NF_REGISTERED",
  "nfInstanceUri": "nfInstanceUri_1",
  "nfProfile": {
    "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
    "nfInstanceName": "nfInstanceName_1",
    "nfType": "AUSF",
    "fqdn": "FQDN_0_0.example1.com",
    "ipv4Addresses": ["10.11.12.253","10.11.12.254"],
    "ipv6Addresses": ["2001:1b70:8230:5501:4401:3301:2201:1101","::0"],
    "nfServices": [
      {
        "serviceInstanceId": "4ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "serviceName": "nausf-auth",
        "versions": [],
        "scheme": "https",
        "nfServiceStatus": "REGISTERED",
        "fqdn": "FQDN1.example2.com",
        "test_api_1_cb_uri_1": "FQDN1.example2.com",
        "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
        "ipEndPoints": [
          {
            "ipv4Address": "10.11.12.253",
            "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
            "transport": "TCP",
            "port": 9092
          }
        ]
      },
      {
        "serviceInstanceId": "5ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "serviceName": "nausf-auth",
        "versions": [],
        "scheme": "http",
        "nfServiceStatus": "REGISTERED",
        "fqdn": "FQDN2.example2.com",
        "test_api_1_cb_uri_1": "FQDN1.example2.com",
        "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
        "ipEndPoints": [
          {
            "ipv4Address": "10.11.12.253",
            "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
            "transport": "TCP",
            "port": 9093
          },
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
}
)"};
  Json expected_resp_body{R"(
    {
      "status":502,
      "title":"fc-fail-nsmf",
      "detail":"fc-fail-detail",
      "cause":"FC_FAIL"
    }
  )"_json};
  runTest(
      request_headers, response_headers, req_body, "",
      {{"3gpp-sbi-target-apiroot-dummy", "http://nrf2.mcc123.mnc456.ericsson.se:30982/some/path"},
       {"3gpp-sbi-target-apiroot-dummy2", "http://nrf2.mcc123.mnc456.ericsson.se:30982"},
       {"3gpp-sbi-target-apiroot-dummy3", "http://nrf2.mcc123.mnc456.ericsson.se/some/path"},
       {"x-cluster", "nrf_pool"}},
      {{":status", "200"}}, {}, nullptr, nullptr);

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.Nnrf_"
                               "NFManagement_NFStatusNotify."
                               "o4n.external.th_fqdn_mapping_req_demap_success_total")
                     ->value());
}

// -------------------------------------------------------------------------
//                Misc Cases
// -------------------------------------------------------------------------
// Case Check if strict resource match passes properly
// in service classifier context

TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToIntMisc1) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_service_case =
      makeConfigExternal(config_eric_proxy_base, service_case_misc, service_case_misc);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_service_case);
  config_helper_.addFilter(config_header_to_metadata);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nsmf-pduinit/v1/some/fixed/resource?hnrf-uri=http://"
                "fakenrf1.mcc123.mnc456.ericsson.se:30982/some/path"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-modify-hdr", "http://fakenrf2.mcc123.mnc456.ericsson.se:30982/some/path"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"},
                                                   {"server", "secret.internal.fqdn.com"},
                                                   {"x-modify-resp", "x-modify-orig-val"},
                                                   {"via", "location"}};

  std::string req_body{R"(
{
  "event": "NF_REGISTERED",
  "nfInstanceUri": "nfInstanceUri_1",
  "nfProfile": {
    "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
    "nfInstanceName": "nfInstanceName_1",
    "nfType": "AUSF",
    "fqdn": "FQDN_0_0.example1.com",
    "ipv4Addresses": ["10.11.12.253","10.11.12.254"],
    "ipv6Addresses": ["2001:1b70:8230:5501:4401:3301:2201:1101","::0"],
    "nfServices": [
      {
        "serviceInstanceId": "4ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "serviceName": "nausf-auth",
        "versions": [],
        "scheme": "https",
        "nfServiceStatus": "REGISTERED",
        "fqdn": "FQDN1.example2.com",
        "test_api_1_cb_uri_1": "FQDN1.example2.com",
        "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
        "ipEndPoints": [
          {
            "ipv4Address": "10.11.12.253",
            "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
            "transport": "TCP",
            "port": 9092
          }
        ]
      },
      {
        "serviceInstanceId": "5ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "serviceName": "nausf-auth",
        "versions": [],
        "scheme": "http",
        "nfServiceStatus": "REGISTERED",
        "fqdn": "FQDN2.example2.com",
        "test_api_1_cb_uri_1": "FQDN1.example2.com",
        "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
        "ipEndPoints": [
          {
            "ipv4Address": "10.11.12.253",
            "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
            "transport": "TCP",
            "port": 9093
          },
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
}
)"};
  Json expected_resp_body{R"(
    {
      "status":502,
      "title":"fc-fail-nsmf",
      "detail":"fc-fail-detail",
      "cause":"FC_FAIL"
    }
  )"_json};
  runTest(request_headers, response_headers, req_body, "",
          {{"x-modify-hdr", "http://nrf2.mcc123.mnc456.ericsson.se:30982/some/path"},
           {"x-cluster", "nrf_pool"}},
          {{":status", "200"}},
          {{"hnrf-uri", "http://nrf1.mcc123.mnc456.ericsson.se:30982/some/path"}}, nullptr,
          nullptr);

  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nsmf_pduinit."
                          "o4n.external.th_fqdn_mapping_req_demap_success_total")
                ->value());
}

// Misc the resource is non-deterministic and uses some nf-instance id
// to index the resource it wshes to modify

TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToIntMisc2) {
  // GTEST_SKIP() << "New test to reproduce bug. Skipped while the one-eric-proxy changes are still
  // ongoing";

  auto config_smf_service_case =
      makeConfigExternal(config_eric_proxy_base, service_case_misc, service_case_misc);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_smf_service_case);
  config_helper_.addFilter(config_header_to_metadata);

  // Agnostic of index in some-id-xxx
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nsmf-pduinit/v1/root/nf-instances/some-id-456-resource?hnrf-uri=http://"
                "fakenrf1.mcc123.mnc456.ericsson.se:30982/some/path"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-modify-hdr", "http://fakenrf2.mcc123.mnc456.ericsson.se:30982/some/path"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"},
                                                   {"server", "secret.internal.fqdn.com"},
                                                   {"x-modify-resp", "x-modify-orig-val"},
                                                   {"via", "location"}};

  std::string req_body{R"(
{
  "event": "NF_REGISTERED",
  "nfInstanceUri": "nfInstanceUri_1",
  "nfProfile": {
    "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
    "nfInstanceName": "nfInstanceName_1",
    "nfType": "AUSF",
    "fqdn": "FQDN_0_0.example1.com",
    "ipv4Addresses": ["10.11.12.253","10.11.12.254"],
    "ipv6Addresses": ["2001:1b70:8230:5501:4401:3301:2201:1101","::0"],
    "nfServices": [
      {
        "serviceInstanceId": "4ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "serviceName": "nausf-auth",
        "versions": [],
        "scheme": "https",
        "nfServiceStatus": "REGISTERED",
        "fqdn": "FQDN1.example2.com",
        "test_api_1_cb_uri_1": "FQDN1.example2.com",
        "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
        "ipEndPoints": [
          {
            "ipv4Address": "10.11.12.253",
            "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
            "transport": "TCP",
            "port": 9092
          }
        ]
      },
      {
        "serviceInstanceId": "5ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "serviceName": "nausf-auth",
        "versions": [],
        "scheme": "http",
        "nfServiceStatus": "REGISTERED",
        "fqdn": "FQDN2.example2.com",
        "test_api_1_cb_uri_1": "FQDN1.example2.com",
        "test_api_1_cb_uri_2": "FQDN_0_2.example1.com",
        "ipEndPoints": [
          {
            "ipv4Address": "10.11.12.253",
            "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
            "transport": "TCP",
            "port": 9093
          },
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
}
)"};
  Json expected_resp_body{R"(
    {
      "status":502,
      "title":"fc-fail-nsmf",
      "detail":"fc-fail-detail",
      "cause":"FC_FAIL"
    }
  )"_json};
  runTest(request_headers, response_headers, req_body, "",
          {{"x-modify-hdr", "http://nrf2.mcc123.mnc456.ericsson.se:30982/some/path"},
           {"x-cluster", "nrf_pool"}},
          {{":status", "200"}},
          {{"hnrf-uri", "http://nrf1.mcc123.mnc456.ericsson.se:30982/some/path"}}, nullptr,
          nullptr);
  // body is modified but identical!!
  EXPECT_EQ(1UL,
            test_server_
                ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.nrf.s5e.nsmf_pduinit."
                          "o4n.external.th_fqdn_mapping_req_demap_success_total")
                ->value());
}

// Test bootstrapping and oauth2 NRF services with the new support for deployment
// specific strings

TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToIntMisc3) {
  auto config_bootstrap_service_case = makeConfigExternal(
      config_eric_proxy_base, service_case_bootstrap_oauth, service_case_bootstrap_oauth);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_bootstrap_service_case);
  config_helper_.addFilter(config_header_to_metadata);

  // Agnostic of index in some-id-xxx
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/some/api/root/bootstrapping/some/fixed/resource"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-modify-hdr", "http://fakenrf2.mcc123.mnc456.ericsson.se:30982/some/path"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"},
                                                   {"server", "secret.internal.fqdn.com"},
                                                   {"x-modify-resp", "x-modify-orig-val"},
                                                   {"via", "location"}};
  runTest(request_headers, response_headers, "", "",
          {{"x-cluster", "nrf_pool"}, {"x-svc-ctx-hdr", "bootstrapping-service"}},
          {{":status", "200"}}, {{}}, nullptr, nullptr);
}

TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ExtToIntMisc4) {
  auto config_bootstrap_service_case = makeConfigExternal(
      config_eric_proxy_base, service_case_bootstrap_oauth, service_case_bootstrap_oauth);
  // ENVOY_LOG(debug,config_smf_udm_service_case);
  config_helper_.addFilter(config_bootstrap_service_case);
  config_helper_.addFilter(config_header_to_metadata);

  // Agnostic of index in some-id-xxx
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/some/api/root/oauth2/some/fixed/resource"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-modify-hdr", "http://fakenrf2.mcc123.mnc456.ericsson.se:30982/some/path"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"},
                                                   {"server", "secret.internal.fqdn.com"},
                                                   {"x-modify-resp", "x-modify-orig-val"},
                                                   {"via", "location"}};
  runTest(request_headers, response_headers, "", "",
          {{"x-cluster", "nrf_pool"}, {"x-svc-ctx-hdr", "oauth2-service"}}, {{":status", "200"}},
          {{}}, nullptr, nullptr, false);
}

// //-------------- Begin Test Nnrf_NFDiscovery -> NFDiscover ---------------

// // Name: NfDiscNoThRp2Smf
// // Description: NF-Discovery request for “nftype=SMF" from RP1 where
// // topology-hiding FQDN Mapping is not configured for the roaming partner RP1
// // Expected Result: The NF-Discovery request is forwarded by the P-SEPP without modification and
// the
// // response is not modified either
// TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, NfDiscNoFqdnMappingRp1Smf) {
//   //GTEST_SKIP();
//   auto config_th_ip_hiding_nf_discovery = makeConfigExternal(config_eric_proxy_base,
//                                                       "", "");
//                                                       // config_test_rp_th);
//   config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
//   config_helper_.addFilter(config_header_to_metadata);

//   HttpIntegrationTest::initialize();

//   Http::TestRequestHeaderMapImpl request_headers{
//       {":method", "GET"},
//       {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
//       {":authority", "sepp.own_plmn.com"},
//       {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
//       {"x-modify-hdr","fakenrf1.mcc123.mnc456.ericsson.se"},
//       {"x-eric-sepp-rp-name", "rp_2"},
//       {"x-eric-sepp-test-san", "rp_B.ext_plmn.com"}};

//   codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
//   IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
//   waitForNextUpstreamRequest(0);

//   Http::TestResponseHeaderMapImpl response_headers{
//       {":status", "200"},
//       // {"content-length", std::to_string(nf_disc_resp_body.length())},
//       // {"content-type", "application/json"},
//       {"server", "secret.internal.fqdn.com"},
//       {"via", "location"}};

//   // Send response
//   upstream_request_->encodeHeaders(response_headers, true);
//   // upstream_request_->complete();
//   // Buffer::OwnedImpl response_data(nf_disc_resp_body);
//   // upstream_request_->encodeData(response_data, true);
//   ASSERT_TRUE(response->waitForEndStream());

//   // Verify upstream request
//   // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
//   // EXPECT_THAT(upstream_request_->headers(),
//   //             Http::HeaderValueOf("x-modify-hdr", "nrf1.mcc123.mnc456.ericsson.se"));
//   // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
//   // EXPECT_THAT(upstream_request_->headers(),
//   //             Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"));

//   // Verify downstream response
//   // Response body should not be modified
//   // EXPECT_EQ("200", response->headers().getStatusValue());
//   // EXPECT_EQ("application/json", response->headers().getContentTypeValue());
//   // EXPECT_THAT(response->headers(),
//   //             Http::HeaderValueOf("content-length",
//   std::to_string(response->body().length()))); Json expected_body =
//   Json::parse(nf_disc_resp_body);
//   // EXPECT_EQ(expected_body, Json::parse(response->body()));

//   // "server" and "via" headers should not be modified
//   // EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
//   // EXPECT_THAT(response->headers(), Http::HeaderValueOf("via", "location"));

//   codec_client_->close();
// }

// // Name: NfDiscFqdnMappingThRp2
// // Description: NF-Discovery request from RP2 where
// // topology-hiding FQDN Mapping is configured for the roaming partner RP2
// // Expected Result: The NF-Discovery request is forwarded by the P-SEPP with mapped fqdns and the
// //    fqdns to be mapped are in the request headers:
// //                       3gpp-Sbi-target-apiRoot, some-other-header-v1
// //    and in the "fictive" query-parameter: target-nrf-fqdn-2, target-nrf-fqdn-3
// // response is  modified as well
// TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, NfDiscFqdnMappingRp2) {
//   //GTEST_SKIP();
//   config_helper_.addFilter(config_eric_proxy_base);
//   config_helper_.addFilter(config_header_to_metadata);

//   HttpIntegrationTest::initialize();

//   Http::TestRequestHeaderMapImpl request_headers{
//       {":method", "GET"},
//       {":path",
//       "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&target-nrf-fqdn-2=nrf2_ext.plmnb.com&target-nrf-fqdn-3=nrf3_ext.plmnc.com"},
//       {":authority", "sepp.own_plmn.com"},
//       {"3gpp-Sbi-target-apiRoot", "nrf1_ext.plmna.com"},
//       {"x-eric-sepp-rp-name", "rp_2"},
//       {"some-other-header-v1", "nrf3_ext.plmnc.com"},
//       {"x-eric-sepp-test-san", "rp_B.ext_plmn.com"}};

//   codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
//   IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
//   waitForNextUpstreamRequest(0);

//   Http::TestResponseHeaderMapImpl response_headers{
//       {":status", "200"},
//       {"content-length", std::to_string(nf_disc_resp_body.length())},
//       {"content-type", "application/json"},
//       {"server", "secret.internal.fqdn.com"},
//       {"via", "location"}};

//   // Send response
//   upstream_request_->encodeHeaders(response_headers, false);
//   Buffer::OwnedImpl response_data(nf_disc_resp_body);
//   upstream_request_->encodeData(response_data, true);
//   ASSERT_TRUE(response->waitForEndStream());

//   // Verify upstream request
//   EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
//   EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
//   EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("some-other-header-v1",
//   "nrf3_int.hplmn.de"));

//   EXPECT_THAT(upstream_request_->headers(),
//               Http::HeaderValueOf(":path",
//               "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&target-nrf-fqdn-2=nrf2_int.hplmn.de&target-nrf-fqdn-3=nrf3_int.hplmn.de"));

//   // Verify downstream response
//   // Response body should not be modified
//   EXPECT_EQ("200", response->headers().getStatusValue());
//   EXPECT_EQ("application/json", response->headers().getContentTypeValue());
//   EXPECT_THAT(response->headers(),
//               Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
//   Json expected_body = Json::parse(nf_disc_resp_body);
//   EXPECT_EQ(expected_body, Json::parse(response->body()));

//   // "server" and "via" headers should be removed
//   EXPECT_EQ(response->headers().get(Http::LowerCaseString("server")).size(), 0);
//   EXPECT_EQ(response->headers().get(Http::LowerCaseString("via")).size(), 0);

//   for (const auto& c : test_server_->counters()) {
//     if (!absl::StrContains(c->name(), "t8e")) {
//       continue;
//     }
//     // The counter should not be initialized at all!
//     EXPECT_STREQ("", c->name().c_str());
//   }
//   codec_client_->close();
// }

// // Name: ReqBodyFqdnMappingThRp2
// // Description: NF-Discovery request from RP2 where
// // topology-hiding FQDN Mapping is configured for the roaming partner RP2
// // Expected Result: The NF-Discovery request is forwarded by the P-SEPP with mapped fqdns and the
// //    fqdns to be mapped are in the request body:
// //                       3gpp-Sbi-target-apiRoot, some-other-header-v1
// //    and in the "fictive" query-parameter: target-nrf-fqdn-2, target-nrf-fqdn-3
// // response is  modified as well
// TEST_P(EricProxyFilterSeppThNrfFqdnMappingTest, ReqBodyFqdnMappingThRp2) {
//   //GTEST_SKIP();
//   config_helper_.addFilter(config_eric_proxy_base);
//   config_helper_.addFilter(config_header_to_metadata);

//   HttpIntegrationTest::initialize();

//   Http::TestRequestHeaderMapImpl request_headers{
//       {":method", "POST"},
//       {":path", "/some-api/v2/nf-instances?target-nf-type=SMF"},
//       {":authority", "sepp.own_plmn.com"},
//       {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
//       {"content-type", "application/json"},
//       {"content-length", std::to_string(some_api_req_body_nf_profile.length())},
//       {"x-eric-sepp-rp-name", "rp_2"},
//       {"x-eric-sepp-test-san", "rp_B.ext_plmn.com"}};

//   codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
//   IntegrationStreamDecoderPtr response =
//       codec_client_->makeRequestWithBody(request_headers, some_api_req_body_nf_profile);
//   waitForNextUpstreamRequest(0);

//   Http::TestResponseHeaderMapImpl response_headers{
//       {":status", "200"},
//       {"content-length", std::to_string(nf_disc_resp_body.length())},
//       {"content-type", "application/json"},
//       {"server", "secret.internal.fqdn.com"},
//       {"via", "location"}};

//   // Send response
//   upstream_request_->encodeHeaders(response_headers, false);
//   Buffer::OwnedImpl response_data(nf_disc_resp_body);
//   upstream_request_->encodeData(response_data, true);
//   ASSERT_TRUE(response->waitForEndStream());

//   // Verify upstream request
//   EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
//   EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));

//   EXPECT_THAT(upstream_request_->headers(),
//               Http::HeaderValueOf(":path", "/some-api/v2/nf-instances?target-nf-type=SMF"));

//   // verify body modifications
//   EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length",
//   std::to_string(upstream_request_->body().length())));

//   auto json_pointer = "/nfProfile/fqdn"_json_pointer;
//   std::string expected_value = "nrf.own_plmn.com";
//   std::string actual_value = Json::parse(upstream_request_->body().toString())[json_pointer];
//   EXPECT_EQ(actual_value, expected_value);

//   // Verify downstream response
//   // Response body should not be modified
//   EXPECT_EQ("200", response->headers().getStatusValue());
//   EXPECT_EQ("application/json", response->headers().getContentTypeValue());
//   EXPECT_THAT(response->headers(),
//               Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
//   Json expected_body = Json::parse(nf_disc_resp_body);
//   EXPECT_EQ(expected_body, Json::parse(response->body()));

//   // "server" and "via" headers should be removed
//   EXPECT_EQ(response->headers().get(Http::LowerCaseString("server")).size(), 0);
//   EXPECT_EQ(response->headers().get(Http::LowerCaseString("via")).size(), 0);

//   for (const auto& c : test_server_->counters()) {
//     if (!absl::StrContains(c->name(), "t8e")) {
//       continue;
//     }
//     // The counter should not be initialized at all!
//     EXPECT_STREQ("", c->name().c_str());
//   }
//   codec_client_->close();
// }

//----- End Test Nnrf_NFManagement -> NFStatusNotify (profileChanges) ----

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
