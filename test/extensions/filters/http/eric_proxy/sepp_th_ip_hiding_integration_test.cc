#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "base_integration_test.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"
#include "include/nlohmann/json.hpp"
#include <cstddef>
#include <ostream>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterSeppThIpHidingTest
    : public EricProxyIntegrationTestBase,
      public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterSeppThIpHidingTest()
      : EricProxyIntegrationTestBase(Http::CodecClient::Type::HTTP1, GetParam(),
                                     EricProxyFilterSeppThIpHidingTest::ericProxyHttpBaseConfig()) {
    setUpstreamCount(1);
  }
  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

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

  //------------------------------------------------------------------------
  // Configuration to test TH IP hiding NF Discovery
  const std::string config_th_ip_hiding_nf_discovery{R"EOF(
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
              rp_1: default_routing
              rp_2: default_routing
            default_fc_for_rp_not_found: default_routing
  rp_name_table : rp_san_to_name
  key_value_tables:
    - name: rp_san_to_name
      entries:
        - key: rp_A.ext_plmn.com
          value: rp_1
        - key: rp_B.ext_plmn.com
          value: rp_2
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: nrf_pool
        condition:
          op_and:
            arg1:
              op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'nrf.own_plmn.com'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: nrf_pool
            routing_behaviour: ROUND_ROBIN
  roaming_partners:
    - name: rp_1
      pool_name: rp1_pool
      topology_hiding:
        ip_hiding:
          ip_hiding_per_target_nf_type:
            SMF:
              response_action:
                respond_with_error:
                  status: 500
                  title: fqdn missing in NF profile
            AMF:
              response_action:
                forward: true
            PCF:
              response_action:
                drop: true
            CHF:
              response_action:
                apply_ip_hiding: true
            AUSF:
              response_action:
                apply_ip_hiding: true
    - name: rp_2
      pool_name: rp2_pool
)EOF"};

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
        ip_hiding:
          ip_hiding_per_target_nf_type:
            SMF:
              request_action:
                respond_with_error:
                  status: 400
                  title: fqdn missing in NF profile
            AMF:
              request_action:
                forward: true
            PCF:
              request_action:
                drop: true
            CHF:
              request_action:
                apply_ip_hiding: true              
          ipv4_subnet_per_target_nf_type:
            SMF:
              subnet_list:
                - 10.0.0.0/24
                - 20.0.0.0/24
            AMF:
              subnet_list:
                - 30.0.0.0/24
                - 40.0.0.0/24
          ipv6_subnet_per_target_nf_type:
            SMF:
              subnet_list:
                - 1000:aaaa:aaaa:aaaa::/64
                - 2000:aaaa:aaaa:aaaa::/64
            AMF:
              subnet_list:
                - 3000:aaaa:aaaa:aaaa::/64
                - 4000:aaaa:aaaa:aaaa::/64
    - name: rp_2
      pool_name: rp2_pool
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

  // NF Discovery response body (NF Instances) with NF Service List
  const std::string nf_disc_resp_body_nf_service_list{R"(
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
      "nfServiceList": {
        "3ec8ac0b-265e-4165-86e9-e0735e6ce100": {
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
      }
    },
    {
      "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce101",
      "nfInstanceName": "nfInstanceName_2",
      "nfType": "AUSF",
      "fqdn": "FQDN_1_0.example1.com",
      "nfServiceList": {
        "4ec8ac0b-265e-4165-86e9-e0735e6ce100": {
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
        "5ec8ac0b-265e-4165-86e9-e0735e6ce100": {
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
      }
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

  // NF Status Notify request body (NF Profile) with NF Service List
  const std::string nf_status_notify_req_body_nf_profile_nf_service_list{R"(
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
    "nfServiceList": {
      "4ec8ac0b-265e-4165-86e9-e0735e6ce100": {
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
      "5ec8ac0b-265e-4165-86e9-e0735e6ce100": {
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
    }
  }
}
)"};

  //------------------------------------------------------------------------
  // NF Status Notify request body (Profile Changes)
  // (NotificationData -> profileChanges)
  const std::string nf_status_notify_req_body_profile_changes{R"(
{
  "event": "NF_PROFILE_CHANGED",
  "nfInstanceUri": "nfInstanceUri_1",
  "profileChanges": [
    {
      "op": "REPLACE",
      "path": "/nfProfile/fqdn",
      "origValue": "FQDN_1.example.com",
      "newValue": "FQDN_2.example.com"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/ipv4Addresses",
      "origValue": ["10.0.0.1","10.0.0.2"],
      "newValue": ["20.0.0.1","20.0.0.2"]
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/ipv6Addresses/0",
      "origValue": "1000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0001",
      "newValue": "2000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0001"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/ipv6Addresses/1",
      "origValue": "1000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0002",
      "newValue": "2000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0002"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/nfServices/0/ipEndPoints/0/ipv4Address",
      "origValue": "10.0.0.3",
      "newValue": "20.0.0.3"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/nfServices/0/ipEndPoints/0/ipv6Address",
      "origValue": "1000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0003",
      "newValue": "2000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0003"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/nfServices/1/ipEndPoints/0/ipv4Address",
      "origValue": "10.0.0.4",
      "newValue": "20.0.0.4"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/nfServices/1/ipEndPoints/0/ipv6Address",
      "origValue": "1000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0004",
      "newValue": "2000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0004"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/nfServices/1/ipEndPoints/1/ipv4Address",
      "origValue": "10.0.0.5",
      "newValue": "20.0.0.5"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/nfServices/1/ipEndPoints/1/ipv6Address",
      "origValue": "1000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0005",
      "newValue": "2000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0005"
    }
  ]
}
)"};

  // NF Status Notify request body (Profile Changes) with NF Service List
  const std::string nf_status_notify_req_body_profile_changes_nf_service_list{R"(
{
  "event": "NF_PROFILE_CHANGED",
  "nfInstanceUri": "nfInstanceUri_1",
  "profileChanges": [
    {
      "op": "REPLACE",
      "path": "/nfProfile/fqdn",
      "origValue": "FQDN_1.example.com",
      "newValue": "FQDN_2.example.com"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/ipv4Addresses",
      "origValue": ["10.0.0.1","10.0.0.2"],
      "newValue": ["20.0.0.1","20.0.0.2"]
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/ipv6Addresses/0",
      "origValue": "1000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0001",
      "newValue": "2000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0001"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/ipv6Addresses/1",
      "origValue": "1000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0002",
      "newValue": "2000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0002"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/nfServiceList/4ec8ac0b-265e-4165-86e9-e0735e6ce100/ipEndPoints/0/ipv4Address",
      "origValue": "10.0.0.3",
      "newValue": "20.0.0.3"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/nfServiceList/4ec8ac0b-265e-4165-86e9-e0735e6ce100/ipEndPoints/0/ipv6Address",
      "origValue": "1000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0003",
      "newValue": "2000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0003"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/nfServiceList/5ec8ac0b-265e-4165-86e9-e0735e6ce100/ipEndPoints/0/ipv4Address",
      "origValue": "10.0.0.4",
      "newValue": "20.0.0.4"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/nfServiceList/5ec8ac0b-265e-4165-86e9-e0735e6ce100/ipEndPoints/0/ipv6Address",
      "origValue": "1000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0004",
      "newValue": "2000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0004"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/nfServiceList/5ec8ac0b-265e-4165-86e9-e0735e6ce100/ipEndPoints/1/ipv4Address",
      "origValue": "10.0.0.5",
      "newValue": "20.0.0.5"
    },
    {
      "op": "REPLACE",
      "path": "/nfProfile/nfServiceList/5ec8ac0b-265e-4165-86e9-e0735e6ce100/ipEndPoints/1/ipv6Address",
      "origValue": "1000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0005",
      "newValue": "2000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0005"
    }
  ]
}
)"};

  // Common function for NF Discovery local reply tests with different scenarios
  void testLocalReplyNfDiscovery(
    const std::string& response_body,
    const Json& expected_body
  ) {
    config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
    config_helper_.addFilter(config_header_to_metadata);

    HttpIntegrationTest::initialize();

    Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}
    };

    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
    waitForNextUpstreamRequest(0);

    Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(response_body.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}
    };

    // Send response
    upstream_request_->encodeHeaders(response_headers, false);
    Buffer::OwnedImpl response_data(response_body);
    upstream_request_->encodeData(response_data, true);
    ASSERT_TRUE(response->waitForEndStream());

    // Verify upstream request
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"));

    // Verify downstream response
    EXPECT_EQ("500", response->headers().getStatusValue());
    EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
    EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
    EXPECT_EQ(expected_body, Json::parse(response->body()));

    // "server" header should be set to "envoy" since
    // the reply is coming from Envoy
    EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "envoy"));
    // "via" header should be removed
    EXPECT_EQ(response->headers().get(Http::LowerCaseString("via")).size(), 0);

    for (const auto& c : test_server_->counters()) {
      if (!absl::StrContains(c->name(), "t8e")) {
        continue;
      }
      // The counter should not be initialized at all!
      EXPECT_STREQ("", c->name().c_str());
    }

    codec_client_->close();
  }

  // Common function for NF Status Notify local reply tests with different scenarios
  void testLocalReplyNfStatusNotify(
    const std::string& request_body,
    const Json& expected_body
  ) { 
    config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

    HttpIntegrationTest::initialize();

    Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(request_body.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}
    };

    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, request_body);
    
    // Wait for the response and close the fake upstream connection
    ASSERT_TRUE(response->waitForEndStream());

    // Verify downstream response
    EXPECT_EQ("400", response->headers().getStatusValue());
    EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
    EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
    EXPECT_EQ(expected_body, Json::parse(response->body()));

    // "server" header should be set to "envoy" since
    // the reply is coming from Envoy
    EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "envoy"));

    for (const auto& c : test_server_->counters()) {
      if (!absl::StrContains(c->name(), "t8e")) {
        continue;
      }
      // The counter should not be initialized at all!
      EXPECT_STREQ("", c->name().c_str());
    }

    codec_client_->close(); 
  }
};

//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------
INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterSeppThIpHidingTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

//-------------- Begin Test Nnrf_NFDiscovery -> NFDiscover ---------------

// Name: NfDiscNoThRp2Smf
// Description: NF-Discovery request for “nftype=SMF" from RP2 where
// topology-hiding is not configured for the roaming partner RP2
// Expected Result: The NF-Discovery request is forwarded by the P-SEPP without modification and the
// response is not modified either
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscNoThRp2Smf) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_2"},
      {"x-eric-sepp-test-san", "rp_B.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"));

  // Verify downstream response
  // Response body should not be modified
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  Json expected_body = Json::parse(nf_disc_resp_body);
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("via", "location"));

  for (const auto& c : test_server_->counters()) {
    if (!absl::StrContains(c->name(), "t8e")) {
      continue;
    }
    // The counter should not be initialized at all!
    EXPECT_STREQ("", c->name().c_str());
  }

  codec_client_->close();
}

// Name: NfDiscNoThIpHidingRp1Udm
// Description: NF-Discovery request for “nftype=UDM” from RP1 where topology-hiding
// IP hiding is configured for the roaming partner RP1 but not for the NF type UDM
// Expected Result: The NF-Discovery request is forwarded by the P-SEPP without modification and the
// response is not modified either
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscNoThIpHidingRp1Udm) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=UDM"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=UDM"));

  // Verify downstream response
  // Response body should not be modified
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  Json expected_body = Json::parse(nf_disc_resp_body);
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("via", "location"));

  for (const auto& c : test_server_->counters()) {
    if (!absl::StrContains(c->name(), "t8e")) {
      continue;
    }
    // The counter should not be initialized at all!
    EXPECT_STREQ("", c->name().c_str());
  }

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Smf
// Description: NF-Discovery request for “nftype=SMF” from RP1. Non-multipart version.
// Expected Result:
// - P-SEPP forwards the request
// - IP addresses of NF Instances and their corresponding
//   NF Services are deleted in the response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"));

  // Verify downstream response
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("content-length", std::to_string(response->body().length())));

  Json expected_body = Json::parse(nf_disc_resp_body);
  const auto num_nf_instances = expected_body.at("nfInstances").size();

  for (unsigned long nf_inst_idx = 0; nf_inst_idx < num_nf_instances; nf_inst_idx++) {
    expected_body.at("nfInstances").at(nf_inst_idx).erase("ipv4Addresses");
    expected_body.at("nfInstances").at(nf_inst_idx).erase("ipv6Addresses");
    const auto num_nf_services =
        expected_body.at("nfInstances").at(nf_inst_idx).at("nfServices").size();

    for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
      const auto num_ip_endpoints = expected_body.at("nfInstances")
                                        .at(nf_inst_idx)
                                        .at("nfServices")
                                        .at(nf_svc_idx)
                                        .at("ipEndPoints")
                                        .size();

      for (unsigned long ip_ep_idx = 0; ip_ep_idx < num_ip_endpoints; ip_ep_idx++) {
        expected_body.at("nfInstances")
            .at(nf_inst_idx)
            .at("nfServices")
            .at(nf_svc_idx)
            .at("ipEndPoints")
            .at(ip_ep_idx)
            .erase("ipv4Address");
        expected_body.at("nfInstances")
            .at(nf_inst_idx)
            .at("nfServices")
            .at(nf_svc_idx)
            .at("ipEndPoints")
            .at(ip_ep_idx)
            .erase("ipv6Address");
      }
    }
  }

  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("via", "location"));

  for (const auto& c : test_server_->counters()) {
    if (!absl::StrContains(c->name(), "t8e")) {
      continue;
    }
    std::cout<<"Counter: " << c->name() << ": " << c->value() << std::endl;
  }

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_discovery.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}


// Name: NfDiscThIpHidingRp1SmfMultipart
// Description: NF-Discovery request for “nftype=SMF” from RP1, version with a multipart
// body in the response
// Expected Result:
// - P-SEPP forwards the request
// - IP addresses of NF Instances and their corresponding
//   NF Services are deleted in the response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1SmfMultipart) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  // Send response
  const std::string content_type{"multipart/related; boundary=boundary"};
  const std::string body_prefix{"This is the preamble"
                                "\r\n--boundary\r\nContent-type: application/json\r\n\r\n"};
  std::string body_suffix =
      "\r\n--boundary\r\nContent-type: text/plain\r\n\r\nThis is a text/binary ";
  body_suffix.push_back('\0'); // necessary because otherwise the \0 terminates the string
  body_suffix.append("\002body part\r\n--boundary--\r\n..and an epilogue");
  std::string nf_disc_resp_body_mp = body_prefix + nf_disc_resp_body + body_suffix;

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body_mp.length())},
      {"content-type", content_type},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};
  
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body_mp);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"));

  // Verify downstream response
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ(content_type, response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("content-length", std::to_string(response->body().length())));

  Json expected_body = Json::parse(nf_disc_resp_body);
  const auto num_nf_instances = expected_body.at("nfInstances").size();

  for (unsigned long nf_inst_idx = 0; nf_inst_idx < num_nf_instances; nf_inst_idx++) {
    expected_body.at("nfInstances").at(nf_inst_idx).erase("ipv4Addresses");
    expected_body.at("nfInstances").at(nf_inst_idx).erase("ipv6Addresses");
    const auto num_nf_services =
        expected_body.at("nfInstances").at(nf_inst_idx).at("nfServices").size();

    for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
      const auto num_ip_endpoints = expected_body.at("nfInstances")
                                        .at(nf_inst_idx)
                                        .at("nfServices")
                                        .at(nf_svc_idx)
                                        .at("ipEndPoints")
                                        .size();

      for (unsigned long ip_ep_idx = 0; ip_ep_idx < num_ip_endpoints; ip_ep_idx++) {
        expected_body.at("nfInstances")
            .at(nf_inst_idx)
            .at("nfServices")
            .at(nf_svc_idx)
            .at("ipEndPoints")
            .at(ip_ep_idx)
            .erase("ipv4Address");
        expected_body.at("nfInstances")
            .at(nf_inst_idx)
            .at("nfServices")
            .at(nf_svc_idx)
            .at("ipEndPoints")
            .at(ip_ep_idx)
            .erase("ipv6Address");
      }
    }
  }

  Body resp_body;
  resp_body.setBodyFromString(response->body(), content_type);
  EXPECT_EQ(expected_body, *(resp_body.getBodyAsJson()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("via", "location"));

  for (const auto& c : test_server_->counters()) {
    if (!absl::StrContains(c->name(), "t8e")) {
      continue;
    }
    std::cout<<"Counter: " << c->name() << ": " << c->value() << std::endl;
  }

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_discovery.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}


TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1SmfTestCounters) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "SMF";
  request_body.at("nfProfile").erase("nfServices");
  std::string nf_status_notify_req_body_no_nf_services = request_body.dump();

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify; apiVersion=2"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_no_nf_services.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  {
    IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(
        request_headers, nf_status_notify_req_body_no_nf_services);
    waitForNextUpstreamRequest(0);
    upstream_request_->encodeHeaders(response_headers, true);
    ASSERT_TRUE(response->waitForEndStream());
    EXPECT_EQ("204", response->headers().getStatusValue());

    EXPECT_EQ(1UL, test_server_
                       ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_"
                                 "status_notify.ip_address_hiding_applied_success")
                       ->value());
  }
  {
    IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(
        request_headers, nf_status_notify_req_body_no_nf_services);
    waitForNextUpstreamRequest(0);
    upstream_request_->encodeHeaders(response_headers, true);
    ASSERT_TRUE(response->waitForEndStream());
    EXPECT_EQ("204", response->headers().getStatusValue());
  }
  {
    IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(
        request_headers, nf_status_notify_req_body_no_nf_services);
    waitForNextUpstreamRequest(0);
    upstream_request_->encodeHeaders(response_headers, true);
    ASSERT_TRUE(response->waitForEndStream());
    EXPECT_EQ("204", response->headers().getStatusValue());
  }

  EXPECT_EQ(3UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_"
                               "status_notify.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1SmfStoredSearchDND_39017
// Description: NF-Discovery request for “nftype=SMF” from RP1
// the path includes "/search/{searchId}" to query for a stored search 
// Expected Result:
// - P-SEPP forwards the request
// - IP addresses of NF Instances and their corresponding
//   NF Services are deleted in the response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1SmfStoredSearch_DND_39045){
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/searches/somesearchID/"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/searches/somesearchID/"));

  // Verify downstream response
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("content-length", std::to_string(response->body().length())));

  Json expected_body = Json::parse(nf_disc_resp_body);
  const auto num_nf_instances = expected_body.at("nfInstances").size();

  for (unsigned long nf_inst_idx = 0; nf_inst_idx < num_nf_instances; nf_inst_idx++) {
    expected_body.at("nfInstances").at(nf_inst_idx).erase("ipv4Addresses");
    expected_body.at("nfInstances").at(nf_inst_idx).erase("ipv6Addresses");
    const auto num_nf_services =
        expected_body.at("nfInstances").at(nf_inst_idx).at("nfServices").size();

    for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
      const auto num_ip_endpoints = expected_body.at("nfInstances")

                                        .at(nf_inst_idx)
                                        .at("nfServices")
                                        .at(nf_svc_idx)
                                        .at("ipEndPoints")
                                        .size();

      for (unsigned long ip_ep_idx = 0; ip_ep_idx < num_ip_endpoints; ip_ep_idx++) {
        expected_body.at("nfInstances")
            .at(nf_inst_idx)
            .at("nfServices")
            .at(nf_svc_idx)
            .at("ipEndPoints")
            .at(ip_ep_idx)
            .erase("ipv4Address");
        expected_body.at("nfInstances")
            .at(nf_inst_idx)
            .at("nfServices")
            .at(nf_svc_idx)
            .at("ipEndPoints")
            .at(ip_ep_idx)
            .erase("ipv6Address");
      }
    }
  }

  EXPECT_EQ(expected_body, Json::parse(response->body()));
  // FAKE TO RUN ALL TESTS
  // expected_body = Json::parse(nf_disc_resp_body_DND_39045);
  // EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("via", "location"));


   for (const auto& c : test_server_->counters()) {
     if (!absl::StrContains(c->name(), "t8e")) {
       continue;
     }
     std::cout<<"Counter: " << c->name() << ": " << c->value() << std::endl;
   }

   EXPECT_EQ(1UL, test_server_
                      ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.AUSF.t2e.nf_discovery.ip_address_hiding_applied_success")
                      ->value());

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Smf_NfServiceList_DND43947
// Description: NF-Discovery request for “nftype=SMF” from RP1 and
// response have NF Service List in NF Instances
// Expected Result:
// - P-SEPP forwards the request
// - IP addresses of NF Instances and their corresponding
//   NF Service List are deleted in the response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf_NfServiceList_DND43947) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body_nf_service_list.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body_nf_service_list);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"));

  // Verify downstream response
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("content-length", std::to_string(response->body().length())));

  Json expected_body = Json::parse(nf_disc_resp_body_nf_service_list);
  for (auto& nf_inst : expected_body.at("nfInstances")) {
    nf_inst.erase("ipv4Addresses");
    nf_inst.erase("ipv6Addresses");
    for (auto& nf_svc : nf_inst.at("nfServiceList").items()) {
      for (auto& ip_ep : nf_svc.value().at("ipEndPoints")) {
        ip_ep.erase("ipv4Address");
        ip_ep.erase("ipv6Address");
      }
    }
  }

  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("via", "location"));

  for (const auto& c : test_server_->counters()) {
    if (!absl::StrContains(c->name(), "t8e")) {
      continue;
    }
    std::cout<<"Counter: " << c->name() << ": " << c->value() << std::endl;
  }

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_discovery.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Smf_NfServicesNfServiceList_DND43947
// Description: NF-Discovery request for “nftype=SMF” from RP1 and
// response have both NF Services and NF Service List in NF
// Instances where there is FQDN in only NF Service List
// Expected Result:
// - P-SEPP forwards the request
// - Error case is checked only in NF Service List
// - IP addresses of NF Instances, their corresponding NF Services
//   and NF Service List are deleted in the response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf_NfServicesNfServiceList_DND43947) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Json nf_services_body = Json::parse(nf_disc_resp_body);
  Json response_body = Json::parse(nf_disc_resp_body_nf_service_list);
  // Create body with nfServices and nfServiceList together
  for (uint32_t nf_inst_idx = 0; nf_inst_idx < response_body.at("nfInstances").size(); nf_inst_idx++) {
    response_body.at("nfInstances").at(nf_inst_idx)["nfServices"] = 
      nf_services_body.at("nfInstances").at(nf_inst_idx).at("nfServices");
  }
  // Keep FQDN only in nfServiceList
  for (auto& nf_inst : response_body.at("nfInstances")) {
    nf_inst.erase("fqdn");
    for (auto& nf_svc : nf_inst.at("nfServices")) {
      nf_svc.erase("fqdn");
    }
  }
  std::string nf_disc_resp_body_mixed = response_body.dump();

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body_mixed.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body_mixed);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"));

  // Verify downstream response
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("content-length", std::to_string(response->body().length())));

  Json expected_body = Json::parse(nf_disc_resp_body_mixed);
  for (auto& nf_inst : expected_body.at("nfInstances")) {
    nf_inst.erase("ipv4Addresses");
    nf_inst.erase("ipv6Addresses");
    for (auto& nf_svc : nf_inst.at("nfServiceList").items()) {
      for (auto& ip_ep : nf_svc.value().at("ipEndPoints")) {
        ip_ep.erase("ipv4Address");
        ip_ep.erase("ipv6Address");
      }
    }
    for (auto& nf_svc : nf_inst.at("nfServices")) {
      for (auto& ip_ep : nf_svc.at("ipEndPoints")) {
        ip_ep.erase("ipv4Address");
        ip_ep.erase("ipv6Address");
      }
    }
  }

  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("via", "location"));

  for (const auto& c : test_server_->counters()) {
    if (!absl::StrContains(c->name(), "t8e")) {
      continue;
    }
    std::cout<<"Counter: " << c->name() << ": " << c->value() << std::endl;
  }

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_discovery.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Smf_NoNfServicesNfServiceList
// Description: NF-Discovery request for “nftype=SMF” from RP1 and
// response have neither NF Services nor NF Service List in
// NF Instances
// Expected Result:
// - P-SEPP forwards the request
// - IP addresses of NF Instances are deleted in the response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf_NoNfServicesNfServiceList) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Json response_body = Json::parse(nf_disc_resp_body);

  for (auto & nf_inst_idx : response_body.at("nfInstances")) {
    nf_inst_idx.erase("nfServices");
  }

  std::string nf_disc_resp_body_no_nf_services = response_body.dump();

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body_no_nf_services.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body_no_nf_services);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"));

  // Verify downstream response
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("content-length", std::to_string(response->body().length())));

  Json expected_body = Json::parse(nf_disc_resp_body_no_nf_services);
  const auto num_nf_instances = expected_body.at("nfInstances").size();

  for (unsigned long nf_inst_idx = 0; nf_inst_idx < num_nf_instances; nf_inst_idx++) {
    expected_body.at("nfInstances").at(nf_inst_idx).erase("ipv4Addresses");
    expected_body.at("nfInstances").at(nf_inst_idx).erase("ipv6Addresses");
  }

  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("via", "location"));

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_"
                               "discovery.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Smf_FqdnOnlyOnNfProfile
// Description: NF-Discovery request for “nftype=SMF” from RP1
// where the response have fqdn only on NF Profile level
// Expected Result:
// - P-SEPP forwards the request
// - IP addresses of NF Instances and their corresponding
//   NF Services are deleted in the response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf_FqdnOnlyOnNfProfile) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Json response_body = Json::parse(nf_disc_resp_body);
  auto num_nf_instances = response_body.at("nfInstances").size();

  for (unsigned long nf_inst_idx = 0; nf_inst_idx < num_nf_instances; nf_inst_idx++) {
    const auto num_nf_services =
        response_body.at("nfInstances").at(nf_inst_idx).at("nfServices").size();

    for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
      response_body.at("nfInstances").at(nf_inst_idx).at("nfServices").at(nf_svc_idx).erase("fqdn");
    }
  }

  std::string nf_disc_resp_body_only_nf_profile_fqdn = response_body.dump();

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body_only_nf_profile_fqdn.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body_only_nf_profile_fqdn);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"));

  // Verify downstream response
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("content-length", std::to_string(response->body().length())));

  Json expected_body = Json::parse(nf_disc_resp_body_only_nf_profile_fqdn);
  num_nf_instances = expected_body.at("nfInstances").size();

  for (unsigned long nf_inst_idx = 0; nf_inst_idx < num_nf_instances; nf_inst_idx++) {
    expected_body.at("nfInstances").at(nf_inst_idx).erase("ipv4Addresses");
    expected_body.at("nfInstances").at(nf_inst_idx).erase("ipv6Addresses");
    const auto num_nf_services =
        expected_body.at("nfInstances").at(nf_inst_idx).at("nfServices").size();

    for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
      const auto num_ip_endpoints = expected_body.at("nfInstances")
                                        .at(nf_inst_idx)
                                        .at("nfServices")
                                        .at(nf_svc_idx)
                                        .at("ipEndPoints")
                                        .size();

      for (unsigned long ip_ep_idx = 0; ip_ep_idx < num_ip_endpoints; ip_ep_idx++) {
        expected_body.at("nfInstances")
            .at(nf_inst_idx)
            .at("nfServices")
            .at(nf_svc_idx)
            .at("ipEndPoints")
            .at(ip_ep_idx)
            .erase("ipv4Address");
        expected_body.at("nfInstances")
            .at(nf_inst_idx)
            .at("nfServices")
            .at(nf_svc_idx)
            .at("ipEndPoints")
            .at(ip_ep_idx)
            .erase("ipv6Address");
      }
    }
  }

  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("via", "location"));

  for (const auto& c : test_server_->counters()) {
    if (!absl::StrContains(c->name(), "t8e")) {
      continue;
    }
    std::cout<<"Counter: " << c->name() << ": " << c->value() << std::endl;
  }

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_discovery.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Amf_NoFqdnAnywhere_Forward
// Description: NF-Discovery request for “nftype=AMF” from RP1
// where the response does not have fqdn anywhere
// Expected Result:
// - P-SEPP forwards the request
// - P-SEPP forwards the NF discovery response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Amf_NoFqdnAnywhere_Forward) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Json response_body = Json::parse(nf_disc_resp_body);
  const auto num_nf_instances = response_body.at("nfInstances").size();

  for (unsigned long nf_inst_idx = 0; nf_inst_idx < num_nf_instances; nf_inst_idx++) {
    response_body.at("nfInstances").at(nf_inst_idx).erase("fqdn");
    const auto num_nf_services =
        response_body.at("nfInstances").at(nf_inst_idx).at("nfServices").size();

    for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
      response_body.at("nfInstances").at(nf_inst_idx).at("nfServices").at(nf_svc_idx).erase("fqdn");
    }
  }

  std::string nf_disc_resp_body_no_fqdn = response_body.dump();

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body_no_fqdn.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body_no_fqdn);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF"));

  // Verify downstream response
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_EQ(Json::parse(nf_disc_resp_body_no_fqdn), Json::parse(response->body()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("via", "location"));

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.AMF.t2e.nf_"
                               "discovery.ip_address_hiding_fqdn_missing")
                     ->value());
  EXPECT_EQ(nullptr,
            test_server_->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e."
                                  "AMF.t2e.nf_discovery.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Chf_NoFqdnAnywhere_ApplyIpHiding
// Description: NF-Discovery request for “nftype=CHF” from RP1
// where the response does not have fqdn anywhere
// Expected Result:
// - P-SEPP forwards the request
// - IP addresses of NF Instances and their corresponding
//   NF Services are deleted in the response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Chf_NoFqdnAnywhere_ApplyIpHiding) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=CHF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Json response_body = Json::parse(nf_disc_resp_body);
  auto num_nf_instances = response_body.at("nfInstances").size();

  for (unsigned long nf_inst_idx = 0; nf_inst_idx < num_nf_instances; nf_inst_idx++) {
    response_body.at("nfInstances").at(nf_inst_idx).erase("fqdn");
    const auto num_nf_services =
        response_body.at("nfInstances").at(nf_inst_idx).at("nfServices").size();

    for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
      response_body.at("nfInstances").at(nf_inst_idx).at("nfServices").at(nf_svc_idx).erase("fqdn");
    }
  }

  std::string nf_disc_resp_body_no_fqdn = response_body.dump();

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body_no_fqdn.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body_no_fqdn);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=CHF"));

  Json expected_body = Json::parse(nf_disc_resp_body_no_fqdn);
  num_nf_instances = expected_body.at("nfInstances").size();

  for (unsigned long nf_inst_idx = 0; nf_inst_idx < num_nf_instances; nf_inst_idx++) {
    expected_body.at("nfInstances").at(nf_inst_idx).erase("ipv4Addresses");
    expected_body.at("nfInstances").at(nf_inst_idx).erase("ipv6Addresses");
    const auto num_nf_services =
        expected_body.at("nfInstances").at(nf_inst_idx).at("nfServices").size();

    for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
      const auto num_ip_endpoints = expected_body.at("nfInstances")
                                        .at(nf_inst_idx)
                                        .at("nfServices")
                                        .at(nf_svc_idx)
                                        .at("ipEndPoints")
                                        .size();

      for (unsigned long ip_ep_idx = 0; ip_ep_idx < num_ip_endpoints; ip_ep_idx++) {
        expected_body.at("nfInstances")
            .at(nf_inst_idx)
            .at("nfServices")
            .at(nf_svc_idx)
            .at("ipEndPoints")
            .at(ip_ep_idx)
            .erase("ipv4Address");
        expected_body.at("nfInstances")
            .at(nf_inst_idx)
            .at("nfServices")
            .at(nf_svc_idx)
            .at("ipEndPoints")
            .at(ip_ep_idx)
            .erase("ipv6Address");
      }
    }
  }

  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // Verify downstream response
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ("application/json", response->headers().getContentTypeValue());
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("via", "location"));

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.CHF.t2e.nf_"
                               "discovery.ip_address_hiding_fqdn_missing")
                     ->value());
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.CHF.t2e.nf_"
                               "discovery.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Smf_NoFqdnAnywhere_RespondWithError
// Description: NF-Discovery request for “nftype=SMF” from RP1
// where the response does not have fqdn anywhere
// Expected Result:
// - P-SEPP forwards the request
// - P-SEPP responds with the configured error
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf_NoFqdnAnywhere_RespondWithError) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Json response_body = Json::parse(nf_disc_resp_body);
  auto num_nf_instances = response_body.at("nfInstances").size();

  for (unsigned long nf_inst_idx = 0; nf_inst_idx < num_nf_instances; nf_inst_idx++) {
    response_body.at("nfInstances").at(nf_inst_idx).erase("fqdn");
    const auto num_nf_services =
        response_body.at("nfInstances").at(nf_inst_idx).at("nfServices").size();

    for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
      response_body.at("nfInstances").at(nf_inst_idx).at("nfServices").at(nf_svc_idx).erase("fqdn");
    }
  }

  std::string nf_disc_resp_body_no_fqdn = response_body.dump();

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body_no_fqdn.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body_no_fqdn);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"));

  // Verify downstream response
  EXPECT_EQ("500", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ("{\"status\": 500, \"title\": \"fqdn missing in NF profile\"}", response->body());

  // "server" header should be set to "envoy" since
  // the reply is coming from Envoy
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "envoy"));
  // "via" header should be removed
  EXPECT_EQ(response->headers().get(Http::LowerCaseString("via")).size(), 0);

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_"
                               "discovery.ip_address_hiding_fqdn_missing")
                     ->value());
  EXPECT_EQ(nullptr,
            test_server_->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e."
                                  "SMF.t2e.nf_discovery.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Pcf_NoFqdnAnywhere_Drop
// Description: NF-Discovery request for “nftype=PCF” from RP1
// where the response does not have fqdn anywhere
// Expected Result:
// - P-SEPP forwards the request
// - P-SEPP drops the response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Pcf_NoFqdnAnywhere_Drop) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=PCF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Json response_body = Json::parse(nf_disc_resp_body);
  auto num_nf_instances = response_body.at("nfInstances").size();

  for (unsigned long nf_inst_idx = 0; nf_inst_idx < num_nf_instances; nf_inst_idx++) {
    response_body.at("nfInstances").at(nf_inst_idx).erase("fqdn");
    const auto num_nf_services =
        response_body.at("nfInstances").at(nf_inst_idx).at("nfServices").size();

    for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
      response_body.at("nfInstances").at(nf_inst_idx).at("nfServices").at(nf_svc_idx).erase("fqdn");
    }
  }

  std::string nf_disc_resp_body_no_fqdn = response_body.dump();

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body_no_fqdn.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body_no_fqdn);
  upstream_request_->encodeData(response_data, true);

  // Drops the response by resetting stream
  ASSERT_TRUE(response->waitForReset());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=PCF"));

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.PCF.t2e.nf_"
                               "discovery.ip_address_hiding_fqdn_missing")
                     ->value());

  EXPECT_EQ(nullptr,
            test_server_->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e."
                                  "PCF.t2e.nf_discovery.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Pcf_NoFqdnInOneInstance_Drop_DND_39546
// Description: NF-Discovery request for “nftype=PCF” from RP1
// where the response does not have fqdn in one of the instances
// Expected Result:
// - P-SEPP forwards the request
// - P-SEPP drops the response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Pcf_NoFqdnInOneInstance_Drop_DND_39546) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=PCF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Json response_body = Json::parse(nf_disc_resp_body);

  // remove all fqdns from instance 1
  unsigned long nf_inst_idx = 1; 

  response_body.at("nfInstances").at(nf_inst_idx).erase("fqdn");
  const auto num_nf_services =
      response_body.at("nfInstances").at(nf_inst_idx).at("nfServices").size();

  for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
    response_body.at("nfInstances").at(nf_inst_idx).at("nfServices").at(nf_svc_idx).erase("fqdn");
  }


  std::string nf_disc_resp_body_no_fqdn = response_body.dump();

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body_no_fqdn.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body_no_fqdn);
  upstream_request_->encodeData(response_data, true);

  // Drops the response by resetting stream
  ASSERT_TRUE(response->waitForReset());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=PCF"));

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.PCF.t2e.nf_"
                               "discovery.ip_address_hiding_fqdn_missing")
                     ->value());

  EXPECT_EQ(nullptr,
            test_server_->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e."
                                  "PCF.t2e.nf_discovery.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Pcf_FqdnOnlyOnFirstNfService_Drop_DND56645
// Description: NF-Discovery request for “nftype=PCF” from RP1
// where the response have fqdn everywhere for first NF
// Instance but have fqdn only in first NF Service for
// second NF Instance
// Expected Result:
// - P-SEPP forwards the request
// - P-SEPP drops the response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Pcf_FqdnOnlyOnFirstNfService_Drop_DND56645) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=PCF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Json response_body = Json::parse(nf_disc_resp_body);
  auto num_nf_instances = response_body.at("nfInstances").size();

  // FQDN is present for only first NF Service of second NF Instance
  for (unsigned long nf_inst_idx = 1; nf_inst_idx < num_nf_instances; nf_inst_idx++) {
    response_body.at("nfInstances").at(nf_inst_idx).erase("fqdn");
    const auto num_nf_services =
        response_body.at("nfInstances").at(nf_inst_idx).at("nfServices").size();

    for (unsigned long nf_svc_idx = 1; nf_svc_idx < num_nf_services; nf_svc_idx++) {
      response_body.at("nfInstances").at(nf_inst_idx).at("nfServices").at(nf_svc_idx).erase("fqdn");
    }
  }

  std::string nf_disc_resp_body_no_fqdn = response_body.dump();

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body_no_fqdn.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body_no_fqdn);
  upstream_request_->encodeData(response_data, true);

  // Drops the response by resetting stream
  ASSERT_TRUE(response->waitForReset());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=PCF"));

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.PCF.t2e.nf_"
                               "discovery.ip_address_hiding_fqdn_missing")
                     ->value());

  EXPECT_EQ(nullptr,
            test_server_->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e."
                                  "PCF.t2e.nf_discovery.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Pcf_NfServiceList_NoFqdnAnywhere_Drop_DND43947
// Description: NF-Discovery request for “nftype=PCF” from RP1
// where the response have NF Service List in NF Instances but
// does not have fqdn anywhere
// Expected Result:
// - P-SEPP forwards the request
// - P-SEPP drops the response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Pcf_NfServiceList_NoFqdnAnywhere_Drop_DND43947) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=PCF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Json response_body = Json::parse(nf_disc_resp_body_nf_service_list);
  for (auto& nf_inst : response_body.at("nfInstances")) {
    nf_inst.erase("fqdn");
    for (auto& nf_svc : nf_inst.at("nfServiceList").items()) {
      nf_svc.value().erase("fqdn");
    }
  }
  std::string nf_disc_resp_body_no_fqdn = response_body.dump();

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body_no_fqdn.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body_no_fqdn);
  upstream_request_->encodeData(response_data, true);

  // Drops the response by resetting stream
  ASSERT_TRUE(response->waitForReset());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=PCF"));

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.PCF.t2e.nf_"
                               "discovery.ip_address_hiding_fqdn_missing")
                     ->value());

  EXPECT_EQ(nullptr,
            test_server_->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e."
                                  "PCF.t2e.nf_discovery.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Pcf_NfServiceList_FqdnOnlyOnFirstNfService_Drop_DND56645
// Description: NF-Discovery request for “nftype=PCF” from RP1
// where the response have NF Service List in NF Instances but
// have fqdn everywhere for first NF Instance and have fqdn
// only in first NF Service for second NF Instance
// Expected Result:
// - P-SEPP forwards the request
// - P-SEPP drops the response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Pcf_NfServiceList_FqdnOnlyOnFirstNfService_Drop_DND56645) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=PCF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Json response_body = Json::parse(nf_disc_resp_body_nf_service_list);

  // FQDN is present for only first NF Service of second NF Instance
  for (auto& nf_inst : response_body.at("nfInstances")) {
    if (nf_inst.at("nfInstanceId") == "2ec8ac0b-265e-4165-86e9-e0735e6ce100") {
      continue;
    }
    nf_inst.erase("fqdn");
    for (auto& nf_svc : nf_inst.at("nfServiceList").items()) {
      if (nf_svc.key() == "4ec8ac0b-265e-4165-86e9-e0735e6ce100") {
        continue;
      }
      nf_svc.value().erase("fqdn");
    }
  }
  std::string nf_disc_resp_body_no_fqdn = response_body.dump();

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body_no_fqdn.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body_no_fqdn);
  upstream_request_->encodeData(response_data, true);

  // Drops the response by resetting stream
  ASSERT_TRUE(response->waitForReset());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=PCF"));

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.PCF.t2e.nf_"
                               "discovery.ip_address_hiding_fqdn_missing")
                     ->value());

  EXPECT_EQ(nullptr,
            test_server_->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e."
                                  "PCF.t2e.nf_discovery.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Pcf_NfServicesNfServiceList_Drop_DND43947
// Description: NF-Discovery request for “nftype=PCF” from RP1
// where the response have both NF Services and NF Service List in NF
// Instances where there is FQDN in only NF Services
// Expected Result:
// - P-SEPP forwards the request
// - Error case is checked only in NF Service List
// - P-SEPP drops the response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Pcf_NfServicesNfServiceList_Drop_DND43947) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=PCF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Json nf_services_body = Json::parse(nf_disc_resp_body);
  Json response_body = Json::parse(nf_disc_resp_body_nf_service_list);
  // Create body with nfServices and nfServiceList together
  for (uint32_t nf_inst_idx = 0; nf_inst_idx < response_body.at("nfInstances").size(); nf_inst_idx++) {
    response_body.at("nfInstances").at(nf_inst_idx)["nfServices"] = 
      nf_services_body.at("nfInstances").at(nf_inst_idx).at("nfServices");
  }
  // Keep FQDN only in nfServices
  for (auto& nf_inst : response_body.at("nfInstances")) {
    nf_inst.erase("fqdn");
    for (auto& nf_svc : nf_inst.at("nfServiceList").items()) {
      nf_svc.value().erase("fqdn");
    }
  }
  std::string nf_disc_resp_body_mixed = response_body.dump();

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body_mixed.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body_mixed);
  upstream_request_->encodeData(response_data, true);

  // Drops the response by resetting stream
  ASSERT_TRUE(response->waitForReset());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=PCF"));

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.PCF.t2e.nf_"
                               "discovery.ip_address_hiding_fqdn_missing")
                     ->value());

  EXPECT_EQ(nullptr,
            test_server_->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e."
                                  "PCF.t2e.nf_discovery.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Pcf_NoNfServicesNfServiceList_NoFqdnAnywhere_Drop
// Description: NF-Discovery request for “nftype=PCF” from RP1 and
// response have neither NF Services nor NF Service List in
// NF Instances as well as it does not have fqdn anywhere
// Expected Result:
// - P-SEPP forwards the request
// - P-SEPP drops the response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf_NoNfServicesNfServiceList_NoFqdnAnywhere_Drop) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=PCF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  Json response_body = Json::parse(nf_disc_resp_body);

  for (auto & nf_inst : response_body.at("nfInstances")) {
    nf_inst.erase("fqdn");
    nf_inst.erase("nfServices");
  }

  std::string nf_disc_resp_body_no_nf_services = response_body.dump();

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(nf_disc_resp_body_no_nf_services.length())},
      {"content-type", "application/json"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(nf_disc_resp_body_no_nf_services);
  upstream_request_->encodeData(response_data, true);

  // Drops the response by resetting stream
  ASSERT_TRUE(response->waitForReset());

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=PCF"));

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.PCF.t2e.nf_"
                               "discovery.ip_address_hiding_fqdn_missing")
                     ->value());

  EXPECT_EQ(nullptr,
            test_server_->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e."
                                  "PCF.t2e.nf_discovery.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1_NoTargetNfType_reject
// Description: NF-Discovery request without "target-nf-type" from RP1
// Expected Result:
// - P-SEPP rejects the request
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1_NoTargetNfType_reject) {
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);

  // Wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());

  const Json expected_body{R"({"cause":"MANDATORY_QUERY_PARAM_MISSING","detail":"missing_target-nf-type","status":400,"title":"Bad Request"})"_json};
  // Verify downstream response
  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" header should be set to "envoy" since
  // the reply is coming from Envoy
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "envoy"));

  EXPECT_EQ(nullptr, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.PCF.t2e.nf_"
                               "discovery.ip_address_hiding_fqdn_missing"));

  EXPECT_EQ(nullptr,
            test_server_->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e."
                                  "PCF.t2e.nf_discovery.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfDiscThIpHidingRp1Smf_InvalidJsonResponseBody
// Description: NF-Discovery request for “nftype=SMF” from RP1 where
// NF-Discovey response body is invalid JSON
// Expected Result:
// - P-SEPP forwards the request
// - Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf_InvalidJsonResponseBody) {
  // Send fake upstream response with fake invalid JSON body
  // The fake body is an invalid JSON: last closing } is missing
  std::string response_body{R"({"key":"value")"};

  const Json expected_body{R"({"status": 500, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_invalid_json_body"})"_json};

  testLocalReplyNfDiscovery(response_body, expected_body);
}

// Name: NfDiscThIpHidingRp1Smf_NoNfInstances
// Description: NF-Discovery request for “nftype=SMF” from RP1 where
// NF-Discovey response body does not contain NF Instances
// Expected Result:
// - P-SEPP forwards the request
// - Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf_NoNfInstances) {
  Json response_body = Json::parse(nf_disc_resp_body);
  response_body.erase("nfInstances");
  std::string nf_disc_resp_body_no_nf_instances = response_body.dump();

  const Json expected_body{R"({"status": 500, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_invalid_json_element"})"_json};

  testLocalReplyNfDiscovery(nf_disc_resp_body_no_nf_instances, expected_body);
}

// Name: NfDiscThIpHidingRp1Smf_WrongTypeNfInstances
// Description: NF-Discovery request for “nftype=SMF” from RP1 where
// NF-Discovey response body contains wrong type of NF Instances
// Expected Result:
// - P-SEPP forwards the request
// - Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf_WrongTypeNfInstances) {
  Json response_body = Json::parse(nf_disc_resp_body);
  response_body.at("nfInstances") = "nfinstances";
  std::string nf_disc_resp_body_wrong_type_nf_instances = response_body.dump();

  const Json expected_body{R"({"status": 500, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_invalid_json_element"})"_json};

  testLocalReplyNfDiscovery(nf_disc_resp_body_wrong_type_nf_instances, expected_body);
}

// Name: NfDiscThIpHidingRp1Smf_NoFqdnNfInstances_WrongTypeNfServices
// Description: NF-Discovery request for “nftype=SMF” from RP1 where
// NF-Discovey response body contains no fqdn on NF Instances level
// and wrong type of NF Services for first index of NF Instances
// Expected Result:
// - P-SEPP forwards the request
// - Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf_NoFqdnNfInstances_WrongTypeNfServices) {
  Json response_body = Json::parse(nf_disc_resp_body);
  response_body.at("nfInstances").at(0).erase("fqdn");
  response_body.at("nfInstances").at(0).at("nfServices") = "nfServices";
  std::string nf_disc_resp_body_no_fqdn_nf_profile_wrong_type_nf_services = response_body.dump();

  const Json expected_body{R"({"status": 500, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_invalid_json_element"})"_json};

  testLocalReplyNfDiscovery(nf_disc_resp_body_no_fqdn_nf_profile_wrong_type_nf_services, expected_body);
}

// Name: NfDiscThIpHidingRp1Smf_WrongTypeNfServices
// Description: NF-Discovery request for “nftype=SMF” from RP1 where
// NF-Discovey response body contains wrong type of NF Services 
// for first index of NF Instances
// Expected Result:
// - P-SEPP forwards the request
// - Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf_WrongTypeNfServices) {
  Json response_body = Json::parse(nf_disc_resp_body);
  response_body.at("nfInstances").at(0).at("nfServices") = "nfServices";
  std::string nf_disc_resp_body_wrong_type_nf_services = response_body.dump();

  const Json expected_body{R"({"status": 500, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_invalid_json_element"})"_json};

  testLocalReplyNfDiscovery(nf_disc_resp_body_wrong_type_nf_services, expected_body);
}

// Name: NfDiscThIpHidingRp1Smf_WrongTypeIpEndPoints
// Description: NF-Discovery request for “nftype=SMF” from RP1 where
// NF-Discovey response body contains wrong type of IP End Points
// for first index of both NF Instances and NF Services
// Expected Result:
// - P-SEPP forwards the request
// - Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf_WrongTypeIpEndPoints) {
  Json response_body = Json::parse(nf_disc_resp_body);
  response_body.at("nfInstances").at(0).at("nfServices").at(0).at("ipEndPoints") = "ipEndPoints";
  std::string nf_disc_resp_body_wrong_type_ip_end_points = response_body.dump();

  const Json expected_body{R"({"status": 500, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_invalid_json_element"})"_json};

  testLocalReplyNfDiscovery(nf_disc_resp_body_wrong_type_ip_end_points, expected_body);
}

// Name: NfDiscThIpHidingRp1Smf_NoFqdnNfInstances_WrongTypeNfServiceList_DND43947
// Description: NF-Discovery request for “nftype=SMF” from RP1 where
// NF-Discovey response body contains no fqdn on NF Instances
// level and wrong type of NF Service List for first index of
// NF Instances
// Expected Result:
// - P-SEPP forwards the request
// - Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf_NoFqdnNfInstances_WrongTypeNfServiceList_DND43947) {
  Json response_body = Json::parse(nf_disc_resp_body_nf_service_list);
  response_body.at("nfInstances").at(0).erase("fqdn");
  response_body.at("nfInstances").at(0).at("nfServiceList") = "nfServiceList";
  std::string nf_disc_resp_body_no_fqdn_nf_profile_wrong_type_nf_service_list = response_body.dump();

  const Json expected_body{R"({"status": 500, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_invalid_json_element"})"_json};

  testLocalReplyNfDiscovery(nf_disc_resp_body_no_fqdn_nf_profile_wrong_type_nf_service_list, expected_body);
}

// Name: NfDiscThIpHidingRp1Smf_WrongTypeNfServiceList_DND43947
// Description: NF-Discovery request for “nftype=SMF” from RP1 where
// NF-Discovey response body contains wrong type of NF Services 
// for first index of NF Instances
// Expected Result:
// - P-SEPP forwards the request
// - Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf_WrongTypeNfServiceList_DND43947) {
  Json response_body = Json::parse(nf_disc_resp_body_nf_service_list);
  response_body.at("nfInstances").at(0).at("nfServiceList") = "nfServiceList";
  std::string nf_disc_resp_body_wrong_type_nf_service_list = response_body.dump();

  const Json expected_body{R"({"status": 500, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_invalid_json_element"})"_json};

  testLocalReplyNfDiscovery(nf_disc_resp_body_wrong_type_nf_service_list, expected_body);
}

// Name: NfDiscThIpHidingRp1Smf_WrongTypeIpEndPointsNfServiceList_DND43947
// Description: NF-Discovery request for “nftype=SMF” from RP1 where NF-Discovey
// response body contains wrong type of IP End Points for first index of
// NF Instances and first key of NF Service List
// Expected Result:
// - P-SEPP forwards the request
// - Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfDiscThIpHidingRp1Smf_WrongTypeIpEndPointsNfServiceList_DND43947) {
  Json response_body = Json::parse(nf_disc_resp_body_nf_service_list);
  response_body.at("nfInstances").at(0).at("nfServiceList").at("3ec8ac0b-265e-4165-86e9-e0735e6ce100").at("ipEndPoints") = "ipEndPoints";
  std::string nf_disc_resp_body_wrong_type_ip_end_points_nf_service_list = response_body.dump();

  const Json expected_body{R"({"status": 500, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_invalid_json_element"})"_json};

  testLocalReplyNfDiscovery(nf_disc_resp_body_wrong_type_ip_end_points_nf_service_list, expected_body);
}

//--------------- End Test Nnrf_NFDiscovery -> NFDiscover ----------------

//------ Begin Test Nnrf_NFManagement -> NFStatusNotify (nfProfile) ------

// Name: NfStatusNotifyNfProfileNoThIpHidingRp2Smf
// Description: NF Status Notify request with NF Profile for “nftype=SMF” to RP2
// where topology-hiding is not configured for the roaming partner RP2
// Expected Result:
// - P-SEPP forwards the request
// - Request body is not modified
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileNoThIpHidingRp2Smf) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "SMF";
  std::string nf_status_notify_req_body_nf_profile = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-456-mcc-456:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_nf_profile);

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp2_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  
  // TODO(enaidev) : Via headers need to be Rel 17 compliant
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  for (const auto& c : test_server_->counters()) {
    if (!absl::StrContains(c->name(), "t8e")) {
      continue;
    }
    // The counter should not be initialized at all!
    EXPECT_STREQ("", c->name().c_str());
  }

  codec_client_->close();
}

// Name: NfStatusNotifyNfProfileNoThIpHidingRp1Udm
// Description: NF Status Notify request with NF Profile for “nftype=UDM” to RP1 where topology-hiding
// IP hiding is configured for the roaming partner RP1 but not for the NF type UDM
// Expected Result:
// - P-SEPP forwards the request
// - Request body is not modified
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileNoThIpHidingRp1Udm) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "UDM";
  std::string nf_status_notify_req_body_nf_profile = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_nf_profile);

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  
  // TODO(enaidev) : Via headers need to be Rel 17 compliant
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  for (const auto& c : test_server_->counters()) {
    if (!absl::StrContains(c->name(), "t8e")) {
      continue;
    }
    // The counter should not be initialized at all!
    EXPECT_STREQ("", c->name().c_str());
  }

  codec_client_->close();
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf
// Description: NF Status Notify request with NF Profile for “nftype=SMF” to RP1.
// Version without multipart-body.
// Expected Result:
// - P-SEPP forwards the request
// - IP addresses of NF Profile and its corresponding
//   NF Services are deleted in the request
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "SMF";
  std::string nf_status_notify_req_body_nf_profile = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_nf_profile);
  expected_body.at("nfProfile").erase("ipv4Addresses");
  expected_body.at("nfProfile").erase("ipv6Addresses");
  const auto num_nf_services = expected_body.at("nfProfile").at("nfServices").size();

  for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
    const auto num_ip_endpoints =
        expected_body.at("nfProfile").at("nfServices").at(nf_svc_idx).at("ipEndPoints").size();

    for (unsigned long ip_ep_idx = 0; ip_ep_idx < num_ip_endpoints; ip_ep_idx++) {
      expected_body.at("nfProfile")
          .at("nfServices")
          .at(nf_svc_idx)
          .at("ipEndPoints")
          .at(ip_ep_idx)
          .erase("ipv4Address");
      expected_body.at("nfProfile")
          .at("nfServices")
          .at(nf_svc_idx)
          .at("ipEndPoints")
          .at(ip_ep_idx)
          .erase("ipv6Address");
    }
  }

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  //TODO:(enaidev) Via headers need to be Rel 17 compliant
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_status_notify.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}


// Name: NfStatusNotifyNfProfileThIpHidingRp1SmfMultipart
// Description: NF Status Notify request with NF Profile for “nftype=SMF” to RP1, version
// with a multipart body request
// Expected Result:
// - P-SEPP forwards the request
// - IP addresses of NF Profile and its corresponding
//   NF Services are deleted in the request
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1SmfMultipart) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "SMF";
  std::string nf_status_notify_req_body_nf_profile = request_body.dump();

  const std::string content_type{"multipart/related; boundary=boundary"};
  const std::string body_prefix{"This is the preamble"
                                "\r\n--boundary\r\nContent-type: application/json\r\n\r\n"};
  std::string body_suffix =
      "\r\n--boundary\r\nContent-type: text/plain\r\n\r\nThis is a text/binary ";
  body_suffix.push_back('\0'); // necessary because otherwise the \0 terminates the string
  body_suffix.append("\002body part\r\n--boundary--\r\n..and an epilogue");
  std::string nf_status_notify_req_body_nf_profile_mp =
      body_prefix + nf_status_notify_req_body_nf_profile + body_suffix;

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", content_type},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile_mp.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile_mp);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_nf_profile);
  expected_body.at("nfProfile").erase("ipv4Addresses");
  expected_body.at("nfProfile").erase("ipv6Addresses");
  const auto num_nf_services = expected_body.at("nfProfile").at("nfServices").size();

  for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
    const auto num_ip_endpoints =
        expected_body.at("nfProfile").at("nfServices").at(nf_svc_idx).at("ipEndPoints").size();

    for (unsigned long ip_ep_idx = 0; ip_ep_idx < num_ip_endpoints; ip_ep_idx++) {
      expected_body.at("nfProfile")
          .at("nfServices")
          .at(nf_svc_idx)
          .at("ipEndPoints")
          .at(ip_ep_idx)
          .erase("ipv4Address");
      expected_body.at("nfProfile")
          .at("nfServices")
          .at(nf_svc_idx)
          .at("ipEndPoints")
          .at(ip_ep_idx)
          .erase("ipv6Address");
    }
  }

  // Verify upstream request
  Body req_body(&(upstream_request_->body()), content_type);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", content_type));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, *(req_body.getBodyAsJson()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  //TODO:(enaidev) Via headers need to be Rel 17 compliant
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_status_notify.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}


// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_NfServiceList_DND43947
// Description: NF Status Notify request with NF Profile and
// NF Service List for “nftype=SMF” to RP1
// Expected Result:
// - P-SEPP forwards the request
// - IP addresses of NF Profile and its corresponding
//   NF Service List are deleted in the request
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_NfServiceList_DND43947) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile_nf_service_list);
  request_body.at("nfProfile").at("nfType") = "SMF";
  std::string nf_status_notify_req_body_nf_profile = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_nf_profile);
  expected_body.at("nfProfile").erase("ipv4Addresses");
  expected_body.at("nfProfile").erase("ipv6Addresses");
  for (auto& nf_svc : expected_body.at("nfProfile").at("nfServiceList").items()) {
    for (auto& ip_ep : nf_svc.value().at("ipEndPoints")) {
      ip_ep.erase("ipv4Address");
      ip_ep.erase("ipv6Address");
    }
  }

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  
  // TODO(enaidev) : Via headers need to be Rel 17 compliant
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));


  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_status_notify.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_NfServicesNfServiceList_DND43947
// Description: NF Status Notify request with NF Profile and
// both NF Services and NF Service List for “nftype=SMF” to
// RP1 where there is FQDN in only NF Service List
// Expected Result:
// - P-SEPP forwards the request
// - Error case is checked only in NF Service List
// - IP addresses of NF Profile and its corresponding NF Services
//   and NF Service List are deleted in the request
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_NfServicesNfServiceList_DND43947) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json nf_services_body = Json::parse(nf_status_notify_req_body_nf_profile);
  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile_nf_service_list);
  request_body.at("nfProfile").at("nfType") = "SMF";
  // Create body with nfServices and nfServiceList together
  request_body.at("nfProfile")["nfServices"] = nf_services_body.at("nfProfile").at("nfServices");
  // Keep FQDN only in nfServiceList
  request_body.at("nfProfile").erase("fqdn");
  for (auto& nf_svc : request_body.at("nfProfile").at("nfServices")) {
    nf_svc.erase("fqdn");
  }
  std::string nf_status_notify_req_body_nf_profile_mixed = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile_mixed.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile_mixed);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_nf_profile_mixed);
  expected_body.at("nfProfile").erase("ipv4Addresses");
  expected_body.at("nfProfile").erase("ipv6Addresses");
  for (auto& nf_svc : expected_body.at("nfProfile").at("nfServiceList").items()) {
    for (auto& ip_ep : nf_svc.value().at("ipEndPoints")) {
      ip_ep.erase("ipv4Address");
      ip_ep.erase("ipv6Address");
    }
  }
  for (auto& nf_svc : expected_body.at("nfProfile").at("nfServices")) {
    for (auto& ip_ep : nf_svc.at("ipEndPoints")) {
      ip_ep.erase("ipv4Address");
      ip_ep.erase("ipv6Address");
    }
  }

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  
  //TODO(enaidev) Via header should be Rel 17 compliant
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_status_notify.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_NoNfServicesNfServiceList
// Description: NF Status Notify request with NF Profile for “nftype=SMF”
// to RP1 and request have neither NF Services nor NF Service List
// in NF Profile
// Expected Result:
// - P-SEPP forwards the request
// - IP addresses of NF Profile are deleted in the request
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_NoNfServicesNfServiceList) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "SMF";
  request_body.at("nfProfile").erase("nfServices");
  std::string nf_status_notify_req_body_no_nf_services = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_no_nf_services.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_no_nf_services);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_no_nf_services);
  expected_body.at("nfProfile").erase("ipv4Addresses");
  expected_body.at("nfProfile").erase("ipv6Addresses");

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  
  // TODO(enaidev) : Via headers need to be Rel 17 compliant
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));


  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_status_notify.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_FqdnOnlyOnNfProfile
// Description: NF Status Notify request with NF Profile for “nftype=SMF” to RP1
// where the request have fqdn only on NF Profile level
// Expected Result:
// - P-SEPP forwards the request
// - IP addresses of NF Profile and its corresponding
//   NF Services are deleted in the request
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_FqdnOnlyOnNfProfile) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "SMF";

  for (auto& nf_svc_idx : request_body.at("nfProfile").at("nfServices")) {
    nf_svc_idx.erase("fqdn");
  }

  std::string nf_status_notify_req_body_nf_profile = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_nf_profile);
  expected_body.at("nfProfile").erase("ipv4Addresses");
  expected_body.at("nfProfile").erase("ipv6Addresses");
  const auto num_nf_services = expected_body.at("nfProfile").at("nfServices").size();

  for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
    const auto num_ip_endpoints =
        expected_body.at("nfProfile").at("nfServices").at(nf_svc_idx).at("ipEndPoints").size();

    for (unsigned long ip_ep_idx = 0; ip_ep_idx < num_ip_endpoints; ip_ep_idx++) {
      expected_body.at("nfProfile")
          .at("nfServices")
          .at(nf_svc_idx)
          .at("ipEndPoints")
          .at(ip_ep_idx)
          .erase("ipv4Address");
      expected_body.at("nfProfile")
          .at("nfServices")
          .at(nf_svc_idx)
          .at("ipEndPoints")
          .at(ip_ep_idx)
          .erase("ipv6Address");
    }
  }

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  
  // TODO(enaidev) : Via headers need to be Rel 17 compliant
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF."
                               "t2e.nf_status_notify.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_InterPlmnFqdn
// Description: NF Status Notify request with NF Profile for “nftype=SMF” to RP1
// where the request have inter plmn fqdn instead of fqdn
// Expected Result:
// - P-SEPP forwards the request
// - IP addresses of NF Profile and its corresponding
//   NF Services are deleted in the request
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_InterPlmnFqdn) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "SMF";
  request_body.at("nfProfile").erase("fqdn");
  request_body.at("nfProfile").push_back({"interPlmnFqdn", "INTER_PLMN_FQDN_0_0.example1.com"});

  for (auto& nf_svc_idx : request_body.at("nfProfile").at("nfServices")) {
    nf_svc_idx.erase("fqdn");
  }

  std::string nf_status_notify_req_body_nf_profile = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_nf_profile);
  expected_body.at("nfProfile").erase("ipv4Addresses");
  expected_body.at("nfProfile").erase("ipv6Addresses");
  const auto num_nf_services = expected_body.at("nfProfile").at("nfServices").size();

  for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
    const auto num_ip_endpoints =
        expected_body.at("nfProfile").at("nfServices").at(nf_svc_idx).at("ipEndPoints").size();

    for (unsigned long ip_ep_idx = 0; ip_ep_idx < num_ip_endpoints; ip_ep_idx++) {
      expected_body.at("nfProfile")
          .at("nfServices")
          .at(nf_svc_idx)
          .at("ipEndPoints")
          .at(ip_ep_idx)
          .erase("ipv4Address");
      expected_body.at("nfProfile")
          .at("nfServices")
          .at(nf_svc_idx)
          .at("ipEndPoints")
          .at(ip_ep_idx)
          .erase("ipv6Address");
    }
  }

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  
  // TODO(enaidev) : Via headers need to be Rel 17 compliant
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF."
                               "t2e.nf_status_notify.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_NoFqdnAnywhere_RespondWithError
// Description: NF Status Notify request with NF Profile for “nftype=SMF”
// to RP1 where the request does not have fqdn anywhere
// Expected Result:
// - P-SEPP does not forward the request
// - P-SEPP responds with error in response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_NoFqdnAnywhere_RespondWithError) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "SMF";
  request_body.at("nfProfile").erase("fqdn");
  const auto num_nf_services = request_body.at("nfProfile").at("nfServices").size();

  for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
    request_body.at("nfProfile").at("nfServices").at(nf_svc_idx).erase("fqdn");
  }

  std::string nf_status_notify_req_body_nf_profile = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile);

  // Wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());

  const Json expected_body{R"({"status":400, "title":"fqdn missing in NF profile"})"_json};

  // Verify downstream response
  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" header should be set to "envoy" since
  // the reply is coming from Envoy
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "envoy"));


  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF."
                               "t2e.nf_status_notify.ip_address_hiding_fqdn_missing")
                     ->value());
  EXPECT_EQ(nullptr, test_server_->counter(
                         "http.ingress.n8e.g3p.topology_hiding.r12r.rp_1."
                         "t8e.SMF.t2e.nf_status_notify.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_FqdnOnlyOnFirstNfService_RespondWithError_DND56645
// Description: NF Status Notify request with NF Profile for “nftype=SMF”
// to RP1 where the request have fqdn only in first NF Service
// Expected Result:
// - P-SEPP does not forward the request
// - P-SEPP responds with error in response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_FqdnOnlyOnFirstNfService_RespondWithError_DND56645) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "SMF";
  request_body.at("nfProfile").erase("fqdn");
  const auto num_nf_services = request_body.at("nfProfile").at("nfServices").size();

  // FQDN only on first NF Service
  for (unsigned long nf_svc_idx = 1; nf_svc_idx < num_nf_services; nf_svc_idx++) {
    request_body.at("nfProfile").at("nfServices").at(nf_svc_idx).erase("fqdn");
  }

  std::string nf_status_notify_req_body_nf_profile = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile);

  // Wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());

  const Json expected_body{R"({"status":400, "title":"fqdn missing in NF profile"})"_json};

  // Verify downstream response
  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" header should be set to "envoy" since
  // the reply is coming from Envoy
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "envoy"));


  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF."
                               "t2e.nf_status_notify.ip_address_hiding_fqdn_missing")
                     ->value());
  EXPECT_EQ(nullptr, test_server_->counter(
                         "http.ingress.n8e.g3p.topology_hiding.r12r.rp_1."
                         "t8e.SMF.t2e.nf_status_notify.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_NfServiceList_NoFqdnAnywhere_RespondWithError_DND43947
// Description: NF Status Notify request with NF Profile for “nftype=SMF”
// to RP1 where the request have NF Service List in NF Profile but
// does not have fqdn anywhere
// Expected Result:
// - P-SEPP does not forward the request
// - P-SEPP responds with error in response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_NfServiceList_NoFqdnAnywhere_RespondWithError_DND43947) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile_nf_service_list);
  request_body.at("nfProfile").at("nfType") = "SMF";
  request_body.at("nfProfile").erase("fqdn");
  for (auto& nf_svc : request_body.at("nfProfile").at("nfServiceList").items()) {
    nf_svc.value().erase("fqdn");
  }
  std::string nf_status_notify_req_body_nf_profile = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile);

  // Wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());

  const Json expected_body{R"({"status":400, "title":"fqdn missing in NF profile"})"_json};

  // Verify downstream response
  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" header should be set to "envoy" since
  // the reply is coming from Envoy
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "envoy"));


  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF."
                               "t2e.nf_status_notify.ip_address_hiding_fqdn_missing")
                     ->value());
  EXPECT_EQ(nullptr, test_server_->counter(
                         "http.ingress.n8e.g3p.topology_hiding.r12r.rp_1."
                         "t8e.SMF.t2e.nf_status_notify.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_NfServiceList_FqdnOnlyOnFirstNfService_RespondWithError_DND56645
// Description: NF Status Notify request with NF Profile for “nftype=SMF”
// to RP1 where the request have NF Service List in NF Profile but
// have fqdn only in first NF Service
// Expected Result:
// - P-SEPP does not forward the request
// - P-SEPP responds with error in response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_NfServiceList_FqdnOnlyOnFirstNfService_RespondWithError_DND56645) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile_nf_service_list);
  request_body.at("nfProfile").at("nfType") = "SMF";
  request_body.at("nfProfile").erase("fqdn");
  // FQDN only on first NF Service
  for (auto& nf_svc : request_body.at("nfProfile").at("nfServiceList").items()) {
    if (nf_svc.key() == "4ec8ac0b-265e-4165-86e9-e0735e6ce100") {
      continue;
    }
    nf_svc.value().erase("fqdn");
  }
  std::string nf_status_notify_req_body_nf_profile = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile);

  // Wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());

  const Json expected_body{R"({"status":400, "title":"fqdn missing in NF profile"})"_json};

  // Verify downstream response
  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" header should be set to "envoy" since
  // the reply is coming from Envoy
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "envoy"));


  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF."
                               "t2e.nf_status_notify.ip_address_hiding_fqdn_missing")
                     ->value());
  EXPECT_EQ(nullptr, test_server_->counter(
                         "http.ingress.n8e.g3p.topology_hiding.r12r.rp_1."
                         "t8e.SMF.t2e.nf_status_notify.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_NfServicesNfServiceList_RespondWithError_DND43947
// Description: NF Status Notify request with NF Profile for “nftype=SMF”
// to RP1 where the request have both NF Services and NF Service List in
// NF Profile but there is FQDN in only NF Services
// Expected Result:
// - P-SEPP does not forward the request
// - Error case is checked only in NF Service List
// - P-SEPP responds with error in response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_NfServicesNfServiceList_RespondWithError_DND43947) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json nf_services_body = Json::parse(nf_status_notify_req_body_nf_profile);
  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile_nf_service_list);
  request_body.at("nfProfile").at("nfType") = "SMF";
  // Create body with nfServices and nfServiceList together
  request_body.at("nfProfile")["nfServices"] = nf_services_body.at("nfProfile").at("nfServices");
  // Keep FQDN only in nfServices
  request_body.at("nfProfile").erase("fqdn");
  for (auto& nf_svc : request_body.at("nfProfile").at("nfServiceList").items()) {
    nf_svc.value().erase("fqdn");
  }
  std::string nf_status_notify_req_body_nf_profile_mixed = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile_mixed.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile_mixed);

  // Wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());

  const Json expected_body{R"({"status":400, "title":"fqdn missing in NF profile"})"_json};

  // Verify downstream response
  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" header should be set to "envoy" since
  // the reply is coming from Envoy
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "envoy"));


  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF."
                               "t2e.nf_status_notify.ip_address_hiding_fqdn_missing")
                     ->value());
  EXPECT_EQ(nullptr, test_server_->counter(
                         "http.ingress.n8e.g3p.topology_hiding.r12r.rp_1."
                         "t8e.SMF.t2e.nf_status_notify.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_NoNfServicesNfServiceList_NoFqdnAnywhere_RespondWithError
// Description: NF Status Notify request with NF Profile for “nftype=SMF”
// to RP1 where the request have neither NF Services nor NF Service List
// in NF Profile as well as it does not have fqdn anywhere
// Expected Result:
// - P-SEPP does not forward the request
// - P-SEPP responds with error in response
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_NoNfServicesNfServiceList_NoFqdnAnywhere_RespondWithError) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "SMF";
  request_body.at("nfProfile").erase("nfServices");
  request_body.at("nfProfile").erase("fqdn");
  std::string nf_status_notify_req_body_no_nf_services = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_no_nf_services.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_no_nf_services);

  // Wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());

  const Json expected_body{R"({"status":400, "title":"fqdn missing in NF profile"})"_json};

  // Verify downstream response
  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // "server" header should be set to "envoy" since
  // the reply is coming from Envoy
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "envoy"));


  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF."
                               "t2e.nf_status_notify.ip_address_hiding_fqdn_missing")
                     ->value());
  EXPECT_EQ(nullptr, test_server_->counter(
                         "http.ingress.n8e.g3p.topology_hiding.r12r.rp_1."
                         "t8e.SMF.t2e.nf_status_notify.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Amf_NoFqdnAnywhere_Forward
// Description: NF Status Notify request with NF Profile for “nftype=AMF"
// to RP1 where the request does not have fqdn anywhere
// Expected Result:
// - P-SEPP forwards the request
// - Request body is not modified
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Amf_NoFqdnAnywhere_Forward) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "AMF";
  request_body.at("nfProfile").erase("fqdn");
  const auto num_nf_services = request_body.at("nfProfile").at("nfServices").size();

  for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
    request_body.at("nfProfile").at("nfServices").at(nf_svc_idx).erase("fqdn");
  }

  std::string nf_status_notify_req_body_nf_profile = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "400"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_nf_profile);

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  
  // TODO(enaidev) : Via headers need to be Rel 17 compliant
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("400", response->headers().getStatusValue());

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.AMF."
                               "t2e.nf_status_notify.ip_address_hiding_fqdn_missing")
                     ->value());
  EXPECT_EQ(nullptr,
            test_server_->counter(
                "http.eric_proxy.n8e.r12r.rp_1.t8e.AMF.request.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Pcf_NoFqdnAnywhere_Drop
// Description: NF Status Notify request with NF Profile for “nftype=PCF”
// to RP1 where the request does not have fqdn anywhere
// Expected Result:
// - P-SEPP drops the request
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Pcf_NoFqdnAnywhere_Drop) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "PCF";
  request_body.at("nfProfile").erase("fqdn");
  const auto num_nf_services = request_body.at("nfProfile").at("nfServices").size();

  for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
    request_body.at("nfProfile").at("nfServices").at(nf_svc_idx).erase("fqdn");
  }

  std::string nf_status_notify_req_body_nf_profile = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile);

  // Drops the request by resetting stream
  ASSERT_TRUE(response->waitForReset());

  EXPECT_EQ(
      1UL, test_server_
               ->counter(
                   "http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.PCF.t2e.nf_status_notify."
                   "ip_address_hiding_fqdn_missing")
               ->value());

  EXPECT_EQ(nullptr,
            test_server_->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e."
                                  "PCF.t2e.nf_status_notify.ip_address_hiding_applied_success"));

  codec_client_->close();
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Chf_NoFqdnAnywhere_ApplyIpHiding
// Description: NF Status Notify request with NF Profile for “nftype=CHF”
// to RP1 where the request does not have fqdn anywhere
// Expected Result:
// - P-SEPP forwards the request
// - IP addresses of NF Profile and its corresponding
//   NF Services are deleted in the request
TEST_P(EricProxyFilterSeppThIpHidingTest,
       NfStatusNotifyNfProfileThIpHidingRp1Chf_NoFqdnAnywhere_ApplyIpHiding) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "CHF";
  request_body.at("nfProfile").erase("fqdn");

  for (auto& nf_svc_idx : request_body.at("nfProfile").at("nfServices")) {
    nf_svc_idx.erase("fqdn");
  }

  std::string nf_status_notify_req_body_nf_profile = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"content-type", "application/json"},
      {"content-length", std::to_string(nf_status_notify_req_body_nf_profile.length())},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response =
      codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_nf_profile);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_nf_profile);
  expected_body.at("nfProfile").erase("ipv4Addresses");
  expected_body.at("nfProfile").erase("ipv6Addresses");
  const auto num_nf_services = expected_body.at("nfProfile").at("nfServices").size();

  for (unsigned long nf_svc_idx = 0; nf_svc_idx < num_nf_services; nf_svc_idx++) {
    const auto num_ip_endpoints =
        expected_body.at("nfProfile").at("nfServices").at(nf_svc_idx).at("ipEndPoints").size();

    for (unsigned long ip_ep_idx = 0; ip_ep_idx < num_ip_endpoints; ip_ep_idx++) {
      expected_body.at("nfProfile")
          .at("nfServices")
          .at(nf_svc_idx)
          .at("ipEndPoints")
          .at(ip_ep_idx)
          .erase("ipv4Address");
      expected_body.at("nfProfile")
          .at("nfServices")
          .at(nf_svc_idx)
          .at("ipEndPoints")
          .at(ip_ep_idx)
          .erase("ipv6Address");
    }
  }

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  
  // TODO(enaidev) : Via headers need to be Rel 17 compliant
  
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.CHF."
                               "t2e.nf_status_notify.ip_address_hiding_fqdn_missing")
                     ->value());

  codec_client_->close();
}

// Name: NfStatusNotifyThIpHidingRp1_InvalidJsonRequestBody
// Description: NF Status Notify request with invalid JSON body to RP1
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyThIpHidingRp1_InvalidJsonRequestBody) {
  // Send fake downstream request with fake invalid JSON body
  // The fake body is an invalid JSON: last closing } is missing
  std::string request_body{R"({"key":"value")"};

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_body"})"_json};

  testLocalReplyNfStatusNotify(request_body, expected_body);
}

// DescriptionL NF Status notify with empty body "" i.e. with end_stream=false
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NFStatus_notify_empty_body1) {

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_body"})"_json};

  testLocalReplyNfStatusNotify("", expected_body);
}


// DescriptionL NF Status notify with empty body i.e. with end_stream=true
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NFStatus_notify_empty_body2) {

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_body"})"_json};

  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

    HttpIntegrationTest::initialize();

    Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
      {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}
    };

    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
    
    // Wait for the response and close the fake upstream connection
    ASSERT_TRUE(response->waitForEndStream());

    // Verify downstream response
    EXPECT_EQ("400", response->headers().getStatusValue());
    EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
    EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
    EXPECT_EQ(expected_body, Json::parse(response->body()));

    // "server" header should be set to "envoy" since
    // the reply is coming from Envoy
    EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "envoy"));

    for (const auto& c : test_server_->counters()) {
      if (!absl::StrContains(c->name(), "t8e")) {
        continue;
      }
      // The counter should not be initialized at all!
      EXPECT_STREQ("", c->name().c_str());
    }

    codec_client_->close(); 
}


// DescriptionL NF Discovery with empty body "" i.e. with end_stream=false
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NFDisc_empty_body1) {

  const Json expected_body{R"({"status": 500, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_invalid_json_body"})"_json};
  testLocalReplyNfDiscovery("", expected_body);
}

// DescriptionL NF Discovery with empty body "" i.e. with end_stream=false
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NFDisc_empty_body2) {

 
  const Json expected_body{R"({"status": 500, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_invalid_json_body"})"_json};
  config_helper_.addFilter(config_th_ip_hiding_nf_discovery);
    config_helper_.addFilter(config_header_to_metadata);

    HttpIntegrationTest::initialize();

    Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"},
      {":authority", "sepp.own_plmn.com"},
      {"3gpp-Sbi-target-apiRoot", "nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name", "rp_1"},
      {"x-eric-sepp-test-san", "rp_A.ext_plmn.com"}
    };

    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
    waitForNextUpstreamRequest(0);

    Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"server", "secret.internal.fqdn.com"},
      {"via", "location"}
    };

    // Send response
    upstream_request_->encodeHeaders(response_headers, true);
    ASSERT_TRUE(response->waitForEndStream());

    // Verify upstream request
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "nrf_pool"));
    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nnrf-disc/v1/nf-instances?target-nf-type=SMF"));

    // Verify downstream response
    EXPECT_EQ("500", response->headers().getStatusValue());
    EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
    EXPECT_THAT(response->headers(), Http::HeaderValueOf("content-length", std::to_string(response->body().length())));
    EXPECT_EQ(expected_body, Json::parse(response->body()));

    // "server" header should be set to "envoy" since
    // the reply is coming from Envoy
    EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "envoy"));
    // "via" header should be removed
    EXPECT_EQ(response->headers().get(Http::LowerCaseString("via")).size(), 0);

    for (const auto& c : test_server_->counters()) {
      if (!absl::StrContains(c->name(), "t8e")) {
        continue;
      }
      // The counter should not be initialized at all!
      EXPECT_STREQ("", c->name().c_str());
    }

    codec_client_->close();
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1_NoNfType
// Description: NF Status Notify request with NF Profile containing no NF Type to RP1
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1_NoNfType) {
  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").erase("nfType");
  std::string nf_status_notify_req_body_nf_profile_no_nf_type = request_body.dump();

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_element"})"_json};

  testLocalReplyNfStatusNotify(nf_status_notify_req_body_nf_profile_no_nf_type, expected_body);
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1_WrongTypeNfType
// Description: NF Status Notify request with NF Profile containing wrong type of NF Type to RP1
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1_WrongTypeNfType) {
  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  Json nf_type_list{R"(["nfType1", "nfType2"])"_json};
  request_body.at("nfProfile").at("nfType") = nf_type_list;
  std::string nf_status_notify_req_body_nf_profile_wrong_type_nf_type = request_body.dump();

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_element"})"_json};

  testLocalReplyNfStatusNotify(nf_status_notify_req_body_nf_profile_wrong_type_nf_type, expected_body);
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_NoFqdnNfProfile_WrongTypeNfServices
// Description: NF Status Notify request with NF Profile containing no fqdn on NF Profile 
// level and wrong type of NF Services for “nftype=SMF” to RP1
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_NoFqdnNfProfile_WrongTypeNfServices) {
  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "SMF";
  request_body.at("nfProfile").erase("fqdn");
  request_body.at("nfProfile").at("nfServices") = "nfServices";
  std::string nf_status_notify_req_body_nf_profile_no_fqdn_nf_profile_wrong_type_nf_services = request_body.dump();

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_element"})"_json};

  testLocalReplyNfStatusNotify(nf_status_notify_req_body_nf_profile_no_fqdn_nf_profile_wrong_type_nf_services, expected_body);
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_WrongTypeNfServices
// Description: NF Status Notify request with NF Profile containing wrong 
// type of NF Services for “nftype=SMF” to RP1
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_WrongTypeNfServices) {
  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "SMF";
  request_body.at("nfProfile").at("nfServices") = "nfServices";
  std::string nf_status_notify_req_body_nf_profile_wrong_type_nf_services = request_body.dump();

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_element"})"_json};

  testLocalReplyNfStatusNotify(nf_status_notify_req_body_nf_profile_wrong_type_nf_services, expected_body);
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_WrongTypeIpEndPoints
// Description: NF Status Notify request with NF Profile containing wrong type
// of IP End Points for first index of NF Services for “nftype=SMF” to RP1
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_WrongTypeIpEndPoints) {
  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile);
  request_body.at("nfProfile").at("nfType") = "SMF";
  request_body.at("nfProfile").at("nfServices").at(0).at("ipEndPoints") = "ipEndPoints";
  std::string nf_status_notify_req_body_nf_profile_wrong_type_ip_end_points = request_body.dump();

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_element"})"_json};

  testLocalReplyNfStatusNotify(nf_status_notify_req_body_nf_profile_wrong_type_ip_end_points, expected_body);
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_NoFqdnNfProfile_WrongTypeNfServiceList_DND43947
// Description: NF Status Notify request with NF Profile containing no fqdn on NF Profile 
// level and wrong type of NF Service List for “nftype=SMF” to RP1
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_NoFqdnNfProfile_WrongTypeNfServiceList_DND43947) {
  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile_nf_service_list);
  request_body.at("nfProfile").at("nfType") = "SMF";
  request_body.at("nfProfile").erase("fqdn");
  request_body.at("nfProfile").at("nfServiceList") = "nfServiceList";
  std::string nf_status_notify_req_body_nf_profile_no_fqdn_nf_profile_wrong_type_nf_service_list = request_body.dump();

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_element"})"_json};

  testLocalReplyNfStatusNotify(nf_status_notify_req_body_nf_profile_no_fqdn_nf_profile_wrong_type_nf_service_list, expected_body);
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_WrongTypeNfServiceList_DND43947
// Description: NF Status Notify request with NF Profile containing wrong 
// type of NF Service List for “nftype=SMF” to RP1
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_WrongTypeNfServiceList_DND43947) {
  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile_nf_service_list);
  request_body.at("nfProfile").at("nfType") = "SMF";
  request_body.at("nfProfile").at("nfServiceList") = "nfServiceList";
  std::string nf_status_notify_req_body_nf_profile_wrong_type_nf_service_list = request_body.dump();

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_element"})"_json};

  testLocalReplyNfStatusNotify(nf_status_notify_req_body_nf_profile_wrong_type_nf_service_list, expected_body);
}

// Name: NfStatusNotifyNfProfileThIpHidingRp1Smf_WrongTypeIpEndPointsNfServiceList_DND43947
// Description: NF Status Notify request with NF Profile containing wrong type
// of IP End Points for first key of NF Service List for “nftype=SMF” to RP1
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyNfProfileThIpHidingRp1Smf_WrongTypeIpEndPointsNfServiceList_DND43947) {
  Json request_body = Json::parse(nf_status_notify_req_body_nf_profile_nf_service_list);
  request_body.at("nfProfile").at("nfType") = "SMF";
  request_body.at("nfProfile").at("nfServiceList").at("4ec8ac0b-265e-4165-86e9-e0735e6ce100").at("ipEndPoints") = "ipEndPoints";
  std::string nf_status_notify_req_body_nf_profile_wrong_type_ip_end_points = request_body.dump();

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_element"})"_json};

  testLocalReplyNfStatusNotify(nf_status_notify_req_body_nf_profile_wrong_type_ip_end_points, expected_body);
}

//------- End Test Nnrf_NFManagement -> NFStatusNotify (nfProfile) -------

//---- Begin Test Nnrf_NFManagement -> NFStatusNotify (profileChanges) ---

// Name: NfStatusNotifyProfileChangesNoThIpHidingRp2Smf
// Description: NF Status Notify request with Profile Changes to RP2 where
// where topology-hiding is not configured for the roaming partner RP2
// Expected Result:
// - P-SEPP forwards the request
// - Request body is not modified
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyProfileChangesNoThIpHidingRp2Smf) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
    {":method", "POST"},
    {":path", "/"},
    {":authority", "host"},
    {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-456-mcc-456:80"},
    {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
    {"content-type", "application/json"},
    {"content-length", std::to_string(nf_status_notify_req_body_profile_changes.length())},
    {"server", "secret.internal.fqdn.com"},
    {"via", "location"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_profile_changes);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_profile_changes);

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp2_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  // TODO(enaidev) : Via headers need to be Rel 17 compliant

  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  for (const auto& c : test_server_->counters()) {
    if (!absl::StrContains(c->name(), "t8e")) {
      continue;
    }
    // The counter should not be initialized at all!
    EXPECT_STREQ("", c->name().c_str());
  }

  codec_client_->close();
}

// Name: NfStatusNotifyProfileChangesNoThIpHidingRp1Udm
// Description: NF Status Notify request with Profile Changes to RP1 where topology-hiding
// IP hiding is configured for the roaming partner RP1 but not for the NF type UDM and
// all the IP addresses belong to the subnet list of “nftype=UDM”
// Expected Result:
// - P-SEPP forwards the request
// - Request body is not modified
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyProfileChangesNoThIpHidingRp1Udm) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_profile_changes);
  request_body.at("profileChanges").at(1).at("newValue").at(0) = "50.0.0.1";
  request_body.at("profileChanges").at(1).at("newValue").at(1) = "50.0.0.2";
  request_body.at("profileChanges").at(2).at("newValue") = "5000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0001";
  request_body.at("profileChanges").at(3).at("newValue") = "5000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0002";
  request_body.at("profileChanges").at(4).at("newValue") = "50.0.0.3";
  request_body.at("profileChanges").at(5).at("newValue") = "5000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0003";
  request_body.at("profileChanges").at(6).at("newValue") = "50.0.0.4";
  request_body.at("profileChanges").at(7).at("newValue") = "5000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0004";
  request_body.at("profileChanges").at(8).at("newValue") = "50.0.0.5";
  request_body.at("profileChanges").at(9).at("newValue") = "5000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0005";
  std::string nf_status_notify_req_body_profile_changes = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
    {":method", "POST"},
    {":path", "/"},
    {":authority", "host"},
    {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
    {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
    {"content-type", "application/json"},
    {"content-length", std::to_string(nf_status_notify_req_body_profile_changes.length())},
    {"server", "secret.internal.fqdn.com"},
    {"via", "location"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_profile_changes);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_profile_changes);

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  // TODO(enaidev) : Via headers need to be Rel 17 compliant

  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  for (const auto& c : test_server_->counters()) {
    if (!absl::StrContains(c->name(), "t8e")) {
      continue;
    }
    // The counter should not be initialized at all!
    EXPECT_STREQ("", c->name().c_str());
  }

  codec_client_->close();
}

// Name: NfStatusNotifyProfileChangesThIpHidingRp1Smf
// Description: NF Status Notify request with Profile Changes to RP1 where
// all the IP addresses belong to the subnet list of “nftype=SMF”
// Expected Result:
// - P-SEPP forwards the request
// - All Profile Changes containing the IP addresses are deleted in the request
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyProfileChangesThIpHidingRp1Smf) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
    {":method", "POST"},
    {":path", "/"},
    {":authority", "host"},
    {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
    {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
    {"content-type", "application/json"},
    {"content-length", std::to_string(nf_status_notify_req_body_profile_changes.length())},
    {"server", "secret.internal.fqdn.com"},
    {"via", "location"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_profile_changes);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_profile_changes);
  int expected_profile_changes_indices[] {1, 1, 1, 1, 1, 1, 1, 1, 1};
  for (auto& itr : expected_profile_changes_indices) {
    expected_body.at("profileChanges").erase(itr);
  }

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  // TODO(enaidev) : Via headers need to be Rel 17 compliant
  
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_status_notify.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}

// Name: NfStatusNotifyProfileChangesThIpHidingRp1Smf_NfServiceList_DND43947
// Description: NF Status Notify request with Profile Changes to RP1 where
// all the IP addresses belong to the subnet list of “nftype=SMF” and
// path contains NF Service List
// Expected Result:
// - P-SEPP forwards the request
// - All Profile Changes containing the IP addresses are deleted in the request
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyProfileChangesThIpHidingRp1Smf_NfServiceList_DND43947) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
    {":method", "POST"},
    {":path", "/"},
    {":authority", "host"},
    {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
    {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
    {"content-type", "application/json"},
    {"content-length", std::to_string(nf_status_notify_req_body_profile_changes_nf_service_list.length())},
    {"server", "secret.internal.fqdn.com"},
    {"via", "location"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_profile_changes_nf_service_list);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_profile_changes_nf_service_list);
  int expected_profile_changes_indices[] {1, 1, 1, 1, 1, 1, 1, 1, 1};
  for (auto& itr : expected_profile_changes_indices) {
    expected_body.at("profileChanges").erase(itr);
  }

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
 // TODO(enaidev) : Via headers need to be Rel 17 compliant

  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_status_notify.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}

// Name: NfStatusNotifyProfileChangesThIpHidingRp1Amf
// Description: NF Status Notify request with Profile Changes to RP1 where
// all the IP addresses belong to the subnet list of “nftype=AMF”
// Expected Result:
// - P-SEPP forwards the request
// - All Profile Changes containing the IP addresses are deleted in the request
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyProfileChangesThIpHidingRp1Amf) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_profile_changes);
  request_body.at("profileChanges").at(1).at("newValue").at(0) = "30.0.0.1";
  request_body.at("profileChanges").at(1).at("newValue").at(1) = "30.0.0.2";
  request_body.at("profileChanges").at(2).at("newValue") = "3000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0001";
  request_body.at("profileChanges").at(3).at("newValue") = "3000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0002";
  request_body.at("profileChanges").at(4).at("newValue") = "30.0.0.3";
  request_body.at("profileChanges").at(5).at("newValue") = "3000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0003";
  request_body.at("profileChanges").at(6).at("newValue") = "30.0.0.4";
  request_body.at("profileChanges").at(7).at("newValue") = "3000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0004";
  request_body.at("profileChanges").at(8).at("newValue") = "30.0.0.5";
  request_body.at("profileChanges").at(9).at("newValue") = "3000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0005";
  std::string nf_status_notify_req_body_profile_changes = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
    {":method", "POST"},
    {":path", "/"},
    {":authority", "host"},
    {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
    {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
    {"content-type", "application/json"},
    {"content-length", std::to_string(nf_status_notify_req_body_profile_changes.length())},
    {"server", "secret.internal.fqdn.com"},
    {"via", "location"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_profile_changes);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_profile_changes);
  int expected_profile_changes_indices[] {1, 1, 1, 1, 1, 1, 1, 1, 1};
  for (auto& itr : expected_profile_changes_indices) {
    expected_body.at("profileChanges").erase(itr);
  }

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  // TODO(enaidev) : Via headers need to be Rel 17 compliant
  
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.AMF.t2e.nf_status_notify.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}

// Name: NfStatusNotifyProfileChangesThIpHidingRp1PartialSmf
// Description: NF Status Notify request with Profile Changes to RP1 where
// some IP addresses belong to the subnet list of “nftype=SMF”
// Expected Result:
// - P-SEPP forwards the request
// - Some Profile Changes containing the IP addresses are deleted in the request
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyProfileChangesThIpHidingRp1PartialSmf) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_profile_changes);
  request_body.at("profileChanges").at(1).at("newValue").at(0) = "50.0.0.1";
  request_body.at("profileChanges").at(2).at("newValue") = "5000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0001";
  request_body.at("profileChanges").at(4).at("newValue") = "50.0.0.3";
  request_body.at("profileChanges").at(7).at("newValue") = "5000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0004";
  request_body.at("profileChanges").at(8).at("newValue") = "50.0.0.5";
  std::string nf_status_notify_req_body_profile_changes = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
    {":method", "POST"},
    {":path", "/"},
    {":authority", "host"},
    {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
    {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
    {"content-type", "application/json"},
    {"content-length", std::to_string(nf_status_notify_req_body_profile_changes.length())},
    {"server", "secret.internal.fqdn.com"},
    {"via", "location"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_profile_changes);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_profile_changes);
  int expected_profile_changes_indices[] {1, 2, 3, 3, 5};
  for (auto& itr : expected_profile_changes_indices) {
    expected_body.at("profileChanges").erase(itr);
  }

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_status_notify.ip_address_hiding_applied_success")
                     ->value());

  codec_client_->close();
}

// Name: NfStatusNotifyProfileChangesThIpHidingRp1SmfAmf
// Description: NF Status Notify request with Profile Changes to RP1 where
// some IP addresses belong to the subnet list of “nftype=SMF” and some
// belong to the subnet list of “nftype=AMF”
// Expected Result:
// - P-SEPP forwards the request
// - Request body is not modified
// - Configuration error case
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyProfileChangesThIpHidingRp1SmfAmf) {
  config_helper_.addFilter(config_th_ip_hiding_nf_status_notify);

  HttpIntegrationTest::initialize();

  Json request_body = Json::parse(nf_status_notify_req_body_profile_changes);
  request_body.at("profileChanges").at(4).at("newValue") = "30.0.0.3";
  request_body.at("profileChanges").at(5).at("newValue") = "4000:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:0003";
  std::string nf_status_notify_req_body_profile_changes = request_body.dump();

  Http::TestRequestHeaderMapImpl request_headers{
    {":method", "POST"},
    {":path", "/"},
    {":authority", "host"},
    {"3gpp-Sbi-target-apiRoot", "https://eric-smfsim-1-mnc-123-mcc-123:80"},
    {"3gpp-Sbi-Callback", "Nnrf_NFManagement_NFStatusNotify"},
    {"content-type", "application/json"},
    {"content-length", std::to_string(nf_status_notify_req_body_profile_changes.length())},
    {"server", "secret.internal.fqdn.com"},
    {"via", "location"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, nf_status_notify_req_body_profile_changes);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"}};

  // Send response
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  Json expected_body = Json::parse(nf_status_notify_req_body_profile_changes);

  // Verify upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "rp1_pool"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-type", "application/json"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(upstream_request_->body().length())));
  EXPECT_EQ(expected_body, Json::parse(upstream_request_->body().toString()));

  // "server" and "via" headers should not be modified
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("server", "secret.internal.fqdn.com"));
  // TODO(enaidev) : Via headers need to be Rel 17 compliant

  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("via", "location"));

  // Verify downstream response
  EXPECT_EQ("204", response->headers().getStatusValue());

  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.topology_hiding.r12r.rp_1.t8e.SMF.t2e.nf_status_notify.ip_address_hiding_configuration_error")
                     ->value());

  codec_client_->close();
}

// Name: NfStatusNotifyProfileChangesThIpHidingRp1_WrongTypeProfileChanges
// Description: NF Status Notify request with wrong type of Profile Changes to RP1
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyProfileChangesThIpHidingRp1_WrongTypeProfileChanges) {
  Json request_body = Json::parse(nf_status_notify_req_body_profile_changes);
  request_body.at("profileChanges") = "profileChanges";
  std::string nf_status_notify_req_body_profile_changes_wrong_type_profile_changes = request_body.dump();

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_element"})"_json};

  testLocalReplyNfStatusNotify(nf_status_notify_req_body_profile_changes_wrong_type_profile_changes, expected_body);
}

// Name: NfStatusNotifyProfileChangesThIpHidingRp1_NoPath
// Description: NF Status Notify request with Profile Changes to RP1 where
// first index of profile changes does not contain path
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyProfileChangesThIpHidingRp1_NoPath) {
  Json request_body = Json::parse(nf_status_notify_req_body_profile_changes);
  request_body.at("profileChanges").at(0).erase("path");
  std::string nf_status_notify_req_body_profile_changes_no_path = request_body.dump();

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_element"})"_json};

  testLocalReplyNfStatusNotify(nf_status_notify_req_body_profile_changes_no_path, expected_body);
}

// Name: NfStatusNotifyProfileChangesThIpHidingRp1_WrongTypePath
// Description: NF Status Notify request with Profile Changes to RP1 where
// first index of profile changes contains wrong type of path
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyProfileChangesThIpHidingRp1_WrongTypePath) {
  Json request_body = Json::parse(nf_status_notify_req_body_profile_changes);
  Json path_list{R"(["path1", "path2"])"_json};
  request_body.at("profileChanges").at(0).at("path") = path_list;
  std::string nf_status_notify_req_body_profile_changes_wrong_type_path = request_body.dump();

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_element"})"_json};

  testLocalReplyNfStatusNotify(nf_status_notify_req_body_profile_changes_wrong_type_path, expected_body);
}

// Name: NfStatusNotifyProfileChangesThIpHidingRp1_WrongTypeNewValue1
// Description: NF Status Notify request with Profile Changes to RP1 where
// second index of profile changes contains wrong type of new value
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyProfileChangesThIpHidingRp1_WrongTypeNewValue1) {
  Json request_body = Json::parse(nf_status_notify_req_body_profile_changes);
  request_body.at("profileChanges").at(1).at("newValue") = "newValue";
  std::string nf_status_notify_req_body_profile_changes_wrong_type_new_value = request_body.dump();

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_element"})"_json};

  testLocalReplyNfStatusNotify(nf_status_notify_req_body_profile_changes_wrong_type_new_value, expected_body);
}

// Name: NfStatusNotifyProfileChangesThIpHidingRp1_WrongTypeNewValue2
// Description: NF Status Notify request with Profile Changes to RP1 where
// second index of profile changes contains wrong type of new value
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyProfileChangesThIpHidingRp1_WrongTypeNewValue2) {
  Json request_body = Json::parse(nf_status_notify_req_body_profile_changes);
  Json new_value_list{R"(["new_value1", "new_value2"])"_json};
  request_body.at("profileChanges").at(1).at("newValue").at(0) = new_value_list;
  std::string nf_status_notify_req_body_profile_changes_wrong_type_new_value = request_body.dump();

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_element"})"_json};

  testLocalReplyNfStatusNotify(nf_status_notify_req_body_profile_changes_wrong_type_new_value, expected_body);
}

// Name: NfStatusNotifyProfileChangesThIpHidingRp1_WrongTypeNewValue3
// Description: NF Status Notify request with Profile Changes to RP1 where
// third index of profile changes contains wrong type of new value
// Expected Result: Corresponding local reply is sent
TEST_P(EricProxyFilterSeppThIpHidingTest, NfStatusNotifyProfileChangesThIpHidingRp1_WrongTypeNewValue3) {
  Json request_body = Json::parse(nf_status_notify_req_body_profile_changes);
  Json new_value_list{R"(["new_value1", "new_value2"])"_json};
  request_body.at("profileChanges").at(2).at("newValue") = new_value_list;
  std::string nf_status_notify_req_body_profile_changes_wrong_type_new_value = request_body.dump();

  const Json expected_body{R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_element"})"_json};

  testLocalReplyNfStatusNotify(nf_status_notify_req_body_profile_changes_wrong_type_new_value, expected_body);
}

//----- End Test Nnrf_NFManagement -> NFStatusNotify (profileChanges) ----

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
