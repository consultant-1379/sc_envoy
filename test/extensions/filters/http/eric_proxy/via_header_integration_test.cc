
#include "config_utils/pluggable_configurator.h"
#include "config_utils/endpoint_md_cluster_md_configurator.h"
namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterViaHeaderIntegrationTest : public PluggableConfigurator {
    public:
        EricProxyFilterViaHeaderIntegrationTest() : PluggableConfigurator(ericProxyHttpConfig()) {}

        std::string ericProxyHttpConfig() {
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
          server_name: envoy.ericsson.com
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
  )EOF", Platform::null_device_path, Platform::null_device_path,
            Platform::null_device_path);
        }


void testRequest(const std::vector<std::string> filter_config,
                      const std::string& cluster_name,
                      const std::map<std::string,std::string> req_header,
                      const std::map<std::string,std::string> resp_header,
                      const std::map<std::string,std::string> exp_upstream_header,
                      const std::map<std::string,std::string> exp_response_header){

    EndpointMetadataClusterConfigurator cluster_config =
        EndpointMetadataClusterConfigurator()
            .withClusterBuilder(ClusterBuilder()
                                    .withName(cluster_name)
                                    .withEndpoint(EndpointBuilder()
                                                      .withHostName("chf1.ericsson.com:80")
                                                      .withHostMd({{"support", {"NF"}}})));
  initConfig(filter_config,cluster_config);

  IntegrationCodecClientPtr codec_client;
  codec_client = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl req_headers;
  std::for_each(req_header.begin(),req_header.end(),
                  [&](const auto& it) { req_headers.addCopy(it.first,it.second);});

  auto response = codec_client->makeHeaderOnlyRequest(req_headers);
  waitForNextUpstreamRequest();

  Http::TestResponseHeaderMapImpl resp_headers;
  std::for_each(resp_header.begin(),resp_header.end(),
                  [&](const auto& it) { resp_headers.addCopy(it.first,it.second);});

  upstream_request_->encodeHeaders(resp_headers, true);

  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection_->close());
  ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
  fake_upstream_connection_.reset();
  ASSERT_TRUE(response->waitForEndStream());

  // Verify upstream request
  
  if(!exp_upstream_header.empty()) {
    std::for_each(exp_upstream_header.begin(),exp_upstream_header.end(),
                  [&](const auto& it){
                    EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(it.first,it.second));
                  });   
  }
  if(!exp_response_header.empty()) { 
    std::for_each(exp_response_header.begin(),exp_response_header.end(),
                  [&](const auto& it){
                    EXPECT_THAT(response->headers(),Http::HeaderValueOf(it.first,it.second));
                  });     
  }
  codec_client->close();

}
};


// ******************** SCP Config **********************

// check Via header on request/resp for 1 VPN

const std::string config_scp_one_vpn = R"EOF(
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
  own_fqdn: scp.own_plmn.com
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
              term_string: chf-pool
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
)EOF";

// check Via header on request/resp for 2 VPN

const std::string config_scp_two_vpn = R"EOF(
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
  own_fqdn: scp.own_plmn.com
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
              term_string: chf-pool
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
)EOF";

// ******************** SEPP Config **********************

// Check Via Header Int-to-Ext Traffic (Internal n/w listener)

  const std::string config_sepp_int_to_ext{R"EOF(
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
        name: "own network"
        start_fc_list:
          - default_routing
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
      - name: rp_A_pool
        condition:
          op_equals:
            typed_config1:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_reqheader: 3gpp-sbi-target-apiroot
            typed_config2:
              "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value
              term_string: http://rp_A.ext_plmn.com 
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
              term_string: http://rp_B.ext_plmn.com 
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_2
            routing_behaviour: ROUND_ROBIN
            preserve_if_indirect: TARGET_API_ROOT
  roaming_partners:
    - name: rp_1
      pool_name: rp1_pool
      own_network_fqdn: sepp.ext_plmn.com
    - name: rp_2
      pool_name: rp2_pool
      own_network_fqdn: sepp.ext_plmn.com
)EOF"};

// Check Via Header Ext-to-Int Traffic (External n/w listener)

  const std::string config_sepp_ext_to_int{R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.ext_nw.com
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
              term_string: http://nrf.own_plmn.com
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
      own_network_fqdn: sepp.own_plmn.com
    - name: rp_2
      pool_name: rp2_pool
      own_network_fqdn: sepp.own_plmn.com
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

//********************* Config End ************************

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterViaHeaderIntegrationTest,
                         testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest())));

// Scenario: Request from NW1 to NW1 for SCP
// Expect:   Via header with FQDN of NW1 on upstream_request
TEST_P(EricProxyFilterViaHeaderIntegrationTest,Scp1)
{
  std::string cluster = "chf-pool";
  const auto filter_config = {config_scp_one_vpn};

  std::map<std::string,std::string> req_headers {
      {":method", "GET"},
      {":authority", "host"},
      {":path", "/nudm-uecm/v1/imsi-2060330007487/registrations"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"}
    };
  
  std::map<std::string,std::string> resp_headers {
    {":status", "200"}
  };
  std::string via = "2.0 SCP-scp.own_plmn.com";
  testRequest(filter_config,cluster,req_headers,resp_headers,{{"x-cluster",cluster},{"via",via}},
                    {});

}

// Scenario: Request from NW1 to NW2 for SCP
// Expect: Via header with FQDN of NW1 on upstream_request
TEST_P(EricProxyFilterViaHeaderIntegrationTest,Scp2)
{
  std::string cluster = "chf-pool";
  const auto filter_config = {config_scp_two_vpn};

  std::map<std::string,std::string> req_headers {
      {":method", "GET"},
      {":authority", "host"},
      {":path", "/nudm-uecm/v1/imsi-2060330007487/registrations"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"}
    };

  std::map<std::string,std::string> resp_headers{{":status", "200"}};
  // Verify upstream request
  std::string via = "2.0 SCP-scp.own_plmn.com";
 
  testRequest(filter_config,cluster,req_headers,resp_headers,{{"x-cluster",cluster},{"via",via}},
                    {});

}

// Scenario: Request from NW1 to NW2 for SCP and
//           response with error and no server header 
// Expect: Via header with FQDN of NW1
TEST_P(EricProxyFilterViaHeaderIntegrationTest,Scp3)
{
 std::string cluster = "chf-pool";
 
  const auto filter_config = {config_scp_two_vpn};
  std::map<std::string,std::string> req_headers {
      {":method", "GET"},
      {":authority", "host"},
      {":path", "/nudm-uecm/v1/imsi-2060330007487/registrations"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"}
    };

  std::map<std::string,std::string> resp_headers{{":status", "502"}};


  // Verify upstream request
  std::string via = "2.0 SCP-scp.own_plmn.com";
  testRequest(filter_config,cluster,req_headers,resp_headers,{{"x-cluster",cluster},{"via",via}},
                    {{"via",via}});
}


// Scenario: Request from NW1 to NW2 for SCP and
//           response with error and with server header 
// Expect: No Via header in response
TEST_P(EricProxyFilterViaHeaderIntegrationTest,Scp4)
{
  std::string cluster = "chf-pool";
 
  const auto filter_config = {config_scp_two_vpn};
  std::map<std::string,std::string> req_headers {
      {":method", "GET"},
      {":authority", "host"},
      {":path", "/nudm-uecm/v1/imsi-2060330007487/registrations"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"}
    };
  std::map<std::string,std::string> resp_headers{
    {":status", "502"},
    {"server","nfp.some_nw.com"}
  };

  // Verify upstream request
  std::string via = "2.0 SCP-scp.own_plmn.com";
  testRequest(filter_config,cluster,req_headers,resp_headers,{{"x-cluster",cluster},{"via",via}},
                    {});  
  
}

// Scenario: Request from NW1 to NW2 for SCP and
//           response with error and with server header 
// Expect: Via header of own SCP is not added in response, if a Via 
//          header already exist
TEST_P(EricProxyFilterViaHeaderIntegrationTest,Scp5)
{
  std::string cluster = "chf-pool";
  const auto filter_config = {config_scp_two_vpn};
  std::map<std::string,std::string> req_headers {
      {":method", "GET"},
      {":authority", "host"},
      {":path", "/nudm-uecm/v1/imsi-2060330007487/registrations"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-6-mnc-456-mcc-456:3777"}
    };
  std::map<std::string,std::string> resp_headers{
      {":status", "502"},
      {"server","nfp.some_nw.com"},
      {"via","2.0 SCP-peer.proxy.oth_nw.com"},
    };

  // Verify upstream request
  std::string via = "2.0 SCP-peer.proxy.oth_nw.com";
  std::map<std::string,std::string> exp_resp_headers {
    {"via",via}
  };
  
  testRequest(filter_config,cluster,req_headers,resp_headers,{{"x-cluster",cluster}},
                    {{"via",via}});
  
}


// Scenario: Request from NW2(ext) to NW1(int) for SEPP
// Expect:   Via header with FQDN of NW1+NW2 on upstream_request
TEST_P(EricProxyFilterViaHeaderIntegrationTest,Sepp1)
{
 std::string cluster = "nrf_pool";
  const auto filter_config = {config_header_to_metadata,config_sepp_ext_to_int};
  std::map<std::string,std::string> req_headers {
      {":method", "GET"},
      {":authority", "host"},
      {":path", "/nudm-uecm/v1/imsi-2060330007487/registrations"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name","rp_1"},
      {"x-eric-sepp-test-san","rp_A.ext_plmn.com"}
    };
  std::map<std::string,std::string> resp_headers{
      {":status", "200"},
      {"server","nfp.some_nw.com"}
    };

  // Verify upstream request
  std::string via = "2.0 SEPP-sepp.own_plmn.com";
  
  testRequest(filter_config,cluster,req_headers,resp_headers,{{"x-cluster",cluster},{"via",via}},
                    {});  
}

// Scenario: Request from NW1(int) to NW2(ext) for SEPP
// Expect: Via header with FQDN of NW2 on upstream_request
TEST_P(EricProxyFilterViaHeaderIntegrationTest,Sepp2)
{
  std::string cluster = "rp1_pool";
  const auto filter_config = {config_sepp_int_to_ext};
  std::map<std::string,std::string> req_headers {
      {":method", "GET"},
      {":authority", "host"},
      {":path", "/nudm-uecm/v1/imsi-2060330007487/registrations"},
      {"3gpp-Sbi-target-apiRoot", "http://rp_A.ext_plmn.com"}
    };
  std::map<std::string,std::string> resp_headers{
      {":status", "200"},
      {"server","nfp.some_nw.com"}
    };

  // Verify upstream request
  std::string via = "2.0 SEPP-sepp.ext_plmn.com";
  
  testRequest(filter_config,cluster,req_headers,resp_headers,{{"x-cluster",cluster},{"via",via}},
                    {});    
}

// Scenario: Request from NW1(int) to NW2(ext) for SEPP and
//           response with error and no server header 
// Expect: Via header with FQDN of NW1 in response
TEST_P(EricProxyFilterViaHeaderIntegrationTest,Sepp3)
{
std::string cluster = "rp1_pool";
  const auto filter_config = {config_sepp_int_to_ext};
  std::map<std::string,std::string> req_headers {
      {":method", "GET"},
      {":authority", "host"},
      {":path", "/nudm-uecm/v1/imsi-2060330007487/registrations"},
      {"3gpp-Sbi-target-apiRoot", "http://rp_A.ext_plmn.com"}
    };
  std::map<std::string,std::string> resp_headers{
      {":status", "502"},
    };

  // Verify upstream request
  std::string via_resp = "2.0 SEPP-sepp.own_plmn.com";
  std::string via_req = "2.0 SEPP-sepp.ext_plmn.com";
  
  testRequest(filter_config,cluster,req_headers,resp_headers,{{"x-cluster",cluster},{"via",via_req}},
                    {{"via",via_resp}});      
}

// Scenario: Request from NW2(ext) to NW1(int) for SEPP and
//           response with error and no server header 
// Expect: Via header with FQDN of NW2 in response
TEST_P(EricProxyFilterViaHeaderIntegrationTest,Sepp4)
{
  std::string cluster = "nrf_pool";
  const auto filter_config = {config_header_to_metadata,config_sepp_ext_to_int};
  std::map<std::string,std::string> req_headers {
      {":method", "GET"},
      {":authority", "host"},
      {":path", "/nudm-uecm/v1/imsi-2060330007487/registrations"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name","rp_1"},
      {"x-eric-sepp-test-san","rp_A.ext_plmn.com"}
    };
  std::map<std::string,std::string> resp_headers{
      {":status", "502"},
    };

  // Verify upstream request
  std::string via_req = "2.0 SEPP-sepp.own_plmn.com";
  std::string via_resp = "2.0 SEPP-sepp.ext_nw.com";
  
  testRequest(filter_config,cluster,req_headers,resp_headers,{{"x-cluster",cluster},{"via",via_req}},
                    {{"via",via_resp}});     

}


// Scenario: Request from NW2(ext) to NW1(int) for SEPP and
//           response with error and with server header 
// Expect: No Via header of own SEPP added to the existing list
TEST_P(EricProxyFilterViaHeaderIntegrationTest,Sepp5)
{
  std::string cluster = "nrf_pool";
  const auto filter_config = {config_header_to_metadata,config_sepp_ext_to_int};
  std::map<std::string,std::string> req_headers {
      {":method", "GET"},
      {":authority", "host"},
      {":path", "/nudm-uecm/v1/imsi-2060330007487/registrations"},
      {"3gpp-Sbi-target-apiRoot", "http://nrf.own_plmn.com"},
      {"x-eric-sepp-rp-name","rp_1"},
      {"x-eric-sepp-test-san","rp_A.ext_plmn.com"}
    };
  std::map<std::string,std::string> resp_headers{
      {":status", "502"},
      {"via","peer_proxy.own_nw.com"},
      {"server","nf_prod.own_nw.com"}
    };

  // Verify upstream request
  std::string via_req = "2.0 SEPP-sepp.own_plmn.com";
  std::string via_resp = "peer_proxy.own_nw.com";
  
  testRequest(filter_config,cluster,req_headers,resp_headers,{{"x-cluster",cluster},{"via",via_req}},
                    {{"via",via_resp}});   
}




} // namespace
} // EricProxy
} // HttpFilters
} // Extensions
} // Envoy