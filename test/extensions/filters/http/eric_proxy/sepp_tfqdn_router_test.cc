#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "base_integration_test.h"
#include "config_utils/pluggable_configurator.h"
#include "config_utils/endpoint_md_cluster_md_configurator.h"
#include "source/extensions/filters/http/eric_proxy/tfqdn_codec.h"
#include "test/integration/http_integration.h"
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
using ClusterDict = std::vector<std::map<std::string, std::vector<std::string>>>;
enum Scope { ALL, SOME, NONE };

// Porting of sepp_tfqdn_router_integration tests
// These tests were earlier doing mock router tests since we didnt know
// back then how to attach endpoint MD and run specific parts of
// onUpstreamHostSelected() , since we now basically force router interaction
// on  every test file, the tfqdn_router mock tests have become redundant 
// so their use-cases are ported to actual router integration tests which
// are more precise validation of router behavior


std::string config_basic_ext_to_int = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_fqdn: sepp.ownplmn.com
  own_external_port: 9090
  rp_name_table: rp_san_to_name
  request_filter_cases:
    routing:
      ext_nw:
        name: ext_network
        ext_nw_fc_config_list: 
        - per_rp_fc_config:
            rp_to_fc_map:
              rp_A: default_routing
  key_value_tables:
    - name: 'rp_san_to_name' 
      entries:
        - key: 'smf1.external_plmn.com'
          value: rp_A
  callback_uri_klv_table: 'callback_uris'
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
      - name: route_to_universal
        condition:
            term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: 'universal-pool'
            routing_behaviour: PREFERRED
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

  // Base configuration for the testcase
  static std::string baseConfigRetry() {
    return fmt::format(R"EOF(
admin:
  access_log_path: {dev_null_path}
  address:
    socket_address:
      address: '127.0.0.1'
      port_value: 0
dynamic_resources:
  lds_config:
    resource_api_version: 'V3'
    path: {dev_null_path}
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
              path: {dev_null_path}
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
                    - name: x-cluster
                      string_match:
                        exact: 'universal-pool'
                route:
                  cluster_header: x-cluster
                  retry_policy:
                    retry_on: "retriable-status-codes"
                    num_retries: 2
                    retry_priority:
                      name: "envoy.retry_priorities.eric_reselect_priorities"
                      typed_config:
                        "@type": type.googleapis.com/envoy.extensions.retry.priority.eric_reselect_priorities.v3.EricReselectPrioritiesConfig
                        preferred_host_retries: 1
                        failover_reselects: 1
                        last_resort_reselects: 0
                    retry_host_predicate:  
                    - name: 'envoy.retry_host_predicates.eric_loop_prevention'
                    - name: 'envoy.retry_host_predicates.previous_hosts'
                    host_selection_retry_max_attempts: 3
                    retriable_status_codes: 
                    - 500 
                    - 501 
                    - 502 
                    - 503 
)EOF",
    "dev_null_path"_a=Platform::null_device_path);
  }



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

// Converged-Charging Create Request Body (shortened)
const std::string cc_create_req_body_tfqdn{R"(
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
    "notifyUri": "http://Qh192v168v0v2j8080.sepp.ownplmn.com/rar",
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

 

//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------
// Cluster config is here so that we can define our own endpoint-metadata
class EricProxyFilterSeppTFqdnRouterTest : public PluggableConfigurator {
public:
  EricProxyFilterSeppTFqdnRouterTest(): PluggableConfigurator(baseConfigRetry()) {}
  void testTfqdnRouter( std::vector<uint64_t> exp_host_list,
                        Http::TestRequestHeaderMapImpl& req_hdr,
                        std::vector<Http::TestResponseHeaderMapImpl> resp_hdr,
                        Json* req_body,
                        std::vector<Json*> resp_body,
                        std::vector<std::map<std::string,std::string>>& exp_upstream_header,
                        std::map<std::string,std::string> exp_resp_header,
                        std::vector<Json*> exp_upstream_body,
                        Json* exp_resp_body) {

      codec_client_ = makeHttpConnection(lookupPort("http"));
      auto response = codec_client_->makeRequestWithBody(req_hdr, req_body->get<std::string>());
      int i = 0;
      for(const auto& idx : exp_host_list){
        waitForNextUpstreamRequest(idx);

        // Send upstream response
        if(!resp_hdr.empty()) {
          if(resp_body.empty() || resp_body.at(i) == nullptr) {
            upstream_request_->encodeHeaders(resp_hdr.at(i), true);
          } else {
            upstream_request_->encodeHeaders(resp_hdr.at(i), false);
            upstream_request_->encodeData(resp_body.at(i)->get<std::string>(),true);
          }

        }

        ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
        ASSERT_TRUE(fake_upstream_connection_->close());
        ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
        fake_upstream_connection_.reset();

        // Verify upstream request
        for(auto itr = exp_upstream_header.at(i).begin(); itr != exp_upstream_header.at(i).end();itr++)
        {
          EXPECT_THAT(upstream_request_->headers(),Http::HeaderValueOf(itr->first,itr->second));
        }
        if(! exp_upstream_body.empty() && exp_upstream_body.at(i) != nullptr) {
          Json actual_body = Json::parse(upstream_request_->body().toString()) ;
          // const auto& actual_body_ref = actual_body;
          const auto exp_body_ref = *exp_upstream_body.at(i);
          // auto res = actual_body==exp_body_ref;
          // EXPECT_THAT(upstream_request_->body().toString(),exp_upstream_body.at(i)->get<std::string>());
          EXPECT_TRUE(actual_body==exp_body_ref);
          // ENVOY_LOG(debug,"### debug act_body:\n{}",actual_body.get<std::string>());
          // ENVOY_LOG(debug,"### debug exp_body:\n{}",exp_body_ref.get<std::string>());
          // ENVOY_LOG(debug,"### debug is body same ?:{}",res);
        }
        i++;
      }

      ASSERT_TRUE(response->waitForEndStream());
      if(exp_resp_body != nullptr){
        EXPECT_THAT(response->body().c_str(),exp_resp_body->get<std::string>());
      }
      for(auto itr = exp_resp_header.begin(); itr != exp_resp_header.end();itr++)
      {
        EXPECT_THAT(response->headers(),Http::HeaderValueOf(itr->first,itr->second));
      }

      codec_client_->close();


  }
};

//-----------------------------------------------------------------------
// All tests have an option of 1 preferred host retry + 1 failover reselect to a peer
// with opposite support val than the first so as to simulate reselection between 
// an endpoint with support TFQDN and support NF
INSTANTIATE_TEST_SUITE_P(IpVersions,EricProxyFilterSeppTFqdnRouterTest,
                         testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest())));

// Request from external to internal n/w endpoint supports TaR
TEST_P(EricProxyFilterSeppTFqdnRouterTest,Test1) {
   EndpointMetadataClusterConfigurator cluster_config =
    EndpointMetadataClusterConfigurator().withClusterBuilder(
        ClusterBuilder()
            .withName("universal-pool")
            .withEndpoint(EndpointBuilder()
                            .withHostName("nf.ownplmn.com:80")
                            .withHostMd({{"support",{"NF"}}}))
            .withEndpoint(EndpointBuilder()
                            .withHostName("tnf.ownplmn.com:80")
                            .withHostMd({{"support",{"TFQDN"}}})));
    initConfig({config_header_to_metadata,config_basic_ext_to_int},cluster_config);

    Http::TestRequestHeaderMapImpl headers {
        {":method","GET"},
        {":path","/nchf-convergedcharging/v2/chargingdata"},
        {":authority","sepp.ownplmn.com:9090"},
        {"3gpp-sbi-target-apiroot","https://nf.ownplmn.com:80"},
        {"x-eric-sepp-rp-name","rp_A"},
    };
    Http::TestRequestHeaderMapImpl resp_hdr{
      {":status","200"}
    };
    Json req_body = Json(cc_create_req_body);
    Json req_body_original = Json::parse(cc_create_req_body);
    auto cl = std::to_string(cc_create_req_body.length());
    std::vector<std::map<std::string,std::string>> exp_headers = 
                  {
                    {{"x-cluster","universal-pool"},{"content-length",cl.c_str()}}
                  };

    std::map<std::string,std::string> exp_resp_headers = 
                  {
                    {":status","200"}
                  };
    testTfqdnRouter({0}, headers,
                    { resp_hdr }, &req_body,{nullptr},exp_headers,
                    exp_resp_headers,{&req_body_original}, nullptr);

                
}

// Request from external to internal n/w endpoint doesnt support TaR
TEST_P(EricProxyFilterSeppTFqdnRouterTest,Test2) {
EndpointMetadataClusterConfigurator cluster_config =
    EndpointMetadataClusterConfigurator().withClusterBuilder(
        ClusterBuilder()
            .withName("universal-pool")
            .withEndpoint(EndpointBuilder()
                            .withHostName("nf.ownplmn.com:80")
                            .withHostMd({{"support",{"NF"}}}))
            .withEndpoint(EndpointBuilder()
                            .withHostName("tnf.ownplmn.com:80")
                            .withHostMd({{"support",{"TFQDN"}}})));
    initConfig({config_header_to_metadata,config_basic_ext_to_int},cluster_config);

    Http::TestRequestHeaderMapImpl headers {
        {":method","GET"},
        {":path","/nchf-convergedcharging/v2/chargingdata"},
        {":authority","sepp.ownplmn.com:9090"},
        {"3gpp-sbi-target-apiroot","https://tnf.ownplmn.com:80"},
        {"x-eric-sepp-rp-name","rp_A"},
    };

    Json req_body = Json(cc_create_req_body);
    Json req_body_tfqdn = Json::parse(cc_create_req_body_tfqdn);
    auto cl = std::to_string(cc_create_req_body.length());
    std::vector<std::map<std::string,std::string>> exp_headers = 
                  {
                    {{"x-cluster","universal-pool"}}
                  };

    std::map<std::string,std::string> exp_resp_headers = 
                  {
                    {":status","200"}
                  };
    Http::TestRequestHeaderMapImpl resp_hdr{
      {":status","200"}
    };

     testTfqdnRouter({1}, headers,
                    { resp_hdr }, &req_body,{nullptr},exp_headers,
                    exp_resp_headers,{&req_body_tfqdn}, nullptr);


}

// Request from external to internal n/w preferred host (supports TaR) fails reselects to
// Tfqdn Endpoint
TEST_P(EricProxyFilterSeppTFqdnRouterTest,Test3) {
  EndpointMetadataClusterConfigurator cluster_config =
    EndpointMetadataClusterConfigurator().withClusterBuilder(
        ClusterBuilder()
            .withName("universal-pool")
            .withEndpoint(EndpointBuilder()
                            .withHostName("nf.ownplmn.com:80")
                            .withHostMd({{"support",{"NF"}}}))
            .withEndpoint(EndpointBuilder()
                            .withHostName("tnf.ownplmn.com:80")
                            .withHostMd({{"support",{"TFQDN"}}})));
    initConfig({config_header_to_metadata,config_basic_ext_to_int},cluster_config);

    Http::TestRequestHeaderMapImpl headers {
        {":method","GET"},
        {":path","/nchf-convergedcharging/v2/chargingdata"},
        {":authority","sepp.ownplmn.com:9090"},
        {"3gpp-sbi-target-apiroot","https://nf.ownplmn.com:80"},
        {"x-eric-sepp-rp-name","rp_A"},
    };
    Json req_body = Json(cc_create_req_body);
    Json req_body_original = Json::parse(cc_create_req_body);
    Json req_body_tfqdn = Json::parse(cc_create_req_body_tfqdn);
    auto cl = std::to_string(cc_create_req_body.length());
    std::vector<std::map<std::string,std::string>> exp_headers = 
                  {
                    {{"x-cluster","universal-pool"}},
                    {{"x-cluster","universal-pool"}},
                    {{"x-cluster","universal-pool"}}
                  };

    std::map<std::string,std::string> exp_resp_headers = 
                  {
                    {":status","200"}
                  };
    Http::TestRequestHeaderMapImpl resp_hdr_2xx{
      {":status","200"}
    };
    Http::TestRequestHeaderMapImpl resp_hdr_5xx{
      {":status","500"}
    };
    testTfqdnRouter({0,0,1}, headers, {resp_hdr_5xx,resp_hdr_5xx,resp_hdr_2xx}, 
                      &req_body, {nullptr,nullptr,nullptr}, 
                      exp_headers, exp_resp_headers, 
                      {&req_body_original,&req_body_original,&req_body_tfqdn},nullptr) ; 

}

// Request from external to internal n/w prefeirred host (supports Tfqdn) fails reselects
// to TaR endpoint
TEST_P(EricProxyFilterSeppTFqdnRouterTest,Test4) {

    EndpointMetadataClusterConfigurator cluster_config =
    EndpointMetadataClusterConfigurator().withClusterBuilder(
        ClusterBuilder()
            .withName("universal-pool")
            .withEndpoint(EndpointBuilder()
                            .withHostName("nf.ownplmn.com:80")
                            .withHostMd({{"support",{"NF"}}}))
            .withEndpoint(EndpointBuilder()
                            .withHostName("tnf.ownplmn.com:80")
                            .withHostMd({{"support",{"TFQDN"}}})));
    initConfig({config_header_to_metadata,config_basic_ext_to_int},cluster_config);

    Http::TestRequestHeaderMapImpl headers {
        {":method","GET"},
        {":path","/nchf-convergedcharging/v2/chargingdata"},
        {":authority","sepp.ownplmn.com:9090"},
        {"3gpp-sbi-target-apiroot","https://tnf.ownplmn.com:80"},
        {"x-eric-sepp-rp-name","rp_A"},
    };
    Json req_body = Json(cc_create_req_body);
    Json req_body_original = Json::parse(cc_create_req_body);
    Json req_body_tfqdn = Json::parse(cc_create_req_body_tfqdn);
    auto cl = std::to_string(cc_create_req_body.length());
    std::vector<std::map<std::string,std::string>> exp_headers = 
                  {
                    {{"x-cluster","universal-pool"}},
                    {{"x-cluster","universal-pool"}},
                    {{"x-cluster","universal-pool"}}
                  };

    std::map<std::string,std::string> exp_resp_headers = 
                  {
                    {":status","200"}
                  };
    Http::TestRequestHeaderMapImpl resp_hdr_2xx{
      {":status","200"}
    };
    Http::TestRequestHeaderMapImpl resp_hdr_5xx{
      {":status","500"}
    };
    testTfqdnRouter({1,1,0}, headers, {resp_hdr_5xx,resp_hdr_5xx,resp_hdr_2xx}, 
                      &req_body, {nullptr,nullptr,nullptr}, 
                      exp_headers, exp_resp_headers, 
                      {&req_body_tfqdn,&req_body_tfqdn,&req_body_original},nullptr) ;
    
}


} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy