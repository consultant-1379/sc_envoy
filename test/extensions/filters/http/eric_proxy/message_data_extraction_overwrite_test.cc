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

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

//------------------------------------------------
//-------------CONFIGS FOR TC---------------------
//------------------------------------------------

//-------------------------------------------------------
//-------------CONFIGS FOR DND-29092---------------------
// Match with first regex put extracted val in variable
// Dont match with second variable
// EXpected value of variable is of first match
//--------------------------------------------------------

  const std::string config_multi_regex = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  own_internal_port: 80
  node_type: SEPP
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
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
      - name: fall_through
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong-pool
            routing_behaviour: ROUND_ROBIN

  )EOF";

//-------------------------------------------------------
//-------------CONFIGS FOR Alexindros bug ---------------------
// Match with first header put extracted val in variable
// Dont match with second regex
// EXpected value of variable is of first match
//--------------------------------------------------------

    const std::string config_multi_variable_regex = R"EOF(
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
  filter_cases:
    - name: default_routing
      filter_data:
      - name: amf-mcc-ex-1
        header: 3gpp-Sbi-target-apiRoot
        variable_name: mcc
      - name: amf-mcc-ex-2
        path: true
        extractor_regex: /nudm-uecm/v1/imsi-(?P<mcc>\d\d\d)(?P<mnc>\d\d\d)\d+/registrations
      filter_rules:
      - name: correct_route
        condition:
          op_equals: 
            typed_config1: 
              '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
              term_var: mcc 
            typed_config2: 
              '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
              term_string: 'dummy-target-apiRoot' 
        actions:
          - action_route_to_pool:
              pool_name:
                term_string: correct-pool
              routing_behaviour: ROUND_ROBIN
      - name: fall_through
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong-pool
            routing_behaviour: ROUND_ROBIN

  )EOF";

const std::string config_multi_regex_variable = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SCP
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
      - name: amf-mcc-ex-2
        path: true
        extractor_regex: /nudm-uecm/v1/imsi-(?P<mcc>\d\d\d)(?P<mnc>\d\d\d)\d+/registrations
      - name: amf-mcc-ex-1
        header: 3gpp-Sbi-target-apiRoot
        variable_name: mcc
      filter_rules:
      - name: correct_route
        condition:
          op_equals: 
            typed_config1: 
              '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
              term_var: mcc 
            typed_config2: 
              '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
              term_string: '206' 
        actions:
          - action_route_to_pool:
              pool_name:
                term_string: correct-pool
              routing_behaviour: ROUND_ROBIN
      - name: fall_through
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong-pool
            routing_behaviour: ROUND_ROBIN

  )EOF";



//------------------------------------------------
//-------------CONFIGS FOR TC---------------------
//------------------------------------------------

    class EricProxyFilterDataOverWriteTest : public EricProxyIntegrationTestBase ,
                        public testing::TestWithParam<Network::Address::IpVersion> {

public :
    EricProxyFilterDataOverWriteTest() 
    :EricProxyIntegrationTestBase(Http::CodecClient::Type::HTTP1
    , GetParam()
    , EricProxyFilterDataOverWriteTest::ericProxyHttpConfig()) {
     //  setUpstreamCount(1); // number of lb_endpoints in the config below

    }

  void SetUp() override { }
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);

    HttpIntegrationTest::initialize();
  }

  // Common configuration that sets the start-routingcase
  std::string ericProxyHttpConfig() {
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
  )EOF", Platform::null_device_path));
  }


};
// End Initializer Class
//------------------------------------------------------------------------
//-------------BEGIN TEST SUITES---------------------
//------------------------------------------------------------------------
INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterDataOverWriteTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

// Scenario as per DND-29092
// Match with first condition and extract into variable
// and then not match with second condition :: Expected op -  
// variable is notEmpty because it matched and extracted under first condition

TEST_P(EricProxyFilterDataOverWriteTest , TestMessageDataVariableOverwrite_Nudm)
{
  config_helper_.addFilter(config_multi_regex);
  HttpIntegrationTest::initialize();


  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/nudm-uecm/v1/imsi-2060330007487/registrations"},
  };
  auto response = codec_client->makeHeaderOnlyRequest(req_headers);
  
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForEndStream());
  
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("x-cluster","correct-pool"));


  codec_client->close();

}


TEST_P(EricProxyFilterDataOverWriteTest , TestMessageDataVariableOverwrite_Namf)
{
  config_helper_.addFilter(config_multi_regex);
  HttpIntegrationTest::initialize();


  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/namf-comm/v1/ue-contexts/imsi-2060330007487/n1-n2-messages/subscriptions"},
  };
  auto response = codec_client->makeHeaderOnlyRequest(req_headers);
  
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForEndStream());
  
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("x-cluster","correct-pool"));


  codec_client->close();

}

//-------------------------------------------------------
//-------------TCs FOR Alexindros bug ---------------------
// Match with first header put extracted val in variable
// Dont match with second regex
// EXpected value of variable is of first match
//--------------------------------------------------------

TEST_P(EricProxyFilterDataOverWriteTest , TestMessageDataVariableOverwrite_variable_regex)
{
  config_helper_.addFilter(config_multi_variable_regex);
  HttpIntegrationTest::initialize();


  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {"3gpp-sbi-target-apiroot", "dummy-target-apiRoot"},
    {":path", "/namf-comm/v1/ue-contexts/imsi-2060330007487/n1-n2-messages/subscriptions"},
  };
  auto response = codec_client->makeHeaderOnlyRequest(req_headers);
  
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForEndStream());
  
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("x-cluster","correct-pool"));


  codec_client->close();

}

TEST_P(EricProxyFilterDataOverWriteTest , TestMessageDataVariableOverwrite_regex_variable)
{
  config_helper_.addFilter(config_multi_regex_variable);
  HttpIntegrationTest::initialize();


  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/nudm-uecm/v1/imsi-2060330007487/registrations"},
  };
  auto response = codec_client->makeHeaderOnlyRequest(req_headers);
  
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForEndStream());
  
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("x-cluster","correct-pool"));


  codec_client->close();

}

TEST_P(EricProxyFilterDataOverWriteTest , TestMessageDataVariableOverwrite_regex_variable_2)
{
  config_helper_.addFilter(config_multi_regex_variable);
  HttpIntegrationTest::initialize();


  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/nudm-uecm/v1/imsi-2060330007487/registrations"},
  };
  auto response = codec_client->makeHeaderOnlyRequest(req_headers);
  
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForEndStream());
  
  EXPECT_THAT(request_stream->headers(),Http::HeaderValueOf("x-cluster","correct-pool"));


  codec_client->close();

}


//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------


} //NO NS
}// Eric Proxy
} // HttpFilters
} // Extensions
} // Envoy
