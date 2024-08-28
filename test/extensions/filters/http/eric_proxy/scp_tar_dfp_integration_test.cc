#include "envoy/http/codes.h"
#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.pb.h"
#include "envoy/http/codes.h"
#include "envoy/http/filter.h"
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"

#include <ostream>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyTaRNotifyIntegrationTest: public HttpIntegrationTest,
                                        public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyTaRNotifyIntegrationTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(),
                            EricProxyTaRNotifyIntegrationTest::ericProxyHttpBaseConfig()) {}
  void SetUp() override { }
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config, const int& upstream_count) {
    config_helper_.addFilter(config);
    setUpstreamCount(upstream_count);
    HttpIntegrationTest::initialize();
  }

  std::string ericProxyHttpBaseConfig() {
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
                    - name: x-eric-fop
                      string_match:
                        exact: notify_and_slc_terminate
                    - name: 3gpp-sbi-callback 
                    - name: x-eric-proxy
                      string_match:
                        exact: ///
                    - name: :scheme
                      string_match:
                        exact: http
                route:
                  cluster: cluster_0
              - name: route1
                match:
                  prefix: "/"
                route:
                  cluster: cluster_0
  )EOF", Platform::null_device_path));
  }

  
  const std::string config_eric_proxy= R"EOF(
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
      - name: default_route
        condition:
          term_boolean: true
        actions:
        - action_add_header:
            name: "x-eric-fop"
            value:
              term_string: notify_and_slc_terminate
            if_exists: REPLACE
        - action_route_to_pool:
            pool_name:
              term_string: universal
            routing_behaviour: STRICT_DFP 
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
)EOF";

void testDfpTaR()
{
  initializeFilter(config_eric_proxy,1);


  Http::TestRequestHeaderMapImpl headers {
    {":method","POST"},
    {":path", "/" },
    {":authority","host"},
    {"3gpp-Sbi-target-apiRoot", "http://host-test:9980"},
    {"3gpp-sbi-callback","Nnrf_NFStatus"}

  };

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;

  codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(headers);
  FakeStreamPtr upstream_request_;

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, upstream_request_));

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
  };  

  upstream_request_->encodeHeaders(response_headers, true);

  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());

  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("x-eric-fop","notify_and_slc_terminate"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf(":authority","host-test:9980"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("3gpp-sbi-target-apiroot","http://host-test:9980"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("3gpp-sbi-callback","Nnrf_NFStatus"));
  codec_client->close();
}
                                        };

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyTaRNotifyIntegrationTest,
                    testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

// DND-38571 Testing for new RoutingBehavior Enum STRICT_DFP
// which modifies authority header with host_port from TaR
TEST_P(EricProxyTaRNotifyIntegrationTest, Test1)
{
  testDfpTaR();
}

TEST_P(EricProxyTaRNotifyIntegrationTest,Test2)
{
  initializeFilter(config_eric_proxy, 1);
  Http::TestRequestHeaderMapImpl headers {
    { ":path","/" },
    {":method", "POST"},
    {":authority","host:8080"},
    {"3gpp-sbi-target-apiroot","http://host-new:8090"},
    {"3gpp-sbi-callback","Nnrf_NFStatus"}
  };

  IntegrationCodecClientPtr codec_client_ = makeHttpConnection(lookupPort("http"));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(headers);
  waitForNextUpstreamRequest(0);

  Http::TestResponseHeaderMapImpl resp_hdrs{
    {":status","200"},
    {"dummy-hdr","new-dummy-hdr value"},
  };

  upstream_request_->encodeHeaders(resp_hdrs, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("x-eric-fop", "notify_and_slc_terminate"));
  EXPECT_THAT(response->headers().getStatusValue(),
              "200");
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("3gpp-sbi-target-apiroot","http://host-new:8090"));
  codec_client_->close();

}

}
}
}
}
}
//