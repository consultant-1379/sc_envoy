#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/extensions/filters/http/eric_proxy/tfqdn_codec.h"
#include "base_integration_test.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"
#include <iostream>
#include <ostream>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

// Test correct handling of server-header:
// - If the response comes from upstream, don't add or modify server header
// - If the response comes from Envoy or our filter (incl. action-reject), set the server-header to our FQDN

// TODO(eedala): remove unnecessary configuration

std::string config_basic = R"EOF(
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
      - name: c_no_test_reject
        condition:
          op_exists: {arg1: {term_reqheader: 'test'}}
        actions:
        - action_reject_message:
            status: 543
            title: "reject test"
            message_format: PLAIN_TEXT
      - name: c_tar_nf1_other_plmn
        condition:
          op_and:
            arg1:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://nf1.other-plmn.com:5678'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':authority'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'sepp.own_plmn.com:80'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: c_tar_nf1_other_plmn
            routing_behaviour: ROUND_ROBIN
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

std::string local_reply_config = {R"EOF(
mappers:
- filter:
    metadata_filter:
      matcher:
        filter: eric_filter
        path:
        - key: local_replied
        value:
          string_match:
            exact: 'true'
      match_if_key_not_found: false
- filter:
    response_flag_filter:
      flags:
      - NC
  status_code: 500
  body_format_override:
    json_format:
      title: Internal Server Error
      status: 500
      cause: SYSTEM_FAILURE
      detail: "%RESPONSE_CODE_DETAILS%"
    content_type: application/problem+json
)EOF"};


//------------------------------------------------------------------------
// Converged-Charging Create Response Body (shortened)
const std::string cc_create_resp_body{R"(
{
  "invocationSequenceNumber": 1,
  "invocationTimeStamp": "2019-03-28T14:30:51.888+0100"
}
  )"};



//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------
// C-SEPP
class EricProxyFilterSeppTFqdnIntegrationTest : public EricProxyIntegrationTestBase,
                                        public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterSeppTFqdnIntegrationTest()
      : EricProxyIntegrationTestBase(Http::CodecClient::Type::HTTP1, GetParam(), EricProxyFilterSeppTFqdnIntegrationTest::ericProxyHttpProxyConfig()) {
      }
  void SetUp() override { }
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);

    HttpIntegrationTest::initialize();
  }

  void setLocalReplyConfig(const std::string& yaml) {
    envoy::extensions::filters::network::http_connection_manager::v3::LocalReplyConfig
        local_reply_config;
    TestUtility::loadFromYaml(yaml, local_reply_config);
    config_helper_.setLocalReply(local_reply_config);
  }

  // Common configuration that sets the start-routingcase
  std::string ericProxyHttpProxyConfig() {
    return absl::StrCat(ConfigHelper::baseConfig(), fmt::format(R"EOF(
    filter_chains:
      filters:
        name: http
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          server_header_transformation: APPEND_IF_ABSENT
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
  )EOF",Platform::null_device_path));
  }

};


//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------
INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterSeppTFqdnIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

// 200 response from upstream without server header -> don't add server header
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, Test200noServerHeader) {
    // The authority-header contains a T-FQDN to trigger the conversion of a Location header
    // in the response:
    Http::TestRequestHeaderMapImpl request_headers{
        {":method", "POST"},
        {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
        {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
        {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
    };
    // Verify no server header exists
    config_helper_.addFilter(config_basic);
    initialize();

    Http::TestResponseHeaderMapImpl response_headers{
        {":status", "200"},
        {"content-length", std::to_string(cc_create_resp_body.length())},
        {"content-type", "application/json"},
    };
    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
    waitForNextUpstreamRequest();

    // Send response:
    upstream_request_->encodeHeaders(response_headers, false);
    Buffer::OwnedImpl response_data(cc_create_resp_body);
    upstream_request_->encodeData(response_data, true);
    ASSERT_TRUE(response->waitForEndStream());

    EXPECT_TRUE(response->headers().get(Http::LowerCaseString("server")).empty());
}


// 200 response from upstream with server header -> don't change server header
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, Test200withServerHeader) {
    // The authority-header contains a T-FQDN to trigger the conversion of a Location header
    // in the response:
    Http::TestRequestHeaderMapImpl request_headers{
        {":method", "POST"},
        {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
        {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
        {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
    };
    // Verify no server header exists
    config_helper_.addFilter(config_basic);
    initialize();

    Http::TestResponseHeaderMapImpl response_headers{
        {":status", "200"},
        {"content-length", std::to_string(cc_create_resp_body.length())},
        {"content-type", "application/json"},
        {"server", "http://server.3gpp.org"},
    };
    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
    waitForNextUpstreamRequest();

    // Send response:
    upstream_request_->encodeHeaders(response_headers, false);
    Buffer::OwnedImpl response_data(cc_create_resp_body);
    upstream_request_->encodeData(response_data, true);
    ASSERT_TRUE(response->waitForEndStream());

    EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "http://server.3gpp.org"));
}


// 500 response from upstream without server header -> don't add server header
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, Test500noServerHeader) {
    // The authority-header contains a T-FQDN to trigger the conversion of a Location header
    // in the response:
    Http::TestRequestHeaderMapImpl request_headers{
        {":method", "POST"},
        {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
        {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
        {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
    };
    // Verify no server header exists
    config_helper_.addFilter(config_basic);
    initialize();

    Http::TestResponseHeaderMapImpl response_headers{
        {":status", "500"},
        {"content-length", std::to_string(cc_create_resp_body.length())},
        {"content-type", "application/json"},
    };
    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
    waitForNextUpstreamRequest();

    // Send response:
    upstream_request_->encodeHeaders(response_headers, false);
    Buffer::OwnedImpl response_data(cc_create_resp_body);
    upstream_request_->encodeData(response_data, true);
    ASSERT_TRUE(response->waitForEndStream());

    EXPECT_TRUE(response->headers().get(Http::LowerCaseString("server")).empty());
}


// 500 response from upstream with server header -> don't change server header
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, Test500withServerHeader) {
    // The authority-header contains a T-FQDN to trigger the conversion of a Location header
    // in the response:
    Http::TestRequestHeaderMapImpl request_headers{
        {":method", "POST"},
        {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
        {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
        {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
    };
    // Verify no server header exists
    config_helper_.addFilter(config_basic);
    initialize();

    Http::TestResponseHeaderMapImpl response_headers{
        {":status", "500"},
        {"content-length", std::to_string(cc_create_resp_body.length())},
        {"content-type", "application/json"},
        {"server", "http://server.3gpp.org"},
    };
    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
    waitForNextUpstreamRequest();

    // Send response:
    upstream_request_->encodeHeaders(response_headers, false);
    Buffer::OwnedImpl response_data(cc_create_resp_body);
    upstream_request_->encodeData(response_data, true);
    ASSERT_TRUE(response->waitForEndStream());

    EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "http://server.3gpp.org"));
}


// 5xx response from Envoy internal -> add Envoy server header
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, Test500EnvoyInternal) {
    config_helper_.addConfigModifier(
      [&](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager&
              hcm) -> void {
        auto* route_config = hcm.mutable_route_config();
        route_config->mutable_validate_clusters()->set_value(false);
      });

  setLocalReplyConfig(local_reply_config);
  auto host = config_helper_.createVirtualHost("foo.com", "/unknown", "unknown_cluster");
  host.mutable_routes(0)->mutable_route()->set_cluster_not_found_response_code(
      envoy::config::route::v3::RouteAction::NOT_FOUND);
  config_helper_.addVirtualHost(host);
  initialize();

  BufferingStreamDecoderPtr response = IntegrationUtil::makeSingleRequest(
      lookupPort("http"), "GET", "/unknown", "", downstream_protocol_, version_, "foo.com");
  ASSERT_TRUE(response->complete());

    EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "envoy"));
}




// 543 response from eric_proxy filter (action-reject) -> add Envoy server header
TEST_P(EricProxyFilterSeppTFqdnIntegrationTest, Test500RejectInScreening) {
    Http::TestRequestHeaderMapImpl request_headers{
        {":method", "POST"},
        {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
        {":authority", "host"},
        {"test", "TEST"},
    };
    // Verify no server header exists
    config_helper_.addFilter(config_basic);
    initialize();

    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(request_headers);

    ASSERT_TRUE(response->waitForEndStream());

    EXPECT_THAT(response->headers(), Http::HeaderValueOf("server", "envoy"));
    codec_client_->close();
}




} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
