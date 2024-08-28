#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/extensions/filters/http/eric_proxy/tfqdn_codec.h"
#include "base_integration_test.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"
#include <algorithm>
#include <iostream>
#include <ostream>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

std::string config_basic = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  nf_peer_info_handling: "ON"
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 80
  request_filter_cases:
    in_request_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - sc_ph3
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
    out_request_screening:
      cluster_fc_config_list:
      - cluster_to_fc_map:
          sepp_rp_A: sc_ph3
  response_filter_cases:
    out_response_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - response_processing
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
    - name: response_processing
      filter_rules:
      - name: delete_resp_nf_header
        condition:
           op_exists: { arg1: {term_respheader: 'please_delete'}}
        actions:
        - action_remove_header:
            name: 3gpp-Sbi-NF-Peer-Info
    - name: sc_ph3
      filter_rules:
      - name: del_header
        condition:
          op_exists: { arg1: {term_reqheader: 'please_delete'}}
        actions:
        - action_remove_header:
            name: "3gpp-Sbi-NF-Peer-Info"
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_A
            routing_behaviour: ROUND_ROBIN
    - name: default_routing
      filter_data:
      - name: apiRoot_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      - name: apiRoot_header
        header: 3gpp-Sbi-target-apiRoot
        variable_name:  apiRoot_hdr
      filter_rules:
      - name: to_rp_A
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
      - name: to_scp
        condition:
          op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-sbi-target-apiroot'},
                      typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'http://scp_test:5678'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: cluster_scp
            routing_behaviour: ROUND_ROBIN
      - name: to_cluster_nf
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: cluster_nf
            routing_behaviour: PREFERRED
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
  roaming_partners:
    - name: rp_A
      pool_name: sepp_rp_A
)EOF";

const std::string cc_create_resp_body{R"(
{
  "invocationSequenceNumber": 1,
  "invocationTimeStamp": "2019-03-28T14:30:51.888+0100"
}
  )"};

class EricProxySbiNfPeerInfoIntegrationTest
    : public EricProxyIntegrationTestBase,
      public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxySbiNfPeerInfoIntegrationTest()
      : EricProxyIntegrationTestBase(
            Http::CodecClient::Type::HTTP1, GetParam(),
            EricProxySbiNfPeerInfoIntegrationTest::ericProxyHttpProxyConfig()) {
    setUpstreamCount(4);
  }
  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  const std::string PEER_SOURCE_INSTANCE = "srcinst=";
  const std::string PEER_SOURCE_SERVICE_INSTANCE = "srcservinst=";
  const std::string PEER_SOURCE_SCP = "srcscp=";
  const std::string PEER_SOURCE_SEPP = "srcsepp=";
  const std::string PEER_DESTINATION_SCP = "dstscp=";
  const std::string PEER_DESTINATION_SEPP = "dstsepp=";
  const std::string PEER_DESTINATION_INSTANCE = "dstinst=";
  const std::string PEER_DESTINATION_SERVICE_INSTANCE = "dstservinst=";
  const std::string scpNfType = "SCP";
  const std::string seppNfType = "SEPP";
  const std::string own_fqdn = "sepp.own_plmn.com";
  const std::string udm1NfInstanceId = "2ec8ac0b-265e-4165-86e9-e0735e6ce309";
  const std::string udm3NfInstanceId = "2ec8ac0b-265e-4165-86e9-e0735e6ce311";

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);

    HttpIntegrationTest::initialize();
  }

  bool checkHeader(const Http::RequestOrResponseHeaderMap& headers,
                   const std::string& expected_header) {
    const std::vector<absl::string_view> original_header_vector = StringUtil::splitToken(
        headers.get(Http::LowerCaseString("3gpp-Sbi-NF-Peer-Info"))[0]->value().getStringView(),
        ";", false, true);
    const std::vector<absl::string_view> exp_header_vector =
        StringUtil::splitToken(expected_header, ";", false, true);

    if (original_header_vector.size() != exp_header_vector.size()) {
      return false;
    }

    for (const auto& t : exp_header_vector) {
      if (std::find(original_header_vector.begin(), original_header_vector.end(), t) ==
          original_header_vector.end()) {
        return false;
      } else {
        continue;
      }
    }

    return true;
  }

  // Common configuration that sets the start-routingcase
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
  clusters:
    - name: cluster_sepp
      load_assignment:
        cluster_name: cluster_sepp
        endpoints:
        - lb_endpoints:
          - endpoint:
              address:
                socket_address:
                  address: 127.0.0.1
                  port_value: 0
              hostname: sepp.host.de
            metadata:
              filter_metadata:
                envoy.eric_proxy:
                  nf_type:
                  - SEPP
                  support:
                  - TFQDN
    - name: cluster_nf
      load_assignment:
        cluster_name: cluster_nf
        endpoints:
        - lb_endpoints:
          - endpoint:
              address:
                socket_address:
                  address: 127.0.0.1
                  port_value: 0
              hostname: nf.host.de
            metadata:
              filter_metadata:
                envoy.eric_proxy:
                  nf_type:
                  - NF
                  nfInstanceId:
                  - "2ec8ac0b-265e-4165-86e9-e0735e6ce309"
                  support:
                  - NF
    - name: cluster_scp
      load_assignment:
        cluster_name: cluster_scp
        endpoints:
        - lb_endpoints:
          - endpoint:
              address:
                socket_address:
                  address: 127.0.0.1
                  port_value: 0
              hostname: scp.host.de:90
            metadata:
              filter_metadata:
                envoy.eric_proxy:
                  nf_type:
                  - SCP
                  support:
                  - TaR
    - name: cluster_nf2
      load_assignment:
        cluster_name: cluster_nf2
        endpoints:
        - lb_endpoints:
          - endpoint:
              address:
                socket_address:
                  address: 127.0.0.1
                  port_value: 0
              hostname: nf.host.de
            metadata:
              filter_metadata:
                envoy.eric_proxy:
                  nf_type:
                  - NF
                  nfInstanceId:
                  - "2ec8ac0b-265e-4165-86e9-e0735e6ce311"
                  support:
                  - NF
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
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - name: route5
                match:
                  prefix: "/"
                  headers:
                    - name: x-cluster
                      string_match:
                        exact: cluster_nf
                route:
                  cluster: cluster_nf
              - name: route4
                match:
                  prefix: "/"
                  headers:
                    - name: x-cluster-nf2
                route:
                  cluster: cluster_nf2
              - name: route3
                match:
                  prefix: "/"
                  headers:
                    - name: x-cluster-nf
                route:
                  cluster: cluster_nf
              - name: route2
                match:
                  prefix: "/"
                  headers:
                    - name: x-cluster-sepp
                route:
                  cluster: cluster_sepp
              - name: route1
                match:
                  prefix: "/"
                  headers:
                    - name: x-cluster-scp
                route:
                  cluster: cluster_scp
  )EOF",
                       Platform::null_device_path, Platform::null_device_path,
                       Platform::null_device_path);
  };
};

//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------
INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxySbiNfPeerInfoIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(EricProxySbiNfPeerInfoIntegrationTest, TestBug) {
  // GTEST_SKIP();

  config_helper_.addFilter(config_basic);
  initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
      {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
      {"x-cluster-scp", "true"},
      {"3gpp-Sbi-NF-Peer-Info",
       "srcinst=2ec8ac0b-265e-4165-86e9-e0735e6ce307; "
       "srcservinst=2ec8ac0b-265e-4165-86e9-e0735e6ce308; "
       "dstscp=SCP-scp.mnc.012.mcc.210.ericsson.se; dstinst=2ec8ac0b-265e-4165-86e9-e0735e6ce309; "
       "dstservinst=2ec8ac0b-265e-4165-86e9-e0735e6ce400"},
      {"3gpp-sbi-target-apiroot", "http://scp_test:5678"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
  };
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(2);

  // Send response:
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(checkHeader(
      upstream_request_->headers(),
      "srcsepp=SEPP-sepp.own_plmn.com; dstscp=SCP-scp.host.de; "
      "dstinst=2ec8ac0b-265e-4165-86e9-e0735e6ce309; srcinst=2ec8ac0b-265e-4165-86e9-e0735e6ce307; "
      "srcservinst=2ec8ac0b-265e-4165-86e9-e0735e6ce308;dstservinst=2ec8ac0b-265e-4165-86e9-"
      "e0735e6ce400"));

  EXPECT_TRUE(
      checkHeader(response->headers(),
                  "srcinst=2ec8ac0b-265e-4165-86e9-e0735e6ce309; "
                  "srcservinst=2ec8ac0b-265e-4165-86e9-e0735e6ce400; "
                  "srcsepp=SEPP-sepp.own_plmn.com; dstinst=2ec8ac0b-265e-4165-86e9-e0735e6ce307; "
                  "dstservinst=2ec8ac0b-265e-4165-86e9-e0735e6ce308"));

  codec_client_->close();
}

TEST_P(EricProxySbiNfPeerInfoIntegrationTest, TC001_SCP) {
  // GTEST_SKIP();

  std::string nfPeerInfoHeaderValue;
  absl::StrAppend(&nfPeerInfoHeaderValue,
                  PEER_SOURCE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce307\u003b",
                  PEER_SOURCE_SERVICE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce308\u003b",
                  PEER_DESTINATION_SCP + scpNfType + "-scp.mnc.012.mcc.210.ericsson.se\u003b",
                  PEER_DESTINATION_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce309\u003b",
                  PEER_DESTINATION_SERVICE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce400");

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
      {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
      {"x-cluster-nf", "true"},
      {"3gpp-Sbi-NF-Peer-Info", nfPeerInfoHeaderValue}};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
      {"3gpp-Sbi-NF-Peer-Info", PEER_SOURCE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}};

  const std::vector<absl::string_view> peerTypes =
      StringUtil::splitToken(nfPeerInfoHeaderValue, ";", false, true);

  absl::string_view expectedReqsrcinst = peerTypes[0];
  absl::string_view expectedReqsrcservinst = peerTypes[1];
  absl::string_view expectedReqdstservinst = peerTypes[4];
  std::string expectedsrcscp = PEER_SOURCE_SCP + scpNfType + "-" + own_fqdn;
  std::string expectedReqdstinst = PEER_DESTINATION_INSTANCE + udm1NfInstanceId;
  std::string expectednfPeerInfoReqHeaderList;
  absl::StrAppend(&expectednfPeerInfoReqHeaderList, expectedReqsrcinst, ";", expectedReqsrcservinst,
                  ";", expectedsrcscp, ";", expectedReqdstinst, ";", expectedReqdstservinst);

  std::string expectedRespsrcinst =
      absl::StrReplaceAll(expectedReqdstinst, {{PEER_DESTINATION_INSTANCE, PEER_SOURCE_INSTANCE}});
  std::string expectedRespsrcservinst = absl::StrReplaceAll(
      expectedReqdstservinst, {{PEER_DESTINATION_SERVICE_INSTANCE, PEER_SOURCE_SERVICE_INSTANCE}});
  std::string expectedRespdstservinst = absl::StrReplaceAll(
      expectedReqsrcservinst, {{PEER_SOURCE_SERVICE_INSTANCE, PEER_DESTINATION_SERVICE_INSTANCE}});
  std::string expectedRespdstinst =
      absl::StrReplaceAll(expectedReqsrcinst, {{PEER_SOURCE_INSTANCE, PEER_DESTINATION_INSTANCE}});
  std::string expectedNfPeerInfoRespHeader;
  absl::StrAppend(&expectedNfPeerInfoRespHeader, expectedRespsrcinst, ";", expectedRespsrcservinst,
                  ";", expectedsrcscp, ";", expectedRespdstinst, ";", expectedRespdstservinst);

  auto scp_config =
      std::regex_replace(config_basic, std::regex("node_type: SEPP"), "node_type: SCP");
  config_helper_.addFilter(scp_config);
  initialize();

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(1);

  // Send response:
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(checkHeader(upstream_request_->headers(), expectednfPeerInfoReqHeaderList));

  EXPECT_TRUE(checkHeader(response->headers(), expectedNfPeerInfoRespHeader));

  codec_client_->close();
}

TEST_P(EricProxySbiNfPeerInfoIntegrationTest, TC012_SCP) {
  // GTEST_SKIP();

  std::string nfPeerInfoHeaderValue;
  absl::StrAppend(&nfPeerInfoHeaderValue,
                  PEER_SOURCE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce307\u003b",
                  PEER_SOURCE_SERVICE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce308\u003b",
                  PEER_DESTINATION_SCP + scpNfType + "-scp.mnc.012.mcc.210.ericsson.se\u003b",
                  PEER_DESTINATION_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce309\u003b",
                  PEER_DESTINATION_SERVICE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce400");

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
      {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
      {"x-cluster-nf2", "true"},
      {"3gpp-Sbi-NF-Peer-Info", nfPeerInfoHeaderValue}};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "503"},
      {"content-type", "application/json"},
      {"3gpp-Sbi-NF-Peer-Info", PEER_SOURCE_INSTANCE + udm3NfInstanceId}

  };

  const std::vector<absl::string_view> peerTypes =
      StringUtil::splitToken(nfPeerInfoHeaderValue, ";", false, true);

  absl::string_view expectedReqsrcinst = peerTypes[0];
  absl::string_view expectedReqsrcservinst = peerTypes[1];
  std::string expectedsrcscp = PEER_SOURCE_SCP + scpNfType + "-" + own_fqdn;
  std::string expectedReqdstinst = PEER_DESTINATION_INSTANCE + udm3NfInstanceId;
  std::string expectednfPeerInfoReqHeaderList;
  absl::StrAppend(&expectednfPeerInfoReqHeaderList, expectedReqsrcinst, ";", expectedReqsrcservinst,
                  ";", expectedsrcscp, ";", expectedReqdstinst);

  std::string expectedRespsrcinst =
      absl::StrReplaceAll(expectedReqdstinst, {{PEER_DESTINATION_INSTANCE, PEER_SOURCE_INSTANCE}});

  std::string expectedRespdstservinst = absl::StrReplaceAll(
      expectedReqsrcservinst, {{PEER_SOURCE_SERVICE_INSTANCE, PEER_DESTINATION_SERVICE_INSTANCE}});
  std::string expectedRespdstinst =
      absl::StrReplaceAll(expectedReqsrcinst, {{PEER_SOURCE_INSTANCE, PEER_DESTINATION_INSTANCE}});
  std::string expectedNfPeerInfoRespHeader;
  absl::StrAppend(&expectedNfPeerInfoRespHeader, expectedRespsrcinst, ";", expectedsrcscp, ";",
                  expectedRespdstinst, ";", expectedRespdstservinst);

  auto scp_config =
      std::regex_replace(config_basic, std::regex("node_type: SEPP"), "node_type: SCP");
  config_helper_.addFilter(scp_config);
  initialize();

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(3);

  // Send response:
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(checkHeader(upstream_request_->headers(), expectednfPeerInfoReqHeaderList));

  EXPECT_TRUE(checkHeader(response->headers(), expectedNfPeerInfoRespHeader));

  codec_client_->close();
}

// local reply with error
// should have srcscp=SCP-sepp.own_plmn.com
TEST_P(EricProxySbiNfPeerInfoIntegrationTest, TC013_SCP) {
  // GTEST_SKIP();

  std::string expectedsrcscp = PEER_SOURCE_SCP + scpNfType + "-" + own_fqdn;

  auto scp_config =
      std::regex_replace(config_basic, std::regex("node_type: SEPP"), "node_type: SCP");
  config_helper_.addFilter(scp_config);
  initialize();

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1"},
      {":authority", "eric-chfsim-6-mnc-1212-mcc-1212:3777"},
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(response->complete());

  EXPECT_TRUE(checkHeader(response->headers(), expectedsrcscp));

  codec_client_->close();
}

// overflow buffer limit
TEST_P(EricProxySbiNfPeerInfoIntegrationTest, TC014_SCP) {
  // GTEST_SKIP();

  auto scp_config =
      std::regex_replace(config_basic, std::regex("node_type: SEPP"), "node_type: SCP");
  config_helper_.addFilter(scp_config);
  config_helper_.setBufferLimits(10, 10);
  initialize();

  std::string nfPeerInfoHeaderValue;
  absl::StrAppend(&nfPeerInfoHeaderValue,
                  PEER_SOURCE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce307\u003b",
                  PEER_DESTINATION_SCP + "SCP-scp.mnc.012.mcc.210.ericsson.se\u003b",
                  PEER_DESTINATION_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce309\u003b",
                  PEER_DESTINATION_SERVICE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce400");

  std::string expectedsrcscp = PEER_SOURCE_SCP + scpNfType + "-" + own_fqdn;
  const std::vector<absl::string_view> peerTypes =
      StringUtil::splitToken(nfPeerInfoHeaderValue, ";", false, true);
  std::string expectedRespdstinst =
      absl::StrReplaceAll(peerTypes[0], {{PEER_SOURCE_INSTANCE, PEER_DESTINATION_INSTANCE}});

  std::string expectedNfPeerInfoRespHeader = expectedsrcscp + ";" + expectedRespdstinst;

  codec_client_ = makeHttpConnection(lookupPort("http"));

  auto response = codec_client_->makeRequestWithBody(
      Http::TestRequestHeaderMapImpl{{":method", "POST"},
                                     {":path", "/dynamo/url"},
                                     {":scheme", "http"},
                                     {":authority", "host"},
                                     {"3gpp-Sbi-NF-Peer-Info", nfPeerInfoHeaderValue},
                                     {"x-forwarded-for", "10.0.0.1"},
                                     {"x-envoy-retry-on", "5xx"}},
      11 * 11);

  ASSERT_TRUE(response->waitForEndStream());
  // With HTTP/1 there's a possible race where if the connection backs up early,
  // the 413-and-connection-close may be sent while the body is still being
  // sent, resulting in a write error and the connection being closed before the
  // response is read.
  if (downstream_protocol_ >= Http::CodecType::HTTP2) {
    ASSERT_TRUE(response->complete());
  }
  if (response->complete()) {
    EXPECT_TRUE(checkHeader(response->headers(), expectedNfPeerInfoRespHeader));
  }

  codec_client_->close();
}

// preffered host
TEST_P(EricProxySbiNfPeerInfoIntegrationTest, TC023_SCP) {
  // GTEST_SKIP();

  std::string nfPeerInfoHeaderValue;
  absl::StrAppend(&nfPeerInfoHeaderValue,
                  PEER_SOURCE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce307\u003b",
                  PEER_SOURCE_SERVICE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce308\u003b",
                  PEER_DESTINATION_SCP + scpNfType + "-scp.mnc.012.mcc.210.ericsson.se\u003b",
                  PEER_DESTINATION_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce309\u003b",
                  PEER_DESTINATION_SERVICE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce400");

  const std::vector<absl::string_view> peerTypes =
      StringUtil::splitToken(nfPeerInfoHeaderValue, ";", false, true);

  absl::string_view expectedReqsrcinst = peerTypes[0];
  absl::string_view expectedReqsrcservinst = peerTypes[1];
  std::string expectedsrcscp = PEER_SOURCE_SCP + scpNfType + "-" + own_fqdn;
  absl::string_view expectedReqdstservinst = peerTypes[4];
  absl::string_view expectedReqdstinst = peerTypes[3];
  std::string expectednfPeerInfoReqHeaderList;
  absl::StrAppend(&expectednfPeerInfoReqHeaderList, expectedReqsrcinst, ";", expectedReqsrcservinst,
                  ";", expectedsrcscp, ";", expectedReqdstinst, ";", expectedReqdstservinst);

  std::string expectedRespsrcinst =
      absl::StrReplaceAll(expectedReqdstinst, {{PEER_DESTINATION_INSTANCE, PEER_SOURCE_INSTANCE}});
  std::string expectedRespsrcservinst = absl::StrReplaceAll(
      expectedReqdstservinst, {{PEER_DESTINATION_SERVICE_INSTANCE, PEER_SOURCE_SERVICE_INSTANCE}});
  std::string expectedRespdstservinst = absl::StrReplaceAll(
      expectedReqsrcservinst, {{PEER_SOURCE_SERVICE_INSTANCE, PEER_DESTINATION_SERVICE_INSTANCE}});
  std::string expectedRespdstinst =
      absl::StrReplaceAll(expectedReqsrcinst, {{PEER_SOURCE_INSTANCE, PEER_DESTINATION_INSTANCE}});
  std::string expectedNfPeerInfoRespHeader;
  absl::StrAppend(&expectedNfPeerInfoRespHeader, expectedRespsrcinst, ";", expectedRespsrcservinst,
                  ";", expectedsrcscp, ";", expectedRespdstinst, ";", expectedRespdstservinst);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
      {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
      {"3gpp-Sbi-target-apiRoot", "https://eric-chfsim-1-mnc-456-mcc-456:443"},
      {"3gpp-Sbi-NF-Peer-Info", nfPeerInfoHeaderValue}};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
      {"3gpp-Sbi-NF-Peer-Info", PEER_SOURCE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}};

  auto scp_config =
      std::regex_replace(config_basic, std::regex("node_type: SEPP"), "node_type: SCP");
  config_helper_.addFilter(scp_config);
  initialize();

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(1);

  // Send response:
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(checkHeader(upstream_request_->headers(), expectednfPeerInfoReqHeaderList));

  EXPECT_TRUE(checkHeader(response->headers(), expectedNfPeerInfoRespHeader));

  codec_client_->close();
}

TEST_P(EricProxySbiNfPeerInfoIntegrationTest, TC011_SEPP) {
  // GTEST_SKIP();

  std::string nfPeerInfoHeaderValue;
  absl::StrAppend(&nfPeerInfoHeaderValue,
                  PEER_SOURCE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce307\u003b",
                  PEER_SOURCE_SERVICE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce308\u003b",
                  PEER_DESTINATION_SEPP + "SEPP" + "-sepp.mnc.012.mcc.210.ericsson.se\u003b",
                  PEER_DESTINATION_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce309\u003b",
                  PEER_DESTINATION_SERVICE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce400");

  const std::vector<absl::string_view> peerTypes =
      StringUtil::splitToken(nfPeerInfoHeaderValue, ";", false, true);

  absl::string_view expectedReqsrcinst = peerTypes[0];
  absl::string_view expectedReqsrcservinst = peerTypes[1];
  absl::string_view expectedReqdstinst = peerTypes[3];
  absl::string_view expectedReqdstservinst = peerTypes[4];
  std::string expectedsrcsepp = PEER_SOURCE_SEPP + seppNfType + "-" + own_fqdn;
  std::string expecteddstscp = PEER_DESTINATION_SCP + scpNfType + "-" + "scp.host.de";

  std::string expectednfPeerInfoReqHeaderList;
  absl::StrAppend(&expectednfPeerInfoReqHeaderList, expectedReqsrcinst, ";", expectedReqsrcservinst,
                  ";", expectedsrcsepp, ";", expecteddstscp, ";", expectedReqdstinst, ";",
                  expectedReqdstservinst);

  std::string expectedRespsrcinst =
      absl::StrReplaceAll(expectedReqdstinst, {{PEER_DESTINATION_INSTANCE, PEER_SOURCE_INSTANCE}});
  std::string expectedRespsrcservinst = absl::StrReplaceAll(
      expectedReqdstservinst, {{PEER_DESTINATION_SERVICE_INSTANCE, PEER_SOURCE_SERVICE_INSTANCE}});
  std::string expectedRespdstservinst = absl::StrReplaceAll(
      expectedReqsrcservinst, {{PEER_SOURCE_SERVICE_INSTANCE, PEER_DESTINATION_SERVICE_INSTANCE}});
  std::string expectedRespdstinst =
      absl::StrReplaceAll(expectedReqsrcinst, {{PEER_SOURCE_INSTANCE, PEER_DESTINATION_INSTANCE}});
  std::string expectedNfPeerInfoRespHeader;
  absl::StrAppend(&expectedNfPeerInfoRespHeader, expectedRespsrcinst, ";", expectedRespsrcservinst,
                  ";", expectedsrcsepp, ";", expectedRespdstinst, ";", expectedRespdstservinst);

  config_helper_.addFilter(config_basic);
  initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
      {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
      {"x-cluster-scp", "true"},
      {"3gpp-Sbi-NF-Peer-Info", nfPeerInfoHeaderValue}};
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
      {"3gpp-Sbi-NF-Peer-Info", PEER_SOURCE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}};

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(2);

  // Send response:
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(checkHeader(upstream_request_->headers(), expectednfPeerInfoReqHeaderList));

  EXPECT_TRUE(checkHeader(response->headers(), expectedNfPeerInfoRespHeader));

  codec_client_->close();
}

TEST_P(EricProxySbiNfPeerInfoIntegrationTest, TC012_SEPP) {
  GTEST_SKIP();
  std::string nfPeerInfoHeaderValue;
  absl::StrAppend(&nfPeerInfoHeaderValue,
                  PEER_SOURCE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce307\u003b",
                  PEER_SOURCE_SERVICE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce308\u003b",
                  PEER_DESTINATION_SEPP + "SEPP" + "-sepp.mnc.012.mcc.210.ericsson.se\u003b",
                  PEER_DESTINATION_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce309\u003b",
                  PEER_DESTINATION_SERVICE_INSTANCE + "2ec8ac0b-265e-4165-86e9-e0735e6ce310");

  const std::vector<absl::string_view> peerTypes =
      StringUtil::splitToken(nfPeerInfoHeaderValue, ";", false, true);

  absl::string_view expectedReqdstservinst = peerTypes[4];
  std::string expectedsrcsepp = PEER_SOURCE_SEPP + seppNfType + "-" + own_fqdn;
  std::string expecteddstsepp = PEER_DESTINATION_SEPP + seppNfType + "-" + "sepp.host.de";
  absl::string_view expectedReqdstinst = peerTypes[3];

  std::string expectednfPeerInfoReqHeaderList;
  absl::StrAppend(&expectednfPeerInfoReqHeaderList, expectedsrcsepp, ";", expectedReqdstinst, ";",
                  expectedReqdstservinst, ";", expecteddstsepp);

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {"please_delete", "true"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
      {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
      {"x-cluster-sepp", "true"},
      {"3gpp-Sbi-NF-Peer-Info", nfPeerInfoHeaderValue}};
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"},
                                                   {"content-type", "application/json"}};

  config_helper_.addFilter(config_basic);
  initialize();

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  // Send response:
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(checkHeader(upstream_request_->headers(), expectednfPeerInfoReqHeaderList));

  EXPECT_TRUE(response->headers().get(Http::LowerCaseString("3gpp-Sbi-NF-Peer-Info")).empty());

  codec_client_->close();
}

// request is from nf
// node type = scp
// nf type = scp
// For request:
// - should set srcscp with own_fqdn
// - should set dstscp with selected host
// - dstinst is preserved
// For response:
// - srcinst is dstinst of request, same for srcservinst
// - srcscp is set with own_fqdn
// - dstinst is set with srcinst in resp, same for dstservinst
// - dstscp/sepp are removed
TEST_P(EricProxySbiNfPeerInfoIntegrationTest, TestNfScpScp) {
  // GTEST_SKIP();

  auto scp_config =
      std::regex_replace(config_basic, std::regex("node_type: SEPP"), "node_type: SCP");

  config_helper_.addFilter(scp_config);
  initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
      {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
      {"x-cluster-scp", "true"},
      {"3gpp-Sbi-NF-Peer-Info", "dstinst=12345;srcinst=789"},
      {"3gpp-sbi-target-apiroot", "http://scp_test:5678"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
  };
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(2);

  // Send response:
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(
      checkHeader(upstream_request_->headers(),
                  "srcscp=SCP-sepp.own_plmn.com;dstscp=SCP-scp.host.de;dstinst=12345;srcinst=789"));

  EXPECT_TRUE(
      checkHeader(response->headers(), "srcinst=12345;srcscp=SCP-sepp.own_plmn.com;dstinst=789"));

  codec_client_->close();
}

#pragma region ScpSepp
// request from scp
// node type = sepp
// nf type = nf
// For request:
// - should set srcsepp with own_fqdn
// - should set dstinst with nf-instance-id of selected host
// - dstservinst should be deleted
// - should remove dstScp and dstSepp
// For response:
// - srcinst is dstinst of request, same for srcservinst
// - srcsepp is own_fqdn
// - dstinst is empty
// - dstscp is srcscp of req
TEST_P(EricProxySbiNfPeerInfoIntegrationTest, TestScpSeppNf) {
  // GTEST_SKIP();

  config_helper_.addFilter(config_basic);
  initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
      {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
      {"x-cluster-nf", "true"},
      {"3gpp-Sbi-NF-Peer-Info", "dstinst=12345;srcscp=SCP-scp124; dstservinst=7546"},
      {"3gpp-sbi-target-apiroot", "http://scp_test:5678"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
  };
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(1);

  // Send response:
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(
      checkHeader(upstream_request_->headers(),
                  "srcsepp=SEPP-sepp.own_plmn.com;dstinst=2ec8ac0b-265e-4165-86e9-e0735e6ce309"));

  EXPECT_TRUE(checkHeader(response->headers(), "srcinst=2ec8ac0b-265e-4165-86e9-e0735e6ce309;"
                                               "srcsepp=SEPP-sepp.own_plmn.com;dstscp=SCP-scp124"));

  codec_client_->close();
}

// request from scp
// node type = sepp
// nf type = scp
// For request:
// - should set srcsepp with own_fqdn
// - should set dstscp with fqdn of selected host
// - dstinst is preserved
// For response:
// - srcinst is dstinst of request, same for srcservinst
// - srcsepp is own_fqdn
// - dstscp is srcscp of req
TEST_P(EricProxySbiNfPeerInfoIntegrationTest, TestScpSeppScp) {
  // GTEST_SKIP();

  config_helper_.addFilter(config_basic);
  initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
      {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
      {"x-cluster-scp", "true"},
      {"3gpp-Sbi-NF-Peer-Info", "dstscp=12345scp;srcscp=SCP-scp124;dstinst=2ec8ac0b"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
  };
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(2);

  // Send response:
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(
      checkHeader(upstream_request_->headers(),
                  "srcsepp=SEPP-sepp.own_plmn.com;dstscp=SCP-scp.host.de;dstinst=2ec8ac0b"));

  EXPECT_TRUE(checkHeader(response->headers(),
                          "srcinst=2ec8ac0b;srcsepp=SEPP-sepp.own_plmn.com;dstscp=SCP-scp124"));

  codec_client_->close();
}

// request from scp
// node type = sepp
// nf type = sepp
// For request:
// - should set srcsepp with own_fqdn
// - should set dstsepp with fqdn of selected host
// - dstinst is preserved
// For response:
// - srcinst is dstinst of request, same for srcservinst
// - srcsepp is own_fqdn
// - dstscp is srcscp of req
TEST_P(EricProxySbiNfPeerInfoIntegrationTest, TestScpSeppSepp) {
  // GTEST_SKIP();

  config_helper_.addFilter(config_basic);
  initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
      {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
      {"x-cluster-sepp", "true"},
      {"3gpp-Sbi-NF-Peer-Info", "dstsepp=12345sepp; srcscp=SCP-scp124; dstinst=2ec8ac0b"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
  };
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  // Send response:
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(
      checkHeader(upstream_request_->headers(),
                  "srcsepp=SEPP-sepp.own_plmn.com;dstsepp=SEPP-sepp.host.de;dstinst=2ec8ac0b"));

  EXPECT_TRUE(checkHeader(response->headers(),
                          "srcinst=2ec8ac0b;srcsepp=SEPP-sepp.own_plmn.com;dstscp=SCP-scp124"));

  codec_client_->close();
}
#pragma endregion ScpSepp

#pragma region SeppSepp
// request from Sepp
// node type = sepp
// nf type = sepp
// For request:
// - should set srcsepp with own_fqdn
// - should set dstsepp with fqdn of selected host
// - dstinst is preserved
// For response:
// - srcinst is dstinst of request, same for srcservinst
// - srcsepp is own_fqdn
// - dstsepp is srcsepp of req
TEST_P(EricProxySbiNfPeerInfoIntegrationTest, TestSeppSeppSepp) {
  // GTEST_SKIP();

  config_helper_.addFilter(config_basic);
  initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
      {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
      {"x-cluster-sepp", "true"},
      {"3gpp-Sbi-NF-Peer-Info", "dstsepp=12345sepp;srcsepp=SEPP-sepp124;dstinst=2ec8ac0b"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
  };
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(0);

  // Send response:
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(
      checkHeader(upstream_request_->headers(),
                  "dstsepp=SEPP-sepp.host.de;srcsepp=SEPP-sepp.own_plmn.com;dstinst=2ec8ac0b"));

  EXPECT_TRUE(checkHeader(response->headers(),
                          "srcinst=2ec8ac0b;srcsepp=SEPP-sepp.own_plmn.com;dstsepp=SEPP-sepp124"));

  codec_client_->close();
}

// request from Sepp
// node type = sepp
// nf type = scp
// For request:
// - should set srcsepp with own_fqdn
// - should set dstscp with fqdn of selected host
// - dstinst is preserved
// For response:
// - srcinst is dstinst of request, same for dstservinst
// - srcsepp is own_fqdn
// - dstsepp is srcsepp of req
TEST_P(EricProxySbiNfPeerInfoIntegrationTest, TestSeppSeppScp) {
  // GTEST_SKIP();

  config_helper_.addFilter(config_basic);
  initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"},
      {":authority", TfqdnCodec::encode("http://prod.plmnB.com:1234") + ".sepp.own_plmn.com:80"},
      {"x-cluster-scp", "true"},
      {"3gpp-Sbi-NF-Peer-Info",
       "dstscp=12345scp;srcsepp=SEPP-sepp124;dstinst=2ec8ac0b; dstservinst=a789s87"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-type", "application/json"},
  };
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest(2);

  // Send response:
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(checkHeader(upstream_request_->headers(),
                          "dstscp=SCP-scp.host.de;srcsepp=SEPP-sepp.own_plmn."
                          "com;dstinst=2ec8ac0b; dstservinst=a789s87"));

  EXPECT_TRUE(checkHeader(
      response->headers(),
      "srcinst=2ec8ac0b;srcsepp=SEPP-sepp.own_plmn.com;dstsepp=SEPP-sepp124; srcservinst=a789s87"));

  codec_client_->close();
}

// should delete srcinst for local reply
TEST_P(EricProxySbiNfPeerInfoIntegrationTest, TestLocalReply) {
  // GTEST_SKIP();

  config_helper_.addFilter(config_basic);
  initialize();

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "sepp.own_plmn_test.com:80"},
      {"3gpp-Sbi-target-apiRoot", "edr_poe"},
      {"3gpp-Sbi-NF-Peer-Info",
       "srcinst=2ec8ac0b-265e-4165-86e9-e0735e6ce307; "
       "srcservinst=2ec8ac0b-265e-4165-86e9-e0735e6ce308; "
       "dstscp=SCP-scp.mnc.012.mcc.210.ericsson.se; dstinst=2ec8ac0b-265e-4165-86e9-e0735e6ce309; "
       "dstservinst=2ec8ac0b-265e-4165-86e9-e0735e6ce400"},
  };

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("404", response->headers().getStatusValue());

  EXPECT_TRUE(
      checkHeader(response->headers(),
                  "srcsepp=SEPP-sepp.own_plmn.com; dstinst=2ec8ac0b-265e-4165-86e9-e0735e6ce307; "
                  "dstservinst=2ec8ac0b-265e-4165-86e9-e0735e6ce308"));

  codec_client_->close();
}
#pragma endregion SeppSepp

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
