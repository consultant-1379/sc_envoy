// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!!!!!!! NOTE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!! Most of the tests in this file do not use an eric_proxy !!!!!!!
// !!!! filter at all.                                          !!!!!!!
// !!!! Instead, they inject metadata directly into the router  !!!!!!!
// !!!! code with the help of the header-to-metadata filter.    !!!!!!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "base_integration_test.h"
#include "pluggable_configurator.h"

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


const std::string config_header_to_metadata_nf = R"EOF(
name: envoy.filters.http.header_to_metadata
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.header_to_metadata.v3.Config
  request_rules:
    - header: x-absolute-path-processing
      on_header_present:
        metadata_namespace: eric_proxy
        key: absolute-path-processing
        type: STRING
    - header: x-tfqdn-cluster-relative
      on_header_present:
        metadata_namespace: eric_proxy
        key: relative-path-value
        type: STRING
    - header: x-sepp-tfqdn-original-body-replaced
      on_header_present:
        metadata_namespace: eric_proxy.sepp.routing
        key: sepp-tfqdn-original-body-was-replaced
        type: STRING
    - header: x-sepp-tfqdn-original-body
      on_header_present:
        metadata_namespace: eric_proxy.sepp.routing
        key: sepp-tfqdn-original-body
        type: STRING
    - header: x-sepp-tfqdn-original-body-len
      on_header_present:
        metadata_namespace: eric_proxy.sepp.routing
        key: sepp-tfqdn-original-body-len
        type: STRING
)EOF";

const std::string config_header_to_metadata_tfqdn = R"EOF(
name: envoy.filters.http.header_to_metadata
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.header_to_metadata.v3.Config
  request_rules:
    - header: x-sepp-routing-direction
      on_header_present:
        metadata_namespace: eric_proxy.sepp.routing
        key: sepp-routing-direction
        type: STRING
    - header: x-sepp-tfqdn-original-body-replaced
      on_header_present:
        metadata_namespace: eric_proxy.sepp.routing
        key: sepp-tfqdn-original-body-was-replaced
        type: STRING
    - header: x-sepp-tfqdn-modified-body
      on_header_present:
        metadata_namespace: eric_proxy.sepp.routing
        key: sepp-tfqdn-modified-body
        type: STRING
    - header: x-sepp-tfqdn-modified-body-len
      on_header_present:
        metadata_namespace: eric_proxy.sepp.routing
        key: sepp-tfqdn-modified-body-len
        type: STRING
    - header: x-absolute-path-processing
      on_header_present:
        metadata_namespace: eric_proxy
        key: absolute-path-processing
        type: STRING
    - header: x-tfqdn-cluster-relative
      on_header_present:
        metadata_namespace: eric_proxy
        key: relative-path-value
        type: STRING
)EOF";

const std::string config_header_to_metadata_tar = R"EOF(
name: envoy.filters.http.header_to_metadata
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.header_to_metadata.v3.Config
  request_rules:
    - header: x-absolute-path-processing
      on_header_present:
        metadata_namespace: eric_proxy
        key: absolute-path-processing
        type: STRING
    - header: x-absolute-path-value
      on_header_present:
        metadata_namespace: eric_proxy
        key: absolute-path-value
        type: STRING
    - header: x-sepp-tfqdn-original-body-replaced
      on_header_present:
        metadata_namespace: eric_proxy.sepp.routing
        key: sepp-tfqdn-original-body-was-replaced
        type: STRING
    - header: x-sepp-tfqdn-original-body
      on_header_present:
        metadata_namespace: eric_proxy.sepp.routing
        key: sepp-tfqdn-original-body
        type: STRING
    - header: x-sepp-tfqdn-original-body-len
      on_header_present:
        metadata_namespace: eric_proxy.sepp.routing
        key: sepp-tfqdn-original-body-len
        type: STRING
    - header: x-target-api-root-processing
      on_header_present:
        metadata_namespace: eric_proxy
        key: target-api-root-processing
        type: STRING
    - header: x-target-api-root-value
      on_header_present:
        metadata_namespace: eric_proxy
        key: target-api-root-value
        type: STRING
)EOF";

const std::string config_header_to_metadata_no_tar = R"EOF(
name: envoy.filters.http.header_to_metadata
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.header_to_metadata.v3.Config
  request_rules:
    - header: x-keep-authority-header
      on_header_present:
        metadata_namespace: eric_proxy
        key: keep-authority-header
        type: STRING
    - header: x-absolute-path-processing
      on_header_present:
        metadata_namespace: eric_proxy
        key: absolute-path-processing
        type: STRING
    - header: x-absolute-path-value
      on_header_present:
        metadata_namespace: eric_proxy
        key: absolute-path-value
        type: STRING
    - header: x-preferred-host
      on_header_present:
        metadata_namespace: eric_proxy
        key: preferred-host
        type: STRING
)EOF";

// config for bug DND-45035
#pragma region DND-45035
const std::string config_header_to_metadata_tar_pref_host = R"EOF(
name: envoy.filters.http.header_to_metadata
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.header_to_metadata.v3.Config
  request_rules:
    - header: x-absolute-path-processing
      on_header_present:
        metadata_namespace: eric_proxy
        key: absolute-path-processing
        type: STRING
    - header: x-absolute-path-value
      on_header_present:
        metadata_namespace: eric_proxy
        key: absolute-path-value
        type: STRING
    - header: x-target-api-root-processing
      on_header_present:
        metadata_namespace: eric_proxy
        key: target-api-root-processing
        type: STRING
    - header: x-target-api-root-value
      on_header_present:
        metadata_namespace: eric_proxy
        key: target-api-root-value
        type: STRING
    - header: x-preferred-host
      on_header_present:
        metadata_namespace: eric_proxy
        key: preferred-host
        type: STRING
)EOF";

const std::string config_basic_sepp = R"EOF(
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
      - name: apiRoot_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: (?i)eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
      - name: apiRoot_header
        header: 3gpp-Sbi-target-apiRoot
        variable_name:  apiRoot_hdr
      - name: chfsim_data
        header: 3gpp-Sbi-target-apiRoot
        extractor_regex: (?i)eric-(?P<chfsim>chfsim-\d+?)-.+
      filter_rules:
      - name: psepp_to_dfw2
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '963'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: universal_pool
            routing_behaviour: STRICT
            preserve_if_indirect: TARGET_API_ROOT
            preferred_target:
              term_header: ":authority"
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
#pragma endregion DND-45035

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
      filter_rules:
      - name: to_sepp
        condition:
          op_and:
            arg1:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'x-target-api-root-value'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'to_sepp'}}
            arg2:
              op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':authority'},
                          typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'sepp.plmnA.com'}}
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: sepp_pool
            routing_behaviour: STRICT
            preferred_target:
              term_header: ":authority"
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

// Converged-Charging Create Response Body (shortened)
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
// Cluster config is here so that we can define our own endpoint-metadata
class EricProxyFilterSeppTFqdnRouterIntegrationTest
    : public PluggableConfigurator {
public:
  EricProxyFilterSeppTFqdnRouterIntegrationTest()
    : PluggableConfigurator(baseConfigWithCatchAllCluster()) {}
};

//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------
INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterSeppTFqdnRouterIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

//------------------------------------------------------------------------
//---- T-FQDN ROUTER INTEGRATION TEST                          -----------
//------------------------------------------------------------------------

// Name: EmptyPath
// Description: DND-29222 Core dump in Envoy caused by wrong Yang configuration
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, EmptyPath) {
  ClusterDict cluster_dict = {{{"catch_all", {"nf_host:80"}}}};
  initConfig({config_header_to_metadata_nf}, cluster_dict, "NF");

  const std::string original_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":scheme", "http"},
      {":authority", "FQDN.EXAMPLE.COM:10100"},
      {"user-agent", "Vert.x-WebClient/4.1.5"},
      {"content-type", "application/json"},
      {"content-length",  std::to_string(original_body.length())},
      {"via", "2.0 scp.ericsson.se"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"x-nf-cluster", "true"},
      {"x-absolute-path-processing", "true"},
      {"x-tfqdn-cluster-relative", "/test/relative/path"},
      // {"x-sepp-tfqdn-original-body", original_body},
      // {"x-sepp-tfqdn-original-body-len", std::to_string(original_body.length())},
      // {"x-sepp-tfqdn-original-body-replaced", "true"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers,
      // cc_create_req_body
      original_body
      );
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_THAT(upstream_request_->headers(),
      Http::HeaderValueOf("content-length", std::to_string(original_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), original_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/test/relative/path"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "nf_host:80"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}


// Name: NfAbsPathTrue
// Description: NF support, orig. body was replaced, Absolute Path Processing is enabled,
// all data is defined in MD
// - Target host has endpoint-metadata "supports: NF"
// - sepp-tfqdn-original-body-was-replaced = true
// - sepp-tfqdn-original-body = test body
// - "x-absolute-path-processing" = "true"
// - "x-tfqdn-cluster-relative" = "/test/relative/path"
// - "3gpp-Sbi-target-apiRoot" = http://eric-chfsim-1-mnc-123-mcc-123:80
// - "x-sepp-tfqdn-original-body-replaced" = "true"
// Expected Result:
// - Original body is restored
// - Relative path is restored
// - 3gpp-Sbi-Target-apiRoot is removed
// - TaR is removed
// - authority = EP host and port
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, NfAbsPathTrue) {
  ClusterDict cluster_dict = {{{"catch_all", {"nf_host:80"}}}};
  initConfig({config_header_to_metadata_nf}, cluster_dict, "NF");

  const std::string original_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "sepp.own_plmn.com:80"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-nf-cluster", "true"},
      {"x-absolute-path-processing", "true"},
      {"x-tfqdn-cluster-relative", "/test/relative/path"},
      // {"x-sepp-tfqdn-original-body", original_body},
      // {"x-sepp-tfqdn-original-body-len", std::to_string(original_body.length())},
      // {"x-sepp-tfqdn-original-body-replaced", "true"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/test/relative/path"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "nf_host:80"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: NfAbsPathTrueNotFull
// Description: NF support, orig. Body was not replaced, Absolute Path Processing is enabled
// - Target host has endpoint-metadata "supports: NF"
// - sepp-tfqdn-original-body-was-replaced = true
// - "x-absolute-path-processing" = "true"
// - "3gpp-Sbi-target-apiRoot" = http://eric-chfsim-1-mnc-123-mcc-123:80
// - "x-sepp-tfqdn-original-body-replaced" = "true"
// Expected Result:
// - Original body is the same
// - path is the same
// - 3gpp-Sbi-Target-apiRoot is removed
// - TaR is removed
// - authority = EP host and port
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, NfAbsPathTrueNotFull) {
  ClusterDict cluster_dict = {{{"catch_all", {"nf_host:80"}}}};
  initConfig({config_header_to_metadata_nf}, cluster_dict, "NF");

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "sepp.own_plmn.com:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-nf-cluster", "true"},
      {"x-absolute-path-processing", "true"},
      // {"x-sepp-tfqdn-original-body-replaced", "true"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nchf-convergedcharging/v2/chargingdata"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "nf_host:80"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: NfAbsPathNotPresentElementIsMissing
// Description: NF support, orig. Body was not replaced, Absolute Path Processing is disabled
// - Target host has endpoint-metadata "supports: NF"
// - sepp-tfqdn-original-body = test body
// - "x-tfqdn-cluster-relative" = "/test/relative/path"
// - "3gpp-Sbi-target-apiRoot" = http://eric-chfsim-1-mnc-123-mcc-123:80
// Expected Result:
// - Original body is not restored
// - Relative path is not restored
// - 3gpp-Sbi-Target-apiRoot is removed
// - TaR is removed
// - authority = EP host and port
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, NfAbsPathNotPresentElementIsMissing) {
  ClusterDict cluster_dict = {{{"catch_all", {"nf_host:80"}}}};
  initConfig({config_header_to_metadata_nf}, cluster_dict, "NF");

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "sepp.own_plmn.com:80"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-nf-cluster", "true"},
      {"x-tfqdn-cluster-relative", "/test/relative/path"},
      // {"x-sepp-tfqdn-original-body", "test body"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "nf_host:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nchf-convergedcharging/v2/chargingdata"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: NfAbsPathFalseElementIsMissing
// Description: NF support, orig. Body was not replaced, Absolute Path Processing is disabled
// - Target host has endpoint-metadata "supports: NF"
// - sepp-tfqdn-original-body = test body
// - "x-tfqdn-cluster-relative" = "/test/relative/path"
// - "3gpp-Sbi-target-apiRoot" = http://eric-chfsim-1-mnc-123-mcc-123:80
// - "x-absolute-path-processing" = "false"
// - "x-tfqdn-cluster-relative" = "/test/relative/path"
// Expected Result:
// - Original body is not restored
// - path is not restored
// - 3gpp-Sbi-Target-apiRoot is removed
// - TaR is removed
// - authority = EP host and port
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, NfAbsPathFalseElementIsMissing) {
  ClusterDict cluster_dict = {{{"catch_all", {"nf_host:80"}}}};
  initConfig({config_header_to_metadata_nf}, cluster_dict, "NF");

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "sepp.own_plmn.com:80"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-nf-cluster", "true"},
      {"x-absolute-path-processing", "false"},
      {"x-tfqdn-cluster-relative", "/test/relative/path"},
      // {"x-sepp-tfqdn-original-body", "test body"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "nf_host:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nchf-convergedcharging/v2/chargingdata"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}


// Name: TFqdnAbsPathTrueExtToInt
// Description: TFQDN support, Absolute Path Processing is enabled, ext_to_int
// - Target host has endpoint-metadata "supports: TFQDN"
// - x-sepp-routing-direction = ext_to_int
// - x-absolute-path-processing = true
// - x-tfqdn-cluster-relative = /test/relative/path
// - x-sepp-tfqdn-modified-body = test body
// - 3gpp-Sbi-target-apiRoot = http://eric-chfsim-1-mnc-123-mcc-123:80
// Expected Result:
// - Body is modified
// - Relative path is restored
// - 3gpp-Sbi-Target-apiRoot is removed
// - TaR is removed
// - authority = EP host and port
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, TFqdnAbsPathTrueExtToInt) {
  GTEST_SKIP() << "Moved to sepp_tfqdn_router_test";
  ClusterDict cluster_dict = {{{"catch_all", {"tfqdn_host:80"}}}};
  initConfig({config_header_to_metadata_tfqdn}, cluster_dict, "TFQDN");

  const std::string modified_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "sepp.own_plmn.com:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-tfqdn-cluster", "true"},
      {"x-sepp-routing-direction", "ext_to_int"},
      {"x-absolute-path-processing", "true"},
      {"x-tfqdn-cluster-relative", "/test/relative/path"},
      {"x-sepp-tfqdn-modified-body", modified_body},
      {"x-sepp-tfqdn-modified-body-len", std::to_string(modified_body.length())},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length",
        std::to_string(modified_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), modified_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "tfqdn_host:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/test/relative/path"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: TFqdnAbsPathTrueExtToIntPathIsMissing
// Description: TFQDN support, Absolute Path Processing is enabled, ext_to_int
// - Target host has endpoint-metadata "supports: TFQDN"
// - x-sepp-routing-direction = ext_to_int
// - x-absolute-path-processing = true
// - x-sepp-tfqdn-modified-body = test body
// - 3gpp-Sbi-target-apiRoot = http://eric-chfsim-1-mnc-123-mcc-123:80
// Expected Result:
// - Body is modified
// - Relative path is the same
// - 3gpp-Sbi-Target-apiRoot is removed
// - TaR is removed
// - authority = EP host and port
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, TFqdnAbsPathTrueExtToIntPathIsMissing) {
  GTEST_SKIP() << "Moved to sepp_tfqdn_router_test";
  ClusterDict cluster_dict = {{{"catch_all", {"tfqdn_host:80"}}}};
  initConfig({config_header_to_metadata_tfqdn}, cluster_dict, "TFQDN");

  const std::string modified_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "sepp.own_plmn.com:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-tfqdn-cluster", "true"},
      {"x-sepp-routing-direction", "ext_to_int"},
      {"x-absolute-path-processing", "true"},
      {"x-sepp-tfqdn-modified-body", modified_body},
      {"x-sepp-tfqdn-modified-body-len", std::to_string(modified_body.length())},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(modified_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), modified_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "tfqdn_host:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nchf-convergedcharging/v2/chargingdata"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: TFqdnNothingIsSet
// Description: TFQDN support
// - Target host has endpoint-metadata "supports: TFQDN"
// Expected Result:
// - Body is not modified
// - Relative path is restored
// - 3gpp-Sbi-Target-apiRoot is removed
// - TaR is removed
// - authority = EP host and port
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, TFqdnNothingIsSet) {
  ClusterDict cluster_dict = {{{"catch_all", {"tfqdn_host:80"}}}};
  initConfig({config_header_to_metadata_tfqdn}, cluster_dict, "TFQDN");

  const std::string modified_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "sepp.own_plmn.com:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-tfqdn-cluster", "true"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "tfqdn_host:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nchf-convergedcharging/v2/chargingdata"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: TFqdnAbsPathFalseExtToInt
// Description: TFQDN support, Absolute Path Processing is enabled, ext_to_int
// - Target host has endpoint-metadata "supports: TFQDN"
// - x-sepp-routing-direction = ext_to_int
// - x-absolute-path-processing = false
// - x-tfqdn-cluster-relative = /test/relative/path
// - x-sepp-tfqdn-modified-body = test body
// - 3gpp-Sbi-target-apiRoot = http://eric-chfsim-1-mnc-123-mcc-123:80
// Expected Result:
// - Body is modified
// - Relative path is not restored
// - 3gpp-Sbi-Target-apiRoot is removed
// - TaR is removed
// - authority = EP host and port
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, TFqdnAbsPathFalseExtToInt) {
  GTEST_SKIP() << "Moved to sepp_tfqdn_router_test";
  ClusterDict cluster_dict = {{{"catch_all", {"tfqdn_host:80"}}}};
  initConfig({config_header_to_metadata_tfqdn}, cluster_dict, "TFQDN");

  const std::string modified_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "sepp.own_plmn.com:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-tfqdn-cluster", "true"},
      {"x-sepp-routing-direction", "ext_to_int"},
      {"x-absolute-path-processing", "false"},
      {"x-tfqdn-cluster-relative", "/test/relative/path"},
      {"x-sepp-tfqdn-modified-body", modified_body},
      {"x-sepp-tfqdn-modified-body-len", std::to_string(modified_body.length())},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(modified_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), modified_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "tfqdn_host:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nchf-convergedcharging/v2/chargingdata"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: TFqdnAbsPathTrue
// Description: TFQDN support, Absolute Path Processing is enabled
// - Target host has endpoint-metadata "supports: TFQDN"
// - x-absolute-path-processing = true
// - x-tfqdn-cluster-relative = /test/relative/path
// - x-sepp-tfqdn-modified-body = test body
// - 3gpp-Sbi-target-apiRoot = http://eric-chfsim-1-mnc-123-mcc-123:80
// Expected Result:
// - Body is not modified
// - path is restored
// - 3gpp-Sbi-Target-apiRoot is removed
// - TaR is removed
// - authority = EP host and port
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, TFqdnAbsPathTrue) {
  ClusterDict cluster_dict = {{{"catch_all", {"tfqdn_host:80"}}}};
  initConfig({config_header_to_metadata_tfqdn}, cluster_dict, "TFQDN");

  const std::string modified_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "sepp.own_plmn.com:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-tfqdn-cluster", "true"},
      {"x-absolute-path-processing", "true"},
      {"x-tfqdn-cluster-relative", "/test/relative/path"},
      // {"x-sepp-tfqdn-modified-body", modified_body},
      // {"x-sepp-tfqdn-modified-body-len", std::to_string(modified_body.length())},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "tfqdn_host:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/test/relative/path"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: TFqdnAbsPathFalse
// Description: TFQDN support, Absolute Path Processing is disabled
// - Target host has endpoint-metadata "supports: TFQDN"
// - x-absolute-path-processing = false
// - x-tfqdn-cluster-relative = /test/relative/path
// - x-sepp-tfqdn-modified-body = test body
// - 3gpp-Sbi-target-apiRoot = http://eric-chfsim-1-mnc-123-mcc-123:80
// Expected Result:
// - Body is not modified
// - path is not restored
// - 3gpp-Sbi-Target-apiRoot is removed
// - TaR is removed
// - authority = EP host and port
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, TFqdnAbsPathFalse) {
  ClusterDict cluster_dict = {{{"catch_all", {"tfqdn_host:80"}}}};
  initConfig({config_header_to_metadata_tfqdn}, cluster_dict, "TFQDN");

  const std::string modified_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "sepp.own_plmn.com:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-tfqdn-cluster", "true"},
      {"x-absolute-path-processing", "false"},
      {"x-tfqdn-cluster-relative", "/test/relative/path"},
      // {"x-sepp-tfqdn-modified-body", modified_body},
      // {"x-sepp-tfqdn-modified-body-len", std::to_string(modified_body.length())},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "tfqdn_host:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nchf-convergedcharging/v2/chargingdata"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: TarBodyReplacedAbsPathTrueTargetApiTrue
// Description: Tar support, body is replaced, abs path processing, target api processing
// - Target host has endpoint-metadata "supports: Indirect"
// - No dyn. MD keep-authority-header = true
// - Body was replaced
// - dyn. MD absolute-path-processing = true
// - "target-api-root-processing" is "true"
// - :authority= scp1.plmnA.com
// Expected Result:
// - body is restored
// - Path is absolute and equal to MD "absolute-path-value"
// - Header 3gpp-Sbi-Target-apiRoot is restored
// - authority = EP host and port
// - SCP node
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, TarBodyReplacedAbsPathTrueTargetApiTrue) {
  ClusterDict cluster_dict = {{{"catch_all", {"indirect_host:80"}}}};
  initConfig({config_header_to_metadata_tar}, cluster_dict, "Indirect");

   const std::string modified_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "scp1.plmnA.com"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-indirect-cluster", "true"},
      {"x-absolute-path-processing", "true"},
      {"x-absolute-path-value", "/test/absolute/path"},
      // {"x-sepp-tfqdn-original-body-replaced", "true"},
      // {"x-sepp-tfqdn-original-body", modified_body},
      // {"x-sepp-tfqdn-original-body-len", std::to_string(modified_body.length())},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"x-target-api-root-processing", "true"},
      {"x-target-api-root-value", "myValue"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());

  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(modified_body.length())));
  // EXPECT_EQ(upstream_request_->body().toString(), modified_body);
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "indirect_host:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/test/absolute/path"));
  EXPECT_FALSE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-Sbi-target-apiRoot", "myValue"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: TarBodyReplacedAbsPathTrueTargetApiTrueValueIsMissing
// Description: Tar support, body is replaced, abs path processing, target api processing, target-api-root-value is missing
// - Target host has endpoint-metadata "supports: Indirect"
// - No dyn. MD keep-authority-header = true
// - Body was replaced
// - dyn. MD absolute-path-processing = true
// - "target-api-root-processing" is "true"
// - :authority= scp1.plmnA.com
// Expected Result:
// - body is restored
// - Path is absolute and equal to MD "absolute-path-value"
// - Header 3gpp-Sbi-Target-apiRoot is removed
// - authority = EP host and port
// - SCP node
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, TarBodyReplacedAbsPathTrueTargetApiTrueValueIsMissing) {
  ClusterDict cluster_dict = {{{"catch_all", {"indirect_host:80"}}}};
  initConfig({config_header_to_metadata_tar}, cluster_dict, "Indirect");

  const std::string modified_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "scp1.plmnA.com"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-indirect-cluster", "true"},
      {"x-absolute-path-processing", "true"},
      {"x-absolute-path-value", "/test/absolute/path"},
      // {"x-sepp-tfqdn-original-body-replaced", "true"},
      // {"x-sepp-tfqdn-original-body", modified_body},
      // {"x-sepp-tfqdn-original-body-len", std::to_string(modified_body.length())},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"x-target-api-root-processing", "true"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());

  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(modified_body.length())));
  // EXPECT_EQ(upstream_request_->body().toString(), modified_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "indirect_host:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/test/absolute/path"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: TarBodyReplacedAbsPathTrueTargetApiTruePathIsMissing
// Description: Tar support, body is replaced, abs path processing, target api processing
// - Target host has endpoint-metadata "supports: Indirect"
// - No dyn. MD keep-authority-header = true
// - Body was replaced
// - dyn. MD absolute-path-processing = true
// - "target-api-root-processing" is "true"
// - :authority= scp1.plmnA.com
// Expected Result:
// - body is restored
// - Path was not changed
// - Header 3gpp-Sbi-Target-apiRoot is restored
// - authority = EP host and port
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, TarBodyReplacedAbsPathTrueTargetApiTruePathIsMissing) {
  ClusterDict cluster_dict = {{{"catch_all", {"indirect_host:80"}}}};
  initConfig({config_header_to_metadata_tar}, cluster_dict, "Indirect");

  const std::string modified_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "scp1.plmnA.com"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-indirect-cluster", "true"},
      {"x-absolute-path-processing", "true"},
      // {"x-sepp-tfqdn-original-body-replaced", "true"},
      // {"x-sepp-tfqdn-original-body", modified_body},
      // {"x-sepp-tfqdn-original-body-len", std::to_string(modified_body.length())},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"x-target-api-root-processing", "true"},
      {"x-target-api-root-value", "myValue"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());

  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(modified_body.length())));
  // EXPECT_EQ(upstream_request_->body().toString(), modified_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "indirect_host:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nchf-convergedcharging/v2/chargingdata"));
  EXPECT_FALSE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-Sbi-target-apiRoot", "myValue"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());
  codec_client_->close();
}

// Name: TarNothing
// Description: Tar support, body is replaced, abs path processing, target api processing
// - Target host has endpoint-metadata "supports: Indirect"
// - No dyn. MD keep-authority-header = true
// Expected Result:
// - body was not changed
// - Path was not modified
// - Header 3gpp-Sbi-Target-apiRoot is removed
// - authority = EP host and port
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, TarNothing) {
  ClusterDict cluster_dict = {{{"catch_all", {"indirect_host:80"}}}};
  initConfig({config_header_to_metadata_tar}, cluster_dict, "Indirect");

  const std::string modified_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "scp1.plmnA.com"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-indirect-cluster", "true"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "indirect_host:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nchf-convergedcharging/v2/chargingdata"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: TarBodyReplacedAbsPathFalseTargetApiTrue
// Description: Tar support, body is replaced, target api processing
// - Target host has endpoint-metadata "supports: Indirect"
// - No dyn. MD keep-authority-header = true
// - Body was replaced
// - dyn. MD absolute-path-processing = false
// - "target-api-root-processing" is "true"
// - :authority= scp1.plmnA.com
// Expected Result:
// - body is restored
// - Path is absolute and equal to MD "absolute-path-value"
// - Header 3gpp-Sbi-Target-apiRoot is restored
// - authority = EP host and port
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, TarBodyReplacedAbsPathFalseTargetApiTrue) {
  ClusterDict cluster_dict = {{{"catch_all", {"indirect_host:80"}}}};
  initConfig({config_header_to_metadata_tar}, cluster_dict, "Indirect");

  const std::string modified_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "scp1.plmnA.com"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-indirect-cluster", "true"},
      {"x-absolute-path-processing", "false"},
      {"x-absolute-path-value", "/test/absolute/path"},
      // {"x-sepp-tfqdn-original-body-replaced", "true"},
      // {"x-sepp-tfqdn-original-body", modified_body},
      // {"x-sepp-tfqdn-original-body-len", std::to_string(modified_body.length())},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"x-target-api-root-processing", "true"},
      {"x-target-api-root-value", "myValue"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());

  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(modified_body.length())));
  // EXPECT_EQ(upstream_request_->body().toString(), modified_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "indirect_host:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nchf-convergedcharging/v2/chargingdata"));
  EXPECT_FALSE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-Sbi-target-apiRoot", "myValue"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: TarBodyReplacedAbsPathFalseTargetApiTrueToSepp
// Description: Tar support, body is replaced, target api processing, fli
// - Target host has endpoint-metadata "supports: Indirect"
// - No dyn. MD keep-authority-header = true
// - Body was replaced
// - dyn. MD absolute-path-processing = false
// - "target-api-root-processing" is "true"
// - :authority= sepp.plmnA.com
// Expected Result:
// - body is restored
// - Path is absolute and equal to MD "absolute-path-value"
// - Header 3gpp-Sbi-Target-apiRoot is restored
// - authority = EP host and port
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, TarBodyReplacedAbsPathFalseTargetApiTrueToSepp) {
  ClusterDict cluster_dict = {
    {{"sepp_pool", {"eric-chfsim-1-mnc-123-mcc-123:80"}}},
    {{"catch_all", {"dummy.op.com:80"}}}};
  initConfig({config_basic, config_header_to_metadata_tar}, cluster_dict, "Indirect");

  const std::string modified_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "sepp.plmnA.com"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-indirect-cluster", "true"},
      {"x-absolute-path-processing", "false"},
      {"x-absolute-path-value", "/test/absolute/path"},
      // {"x-sepp-tfqdn-original-body-replaced", "true"},
      // {"x-sepp-tfqdn-original-body", modified_body},
      // {"x-sepp-tfqdn-original-body-len", std::to_string(modified_body.length())},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"x-target-api-root-processing", "true"},
      {"x-target-api-root-value", "to_sepp"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());

  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(modified_body.length())));
  // EXPECT_EQ(upstream_request_->body().toString(), modified_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "eric-chfsim-1-mnc-123-mcc-123:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nchf-convergedcharging/v2/chargingdata"));
  EXPECT_FALSE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  // DND-50654
  // After moving the location where value of TaR is filled in target-api-root-value i.e post egress screening ,
  // the following validation doesnt apply
  //EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("3gpp-Sbi-target-apiRoot", "to_sepp"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: TarBodyReplacedAbsPathTrueTargetApiFalse
// Description: Tar support, body is replaced, abs path processing
// - Target host has endpoint-metadata "supports: Indirect"
// - No dyn. MD keep-authority-header = true
// - Body was replaced
// - dyn. MD absolute-path-processing = true
// - "target-api-root-processing" is "false"
// - :authority= scp1.plmnA.com
// Expected Result:
// - body is restored
// - Original path
// - Header 3gpp-Sbi-Target-apiRoot is removed
// - authority = EP host and port
// - SCP node
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, TarBodyReplacedAbsPathTrueTargetApiFalse) {
  ClusterDict cluster_dict = {{{"catch_all", {"indirect_host:80"}}}};
  initConfig({config_header_to_metadata_tar}, cluster_dict, "Indirect");

  const std::string modified_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "scp1.plmnA.com"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-indirect-cluster", "true"},
      {"x-absolute-path-processing", "true"},
      {"x-absolute-path-value", "/test/absolute/path"},
      // {"x-sepp-tfqdn-original-body-replaced", "true"},
      // {"x-sepp-tfqdn-original-body", modified_body},
      // {"x-sepp-tfqdn-original-body-len", std::to_string(modified_body.length())},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"x-target-api-root-processing", "false"},
      {"x-target-api-root-value", "myValue"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());

  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(modified_body.length())));
  // EXPECT_EQ(upstream_request_->body().toString(), modified_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "indirect_host:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/test/absolute/path"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: TarBodyReplacedAbsPathFalseTargetApiFalse
// Description: Tar support, body is replaced
// - Target host has endpoint-metadata "supports: Indirect"
// - No dyn. MD keep-authority-header = true
// - Body was replaced
// - dyn. MD absolute-path-processing = false
// - "target-api-root-processing" is "false"
// - :authority= scp1.plmnA.com
// Expected Result:
// - body is restored
// - Original path
// - Header 3gpp-Sbi-Target-apiRoot is removed
// - authority = EP host and port
// - SCP node
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, TarBodyReplacedAbsPathFalseTargetApiFalse) {
  ClusterDict cluster_dict = {{{"catch_all", {"indirect_host:80"}}}};
  initConfig({config_header_to_metadata_tar}, cluster_dict, "Indirect");

  const std::string modified_body{"test body"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "scp1.plmnA.com"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-indirect-cluster", "true"},
      {"x-absolute-path-processing", "false"},
      {"x-absolute-path-value", "/test/absolute/path"},
      // {"x-sepp-tfqdn-original-body-replaced", "true"},
      // {"x-sepp-tfqdn-original-body", modified_body},
      // {"x-sepp-tfqdn-original-body-len", std::to_string(modified_body.length())},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-123-mcc-123:80"},
      {"x-target-api-root-processing", "false"},
      {"x-target-api-root-value", "myValue"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());

  // EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(modified_body.length())));
  // EXPECT_EQ(upstream_request_->body().toString(), modified_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "indirect_host:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nchf-convergedcharging/v2/chargingdata"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: NoTarAbsPathTrueHostIsMissing
// Description: No-Tar support
// - Target host has endpoint-metadata "supports: Indirect"
// - dyn. MD keep-authority-header = true
// - x-absolute-path-processing = true
// - :authority= prod2.plmnB.com
// Expected Result:
// - Path is absolute and equal to MD "absolute-path-value"
// - Header 3gpp-Sbi-Target-apiRoot is removed
// - authority = did not change
// - SEPP node
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, NoTarAbsPathTrueHostIsMissing) {
  ClusterDict cluster_dict = {{{"catch_all", {"scp1.plmnA.com:80"}}}};
  initConfig({config_header_to_metadata_no_tar}, cluster_dict, "Indirect");

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "scp1.plmnA.com"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-indirect-cluster", "true"},
      {"x-keep-authority-header", "true"},
      {"x-absolute-path-processing", "true"},
      {"x-absolute-path-value", "/test/absolute/path"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "scp1.plmnA.com"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/test/absolute/path"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

#ifdef LATER
// DND-45035
// TODO: see fixme comments on actions_routing
// the outgoing authority header should be set based on preferred header :authority
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, TarPreferredHostIsSet) {
  //TODO: adapt to initConfig() of pluggable_config.h
  //config_helper_.addFilter(config_basic_sepp);
  //config_helper_.addFilter(config_header_to_metadata_tar_pref_host);
  //initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "sepp.own_plmn.com:80"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-963-mcc-963:80"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-indirect-cluster", "true"},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());

  upstream_request_->headers().forEach([](absl::string_view key, absl::string_view val) {
    std::cerr << key << ": " << val << std::endl;
    return true;
  });

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "sepp.own_plmn.com:80"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-host", "sepp.own_plmn.com:80"));

  codec_client_->close();
}
#endif

// Name: NoTarAbsPathTrue
// Description: No-Tar support
// - Target host has endpoint-metadata "supports: Indirect"
// - dyn. MD keep-authority-header = true
// - x-absolute-path-processing = true
// - preferred host = my.host.de
// Expected Result:
// - path was chanded
// - Header 3gpp-Sbi-Target-apiRoot is removed
// - authority is set to preferred host
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, NoTarAbsPathTrue) {
  const std::string preferred_host{"my.host.de"};

  ClusterDict cluster_dict = {{{"catch_all", {preferred_host}}}};
  initConfig({config_header_to_metadata_no_tar}, cluster_dict, "Indirect");

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "scp1.plmnA.com"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-indirect-cluster", "true"},
      {"x-keep-authority-header", "true"},
      {"x-absolute-path-processing", "true"},
      {"x-absolute-path-value", "/test/absolute/path"},
      {"x-preferred-host", preferred_host},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", preferred_host));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/test/absolute/path"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: NoTarAbsPathTruePathIsMissing
// Description: No-Tar support
// - Target host has endpoint-metadata "supports: Indirect"
// - dyn. MD keep-authority-header = true
// - x-absolute-path-processing = false
// - preferred host = my.host.de
// Expected Result:
// - path was not chanded
// - Header 3gpp-Sbi-Target-apiRoot is removed
// - authority is set to preferred host
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, NoTarAbsPathTruePathIsMissing) {
  const std::string preferred_host{"my.host.de"};

  ClusterDict cluster_dict = {{{"catch_all", {preferred_host}}}};
  initConfig({config_header_to_metadata_no_tar}, cluster_dict, "Indirect");

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "scp1.plmnA.com"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-indirect-cluster", "true"},
      {"x-keep-authority-header", "true"},
      {"x-absolute-path-processing", "true"},
      {"x-preferred-host", preferred_host},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", preferred_host));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nchf-convergedcharging/v2/chargingdata"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: NoTarempty
// Description: No-Tar support
// - Target host has endpoint-metadata "supports: Indirect"
// - dyn. MD keep-authority-header = true
// - :authority= prod2.plmnB.com
// Expected Result:
// - Path is the same
// - Header 3gpp-Sbi-Target-apiRoot is removed
// - authority = did not changed
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, NoTarempty) {
  ClusterDict cluster_dict = {{{"catch_all", {"scp1.plmnA.com:80"}}}};
  initConfig({config_header_to_metadata_no_tar}, cluster_dict, "Indirect");

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "scp1.plmnA.com"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-indirect-cluster", "true"},
      {"x-keep-authority-header", "true"}
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", "scp1.plmnA.com"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nchf-convergedcharging/v2/chargingdata"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}

// Name: NoTarAbsPathFalse
// Description: No-Tar support
// - Target host has endpoint-metadata "supports: Indirect"
// - dyn. MD keep-authority-header = true
// - x-absolute-path-processing = false
// - preferred host = my.host.de
// Expected Result:
// - Original Path
// - Header 3gpp-Sbi-Target-apiRoot is removed
// - authority = EP host and port
// - SEPP node
// - authority is set to preferred host
TEST_P(EricProxyFilterSeppTFqdnRouterIntegrationTest, NoTarAbsPathFalse) {
  const std::string preferred_host{"my.host.de"};

  ClusterDict cluster_dict = {{{"catch_all", {preferred_host}}}};
  initConfig({config_header_to_metadata_no_tar}, cluster_dict, "Indirect");

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "POST"},
      {":path", "/nchf-convergedcharging/v2/chargingdata"},
      {":authority", "scp1.plmnA.com"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"x-indirect-cluster", "true"},
      {"x-keep-authority-header", "true"},
      {"x-absolute-path-processing", "false"},
      {"x-absolute-path-value", "/test/absolute/path"},
      {"x-preferred-host", preferred_host},
  };

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(cc_create_req_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}
  };

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  IntegrationStreamDecoderPtr response = codec_client_->makeRequestWithBody(request_headers, cc_create_req_body);
  waitForNextUpstreamRequest();

  // Send response:
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(cc_create_resp_body);
  upstream_request_->encodeData(response_data, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(upstream_request_->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("content-length", std::to_string(cc_create_req_body.length())));
  EXPECT_EQ(upstream_request_->body().toString(), cc_create_req_body);
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":authority", preferred_host));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf(":path", "/nchf-convergedcharging/v2/chargingdata"));
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot")).empty());
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("Target-Api-Root")).empty());

  codec_client_->close();
}


} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
