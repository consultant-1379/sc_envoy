#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"
#include <ostream>
#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

using ::testing::_;
using ::testing::AnyOf;
using ::testing::Not;

class EricProxyFilterNfDiscIntegrationTest
    : public HttpIntegrationTest,
      public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterNfDiscIntegrationTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(),
                            EricProxyFilterNfDiscIntegrationTest::ericProxyHttpProxyConfig()) {}
  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);
    setUpstreamCount(2);
    HttpIntegrationTest::initialize();
  }

  void execTestWithBasicAssertions(Http::TestRequestHeaderMapImpl req_headers,
                                   std::string nlf_resp_status_code, std::string nlf_resp_body,
                                   Http::TestRequestHeaderMapImpl expected_nlf_headers,
                                   Http::TestRequestHeaderMapImpl expected_req_headers,
                                   std::vector<std::string> not_expected_req_header_names = {}) {
    IntegrationCodecClientPtr codec_client;
    FakeHttpConnectionPtr fake_upstream_connection;
    FakeStreamPtr request_stream;

    codec_client = makeHttpConnection(lookupPort("http"));
    auto response = codec_client->makeHeaderOnlyRequest(req_headers);
    FakeStreamPtr nlf_request_stream =
        sendNlfResponse({{":status", nlf_resp_status_code}}, nlf_resp_body);

    ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
    ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));

    ASSERT_TRUE(nlf_request_stream->waitForEndStream(*dispatcher_));
    ASSERT_TRUE(fake_nlf_connection_->close());

    ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

    ASSERT_TRUE(fake_upstream_connection->close());
    ASSERT_TRUE(response->waitForEndStream());

    // Validate that all expected headers towards NLF are present and have the correct value:
    EXPECT_THAT(nlf_request_stream->headers(), Http::IsSupersetOfHeaders(expected_nlf_headers));

    // Validate that all expected request headers on egress are present and have the correct value:
    EXPECT_THAT(request_stream->headers(), Http::IsSupersetOfHeaders(expected_req_headers));

    // Validate that headers that should not be there are not there:
    for (auto header_name : not_expected_req_header_names) {
      EXPECT_THAT(request_stream->headers(), Not(Http::HeaderValueOf(header_name, _)));
    }

    codec_client->close();
  }

  void execErrorTestWithBasicAssertions(Http::TestRequestHeaderMapImpl req_headers,
                                        int expected_attempts_to_nlf,
                                        Http::TestRequestHeaderMapImpl nlf_resp_headers,
                                        std::string nlf_resp_body,
                                        Http::TestRequestHeaderMapImpl expected_nlf_headers,
                                        Http::TestRequestHeaderMapImpl expected_resp_headers,
                                        std::string expected_resp_body) {
    IntegrationCodecClientPtr codec_client;

    codec_client = makeHttpConnection(lookupPort("http"));
    auto response = codec_client->makeHeaderOnlyRequest(req_headers);
    FakeStreamPtr nlf_request_stream;

    // To serve also the retries (in case of a 5xx response):
    for (int i = 0; i < expected_attempts_to_nlf; i++) {
      nlf_request_stream = sendNlfResponse(nlf_resp_headers, nlf_resp_body);
      ASSERT_TRUE(nlf_request_stream->waitForEndStream(*dispatcher_));
    }
    ASSERT_TRUE(fake_nlf_connection_->close());
    ASSERT_TRUE(response->waitForEndStream());

    // Validate that all expected headers towards NLF are present and have the correct value:
    EXPECT_THAT(nlf_request_stream->headers(), Http::IsSupersetOfHeaders(expected_nlf_headers));

    // Validate error response headers and body:
    EXPECT_THAT(response->headers(), Http::IsSupersetOfHeaders(expected_resp_headers));
    EXPECT_EQ(response->headers().getContentLengthValue(),
              fmt::format("{}", response->body().size()));
    EXPECT_EQ(response->body(), expected_resp_body);

    codec_client->close();
  }

  std::string baseConfig() {
    return fmt::format(R"EOF(
admin:
  access_log_path: {}
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
    - name: cluster_0
      connect_timeout: 15s
      load_assignment:
        cluster_name: cluster_0
        endpoints:
        - lb_endpoints:
          - endpoint:
              address:
                socket_address:
                  address: 127.0.0.1
                  port_value: 0
              hostname: cluster_0_host_0
            metadata:
              filter_metadata:
                envoy.eric_proxy:
                  support:
                  - NF
    - name: cluster_1
      connect_timeout: 15s
      load_assignment:
        cluster_name: cluster_1
        endpoints:
        - lb_endpoints:
          - endpoint:
              address:
                socket_address:
                  address: 127.0.0.1
                  port_value: 0
              hostname: cluster_1_host_0
            metadata:
              filter_metadata:
                envoy.eric_proxy:
                  support:
                  - NF
  listeners:
    name: listener_0
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 0
)EOF",
                       Platform::null_device_path, Platform::null_device_path);
  }

  // Note: num_retries is set to zero to be able to test the error cases
  // to the NLF more easily
  std::string ericProxyHttpProxyConfig() {
    return absl::StrCat(baseConfig(), fmt::format(R"EOF(
    filter_chains:
      filters:
        name: http
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress.n8e.West1.g3p.ingress
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
              - match:
                  prefix: "/"
                route:
                  cluster: cluster_0
                  retry_policy:
                    num_retries: 0
  )EOF",
                                                  Platform::null_device_path));
  }

  // Configuration for basic positive tests
  // Check for correct values in preferred host and nfset after action-nf-discovery
  std::string config_basic = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: "SCP Test"
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
      - name: "variable for add_parameters_if_missing"
        header: addvarheader
        variable_name: addvar
      filter_rules:
      - name: nf_disc
        condition:
          term_boolean: true
        actions:
        - action_nf_discovery:
            cluster_name: cluster_1
            timeout: 1000
            nrf_group_name: nrfgroup_1
            use_all_parameters: true
            add_parameters_if_missing:
            - key: test-1
              value:
                term_string: testvalue1
            - key: test-2
              value:
                term_var: addvar
            nf_selection_on_priority:
              var_name_preferred_host: pref
              var_name_nf_set: nfset
            ip_version: IPv4
      - name: nf_sel
        condition:
          op_and:
            arg1:
              op_equals:
                typed_config1:
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_var: pref
                typed_config2:
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_string: 'FQDN-1.example.com:9091'
            arg2:
              op_equals:
                typed_config1:
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_var: nfset
                typed_config2:
                  '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                  term_string: 'setA'
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: correct_pool
            routing_behaviour: ROUND_ROBIN
      - name: failed
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";

  // Configuration for basic positive tests
  // - add-parameters contains one param (target-nf-type) that would (but shall not)
  //   overwrite the value from the request
  // - the selected NF (= highest prio) has two services = two endpoints
  std::string config_basic2 = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: "SCP Test"
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
      filter_rules:
      - name: nf_disc
        condition:
          term_boolean: true
        actions:
        - action_nf_discovery:
            cluster_name: cluster_1
            timeout: 1000
            nrf_group_name: nrfgroup_1
            use_all_parameters: true
            add_parameters_if_missing:
            - key: target-nf-type
              value:
                term_string: SMF
            - key: test-2
              value:
                term_string: testvalue2
            nf_selection_on_priority:
              var_name_preferred_host: pref
              var_name_nf_set: nfset
            ip_version: IPv4
      - name: nf_sel
        condition:
            op_equals:
              typed_config1:
                '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                term_var: nfset
              typed_config2:
                '@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value'
                term_string: 'setB'
        actions:
        - action_route_to_pool:
            preferred_target:
              term_var: pref
            pool_name:
              term_var: nfset
            routing_behaviour: PREFERRED
      - name: failed
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: wrong_pool
            routing_behaviour: ROUND_ROBIN
)EOF";

  // Configuration for basic positive tests
  // - no add-parameters
  // - use-params for specific discovery-parameters only
  std::string config_basic3 = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: "SCP Test"
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
      filter_rules:
      - name: nf_disc
        condition:
          term_boolean: true
        actions:
        - action_nf_discovery:
            cluster_name: cluster_1
            timeout: 1000
            nrf_group_name: nrfgroup_1
            use_parameters:
              values:
              - requester-nf-type
              - non-existing
            add_parameters_if_missing:
            - key: target-nf-type
              value:
                term_string: CHF
            nf_selection_on_priority:
              var_name_preferred_host: pref
              var_name_nf_set: nfset
            ip_version: IPv4
        - action_route_to_pool:
            pool_name:
              term_string: correct_pool
            routing_behaviour: ROUND_ROBIN
)EOF";

  // Configuration for basic positive tests
  // No nf_selection_on_priority is configured, should be ok because action-route-remote-rr
  // does not need nf_selection_on_priority.
  std::string config_basic4 = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: "SCP Test"
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
      filter_rules:
      - name: nf_disc
        condition:
          term_boolean: true
        actions:
        - action_nf_discovery:
            cluster_name: cluster_1
            timeout: 1000
            nrf_group_name: nrfgroup_1
            use_all_parameters: true
            add_parameters_if_missing:
            - key: test-1
              value:
                term_string: testvalue1
            - key: test-2
              value:
                term_string: testvalue2
            ip_version: IPv4
      - name: nf_sel
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool:
            pool_name:
              term_string: correct_pool
            routing_behaviour: ROUND_ROBIN
)EOF";

  std::string config_basic_peer = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: "SCP Test"
  node_type: SCP
  own_fqdn: scp.own_plmn.com
  nf_peer_info_handling: "ON"
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
      - name: nf_disc
        condition:
          term_boolean: true
        actions:
        - action_nf_discovery:
            cluster_name: cluster_1
            timeout: 1000
            nrf_group_name: nrfgroup_1
            use_parameters:
              values:
              - requester-nf-type
              - non-existing
            add_parameters_if_missing:
            - key: target-nf-type
              value:
                term_string: CHF
            nf_selection_on_priority:
              var_name_preferred_host: pref
              var_name_nf_set: nfset
            ip_version: IPv4
        - action_route_to_pool:
            pool_name:
              term_string: correct_pool
            routing_behaviour: ROUND_ROBIN
)EOF";

  // NLF response: One NF with highest priority, one NF on second prio
  std::string nlfResponseBodyProfile1() {
    return R"EOT(
{
  "validityPeriod": 60,
  "nfInstances": [
    {
      "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
      "nfInstanceName": "nfInstanceName_1",
      "nfType": "AUSF",
      "nfSetIdList": [
        "setA"
      ],
      "nfServices": [
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce100",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "FQDN-1.example.com",
          "priority": 1,
          "capacity": 60000,
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
      "nfSetIdList": [
        "setB"
      ],
      "nfServices": [
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce101",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "FQDN-2.example.com",
          "priority": 2,
          "capacity": 60000,
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
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce102",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "FQDN-3.example.com",
          "priority": 3,
          "capacity": 60000,
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
)EOT";
  }

  // NLF response: One NF with two services on highest priority
  std::string nlfResponseBodyProfile2() {
    return R"EOT(
{
  "validityPeriod": 60,
  "nfInstances": [
    {
      "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
      "nfInstanceName": "nfInstanceName_1",
      "nfType": "AUSF",
      "nfSetIdList": [
        "setA"
      ],
      "nfServices": [
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce100",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "FQDN-1.example.com",
          "priority": 2,
          "capacity": 60000,
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
      "nfSetIdList": [
        "setB"
      ],
      "nfServices": [
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce101",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "FQDN-2.example.com",
          "priority": 1,
          "capacity": 60000,
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
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce102",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "FQDN-3.example.com",
          "priority": 1,
          "capacity": 60000,
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
)EOT";
  }

  // Fake NLF Functionality: Send a response from "NLF" to Envoy with the supplied
  // headers, and body.  Return the stream.
  // The headers MUST at least include the :status header!
  FakeStreamPtr sendNlfResponse(const Http::TestResponseHeaderMapImpl headers,
                                const std::string& body) {
    if (!fake_nlf_connection_) {
      AssertionResult result =
          fake_upstreams_[1]->waitForHttpConnection(*dispatcher_, fake_nlf_connection_);
      RELEASE_ASSERT(result, result.message());
    }

    FakeStreamPtr request_stream;
    AssertionResult result = fake_nlf_connection_->waitForNewStream(*dispatcher_, request_stream);
    RELEASE_ASSERT(result, result.message());
    result = request_stream->waitForEndStream(*dispatcher_);

    if (body.empty()) {
      request_stream->encodeHeaders(headers, true);
    } else {
      request_stream->encodeHeaders(headers, false);
      Buffer::OwnedImpl responseBuffer(body);
      request_stream->encodeData(responseBuffer, true);
    }

    return request_stream;
  }

  // NLF doesn't respond after accepting the stream
  FakeStreamPtr noNlfResponse() {
    ENVOY_LOG(debug, "noNlfResponse()");
    if (!fake_nlf_connection_) {
      AssertionResult result =
          fake_upstreams_[1]->waitForHttpConnection(*dispatcher_, fake_nlf_connection_);
      RELEASE_ASSERT(result, result.message());
    }

    FakeStreamPtr request_stream;
    AssertionResult result = fake_nlf_connection_->waitForNewStream(*dispatcher_, request_stream);
    RELEASE_ASSERT(result, result.message());
    result = request_stream->waitForEndStream(*dispatcher_);
    RELEASE_ASSERT(result, result.message());

    return request_stream;
  }

  // Helper function to validate the results of a 5xx response
  void verifyResponse5xx(IntegrationStreamDecoderPtr& response, std::string status,
                         std::string expected_resp_body) {
    EXPECT_THAT(response->headers(), Http::HttpStatusIs(status));
    EXPECT_EQ(response->headers().getContentTypeValue(), "application/problem+json");
    EXPECT_EQ(response->headers().getContentLengthValue(),
              fmt::format("{}", response->body().size()));
    EXPECT_EQ(response->body(), expected_resp_body);
  }

  // Helper for tests that receive an empty or malformed JSON response from the NRF
  void testEmptyOrMalformedResponse(std::string json_result_body, std::string expected_status,
                                    std::string expected_resp_body) {
    initializeFilter(config_basic);
    Http::TestRequestHeaderMapImpl req_headers{
        {":method", "GET"},
        {":path", "/"},
        {":authority", "host"},
        {"addvarheader", "testvalue2"},
        {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
        {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
        {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
        {"3gpp-sbi-discovery-target-plmn-list",
         R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
        {"3gpp-sbi-correlation-info", "imsi-345012123123123"},
    };

    std::string nnlf_path =
        "/nnlf-disc/v0/nf-instances/"
        "scp?target-nf-type=AUSF&requester-nf-type=SMF&service-names=nausf-auth&target-plmn-list=%"
        "5B%7B%22mcc%22%3A%22123%22%2C%22mnc%22%3A%22456%22%7D%2C%7B%22mcc%22%3A%22234%22%2C%22mnc%"
        "22%3A%22567%22%7D%5D&test-1=testvalue1&test-2=testvalue2&";

    execErrorTestWithBasicAssertions(req_headers,
                                     1,                    // Expected number of tries
                                     {{":status", "200"}}, // NLF response headers to send
                                     json_result_body,     // NLF response body to send
                                     // Expected headers towards NLF:
                                     {{":path", nnlf_path},
                                      {"nrf-group", "nrfgroup_1"},
                                      {"3gpp-sbi-correlation-info", "imsi-345012123123123"}},
                                     // Expected error response headers:
                                     {{":status", expected_status},
                                      {"content-type", "application/problem+json"},
                                      {"3gpp-sbi-correlation-info", "imsi-345012123123123"}},
                                     expected_resp_body);
  }
  FakeHttpConnectionPtr fake_nlf_connection_;
};

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterNfDiscIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

//------ Basic Positive Tests ---------------------------------------------

// Delegated discovery
// - use-all-parameters
// - add-parameters-if-missing for non-existing parameters
// - percent-encoding for target-plmn-list
// - check preferred host and nfset/cluster afterwards
// - check that towards NLF, the user-agent is "SCP" and for the outgoing upstream
//   request it's the original value again ("AMF")
// Successful outcome is expected.
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestSuccessfulDiscovery1) {
  initializeFilter(config_basic);
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"addvarheader", "testvalue2"},
      {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
      {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
      {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
      {"3gpp-sbi-discovery-target-plmn-list",
       R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
      {"3gpp-sbi-correlation-info", "imsi-345012123123123"},
      {"user-agent", "AMF"},
  };

  std::string nnlf_path =
      "/nnlf-disc/v0/nf-instances/"
      "scp?target-nf-type=AUSF&requester-nf-type=SMF&service-names=nausf-auth&target-plmn-list=%5B%"
      "7B%22mcc%22%3A%22123%22%2C%22mnc%22%3A%22456%22%7D%2C%7B%22mcc%22%3A%22234%22%2C%22mnc%22%"
      "3A%22567%22%7D%5D&test-1=testvalue1&test-2=testvalue2&";
  execTestWithBasicAssertions(request_headers, "200", nlfResponseBodyProfile1(),
                              // Expected headers towards NLF:
                              {{":path", nnlf_path},
                               {"nrf-group", "nrfgroup_1"},
                               {"3gpp-sbi-correlation-info", "imsi-345012123123123"},
                               {"user-agent", "SCP"}},
                              // Expected request headers on egress
                              {{"x-eric-proxy", "///"},
                               {"x-cluster", "correct_pool"},
                               {"user-agent", "AMF"}});
}

// Delegated discovery
// - use-all-parameters
// - add-parameters-if-missing for non-existing parameters
// - percent-encoding for target-plmn-list
// - check preferred host and nfset/cluster afterwards
// - the list of service-names and required-features are changed to a single (the first)
//   value in the query-parameters.  See TS 29.510 v16.12 table 6.2.3.2.3.1-1.
// - the user-agent header is automatically added to the NLF request. Because there was
//   no user-agent header in the incoming request from downstream, there is also no
//   user-agent header expected on upstream
// Successful outcome is expected.
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestSuccessfulDiscovery1b) {
  initializeFilter(config_basic);
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"addvarheader", "testvalue2"},
      {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
      {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
      {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth,nchf-convergedcharging,nudm-sdm"},
      {"3GPP-SBI-DISCOVERY-required-features", "feature-a , feature-b, feature-c"},
      {"3gpp-sbi-discovery-target-plmn-list",
       R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
      {"3gpp-sbi-correlation-info", "imsi-345012123123123"},
  };

  std::string nnlf_path =
      "/nnlf-disc/v0/nf-instances/"
      "scp?target-nf-type=AUSF&requester-nf-type=SMF&service-names=nausf-auth&"
      "required-features=feature-a&target-plmn-list=%5B%"
      "7B%22mcc%22%3A%22123%22%2C%22mnc%22%3A%22456%22%7D%2C%7B%22mcc%22%3A%22234%22%2C%22mnc%22%"
      "3A%22567%22%7D%5D&test-1=testvalue1&test-2=testvalue2&";
  execTestWithBasicAssertions(request_headers, "200", nlfResponseBodyProfile1(),
                              // Expected headers towards NLF:
                              {{":path", nnlf_path},
                               {"nrf-group", "nrfgroup_1"},
                               {"3gpp-sbi-correlation-info", "imsi-345012123123123"},
                               {"user-agent", "SCP"}},
                              // Expected request headers on egress
                              {{"x-eric-proxy", "///"}, {"x-cluster", "correct_pool"}},
                              {"user-agent"});  // header names that must not be present on egress
}

// Delegated discovery
// - use-all-parameters
// - add-parameters-if-missing for one existing and one non-existing parameter
// - percent-encoding for target-plmn-list
// Successful outcome is expected.  The add-parameters-if-missing for the paramater
// that already exists in the header is ignored (= the value from the header is expected).
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestSuccessfulDiscovery2) {
  initializeFilter(config_basic2);
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
      {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
      {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
      {"3gpp-sbi-discovery-target-plmn-list",
       R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
  };

  std::string nnlf_path =
      "/nnlf-disc/v0/nf-instances/"
      "scp?target-nf-type=AUSF&requester-nf-type=SMF&service-names=nausf-auth&target-plmn-list=%5B%"
      "7B%22mcc%22%3A%22123%22%2C%22mnc%22%3A%22456%22%7D%2C%7B%22mcc%22%3A%22234%22%2C%22mnc%22%"
      "3A%22567%22%7D%5D&test-2=testvalue2&";

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(request_headers);
  FakeStreamPtr nlf_request_stream =
      sendNlfResponse({{":status", "200"}}, nlfResponseBodyProfile2());

  EXPECT_THAT(nlf_request_stream->headers(), Http::HeaderValueOf(":path", nnlf_path));

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));

  ASSERT_TRUE(nlf_request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_nlf_connection_->close());

  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForEndStream());

  // Validate that all expected headers towards NLF are present and have the correct value:
  EXPECT_THAT(nlf_request_stream->headers(), Http::HeaderValueOf("nrf-group", "nrfgroup_1"));

  // Validate that all expected request headers on egress are present and have the correct value:
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "setB"));

  // Validate that the preferred host is correct (fqdn-3 can have port 9093 or 9094)
  EXPECT_THAT(request_stream->headers(),
              AnyOf(Http::HeaderValueOf("x-host", "fqdn-2.example.com:9092"),
                    Http::HeaderValueOf("x-host", "fqdn-3.example.com:9093"),
                    Http::HeaderValueOf("x-host", "fqdn-3.example.com:9094")));

  codec_client->close();
}

// Delegated discovery
// - use-parameters
// - no add-parameters-if-missing
// Successful outcome is expected.
// Only the discovery parameters listed in use-parameters + add_parameters_if_missing
// are expected in the query-string.
// The target-nf-type is in the request, not in use-parameters, but in add_parameters_if_missing
// and is thus expected in the request to the NLF (with the value from add_parameters_if_missing).
// The use-parameters value that is not in the received headers is not copied to the query-string.
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestSuccessfulDiscovery3) {
  initializeFilter(config_basic3);
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
      {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
      {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
      {"3gpp-sbi-discovery-target-plmn-list",
       R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
  };

  std::string nnlf_path =
      "/nnlf-disc/v0/nf-instances/scp?requester-nf-type=SMF&target-nf-type=CHF&";
  execTestWithBasicAssertions(request_headers,
                              "200", // Fake NLF response status
                              nlfResponseBodyProfile1(),
                              // Expected headers towards NLF:
                              {{":path", nnlf_path}, {"nrf-group", "nrfgroup_1"}},
                              // Expected request headers on egress
                              {{"x-eric-proxy", "///"}, {"x-cluster", "correct_pool"}});
}

TEST_P(EricProxyFilterNfDiscIntegrationTest, TestSuccessfulDiscoveryAndPeerInfoHeader) {
  initializeFilter(config_basic_peer);
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-NF-Peer-Info",
       "srcinst=2ec8ac0b-265e-4165-86e9-e0735e6ce307;srcservinst=2ec8ac0b-265e-4165-86e9-"
       "e0735e6ce308;dstscp=SCP-scp.mnc.012.mcc.210.ericsson.se;dstinst=2ec8ac0b-265e-4165-86e9-"
       "e0735e6ce310;dstservinst=2ec8ac0b-265e-4165-86e9-e0735e6ce400"},
      {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
      {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
      {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
      {"3gpp-sbi-discovery-target-plmn-list",
       R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
  };

  std::string nnlf_path =
      "/nnlf-disc/v0/nf-instances/scp?requester-nf-type=SMF&target-nf-type=CHF&";

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(request_headers);
  FakeStreamPtr nlf_request_stream =
      sendNlfResponse({{":status", "200"}}, nlfResponseBodyProfile1());

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));

  ASSERT_TRUE(nlf_request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_nlf_connection_->close());

  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

  EXPECT_EQ(
      request_stream->headers()
          .get(Http::LowerCaseString("3gpp-Sbi-NF-Peer-Info"))[0]
          ->value()
          .getStringView(),
      "srcscp=SCP-scp.own_plmn.com; dstscp=SCP-cluster_0_host_0; "
      "dstinst=2ec8ac0b-265e-4165-86e9-e0735e6ce100; srcinst=2ec8ac0b-265e-4165-86e9-e0735e6ce307; "
      "srcservinst=2ec8ac0b-265e-4165-86e9-e0735e6ce308");

  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ(response->headers()
                .get(Http::LowerCaseString("3gpp-Sbi-NF-Peer-Info"))[0]
                ->value()
                .getStringView(),
            "srcinst=2ec8ac0b-265e-4165-86e9-e0735e6ce100; srcscp=SCP-scp.own_plmn.com; "
            "dstinst=2ec8ac0b-265e-4165-86e9-e0735e6ce307; "
            "dstservinst=2ec8ac0b-265e-4165-86e9-e0735e6ce308");

  codec_client->close();
}

// Delegated discovery
// - mainly tests that it's possible to not configure nf_selection_on_priority
//   (because action-route-remote-round-robin doesn't need it)
// - use-all-parameters
// - add-parameters-if-missing for non-existing parameters
// - percent-encoding for target-plmn-list
// - check preferred host and nfset/cluster afterwards
// Successful outcome is expected.
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestSuccessfulDiscovery4) {
  initializeFilter(config_basic);
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"addvarheader", "testvalue2"},
      {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
      {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
      {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
      {"3gpp-sbi-discovery-target-plmn-list",
       R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
      {"3gpp-sbi-correlation-info", "imsi-345012123123123"},
  };

  std::string nnlf_path =
      "/nnlf-disc/v0/nf-instances/"
      "scp?target-nf-type=AUSF&requester-nf-type=SMF&service-names=nausf-auth&target-plmn-list=%5B%"
      "7B%22mcc%22%3A%22123%22%2C%22mnc%22%3A%22456%22%7D%2C%7B%22mcc%22%3A%22234%22%2C%22mnc%22%"
      "3A%22567%22%7D%5D&test-1=testvalue1&test-2=testvalue2&";
  execTestWithBasicAssertions(request_headers, "200", nlfResponseBodyProfile1(),
                              // Expected headers towards NLF:
                              {{":path", nnlf_path},
                               {"nrf-group", "nrfgroup_1"},
                               {"3gpp-sbi-correlation-info", "imsi-345012123123123"}},
                              // Expected request headers on egress
                              {{"x-eric-proxy", "///"}, {"x-cluster", "correct_pool"}});
}

// Delegated discovery
// - use-all-parameters
// - add-parameters-if-missing for one existing and one non-existing parameter
// - percent-encoding for target-plmn-list
// Successful outcome is expected. The add-parameters-if-missing for the paramater
// that already exists in the header is ignored (= the value from the header is expected).
// FQDNs are missing from highest priority NF, therefore IP address should be present
// instead of FQDN according to configured NF discovery IP version.
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestSuccessfulDiscovery5) {
  initializeFilter(config_basic2);
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
      {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
      {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
      {"3gpp-sbi-discovery-target-plmn-list",
       R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
  };

  Json json_body = Json::parse(nlfResponseBodyProfile2());
  json_body.at("nfInstances").at(1).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(1).at("nfServices").at(1).erase("fqdn");
  const std::string& nlf_response_body = json_body.dump();

  std::string nnlf_path =
      "/nnlf-disc/v0/nf-instances/"
      "scp?target-nf-type=AUSF&requester-nf-type=SMF&service-names=nausf-auth&target-plmn-list=%5B%"
      "7B%22mcc%22%3A%22123%22%2C%22mnc%22%3A%22456%22%7D%2C%7B%22mcc%22%3A%22234%22%2C%22mnc%22%"
      "3A%22567%22%7D%5D&test-2=testvalue2&";

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(request_headers);
  FakeStreamPtr nlf_request_stream =
      sendNlfResponse({{":status", "200"}}, nlf_response_body);

  EXPECT_THAT(nlf_request_stream->headers(), Http::HeaderValueOf(":path", nnlf_path));

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));

  ASSERT_TRUE(nlf_request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_nlf_connection_->close());

  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));

  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(response->waitForEndStream());

  // Validate that all expected headers towards NLF are present and have the correct value:
  EXPECT_THAT(nlf_request_stream->headers(), Http::HeaderValueOf("nrf-group", "nrfgroup_1"));

  // Validate that all expected request headers on egress are present and have the correct value:
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-cluster", "setB"));

  // Validate that the preferred host is correct (IP address is present instead of FQDN)
  EXPECT_THAT(request_stream->headers(),
              AnyOf(Http::HeaderValueOf("x-host", "10.11.12.253:9092"),
                    Http::HeaderValueOf("x-host", "10.11.12.253:9093"),
                    Http::HeaderValueOf("x-host", "10.11.12.253:9094")));

  codec_client->close();
}

//------------------------------------------------------------------------
//  Error cases
//------------------------------------------------------------------------
// action-nf-discovery has a non-existing cluster for NLF
// Expected result is 504, NRF_NOT_REACHABLE
// ULID A02
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestErrorNlfClusterWrong) {
  initializeFilter(
      std::regex_replace(config_basic, std::regex("cluster_1"), "no_existing_cluster"));
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"addvarheader", "testvalue2"},
      {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
      {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
      {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
      {"3gpp-sbi-discovery-target-plmn-list",
       R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
      {"3gpp-sbi-correlation-info", "imsi-345012123123123"},
  };

  auto expected_resp_body =
      R"({"status": 504, "title": "Gateway Timeout", "cause": "NRF_NOT_REACHABLE", "detail": "nf_discovery_nrf_not_reachable"})";

  IntegrationCodecClientPtr codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  verifyResponse5xx(response, "504", expected_resp_body);
  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("3gpp-sbi-correlation-info", "imsi-345012123123123"));

  codec_client->close();
}

// TODO: How to test ULID A04??

// TODO: How to test ULID A07??

// Timeout error: connection set up OK, but stream is not setup before timeout expires
// Expect 504 NRF_NOT_REACHABLE
// ULID A08
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestTimeoutWaitingForNlfResponse) {
  initializeFilter(config_basic);
  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"addvarheader", "testvalue2"},
      {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
      {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
      {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
      {"3gpp-sbi-discovery-target-plmn-list",
       R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
      {"3gpp-sbi-correlation-info", "imsi-345012123123123"},
  };

  std::string nnlf_path =
      "/nnlf-disc/v0/nf-instances/"
      "scp?target-nf-type=AUSF&requester-nf-type=SMF&service-names=nausf-auth&target-plmn-list=%5B%"
      "7B%22mcc%22%3A%22123%22%2C%22mnc%22%3A%22456%22%7D%2C%7B%22mcc%22%3A%22234%22%2C%22mnc%22%"
      "3A%22567%22%7D%5D&test-1=testvalue1&test-2=testvalue2&";

  std::string expected_resp_body =
      R"({"status": 504, "title": "Gateway Timeout", "cause": "NRF_NOT_REACHABLE", "detail": "nf_discovery_nrf_not_reachable"})";

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(req_headers);
  if (!fake_nlf_connection_) {
    AssertionResult result =
        fake_upstreams_[1]->waitForHttpConnection(*dispatcher_, fake_nlf_connection_);
    RELEASE_ASSERT(result, result.message());
  }
  FakeStreamPtr nlf_request_stream = noNlfResponse();
  // Force the timeout to expire, 1000 ms is the timeout in action-nf-lookup
  // in the configuration for this testcase
  timeSystem().advanceTimeWaitImpl(std::chrono::milliseconds(2 * 1000));

  ASSERT_TRUE(fake_nlf_connection_->close());
  ASSERT_TRUE(response->waitForEndStream());

  verifyResponse5xx(response, "504", expected_resp_body);
  EXPECT_THAT(response->headers(),
              Http::HeaderValueOf("3gpp-sbi-correlation-info", "imsi-345012123123123"));

  codec_client->close();
}

// Connect error, connection closed by NLF before stream was accepted
// Expect 502 NF_DISCOVERY_ERROR
// ULID A09 + A11
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestConnectionClosed) {
  initializeFilter(config_basic);
  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"addvarheader", "testvalue2"},
      {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
      {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
      {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
      {"3gpp-sbi-discovery-target-plmn-list",
       R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
  };

  std::string nnlf_path =
      "/nnlf-disc/v0/nf-instances/"
      "scp?target-nf-type=AUSF&requester-nf-type=SMF&service-names=nausf-auth&target-plmn-list=%5B%"
      "7B%22mcc%22%3A%22123%22%2C%22mnc%22%3A%22456%22%7D%2C%7B%22mcc%22%3A%22234%22%2C%22mnc%22%"
      "3A%22567%22%7D%5D&test-1=testvalue1&test-2=testvalue2&";

  auto expected_resp_body{
      R"({"status": 502, "title": "Bad Gateway", "cause": "NF_DISCOVERY_ERROR", "detail": "nf_discovery_error_response_received"})"};

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(req_headers);
  // Repeat twice because of retries
  for (int i = 0; i < 2; i++) {
    if (!fake_nlf_connection_) {
      AssertionResult result =
          fake_upstreams_[1]->waitForHttpConnection(*dispatcher_, fake_nlf_connection_);
      RELEASE_ASSERT(result, result.message());
    }
    ASSERT_TRUE(fake_nlf_connection_->close());
    fake_nlf_connection_ = nullptr;
  }
  ASSERT_TRUE(response->waitForEndStream());

  verifyResponse5xx(response, "502", expected_resp_body);
  // Expect that the correlation-info header is **not** present (because
  // it is not in the incoming request):
  EXPECT_THAT(response->headers(), Not(Http::HeaderValueOf("3gpp-sbi-correlation-info", _)));

  codec_client->close();
}

// Connect error, stream closed without response from NLF ("upstream request timeout" in Envoy)
// Expect 504 NRF_NOT_REACHABLE
// ULID A08
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestNoResponseFromNlf) {
  initializeFilter(config_basic);

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
      {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
      {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
      {"3gpp-sbi-discovery-target-plmn-list",
       R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
  };

  std::string expected_resp_body =
      R"({"status": 504, "title": "Gateway Timeout", "cause": "NRF_NOT_REACHABLE", "detail": "nf_discovery_nrf_not_reachable"})";

  IntegrationCodecClientPtr codec_client;
  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client = makeHttpConnection(lookupPort("http"));
  auto response = codec_client->makeHeaderOnlyRequest(headers);
  FakeStreamPtr nlf_request_stream = noNlfResponse();

  ASSERT_TRUE(nlf_request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_nlf_connection_->close());

  ASSERT_TRUE(response->waitForEndStream());

  verifyResponse5xx(response, "504", expected_resp_body);
  // Expect that the correlation-info header is **not** present (because
  // it is not in the incoming request):
  EXPECT_THAT(response->headers(), Not(Http::HeaderValueOf("3gpp-sbi-correlation-info", _)));

  codec_client->close();
}

// NRF returned a non-JSON result
// Expected response: 400 Bad Request, NF_DISCOVERY_FAILURE, nf_discovery_response_malformed
// ULID A13
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestErrorEmptyJson) {
  std::string nrf_result_body{"scp is great"};
  std::string expected_status{"400"};
  std::string expected_resp_body{
      R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_response_malformed"})"};
  testEmptyOrMalformedResponse(nrf_result_body, expected_status, expected_resp_body);
}

// NRF returned an empty JSON message
// Expected response: 400 Bad Request, NF_DISCOVERY_FAILURE, nf_discovery_empty_result
// Tests ULID A14
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestErrorEmptyJsonObject) {
  std::string nrf_result_body{"{}"};
  std::string expected_status{"400"};
  std::string expected_resp_body{
      R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_empty_result"})"};
  testEmptyOrMalformedResponse(nrf_result_body, expected_status, expected_resp_body);
}

// NRF returned a query result without NF-instances
// Expected response: 400 Bad Request, NF_DISCOVERY_FAILURE, nf_discovery_empty_result
// Tests ULID A14
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestErrorNoNfInstances) {
  std::string nrf_result_body{R"({"validityPeriod": 7200, "searchId": "52134"})"};
  std::string expected_status{"400"};
  std::string expected_resp_body{
      R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_empty_result"})"};
  testEmptyOrMalformedResponse(nrf_result_body, expected_status, expected_resp_body);
}

// NRF returned a query result with empty NF-instances
// Expected response: 400 Bad Request, NF_DISCOVERY_FAILURE, nf_discovery_empty_result
// Tests ULID A14
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestErrorEmptyNfInstances) {
  std::string nrf_result_body{
      R"({"validityPeriod": 7200, "nfInstances": [], "searchId": "52134"})"};
  std::string expected_status{"400"};
  std::string expected_resp_body{
      R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_empty_result"})"};
  testEmptyOrMalformedResponse(nrf_result_body, expected_status, expected_resp_body);
}

// NRF returned a result where nfInstances is a string (not an array)
// Expected response: 400 Bad Request, NF_DISCOVERY_FAILURE, nf_discovery_response_malformed
// ULID A15
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestErrorMalformedNfInst) {
  std::string nrf_result_body{
      R"({"validityPeriod": 7200, "nfInstances": "not an array", "searchId": "52134"})"};
  std::string expected_status{"400"};
  std::string expected_resp_body{
      R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_response_malformed"})"};
  testEmptyOrMalformedResponse(nrf_result_body, expected_status, expected_resp_body);
}

// NRF returned a result where nfServices under nfInstances is a string (not an array)
// Expected response: 400 Bad Request, NF_DISCOVERY_FAILURE, nf_discovery_response_malformed
// ULID A18
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestErrorMalformedNfServices) {
  std::string nrf_result_body{
      R"({"validityPeriod": 7200, "nfInstances": [{"nfServices": "not an array"}], "searchId": "52134"})"};
  std::string expected_status{"400"};
  std::string expected_resp_body{
      R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_response_malformed"})"};
  testEmptyOrMalformedResponse(nrf_result_body, expected_status, expected_resp_body);
}

// NRF returned a result where nfServiceList under nfInstances is a string (not an object)
// Expected response: 400 Bad Request, NF_DISCOVERY_FAILURE, nf_discovery_response_malformed
// ULID A17
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestErrorMalformedNfServiceList) {
  std::string nrf_result_body{
      R"({"validityPeriod": 7200, "nfInstances": [{"nfServiceList": "not an object"}], "searchId": "52134"})"};
  std::string expected_status{"400"};
  std::string expected_resp_body{
      R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_response_malformed"})"};
  testEmptyOrMalformedResponse(nrf_result_body, expected_status, expected_resp_body);
}

// NLF or NRF returned error 429 (any 5xx or 429)
// Expected result: local reject with 502 NF_DISCOVERY_ERROR
// ULID A09
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestError429to502) {
  initializeFilter(config_basic);
  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"addvarheader", "testvalue2"},
      {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
      {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
      {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
      {"3gpp-sbi-discovery-target-plmn-list",
       R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
      {"3gpp-sbi-correlation-info", "imsi-345012123123123"},
  };

  std::string nnlf_path =
      "/nnlf-disc/v0/nf-instances/"
      "scp?target-nf-type=AUSF&requester-nf-type=SMF&service-names=nausf-auth&target-plmn-list=%5B%"
      "7B%22mcc%22%3A%22123%22%2C%22mnc%22%3A%22456%22%7D%2C%7B%22mcc%22%3A%22234%22%2C%22mnc%22%"
      "3A%22567%22%7D%5D&test-1=testvalue1&test-2=testvalue2&";
  auto expected_resp_body{
      R"({"status": 502, "title": "Bad Gateway", "cause": "NF_DISCOVERY_ERROR", "detail": "nf_discovery_error_response_received"})"};

  execErrorTestWithBasicAssertions(req_headers,
                                   1,                    // Expected number of tries
                                   {{":status", "429"}}, // NLF response headers to send
                                   "",                   // NLF response body to send
                                   // Expected headers towards NLF:
                                   {{":path", nnlf_path},
                                    {"nrf-group", "nrfgroup_1"},
                                    {"3gpp-sbi-correlation-info", "imsi-345012123123123"}},
                                   // Expected error response headers:
                                   {{":status", "502"},
                                    {"content-type", "application/problem+json"},
                                    {"3gpp-sbi-correlation-info", "imsi-345012123123123"}},
                                   expected_resp_body);
}

// NLF or NRF returned error 500 (429 or any 5xx except 503, 504)
// Expected result: local reject with 502 NF_DISCOVERY_ERROR
// ULID A09
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestError500to502) {
  initializeFilter(config_basic);
  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"addvarheader", "testvalue2"},
      {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
      {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
      {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
      {"3gpp-sbi-discovery-target-plmn-list",
       R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
      {"3gpp-sbi-correlation-info", "imsi-345012123123123"},
  };

  std::string nnlf_path =
      "/nnlf-disc/v0/nf-instances/"
      "scp?target-nf-type=AUSF&requester-nf-type=SMF&service-names=nausf-auth&target-plmn-list=%5B%"
      "7B%22mcc%22%3A%22123%22%2C%22mnc%22%3A%22456%22%7D%2C%7B%22mcc%22%3A%22234%22%2C%22mnc%22%"
      "3A%22567%22%7D%5D&test-1=testvalue1&test-2=testvalue2&";
  auto expected_resp_body{
      R"({"status": 502, "title": "Bad Gateway", "cause": "NF_DISCOVERY_ERROR", "detail": "nf_discovery_error_response_received"})"};

  execErrorTestWithBasicAssertions(req_headers,
                                   2,                    // Expected number of tries + retries
                                   {{":status", "500"}}, // NLF response headers to send
                                   "",                   // NLF response body to send
                                   // Expected headers towards NLF:
                                   {{":path", nnlf_path},
                                    {"nrf-group", "nrfgroup_1"},
                                    {"3gpp-sbi-correlation-info", "imsi-345012123123123"}},
                                   // Expected error response headers:
                                   {{":status", "502"},
                                    {"content-type", "application/problem+json"},
                                    {"3gpp-sbi-correlation-info", "imsi-345012123123123"}},
                                   expected_resp_body);
}

// NLF or NRF returned error 404
// Expected result: pass through the response from NLF to the requester
// ULID A10
TEST_P(EricProxyFilterNfDiscIntegrationTest, TestError404PassThrough) {
  initializeFilter(config_basic);
  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"addvarheader", "testvalue2"},
      {"3gpp-sbi-discovery-target-nf-type", "AUSF"},
      {"3gpp-Sbi-Discovery-Requester-Nf-Type", "SMF"},
      {"3GPP-SBI-DISCOVERY-SERVICE-NAMES", "nausf-auth"},
      {"3gpp-sbi-discovery-target-plmn-list",
       R"EOT([{"mcc":"123","mnc":"456"},{"mcc":"234","mnc":"567"}])EOT"},
      {"3gpp-sbi-correlation-info", "imsi-345012123123123"},
  };

  std::string nnlf_path =
      "/nnlf-disc/v0/nf-instances/"
      "scp?target-nf-type=AUSF&requester-nf-type=SMF&service-names=nausf-auth&target-plmn-list=%5B%"
      "7B%22mcc%22%3A%22123%22%2C%22mnc%22%3A%22456%22%7D%2C%7B%22mcc%22%3A%22234%22%2C%22mnc%22%"
      "3A%22567%22%7D%5D&test-1=testvalue1&test-2=testvalue2&";
  auto nlf_resp_body{
      R"({"status": 404, "title": "Not Found", "cause": "NF_DISCOVERY_ERROR", "detail": "NRF returned 404"})"};

  execErrorTestWithBasicAssertions(
      req_headers,
      1,                    // Expected number of tries
      {{":status", "404"}}, // NLF response headers to send
      nlf_resp_body,        // NLF response body to send
      // Expected headers towards NLF:
      {{":path", nnlf_path},
       {"nrf-group", "nrfgroup_1"},
       {"3gpp-sbi-correlation-info", "imsi-345012123123123"}},
      // Expected error response headers:
      {{":status", "404"}, {"3gpp-sbi-correlation-info", "imsi-345012123123123"}}, nlf_resp_body);
}

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
