#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_ingress_ratelimit/ratelimit.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"
#include <ostream>
#include <string>
#include "absl/strings/str_replace.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IngressRateLimitFilter {
namespace {

enum RlfSvcErrorAction { PASS, DROP, REJECT };

using Json = nlohmann::json;

class EricIngressRatelimitIntegrationTest
    : public HttpIntegrationTest,
      public testing::TestWithParam<std::tuple<Network::Address::IpVersion, RlfSvcErrorAction>> {
public:
  EricIngressRatelimitIntegrationTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, std::get<0>(GetParam()),
                            EricIngressRatelimitIntegrationTest::conManagerConfig()) {}
  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }
  RlfSvcErrorAction getRlfSvcErrorAction() const { return std::get<1>(GetParam()); }
  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config_cdn_loop_filter);
    config_helper_.addFilter(config_buffer);
    config_helper_.addFilter(config);
    setUpstreamCount(2);
    HttpIntegrationTest::initialize();
  }

  // function accepts two json arrays and compares them
  // for float comparison an approximation is considered
  void compareJsonBodies(Json rec_list, Json expected_list) {
    ASSERT(rec_list.is_array());
    ASSERT(expected_list.is_array());

    EXPECT_EQ(rec_list.size(), expected_list.size());
    size_t index = 0;
    while (index < rec_list.size()) {
      Json rec = rec_list[index];
      Json expected = expected_list[index];
      EXPECT_EQ(rec.size(), expected.size());

      for (Json::iterator it = rec.begin(); it != rec.end(); ++it) {
        EXPECT_TRUE(expected.contains(it.key()));
        // comparing float values is done by approximation
        if (it.key() == "watermark") {
          float diff = static_cast<float>(it.value()) - static_cast<float>(expected[it.key()]);
          EXPECT_LE(std::fabs(diff), 0.1f);
        } else {
          EXPECT_EQ(expected[it.key()], it.value());
        }
      }
      index++;
    }
  }

  std::string config_network_drop = R"EOF(
name: envoy.filters.http.eric_ingress_ratelimit
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_ingress_ratelimit.v3.IngressRateLimit
  namespace: SEPP
  timeout: 1s
  limits:
  - network:
      bucket_action:
        bucket_name: ingress=GRLname.own=myNetwork
        over_limit_action: 
          action_drop_message: true
  watermarks:
  - 0
  - 1.40625
  - 2.8125
  - 4.21875
  - 5.625
  - 7.03125
  - 8.4375
  - 9.84375
  - 11.25
  - 12.65625
  - 14.0625
  - 15.46875
  - 16.875
  - 18.28125
  - 19.6875
  - 21.09375
  - 22.5
  - 23.90625
  - 25.3125
  - 26.71875
  - 28.125
  - 29.53125
  - 30.9375
  - 32.34375
  - 33.75
  - 35.15625
  - 36.5625
  - 37.96875
  - 39.375
  - 40.78125
  - 42.1875
  - 43.59375
)EOF";

  std::string config_network_reject = R"EOF(
name: envoy.filters.http.eric_ingress_ratelimit
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_ingress_ratelimit.v3.IngressRateLimit
  namespace: SEPP
  timeout: 1s
  limits:
  - network:
      bucket_action:
        bucket_name: ingress=GRLname.own=myNetwork
        over_limit_action: 
          action_reject_message:
            status: 429
            title: Too Many Requests
            detail: Request limit exceeded
            retry_after_header: SECONDS
  watermarks:
  - 0
  - 1.40625
  - 2.8125
  - 4.21875
  - 5.625
  - 7.03125
  - 8.4375
  - 9.84375
  - 11.25
  - 12.65625
  - 14.0625
  - 15.46875
  - 16.875
  - 18.28125
  - 19.6875
  - 21.09375
  - 22.5
  - 23.90625
  - 25.3125
  - 26.71875
  - 28.125
  - 29.53125
  - 30.9375
  - 32.34375
  - 33.75
  - 35.15625
  - 36.5625
  - 37.96875
  - 39.375
  - 40.78125
  - 42.1875
  - 43.59375
)EOF";
  std::string service_config_for_rl = R"EOF(
  rate_limit_service:
    service_error_action:
      action_pass_message: true
    service_cluster_name: cluster_1
)EOF";

  std::string service_config_reject_for_rl = R"EOF(
  rate_limit_service:
    service_error_action:
      action_reject_message:
        status: 429
        title: Too Many Requests
        detail: Rlf Service Error
        cause: rlf_service_error
    service_cluster_name: cluster_1
)EOF";

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
    - name: cluster_2
      connect_timeout: 15s
      load_assignment:
        cluster_name: cluster_1
  listeners:
    name: listener_0
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 0
)EOF",
                       Platform::null_device_path, Platform::null_device_path);
  }

  const std::string config_cdn_loop_filter = R"EOF(
name: envoy.filters.http.cdn_loop
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.cdn_loop.v3.CdnLoopConfig
  cdn_id: "2.0 scp.ericsson.se"
)EOF";

  const std::string config_buffer = R"EOF(
name: envoy.filters.http.buffer
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.buffer.v3.Buffer
  max_request_bytes: 65535
)EOF";

  std::string conManagerConfig() {
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
    )EOF",
                                                  Platform::null_device_path));
  }

  // RLF response underlimit
  std::string rlfResponseResponseUnderlimit() {
    return R"EOF(
    [{"rc": 200}]
    )EOF";
  }

  // RLF response overlimit
  std::string rlfResponseResponseOverlimit() {
    return R"EOF(
    [{"rc": 429}]
    )EOF";
  }

  // RLF response overlimit
  std::string rlfResponseResponseOverlimitWithRa() {
    return R"EOF(
    [{"rc": 429,"ra": 12345}]
    )EOF";
  }

  // RLF response 400 bucket not found
  std::string rlfResponseResponseBucketNotFound() {
    return R"EOF(
    [{"rc": 404}]
    )EOF";
  }
  // Fake rlf Functionality

  FakeStreamPtr sendRlfRequest(const std::string& status, const std::string& body) {
    ENVOY_LOG(debug, "sendRlfRequest()");
    if (!fake_rlf_connection_) {
      AssertionResult result =
          fake_upstreams_[1]->waitForHttpConnection(*dispatcher_, fake_rlf_connection_);
      RELEASE_ASSERT(result, result.message());
    }

    FakeStreamPtr request_stream;
    AssertionResult result = fake_rlf_connection_->waitForNewStream(*dispatcher_, request_stream);
    RELEASE_ASSERT(result, result.message());
    result = request_stream->waitForEndStream(*dispatcher_);

    RELEASE_ASSERT(result, result.message());
    if (body.empty()) {
      request_stream->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", status}}, true);
    } else {
      request_stream->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", status}}, false);
      Buffer::OwnedImpl responseBuffer(body);
      request_stream->encodeData(responseBuffer, true);
    }

    return request_stream;
  }
  FakeStreamPtr noRlfResponse() {
    ENVOY_LOG(debug, "norlfResponse()");
    if (!fake_rlf_connection_) {
      AssertionResult result =
          fake_upstreams_[1]->waitForHttpConnection(*dispatcher_, fake_rlf_connection_);
      RELEASE_ASSERT(result, result.message());
    }

    FakeStreamPtr request_stream;
    AssertionResult result = fake_rlf_connection_->waitForNewStream(*dispatcher_, request_stream);
    RELEASE_ASSERT(result, result.message());
    result = request_stream->waitForEndStream(*dispatcher_);
    RELEASE_ASSERT(result, result.message());

    return request_stream;
  }

  FakeHttpConnectionPtr fake_rlf_connection_;
};

INSTANTIATE_TEST_SUITE_P(
    IpVersions, EricIngressRatelimitIntegrationTest,
    testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                     testing::Values(RlfSvcErrorAction::PASS, RlfSvcErrorAction::DROP,
                                     RlfSvcErrorAction::REJECT)));

// underlimit response from rlf -> message pass
TEST_P(EricIngressRatelimitIntegrationTest, TestNetworkUnderlimit) {

  // don't run all combinations of tests on tcs where service error action is not triggered
  if (getRlfSvcErrorAction() != RlfSvcErrorAction::PASS) {
    GTEST_SUCCEED();
    return;
  }
  initializeFilter(absl::StrCat(config_network_drop, service_config_for_rl));
  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-sbi-message-priority", "1"},
  };

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(req_headers);
  FakeStreamPtr rlf_request_stream = sendRlfRequest("200", rlfResponseResponseUnderlimit());
  EXPECT_THAT(rlf_request_stream->headers(),
              Http::HeaderValueOf(":path", "/nrlf-ratelimiting/v0/tokens/sepp"));
  compareJsonBodies(
      Json::parse(rlf_request_stream->body().toString()),
      "[{\"amount\":1,\"name\":\"ingress=GRLname.own=myNetwork\",\"watermark\":1.40625}]"_json);

  ASSERT_TRUE(rlf_request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_rlf_connection_->close());

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));

  // Send fake upstream response:
  std::string fake_body{R"({"validityPeriod": 60})"};

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(fake_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}};
  request_stream->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(fake_body);
  request_stream->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());

  // Verify response status codez
  EXPECT_EQ("200", response->headers().getStatusValue());
  ENVOY_LOG(trace, printCounters(test_server_, "http.eirl"));

  // Counter evaluation

  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_accepted", 1);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_accepted_per_network", 1);
  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_dropped", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_dropped_per_network", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_rejected", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_rejected_per_network", 0);

  test_server_->waitForCounterGe("cluster.cluster_1.upstream_rq_2xx", 1);
  // test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.rlf_lookup_failure", 0);

  EXPECT_EQ(
      1,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_accepted")->value());
  EXPECT_EQ(1, test_server_
                   ->counter("http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_"
                             "accepted_per_network")
                   ->value());

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_dropped")->value());
  EXPECT_EQ(
      0,
      test_server_
          ->counter(
              "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_dropped_per_network")
          ->value());

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_rejected")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_"
                             "rejected_per_network")
                   ->value());

  // EXPECT_EQ(0,
  // test_server_->counter("http.eirl.n8e.West1.g3p.ingress.rlf_lookup_failure")->value());
  EXPECT_EQ(1, test_server_->counter("cluster.cluster_1.upstream_rq_2xx")->value());

  codec_client_->close();
}

// overlimit response from rlf -> message drop

TEST_P(EricIngressRatelimitIntegrationTest, TestNetworkOverlimit) {
  // don't run all combinations of tests on tcs where service error action is not triggered
  if (getRlfSvcErrorAction() != RlfSvcErrorAction::PASS) {
    GTEST_SUCCEED();
    return;
  }
  initializeFilter(absl::StrCat(config_network_drop, service_config_for_rl));

  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-sbi-message-priority", "3"},
  };

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(req_headers);
  FakeStreamPtr rlf_request_stream = sendRlfRequest("200", rlfResponseResponseOverlimit());
  EXPECT_THAT(rlf_request_stream->headers(),
              Http::HeaderValueOf(":path", "/nrlf-ratelimiting/v0/tokens/sepp"));
  compareJsonBodies(
      Json::parse(rlf_request_stream->body().toString()),
      "[{\"amount\":1,\"name\":\"ingress=GRLname.own=myNetwork\",\"watermark\":4.21875}]"_json);

  ASSERT_TRUE(rlf_request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_rlf_connection_->close());

  ASSERT_TRUE(response->waitForReset());
  ENVOY_LOG(trace, printCounters(test_server_, "http.eirl"));

  // Counter evaluation

  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_accepted", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_accepted_per_network", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_dropped", 1);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_dropped_per_network", 1);
  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_rejected", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_rejected_per_network", 0);

  test_server_->waitForCounterGe("cluster.cluster_1.upstream_rq_2xx", 1);
  // test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.rlf_lookup_failure", 0);

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_accepted")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_"
                             "accepted_per_network")
                   ->value());

  EXPECT_EQ(
      1,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_dropped")->value());
  EXPECT_EQ(
      1,
      test_server_
          ->counter(
              "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_dropped_per_network")
          ->value());

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_rejected")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_"
                             "rejected_per_network")
                   ->value());

  // EXPECT_EQ(0,
  // test_server_->counter("http.eirl.n8e.West1.g3p.ingress.rlf_lookup_failure")->value());
  EXPECT_EQ(1, test_server_->counter("cluster.cluster_1.upstream_rq_2xx")->value());

  codec_client_->close();
}

// underlimit response from rlf -> message reject with retry-after header

TEST_P(EricIngressRatelimitIntegrationTest, TestNetworkOverlimitRA) {

  // don't run all combinations of tests on tcs where service error action is not triggered
  if (getRlfSvcErrorAction() != RlfSvcErrorAction::PASS) {
    GTEST_SUCCEED();
    return;
  }
  initializeFilter(absl::StrCat(config_network_reject, service_config_for_rl));

  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-sbi-message-priority", "30"},
  };

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;
  std::string fake_body{R"({"validityPeriod": 60})"};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(req_headers, fake_body);
  FakeStreamPtr rlf_request_stream = sendRlfRequest("200", rlfResponseResponseOverlimitWithRa());
  EXPECT_THAT(rlf_request_stream->headers(),
              Http::HeaderValueOf(":path", "/nrlf-ratelimiting/v0/tokens/sepp"));

  ASSERT_TRUE(rlf_request_stream->waitForEndStream(*dispatcher_));
  compareJsonBodies(
      Json::parse(rlf_request_stream->body().toString()),
      "[{\"amount\":1,\"name\":\"ingress=GRLname.own=myNetwork\",\"watermark\":42.1875}]"_json);
  ASSERT_TRUE(fake_rlf_connection_->close());
  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("429", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ(
      "{\"status\": 429, \"title\": \"Too Many Requests\", \"detail\": \"Request limit exceeded\"}",
      response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());
  EXPECT_EQ(
      "13",
      response->headers().get(Http::LowerCaseString("retry-after"))[0]->value().getStringView());

  ENVOY_LOG(trace, printCounters(test_server_, "http.eirl"));

  // Counter evaluation

  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_accepted", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_accepted_per_network", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_dropped", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_dropped_per_network", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_rejected", 1);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_rejected_per_network", 1);

  test_server_->waitForCounterGe("cluster.cluster_1.upstream_rq_2xx", 1);
  // test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.rlf_lookup_failure", 0);

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_accepted")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_"
                             "accepted_per_network")
                   ->value());

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_dropped")->value());
  EXPECT_EQ(
      0,
      test_server_
          ->counter(
              "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_dropped_per_network")
          ->value());

  EXPECT_EQ(
      1,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_rejected")->value());
  EXPECT_EQ(1, test_server_
                   ->counter("http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_"
                             "rejected_per_network")
                   ->value());

  // EXPECT_EQ(0,
  // test_server_->counter("http.eirl.n8e.West1.g3p.ingress.rlf_lookup_failure")->value());
  EXPECT_EQ(1, test_server_->counter("cluster.cluster_1.upstream_rq_2xx")->value());

  codec_client_->close();
}

// **************************************************************************

// RLF service errors test cases

// **************************************************************************

// rlf request timeout, service_error_action: pass -> pass request
TEST_P(EricIngressRatelimitIntegrationTest, TestServiceResponseTimeout) {

  if (getRlfSvcErrorAction() == RlfSvcErrorAction::PASS) {
    initializeFilter(absl::StrCat(config_network_reject, service_config_for_rl));

  } else if (getRlfSvcErrorAction() == RlfSvcErrorAction::DROP) {
    initializeFilter(absl::StrCat(config_network_reject,
                                  absl::StrReplaceAll(service_config_for_rl, {{"pass", "drop"}})));
  } else if (getRlfSvcErrorAction() == RlfSvcErrorAction::REJECT) {
    initializeFilter(absl::StrCat(config_network_reject, service_config_reject_for_rl));
  }
  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-sbi-message-priority", "0"},
  };

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;
  std::string fake_body{R"({"validityPeriod": 60})"};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(req_headers, fake_body);
  FakeStreamPtr rlf_request_stream = noRlfResponse();
  EXPECT_THAT(rlf_request_stream->headers(),
              Http::HeaderValueOf(":path", "/nrlf-ratelimiting/v0/tokens/sepp"));

  if (getRlfSvcErrorAction() == RlfSvcErrorAction::PASS) {
    ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
    ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));

    // Send fake upstream response:

    Http::TestResponseHeaderMapImpl response_headers{
        {":status", "200"},
        {"content-length", std::to_string(fake_body.length())},
        {"content-type", "application/json"},
        {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}};
    request_stream->encodeHeaders(response_headers, false);
    Buffer::OwnedImpl response_data(fake_body);
    request_stream->encodeData(response_data, true);

    // wait for the response and close the fake upstream connection
    ASSERT_TRUE(response->waitForEndStream());
    ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
    ASSERT_TRUE(fake_upstream_connection->close());

    // Verify response status codez
    EXPECT_EQ("200", response->headers().getStatusValue());
    ENVOY_LOG(trace, printCounters(test_server_, "http.eirl"));
  } else if (getRlfSvcErrorAction() == RlfSvcErrorAction::DROP) {
    ASSERT_TRUE(response->waitForReset());
  } else if (getRlfSvcErrorAction() == RlfSvcErrorAction::REJECT) {
    ASSERT_TRUE(response->waitForEndStream());

    EXPECT_EQ("429", response->headers().getStatusValue());
    EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
    EXPECT_EQ("{\"status\": 429, \"title\": \"Too Many Requests\", \"detail\": \"Rlf Service "
              "Error\", \"cause\": \"rlf_service_error\"}",
              response->body());
    EXPECT_EQ(fmt::format("{}", response->body().size()),
              response->headers().getContentLengthValue());
  }
  // Counter evaluation

  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_accepted", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_accepted_per_network", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_dropped", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_dropped_per_network", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_rejected", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_rejected_per_network", 0);
  test_server_->waitForCounterGe("cluster.cluster_1.upstream_rq_timeout", 1);
  test_server_->waitForCounterGe("cluster.cluster_1.upstream_rq_504", 1);

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_accepted")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_"
                             "accepted_per_network")
                   ->value());

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_dropped")->value());
  EXPECT_EQ(
      0,
      test_server_
          ->counter(
              "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_dropped_per_network")
          ->value());

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_rejected")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_"
                             "rejected_per_network")
                   ->value());

  EXPECT_EQ(1, test_server_->counter("cluster.cluster_1.upstream_rq_timeout")->value());
  EXPECT_EQ(1, test_server_->counter("cluster.cluster_1.upstream_rq_504")->value());

  codec_client_->close();
}

TEST_P(EricIngressRatelimitIntegrationTest, TestServiceNoHealthyUpstream) {
  if (getRlfSvcErrorAction() == RlfSvcErrorAction::PASS) {
    initializeFilter(
        absl::StrCat(config_network_reject,
                     absl::StrReplaceAll(service_config_for_rl, {{"cluster_1", "cluster_2"}})));

  } else if (getRlfSvcErrorAction() == RlfSvcErrorAction::DROP) {

    initializeFilter(absl::StrCat(
        config_network_reject,
        absl::StrReplaceAll(absl::StrReplaceAll(service_config_for_rl, {{"pass", "drop"}}),
                            {{"cluster_1", "cluster_2"}})));
  } else if (getRlfSvcErrorAction() == RlfSvcErrorAction::REJECT) {
    initializeFilter(
        absl::StrCat(config_network_reject, absl::StrReplaceAll(service_config_reject_for_rl,
                                                                {{"cluster_1", "cluster_2"}})));
  }

  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-sbi-message-priority", "0"},
  };

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;
  std::string fake_body{R"({"validityPeriod": 60})"};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(req_headers, fake_body);



  if (getRlfSvcErrorAction() == RlfSvcErrorAction::PASS) {
      ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
    
    // Send fake upstream response:

    Http::TestResponseHeaderMapImpl response_headers{
        {":status", "200"},
        {"content-length", std::to_string(fake_body.length())},
        {"content-type", "application/json"},
        {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}};
    request_stream->encodeHeaders(response_headers, false);
    Buffer::OwnedImpl response_data(fake_body);
    request_stream->encodeData(response_data, true);

    // wait for the response and close the fake upstream connection
    ASSERT_TRUE(response->waitForEndStream());
    ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
    ASSERT_TRUE(fake_upstream_connection->close());

    // Verify response status codez
    EXPECT_EQ("200", response->headers().getStatusValue());
  } else if (getRlfSvcErrorAction() == RlfSvcErrorAction::DROP) {
    ASSERT_TRUE(response->waitForReset());
  } else if (getRlfSvcErrorAction() == RlfSvcErrorAction::REJECT) {
    ASSERT_TRUE(response->waitForEndStream());

    EXPECT_EQ("429", response->headers().getStatusValue());
    EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
    EXPECT_EQ("{\"status\": 429, \"title\": \"Too Many Requests\", \"detail\": \"Rlf Service "
              "Error\", \"cause\": \"rlf_service_error\"}",
              response->body());
    EXPECT_EQ(fmt::format("{}", response->body().size()),
              response->headers().getContentLengthValue());
  }
  ENVOY_LOG(trace, printCounters(test_server_, "http.eirl"));

  // Counter evaluation

  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_accepted", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_accepted_per_network", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_dropped", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_dropped_per_network", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_rejected", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_rejected_per_network", 0);
  // test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.rlf_lookup_failure", 0);
  test_server_->waitForCounterGe("cluster.cluster_2.upstream_cx_none_healthy", 1);
  test_server_->waitForCounterGe("cluster.cluster_2.upstream_rq_503", 1);

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_accepted")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_"
                             "accepted_per_network")
                   ->value());

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_dropped")->value());
  EXPECT_EQ(
      0,
      test_server_
          ->counter(
              "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_dropped_per_network")
          ->value());

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_rejected")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_"
                             "rejected_per_network")
                   ->value());

  //  EXPECT_EQ(0,
  //  test_server_->counter("http.eirl.n8e.West1.g3p.ingress.rlf_lookup_failure")->value());
  EXPECT_EQ(1, test_server_->counter("cluster.cluster_2.upstream_cx_none_healthy")->value());
  EXPECT_EQ(1, test_server_->counter("cluster.cluster_2.upstream_rq_503")->value());

  codec_client_->close();
}

TEST_P(EricIngressRatelimitIntegrationTest, TestInvalidRlfCluster) {

  if (getRlfSvcErrorAction() != RlfSvcErrorAction::PASS) {
    // the action here does not main a difference
    GTEST_SUCCEED();
    return;
  }
  // cluster_3 does not exist in the configuration
  initializeFilter(
      absl::StrCat(config_network_reject,
                   absl::StrReplaceAll(service_config_for_rl, {{"cluster_1", "cluster_3"}})));
  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-sbi-message-priority", "0"},
  };

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;
  std::string fake_body{R"({"validityPeriod": 60})"};

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(req_headers, fake_body);

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));

  // Send fake upstream response:

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(fake_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}};
  request_stream->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(fake_body);
  request_stream->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());

  // Verify response status codez
  EXPECT_EQ("200", response->headers().getStatusValue());
  ENVOY_LOG(trace, printCounters(test_server_, "http.eirl"));

  // Counter evaluation

  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_accepted", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_accepted_per_network", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_dropped", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_dropped_per_network", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_rejected", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_rejected_per_network", 0);

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_accepted")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_"
                             "accepted_per_network")
                   ->value());

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_dropped")->value());
  EXPECT_EQ(
      0,
      test_server_
          ->counter(
              "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_dropped_per_network")
          ->value());

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_rejected")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_"
                             "rejected_per_network")
                   ->value());

  codec_client_->close();
}

// underlimit response from rlf -> message pass
TEST_P(EricIngressRatelimitIntegrationTest, TestServiceBucketNotFound) {

  if (getRlfSvcErrorAction() == RlfSvcErrorAction::PASS) {
    initializeFilter(absl::StrCat(config_network_drop, service_config_for_rl));

  } else if (getRlfSvcErrorAction() == RlfSvcErrorAction::DROP) {

    initializeFilter(absl::StrCat(config_network_drop,
                                  absl::StrReplaceAll(service_config_for_rl, {{"pass", "drop"}})));
  } else if (getRlfSvcErrorAction() == RlfSvcErrorAction::REJECT) {
    initializeFilter(absl::StrCat(config_network_drop, service_config_reject_for_rl));
  }
  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-sbi-message-priority", "1"},
  };

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(req_headers);
  FakeStreamPtr rlf_request_stream = sendRlfRequest("200", rlfResponseResponseBucketNotFound());
  EXPECT_THAT(rlf_request_stream->headers(),
              Http::HeaderValueOf(":path", "/nrlf-ratelimiting/v0/tokens/sepp"));
  compareJsonBodies(
      Json::parse(rlf_request_stream->body().toString()),
      "[{\"amount\":1,\"name\":\"ingress=GRLname.own=myNetwork\",\"watermark\":1.40625}]"_json);

  ASSERT_TRUE(rlf_request_stream->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_rlf_connection_->close());


  if (getRlfSvcErrorAction() == RlfSvcErrorAction::PASS) {


    ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
    ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
    // Send fake upstream response:
    std::string fake_body{R"({"validityPeriod": 60})"};

    Http::TestResponseHeaderMapImpl response_headers{
        {":status", "200"},
        {"content-length", std::to_string(fake_body.length())},
        {"content-type", "application/json"},
        {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}};
    request_stream->encodeHeaders(response_headers, false);
    Buffer::OwnedImpl response_data(fake_body);
    request_stream->encodeData(response_data, true);

    // wait for the response and close the fake upstream connection
    ASSERT_TRUE(response->waitForEndStream());
    ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
    ASSERT_TRUE(fake_upstream_connection->close());

    // Verify response status codez
    EXPECT_EQ("200", response->headers().getStatusValue());
  } else if (getRlfSvcErrorAction() == RlfSvcErrorAction::REJECT) {

    ASSERT_TRUE(response->waitForEndStream());

    EXPECT_EQ("429", response->headers().getStatusValue());
    EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
    EXPECT_EQ("{\"status\": 429, \"title\": \"Too Many Requests\", \"detail\": \"Rlf Service "
              "Error\", \"cause\": \"rlf_service_error\"}",
              response->body());
    EXPECT_EQ(fmt::format("{}", response->body().size()),
              response->headers().getContentLengthValue());

  } else if (getRlfSvcErrorAction() == RlfSvcErrorAction::DROP) {
    ASSERT_TRUE(response->waitForReset());
  }

  ENVOY_LOG(trace, printCounters(test_server_, "http.eirl"));

  // Counter evaluation

  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_accepted", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_accepted_per_network", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_dropped", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_dropped_per_network", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_rejected", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_rejected_per_network", 0);

  test_server_->waitForCounterGe("cluster.cluster_1.upstream_rq_2xx", 1);
  test_server_->waitForCounterGe("http.eirl.n8e.West1.g3p.ingress.rlf_lookup_failure", 1);

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_accepted")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_"
                             "accepted_per_network")
                   ->value());

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_dropped")->value());
  EXPECT_EQ(
      0,
      test_server_
          ->counter(
              "http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_dropped_per_network")
          ->value());

  EXPECT_EQ(
      0,
      test_server_->counter("http.eirl.n8e.West1.g3p.ingress.global_rate_limit_rejected")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.West1.g3p.ingress.n5k.myNetwork.global_rate_limit_"
                             "rejected_per_network")
                   ->value());

  EXPECT_EQ(1,
            test_server_->counter("http.eirl.n8e.West1.g3p.ingress.rlf_lookup_failure")->value());
  EXPECT_EQ(1, test_server_->counter("cluster.cluster_1.upstream_rq_2xx")->value());

  codec_client_->close();
}

} // namespace
} // namespace IngressRateLimitFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy