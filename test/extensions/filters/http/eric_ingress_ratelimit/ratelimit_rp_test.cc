#include "envoy/http/codes.h"
#include "envoy/http/filter.h"
#include "base_integration_test.h"
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

using json = nlohmann::json;

class EricIngressRatelimitRpIntegrationTest
    : public RatelimitIntegrationTestSsl,
      public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricIngressRatelimitRpIntegrationTest() : RatelimitIntegrationTestSsl(GetParam()) {}
  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);
    setUpstreamCount(2);
    HttpIntegrationTest::initialize();
  }

  std::string ratelimit_base_config = R"EOF(
name: envoy.filters.http.eric_ingress_ratelimit
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_ingress_ratelimit.v3.IngressRateLimit
  namespace: SEPP
  rate_limit_service:
    service_error_action:
      action_pass_message: true
    service_cluster_name: cluster_0
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

  std::string ratelimit_rp_config_reject = R"EOF(

  limits:
  - roaming_partner:
      rp_not_found_action:
        action_reject_message:
          status: 403
          title: Unauthorized
          detail: Roaming partner not found
      rp_bucket_action_table:
        smf1.external_plmn.com:
          rp_name: rp-A
          bucket_action_pair:
            bucket_name: ingress=GRLname.rp=rp-A
            over_limit_action:
              action_reject_message:
                status: 429
                title: Too Many Requests
        smf2.outer_space_plmn.com:
          rp_name: rp_B
          bucket_action_pair:
            bucket_name: ingress=GRLname.rp=rp_B
            over_limit_action:
              action_reject_message:
                status: 429
                title: Too Many Requests
)EOF";

  std::string ratelimit_rp_not_found_pass = R"EOF(

  limits:
  - roaming_partner:
      rp_not_found_action:
        action_pass_message: true
      rp_bucket_action_table:
        invalid_dn.com:
          rp_name: rp-A
          bucket_action_pair:
            bucket_name: ingress=GRLname.rp=rp-A
            over_limit_action:
              action_reject_message:
                status: 429
                title: Too Many Requests
        smf2.outer_space_plmn.com:
          rp_name: rp_B
          bucket_action_pair:
            bucket_name: ingress=GRLname.rp=rp_B
            over_limit_action:
              action_reject_message:
                status: 429
                title: Too Many Requests
)EOF";

  std::string ratelimit_rp_config_drop = R"EOF(

  limits:
  - roaming_partner:
      rp_not_found_action:
        action_drop_message: true
      rp_bucket_action_table:
        random_name.outer_space.com:
          rp_name: rp-A
          bucket_action_pair:
            bucket_name: ingress=GRLname.rp=rp-A
            over_limit_action:
              action_reject_message:
                status: 429
                title: Too Many Requests
        smf1.external_plmn.com:
          rp_name: rp_B
          bucket_action_pair:
            bucket_name: ingress=GRLname.rp=rp_B
            over_limit_action:
              action_drop_message: true
)EOF";

  const std::string rp_limit_not_configured = R"EOF(

  limits:
  - roaming_partner:
      rp_not_found_action:
        action_drop_message: true
      rp_bucket_action_table:
        random_name.outer_space.com:
          rp_name: rp-A
          bucket_action_pair:
            bucket_name: ingress=GRLname.rp=rp-A
            over_limit_action:
              action_reject_message:
                status: 429
                title: Too Many Requests
        smf1.external_plmn.com:
          rp_name: rp_B
)EOF";

  // Configuration for http filter with route MD
  const std::string config_route_md = R"EOF(
    name: local_route
    virtual_hosts:
    - name: local_service
      domains: ["*"]
      routes:
      - name: route1
        match:
          prefix: "/"
        route:
          cluster: cluster_0
  )EOF";

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

  // Fake rlf Functionality

  FakeStreamPtr sendRlfRequest(const std::string& status, const std::string& body) {
    ENVOY_LOG(debug, "sendRlfRequest()");
    if (!fake_rlf_connection_) {
      AssertionResult result =
          fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_rlf_connection_);
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
          fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_rlf_connection_);
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

INSTANTIATE_TEST_SUITE_P(IpVersions, EricIngressRatelimitRpIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(EricIngressRatelimitRpIntegrationTest, TestRpUnderlimit) {
  config_helper_.addFilter(absl::StrCat(ratelimit_base_config, ratelimit_rp_config_reject));
  initializeWithRouteConfigFromYaml(config_route_md);

  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
  };

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;
  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeRequestWithBody(req_headers, fake_body);

  // auto response = codec_client_->makeHeaderOnlyRequest(req_headers);
  FakeStreamPtr rlf_request_stream = sendRlfRequest("200", rlfResponseResponseUnderlimit());
  EXPECT_THAT(rlf_request_stream->headers(),
              Http::HeaderValueOf(":path", "/nrlf-ratelimiting/v0/tokens/sepp"));

  ASSERT_TRUE(rlf_request_stream->waitForEndStream(*dispatcher_));
  compareJsonBodies(
      json::parse(rlf_request_stream->body().toString()),
      "[{\"amount\":1,\"name\":\"ingress=GRLname.rp=rp-A\",\"watermark\":33.75}]"_json);

  ASSERT_TRUE(fake_rlf_connection_->close());
  //Remove the response part until rlf requests are sent to a separate cluster in tls scenarios
  // so that the TC doesn't fail(TODO)
/**
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

**/
  // Counter evaluation
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.global_rate_limit_accepted", 1);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_accepted_per_roaming_partner", 1);
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.global_rate_limit_dropped", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_dropped_per_roaming_partner", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.global_rate_limit_rejected", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_rejected_per_roaming_partner", 0);
  //test_server_->waitForCounterGe("cluster.cluster_1.upstream_rq_2xx", 1);
  
  EXPECT_EQ(1, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_accepted")->value());
  EXPECT_EQ(1, test_server_
                   ->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_accepted_"
                             "per_roaming_partner")
                   ->value());
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_dropped")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_dropped_"
                             "per_roaming_partner")
                   ->value());
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_rejected")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_rejected_"
                             "per_roaming_partner")
                   ->value());
  //EXPECT_EQ(1, test_server_->counter("cluster.cluster_1.upstream_rq_2xx")->value());

  codec_client_->close();
}

TEST_P(EricIngressRatelimitRpIntegrationTest, TestRpOverlimitReject) {
  config_helper_.addFilter(absl::StrCat(ratelimit_base_config, ratelimit_rp_config_reject));
  initializeWithRouteConfigFromYaml(config_route_md);

  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
  };

  FakeStreamPtr request_stream;
  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeRequestWithBody(req_headers, fake_body);
  // auto response = codec_client_->makeHeaderOnlyRequest(req_headers);

  FakeStreamPtr rlf_request_stream = sendRlfRequest("200", rlfResponseResponseOverlimit());
  EXPECT_THAT(rlf_request_stream->headers(),
              Http::HeaderValueOf(":path", "/nrlf-ratelimiting/v0/tokens/sepp"));

  ASSERT_TRUE(rlf_request_stream->waitForEndStream(*dispatcher_));
  compareJsonBodies(
      json::parse(rlf_request_stream->body().toString()),
      "[{\"amount\":1,\"name\":\"ingress=GRLname.rp=rp-A\",\"watermark\":33.75}]"_json);

  ASSERT_TRUE(fake_rlf_connection_->close());

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("429", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ("{\"status\": 429, \"title\": \"Too Many Requests\"}",
            response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());
  ENVOY_LOG(trace, printCounters(test_server_, "http.eirl"));

  // Counter evaluation
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.global_rate_limit_accepted", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_accepted_per_roaming_partner", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.global_rate_limit_dropped", 0);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_dropped_per_roaming_partner", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.global_rate_limit_rejected", 1);
  test_server_->waitForCounterGe(
      "http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_rejected_per_roaming_partner", 1);
  //test_server_->waitForCounterGe("cluster.cluster_1.upstream_rq_2xx", 1);
  
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_accepted")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_accepted_"
                             "per_roaming_partner")
                   ->value());
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_dropped")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_dropped_"
                             "per_roaming_partner")
                   ->value());
  EXPECT_EQ(1, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_rejected")->value());
  EXPECT_EQ(1, test_server_
                   ->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_rejected_"
                             "per_roaming_partner")
                   ->value());
  //EXPECT_EQ(1, test_server_->counter("cluster.cluster_1.upstream_rq_2xx")->value());


  codec_client_->close();
}



TEST_P(EricIngressRatelimitRpIntegrationTest, TestRpOverlimitRejectWildcard) {
  //replaces the dn of rpB with a wildcard dn
  config_helper_.addFilter(absl::StrCat(ratelimit_base_config, absl::StrReplaceAll(ratelimit_rp_not_found_pass, {{"smf2.outer_space_plmn.com", "'*.external_plmn.com'"}})));
  initializeWithRouteConfigFromYaml(config_route_md);

  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
  };

  FakeStreamPtr request_stream;
  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeRequestWithBody(req_headers, fake_body);
  // auto response = codec_client_->makeHeaderOnlyRequest(req_headers);

  FakeStreamPtr rlf_request_stream = sendRlfRequest("200", rlfResponseResponseOverlimit());
  EXPECT_THAT(rlf_request_stream->headers(),
              Http::HeaderValueOf(":path", "/nrlf-ratelimiting/v0/tokens/sepp"));

  ASSERT_TRUE(rlf_request_stream->waitForEndStream(*dispatcher_));
  compareJsonBodies(
      json::parse(rlf_request_stream->body().toString()),
      "[{\"amount\":1,\"name\":\"ingress=GRLname.rp=rp_B\",\"watermark\":33.75}]"_json);

  ASSERT_TRUE(fake_rlf_connection_->close());

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("429", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ("{\"status\": 429, \"title\": \"Too Many Requests\"}",
            response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());
  ENVOY_LOG(trace, printCounters(test_server_, "http.eirl"));

  // Counter evaluation
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.global_rate_limit_accepted", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.r12r.rp_B.global_rate_limit_accepted_per_roaming_partner", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.global_rate_limit_dropped", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.r12r.rp_B.global_rate_limit_dropped_per_roaming_partner", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.global_rate_limit_rejected", 1);
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.r12r.rp_B.global_rate_limit_rejected_per_roaming_partner", 1);
  //test_server_->waitForCounterGe("cluster.cluster_1.upstream_rq_2xx", 1);
  
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_accepted")->value());
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp_B.global_rate_limit_accepted_per_roaming_partner")->value());
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_dropped")->value());
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp_B.global_rate_limit_dropped_per_roaming_partner")->value());
  EXPECT_EQ(1, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_rejected")->value());
  EXPECT_EQ(1, test_server_->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp_B.global_rate_limit_rejected_per_roaming_partner")->value());
  //EXPECT_EQ(1, test_server_->counter("cluster.cluster_1.upstream_rq_2xx")->value());


  codec_client_->close();
}



// limit on rp_B -> action drop message
TEST_P(EricIngressRatelimitRpIntegrationTest, TestRpOverlimitDrop) {

  config_helper_.addFilter(absl::StrCat(ratelimit_base_config, ratelimit_rp_config_drop));
  initializeWithRouteConfigFromYaml(config_route_md);

  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-sbi-message-priority", "1"},
  };

  FakeStreamPtr request_stream;
  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeRequestWithBody(req_headers, fake_body);

  FakeStreamPtr rlf_request_stream = sendRlfRequest("200", rlfResponseResponseOverlimit());
  EXPECT_THAT(rlf_request_stream->headers(),
              Http::HeaderValueOf(":path", "/nrlf-ratelimiting/v0/tokens/sepp"));

  ASSERT_TRUE(rlf_request_stream->waitForEndStream(*dispatcher_));

  compareJsonBodies(
      json::parse(rlf_request_stream->body().toString()),
      "[{\"amount\":1,\"name\":\"ingress=GRLname.rp=rp_B\",\"watermark\":1.40}]"_json);

  ASSERT_TRUE(fake_rlf_connection_->close());

  ASSERT_TRUE(response->waitForReset());
  ENVOY_LOG(trace, printCounters(test_server_, "http.eirl"));

  // Counter evaluation
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.global_rate_limit_accepted", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.r12r.rp_B.global_rate_limit_accepted_per_roaming_partner", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.global_rate_limit_dropped", 1);
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.r12r.rp_B.global_rate_limit_dropped_per_roaming_partner", 1);
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.global_rate_limit_rejected", 0);
  test_server_->waitForCounterGe("http.eirl.n8e.null.g3p.ingress.r12r.rp_B.global_rate_limit_rejected_per_roaming_partner", 0);
  //test_server_->waitForCounterGe("cluster.cluster_1.upstream_rq_2xx", 1);
  
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_accepted")->value());
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp_B.global_rate_limit_accepted_per_roaming_partner")->value());
  EXPECT_EQ(1, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_dropped")->value());
  EXPECT_EQ(1, test_server_->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp_B.global_rate_limit_dropped_per_roaming_partner")->value());
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_rejected")->value());
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp_B.global_rate_limit_rejected_per_roaming_partner")->value());
  //EXPECT_EQ(1, test_server_->counter("cluster.cluster_1.upstream_rq_2xx")->value());

  codec_client_->close();
}

// ingress RP not found -> configured rp_not_found action (reject with message) is executed

TEST_P(EricIngressRatelimitRpIntegrationTest, TestRpNotFound) {
  config_helper_.addFilter(
      absl::StrCat(ratelimit_base_config,
                   absl::StrReplaceAll(ratelimit_rp_config_reject, {{"smf1.external", "invalidDN.outer_space"}})));
  initializeWithRouteConfigFromYaml(config_route_md);

  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
  };

  FakeStreamPtr request_stream;
  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeRequestWithBody(req_headers, fake_body);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());

  EXPECT_EQ("403", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ("{\"status\": 403, \"title\": \"Unauthorized\", \"detail\": \"Roaming partner not "
            "found\"}",
            response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()),
            response->headers().getContentLengthValue());
  ENVOY_LOG(trace, printCounters(test_server_, "http.eirl"));

  // Counter evaluation

  
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_accepted")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_accepted_"
                             "per_roaming_partner")
                   ->value());
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_dropped")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_dropped_"
                             "per_roaming_partner")
                   ->value());
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_rejected")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_rejected_"
                             "per_roaming_partner")
                   ->value());

  codec_client_->close();
}



// ingress RP not found -> configured rp_not_found action (pass) is executed

TEST_P(EricIngressRatelimitRpIntegrationTest, TestRpNotFoundPass) {
  config_helper_.addFilter(
      absl::StrCat(ratelimit_base_config,
                   ratelimit_rp_not_found_pass));
  initializeWithRouteConfigFromYaml(config_route_md);

  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
  };

  FakeStreamPtr request_stream;
  FakeHttpConnectionPtr fake_upstream_connection;

  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeRequestWithBody(req_headers, fake_body);

  // wait for the response and close the fake upstream connection
  //ASSERT_TRUE(response->waitForEndStream());

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



  // Counter evaluation

  
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_accepted")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_accepted_"
                             "per_roaming_partner")
                   ->value());
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_dropped")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_dropped_"
                             "per_roaming_partner")
                   ->value());
  EXPECT_EQ(0, test_server_->counter("http.eirl.n8e.null.g3p.ingress.global_rate_limit_rejected")->value());
  EXPECT_EQ(0, test_server_
                   ->counter("http.eirl.n8e.null.g3p.ingress.r12r.rp-A.global_rate_limit_rejected_"
                             "per_roaming_partner")
                   ->value());

  codec_client_->close();
}

TEST_P(EricIngressRatelimitRpIntegrationTest, TestRpLimitNotConfigured) {
  config_helper_.addFilter(absl::StrCat(ratelimit_base_config, rp_limit_not_configured));
  initializeWithRouteConfigFromYaml(config_route_md);

  Http::TestRequestHeaderMapImpl req_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
  };

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr request_stream;
  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

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

  codec_client_->close();
}

} // namespace
} // namespace IngressRateLimitFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy