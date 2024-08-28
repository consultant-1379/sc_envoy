#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "test/integration/socket_interface_swap.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "test/integration/http_integration.h"
#include <chrono>
#include <ratio>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyPerNfCountersIntegrationTest
    : public testing::TestWithParam<Network::Address::IpVersion>,
      public HttpIntegrationTest {
public:
  EricProxyPerNfCountersIntegrationTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP2, GetParam()) {}
  /**
   * Initializer for an individual integration test.
   */
  void SetUp() override { initialize(); }
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  static constexpr uint64_t IdleTimeoutMs = 300 * TSAN_TIMEOUT_FACTOR;

  void initialize() override {
    setUpstreamCount(1);
    setUpstreamProtocol(FakeHttpConnection::Type::HTTP2);
    config_helper_.addConfigModifier([](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      auto* cluster_0 = bootstrap.mutable_static_resources()->mutable_clusters()->Mutable(0);
      ASSERT(cluster_0->name() == "cluster_0");
      ConfigHelper::setHttp2(*cluster_0);
      auto* endpoint = cluster_0->mutable_load_assignment()->mutable_endpoints()->Mutable(0);
      const std::string EndpointsYaml = R"EOF(
        lb_endpoints:
        - endpoint:
            hostname: foo
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 0
          metadata:
            filter_metadata:
              envoy.lb:
                host: nf.nf.com
              envoy.eric_proxy:
                nfInstanceId:
                    - 12345-4578-789
                pernfcounter: true
                support: ["NF"]
      )EOF";
      envoy::config::endpoint::v3::LocalityLbEndpoints new_lb_endpints;
      TestUtility::loadFromYaml(EndpointsYaml, new_lb_endpints);
      auto* socket_address = new_lb_endpints.mutable_lb_endpoints(0)
                                 ->mutable_endpoint()
                                 ->mutable_address()
                                 ->mutable_socket_address();
      socket_address->set_address(Network::Test::getLoopbackAddressString(GetParam()));
      *endpoint = new_lb_endpints;
    });

    config_helper_.addConfigModifier(
        [](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager&
               hcm) {
          // 100 millisecond timeout. The shadow inherits the timeout value from the route.
          auto* route_config = hcm.mutable_route_config();
          auto* virtual_host = route_config->mutable_virtual_hosts(0);
          auto* route = virtual_host->mutable_routes(0)->mutable_route();
          route->mutable_timeout()->set_seconds(0);
          route->mutable_timeout()->set_nanos(IdleTimeoutMs * 1000 * 1000);

          auto* request_headers_timeout = hcm.mutable_request_headers_timeout();
          request_headers_timeout->set_seconds(0);
          request_headers_timeout->set_nanos(IdleTimeoutMs * 1000 * 1000);
        });
    config_helper_.disableDelayClose();

    config_helper_.prependFilter(config_common_eric_proxy);
    // Create virtual host with domain `stateful.session.com` and default route to `cluster_0`
    auto virtual_host = config_helper_.createVirtualHost("stateful.session.com");

    config_helper_.addVirtualHost(virtual_host);
    HttpIntegrationTest::initialize();
  }

  // Common configuration for eric proxy filter
  const std::string config_common_eric_proxy = R"EOF(
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
        - action_route_to_pool:
            pool_name:
              term_string: cluster_0
            routing_behaviour: PREFERRED
            preferred_target:
              term_header: "3gpp-Sbi-target-apiRoot"
)EOF";

  // check one counter
  void checkCounter(const std::string& name, const uint64_t value) {
    const auto& v = test_server_->counters();
    const auto pos =
        std::find_if(v.cbegin(), v.cend(), [&name](const Stats::CounterSharedPtr stat) -> bool {
          return absl::EndsWithIgnoreCase(stat->name(), name);
        });
    ENVOY_LOG(debug, "Check the counter: " + name);
    ASSERT_NE(pos, v.cend());
    const auto stat = *pos;
    ASSERT_TRUE(stat); // reference should exist
    EXPECT_EQ(stat->value(), value);
  }
  // check counters for all nf instances
  void checkCounters(const std::string& name, const uint64_t value) {
    ENVOY_LOG(debug, "Check the counter: " + name);
    const auto& v = test_server_->counters();
    const auto sum = std::accumulate(
        v.cbegin(), v.cend(), 0, [&name](uint64_t acc, const Stats::CounterSharedPtr stat) {
          return absl::EndsWithIgnoreCase(stat->name(), name) ? acc + stat->value() : acc;
        });
    EXPECT_EQ(sum, value);
  }

  void checkCountersByTags(const std::vector<std::string>& tags, const uint64_t value) {
    ENVOY_LOG(debug, "Check the counter by tag: " + absl::StrJoin(tags, "."));
    const auto contains = [](const std::string& name,
                             const std::vector<std::string>& tags) -> bool {
      for (const auto& tag : tags) {
        if (absl::StrContainsIgnoreCase(name, tag)) {
          continue;
        } else {
          return false;
        }
      }
      return true;
    };
    const auto& v = test_server_->counters();
    const auto sum =
        std::accumulate(v.cbegin(), v.cend(), 0,
                        [&tags, &contains](uint64_t acc, const Stats::CounterSharedPtr stat) {
                          return contains(stat->name(), tags) ? acc + stat->value() : acc;
                        });
    EXPECT_EQ(sum, value);
  }

  std::string getCounters(const std::vector<Stats::CounterSharedPtr>& counters,
                          const std::vector<absl::string_view> greps) {
    // returns true if name contains all greps
    const auto contains = [&greps](const std::string& name) -> bool {
      if (greps.empty()) {
        return true;
      }
      for (const auto g : greps) {
        if (!g.empty() && name.find(g) == std::string::npos) {
          return false;
        } else {
          continue;
        }
      }
      return true;
    };
    std::vector<Stats::CounterSharedPtr> sorted_counters;
    for (const auto& counter : counters) {
      if (!contains(counter->name())) {
        continue;
      } else {
        sorted_counters.push_back(counter);
      }
    }
    std::sort(sorted_counters.begin(), sorted_counters.end(),
              [](const Stats::CounterSharedPtr a, const Stats::CounterSharedPtr b) -> bool {
                return a->name() > b->name();
              });
    std::string res = "";
    res += "counter_map = {";
    for (const auto& counter : sorted_counters) {
      absl::StrAppend(&res, "\n", "{\"", counter->name(), "\", \"", counter->value(), "\"},");
    }
    absl::StrAppend(&res, "\n}");
    return res;
  }
};

//--------------------------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyPerNfCountersIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(EricProxyPerNfCountersIntegrationTest, test_timeout) {
  // Lock up fake upstream so that it won't accept connections.
  absl::MutexLock l(&fake_upstreams_[0]->lock());

  codec_client_ = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl request_headers{{":method", "GET"},
                                                 {":path", "/test"},
                                                 {":scheme", "http"},
                                                 {"x-envoy-upstream-rq-timeout-ms", "500"},
                                                 {"x-envoy-expected-rq-timeout-ms", "300"},
                                                 {":authority", "stateful.session.com"}};

  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);

  ASSERT_TRUE(response->waitForEndStream(std::chrono::milliseconds(15050) * TSAN_TIMEOUT_FACTOR));
  EXPECT_EQ("504", response->headers().getStatusValue());

  checkCounter("cluster.cluster_0.upstream_rq_tx_reset", 1);
  checkCounter("cluster.cluster_0.upstream_rq_timeout", 1);

  checkCountersByTags({"12345-4578-789", "upstream_rq_tx_reset_per_nf"}, 1);
  checkCountersByTags({"12345-4578-789", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"12345-4578-789", "upstream_rq_timeout_per_nf"}, 1);
  checkCountersByTags({"12345-4578-789", "upstream_rq_5xx_per_nf"}, 0);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.cluster_0"}));
}

TEST_P(EricProxyPerNfCountersIntegrationTest, test_reset) {
  codec_client_ = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl request_headers{{":method", "GET"},
                                                 {":path", "/test"},
                                                 {":scheme", "http"},
                                                 {":authority", "stateful.session.com"}};

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr upstream_request;

  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, upstream_request));

  upstream_request->encodeResetStream();

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(response->complete());
  EXPECT_EQ("503", response->headers().getStatusValue());

  checkCounter("cluster.cluster_0.upstream_rq_rx_reset", 1);
  checkCounter("cluster.cluster_0.n10d.12345-4578-789.upstream_rq_total_per_nf", 1);
  checkCounter("cluster.cluster_0.n10d.12345-4578-789.upstream_rq_rx_reset_per_nf", 1);
  checkCountersByTags({"12345-4578-789", "upstream_rq_5xx_per_nf"}, 0);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.cluster_0"}));
}

TEST_P(EricProxyPerNfCountersIntegrationTest, test_connection_error) {
  codec_client_ = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl request_headers{{":method", "GET"},
                                                 {":path", "/test"},
                                                 {":scheme", "http"},
                                                 {":authority", "stateful.session.com"}};

  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);

  fake_upstreams_[0].reset();

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(response->complete());
  EXPECT_EQ("503", response->headers().getStatusValue());

  checkCounter("cluster.cluster_0.upstream_cx_total", 1);
  checkCounter("cluster.cluster_0.upstream_cx_connect_fail", 1);
  checkCounter("cluster.cluster_0.upstream_rq_pending_total", 1);
  checkCounter("cluster.cluster_0.n10d.12345-4578-789.upstream_rq_total_per_nf", 1);
  checkCounter("cluster.cluster_0.n10d.12345-4578-789.upstream_rq_pending_failure_eject_per_nf", 1);
  checkCountersByTags({"12345-4578-789", "upstream_rq_5xx_per_nf"}, 0);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.cluster_0"}));
}

TEST_P(EricProxyPerNfCountersIntegrationTest, test_2xx) {
  codec_client_ = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl request_headers{{":method", "GET"},
                                                 {":path", "/test"},
                                                 {":scheme", "http"},
                                                 {"x-envoy-upstream-rq-timeout-ms", "500"},
                                                 {"x-envoy-expected-rq-timeout-ms", "300"},
                                                 {":authority", "stateful.session.com"}};

  auto response = sendRequestAndWaitForResponse(request_headers, 0, default_response_headers_, 0);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(response->complete());
  EXPECT_EQ("200", response->headers().getStatusValue());

  checkCounter("cluster.cluster_0.upstream_rq_total", 1);
  checkCounter("cluster.cluster_0.upstream_rq_2xx", 1);
  checkCounter("cluster.cluster_0.n10d.12345-4578-789.upstream_rq_total_per_nf", 1);
  checkCounter("cluster.cluster_0.n10d.12345-4578-789.upstream_rq_2xx_per_nf", 1);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.cluster_0"}));
}

// DND-60533 Remove Conteet Length for 204 Responses with empty data frame
TEST_P(EricProxyPerNfCountersIntegrationTest, test_204) {
  codec_client_ = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl request_headers{{":method", "GET"},
                                                 {":path", "/test"},
                                                 {":scheme", "http"},
                                                 {"x-envoy-upstream-rq-timeout-ms", "500"},
                                                 {"x-envoy-expected-rq-timeout-ms", "300"},
                                                 {":authority", "stateful.session.com"}};

  Http::TestResponseHeaderMapImpl response_headers{{":status", "204"},{"content-length","0"},{"foo","bar"}};
  // auto response = sendRequestAndWaitForResponse(request_headers, 0, response_headers, 0);
  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);
  waitForNextUpstreamRequest();
  upstream_request_->encodeHeaders(response_headers,false);
  upstream_request_->encodeData("",true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(response->complete());
  EXPECT_EQ("204", response->headers().getStatusValue());
  EXPECT_TRUE(response->headers().ContentLength() == nullptr);
  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.cluster_0"}));
}

TEST_P(EricProxyPerNfCountersIntegrationTest, test_3xx) {
  codec_client_ = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl request_headers{{":method", "GET"},
                                                 {":path", "/test"},
                                                 {":scheme", "http"},
                                                 {"x-envoy-upstream-rq-timeout-ms", "500"},
                                                 {"x-envoy-expected-rq-timeout-ms", "300"},
                                                 {":authority", "stateful.session.com"}};
  Http::TestResponseHeaderMapImpl response_headers{{":status", "321"}};

  auto response = sendRequestAndWaitForResponse(request_headers, 0, response_headers, 0);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(response->complete());
  EXPECT_EQ("321", response->headers().getStatusValue());

  checkCounter("cluster.cluster_0.upstream_rq_total", 1);
  checkCounter("cluster.cluster_0.upstream_rq_3xx", 1);
  checkCounter("cluster.cluster_0.n10d.12345-4578-789.upstream_rq_total_per_nf", 1);
  checkCounter("cluster.cluster_0.n10d.12345-4578-789.upstream_rq_3xx_per_nf", 1);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.cluster_0"}));
}

TEST_P(EricProxyPerNfCountersIntegrationTest, test_4xx) {
  codec_client_ = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl request_headers{{":method", "GET"},
                                                 {":path", "/test"},
                                                 {":scheme", "http"},
                                                 {"x-envoy-upstream-rq-timeout-ms", "500"},
                                                 {"x-envoy-expected-rq-timeout-ms", "300"},
                                                 {":authority", "stateful.session.com"}};
  Http::TestResponseHeaderMapImpl response_headers{{":status", "421"}};

  auto response = sendRequestAndWaitForResponse(request_headers, 0, response_headers, 0);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(response->complete());
  EXPECT_EQ("421", response->headers().getStatusValue());

  checkCounter("cluster.cluster_0.upstream_rq_total", 1);
  checkCounter("cluster.cluster_0.upstream_rq_4xx", 1);
  checkCounter("cluster.cluster_0.n10d.12345-4578-789.upstream_rq_total_per_nf", 1);
  checkCounter("cluster.cluster_0.n10d.12345-4578-789.upstream_rq_4xx_per_nf", 1);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.cluster_0"}));
}

TEST_P(EricProxyPerNfCountersIntegrationTest, test_1xx) {
  codec_client_ = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl request_headers{{":method", "GET"},
                                                 {":path", "/test"},
                                                 {":scheme", "http"},
                                                 {"x-envoy-upstream-rq-timeout-ms", "500"},
                                                 {"x-envoy-expected-rq-timeout-ms", "300"},
                                                 {":authority", "stateful.session.com"}};
  Http::TestResponseHeaderMapImpl response_headers{{":status", "100"}};

  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr upstream_request_;

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, upstream_request_));
  upstream_request_->encode1xxHeaders(response_headers);
  upstream_request_->encodeHeaders(response_headers, true);
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));

  checkCounter("cluster.cluster_0.upstream_rq_total", 1);
  checkCounter("cluster.cluster_0.upstream_rq_1xx", 1);
  checkCounter("cluster.cluster_0.n10d.12345-4578-789.upstream_rq_total_per_nf", 1);
  checkCounter("cluster.cluster_0.n10d.12345-4578-789.upstream_rq_1xx_per_nf", 1);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.cluster_0"}));
}

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy