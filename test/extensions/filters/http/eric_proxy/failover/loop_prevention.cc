#include "base_failover.h"
#include <ostream>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class FailoverLoopPreventionTest : public EricProxyFailoverTestBase {
public:
  FailoverLoopPreventionTest() : EricProxyFailoverTestBase(false, true){};
  // Common function for nf pool reselection tests with different scenarios
  void testNfPoolReselection(std::string target_cluster, RoutingBehaviourWrapper rb,
                             const std::vector<std::vector<uint64_t>> expected_hosts_list,
                             std::string& via_hdr) {

    Http::TestRequestHeaderMapImpl headers{
        {":scheme","http"},
        {":method", "GET"},
        {":path", "/"},
        {":authority", "scp.ericsson.se"},
    };
    headers.addCopy("via", via_hdr);

    if (rb.preferredHost()) {
      headers.addCopy("3gpp-Sbi-target-apiRoot",
                      fmt::format("https://{}", rb.preferredHost().value()));
    }

    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(headers);

    // if we don't expect an upstream host to reply, it's a local reply
    if (expected_hosts_list.empty()) {
      ASSERT_TRUE(response->waitForEndStream());
      EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "503"));
      ENVOY_LOG(trace, printCounters(test_server_, "cluster."));
      std::replace(target_cluster.begin(), target_cluster.end(), ':', '_');
      // verify no retries took place
      EXPECT_EQ(0, test_server_
                       ->counter("cluster." + target_cluster + ".upstream_rq_retry_limit_exceeded")
                       ->value());
      EXPECT_EQ(0,
                test_server_->counter("cluster." + target_cluster + ".upstream_rq_retry")->value());
      // local reply of no healthy upstream
      EXPECT_EQ(1, test_server_->counter("cluster." + target_cluster + ".upstream_cx_none_healthy")
                       ->value());

      EXPECT_EQ(1,
                test_server_->counter("cluster." + target_cluster + ".upstream_rq_503")->value());

      codec_client_->close();
      return;
    }

    // Extracting and testing the expected producers from the expected list in a sequence
    for (const auto& per_try_indx : expected_hosts_list) {

      waitForNextUpstreamRequest(per_try_indx);

      // Send fake 500 status upstream response
      upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "500"}}, true);

      ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
      ASSERT_TRUE(fake_upstream_connection_->close());
      ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
      fake_upstream_connection_.reset();

      // Verify upstream request
      EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
      EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", target_cluster));
      // todo: remove me later
      if (!rb.isRoundRobin() && rb.preferredHost()) {

        EXPECT_THAT(
            upstream_request_->headers(),
            Http::HeaderValueOf("x-host", absl::AsciiStrToLower(rb.preferredHost().value())));
      }
    }

    // ENVOY_LOG(trace, "{}", fmt::format("tried hosts?->{}\n", tried_hosts));
    // Verify downstream response

    // Wait for the response and close the fake upstream connection
    ASSERT_TRUE(response->waitForEndStream());
    // ASSERT_TRUE(fake_upstream_connection_->close());

    EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "500"));
    std::replace(target_cluster.begin(), target_cluster.end(), ':', '_');
    EXPECT_EQ(
        1, test_server_->counter("cluster." + target_cluster + ".upstream_rq_retry_limit_exceeded")
               ->value());
    EXPECT_EQ(expected_hosts_list.size() - 1,
              test_server_->counter("cluster." + target_cluster + ".upstream_rq_retry")->value());

    codec_client_->close();
  }
};

//------------------------------------------------------------------------
//-------------BEGIN TEST SUITES---------------------
//------------------------------------------------------------------------

//------------------------------------------------------------------------
//----------------------- Preferred Host ---------------------------------
//------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(IpVersions, FailoverLoopPreventionTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(FailoverLoopPreventionTest, TestPreferred1) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "1"}}};
  std::string via_hdr =
      "1.0 SCP-scp1.ericsson.se:443, 1.1 scp2.ericsson.com, HTTP/2.0 scp3.ericsson.com";
  std::vector<uint64_t> retry_params{3, 2, 1, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {0}, {0}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects, via_hdr);
  ENVOY_LOG(trace, printCounters(test_server_, "cluster."));
}

TEST_P(FailoverLoopPreventionTest, TestPreferred2) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "2"}}, // 3
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "2"}}, // 4
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "3"}}, // 5
  };
  std::string via_hdr =
      "1.0 scp2.ericsson.se:443, 1.1 SEPP-scp2.ericsson.com, HTTP/2.0 SEPP-scp3.ericsson.com";
  std::vector<uint64_t> retry_params{7, 2, 5, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{3}, {3}, {3}, {0}, {1, 2}, {1, 2}, {5}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "scp1.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects, via_hdr);
  //       ENVOY_LOG(trace,printCounters(test_server_, "cluster."));
}

// preferred routing on cluster with LRP,  last host in LRP included in via header
TEST_P(FailoverLoopPreventionTest, TestPreferredLrp) {

  std::string aggregate_cluster = "chf_primary#!_#LRP:chf_lr_pool#!_#aggr:";
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}, // 1
  };
  std::string last_resort_cluster = "chf_lr_pool";

  std::vector<std::map<std::string, std::string>> last_resort_hosts = {

      {{"hostname", "lr01.ericsson.se:443"}, {"priority", "0"}}, // 2
      {{"hostname", "lr02.ericsson.se:443"}, {"priority", "1"}}, // 3
  };
  std::string via_hdr =
      "1.0 scp2.ericsson.se:443, 1.1 lr02.ericsson.se:443, HTTP/2.0 scp3.ericsson.com";
  std::vector<uint64_t> retry_params{6, 1, 3, 2};

  std::vector<std::vector<uint64_t>> expected_reselects = {{1}, {1}, {0}, {2}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf1.ericsson.se:443");
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params);
  testNfPoolReselection(aggregate_cluster, rb, expected_reselects, via_hdr);
}

TEST_P(FailoverLoopPreventionTest, TestIndirectPreferred1) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp3.ericsson.se:443"}, {"priority", "2"}}  // 3
  };
  std::string cluster_metadata = R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf1.ericsson.se:443:
      - fqdn: scp1.ericsson.se:443
        ip: 10.10.10.1:443
      - fqdn: scp2.ericsson.se:443
        ip: 10.10.10.2:443
      chf2.ericsson.se:443:
      - fqdn: scp3.ericsson.se:443
        ip: 10.10.10.3:443
)EOF";
  std::string via_hdr =
      "1.0 scp1.ericsson.se:443, 1.1 scp2.ericsson.se:443, HTTP/2.0 scp3.ericsson.se:443";
  std::vector<uint64_t> retry_params{3, 2, 1, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {0}, {0}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params, cluster_metadata);
  testNfPoolReselection(primary_cluster, rb, expected_reselects, via_hdr);
  ENVOY_LOG(trace, printCounters(test_server_, "cluster."));
}

TEST_P(FailoverLoopPreventionTest, TestIndirectPreferred2) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp3.ericsson.se:443"}, {"priority", "2"}}  // 3
  };
  std::string cluster_metadata = R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf1.ericsson.se:443:
      - fqdn: scp1.ericsson.se:443
        ip: 10.10.10.1:443
      - fqdn: scp2.ericsson.se:443
        ip: 10.10.10.2:443
      chf2.ericsson.se:443:
      - fqdn: scp3.ericsson.se:443
        ip: 10.10.10.3:443
)EOF";
  std::string via_hdr =
      "1.0 scp1.ericsson.se:443, 1.1 scp2.ericsson.se:443";
  std::vector<uint64_t> retry_params{3, 2, 1, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {3}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf1.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params, cluster_metadata);
  testNfPoolReselection(primary_cluster, rb, expected_reselects, via_hdr);
  ENVOY_LOG(trace, printCounters(test_server_, "cluster."));
}

TEST_P(FailoverLoopPreventionTest, TestIndirectPreferred3) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp3.ericsson.se:443"}, {"priority", "2"}}  // 3
  };
  std::string cluster_metadata = R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf1.ericsson.se:443:
      - fqdn: scp1.ericsson.se:443
        ip: 10.10.10.1:443
      - fqdn: scp2.ericsson.se:443
        ip: 10.10.10.2:443
      chf2.ericsson.se:443:
      - fqdn: scp3.ericsson.se:443
        ip: 10.10.10.3:443
)EOF";
  std::string via_hdr =
      "1.0 SCP-scp1.ericsson.se:443, HTTP/2.0 SCP-scp3.ericsson.se:443";
  std::vector<uint64_t> retry_params{3, 2, 1, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{2}, {2}, {2}, {0}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf1.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params, cluster_metadata);
  testNfPoolReselection(primary_cluster, rb, expected_reselects, via_hdr);
  ENVOY_LOG(trace, printCounters(test_server_, "cluster."));
}

TEST_P(FailoverLoopPreventionTest, TestIndirectPreferred4) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp3.ericsson.se:443"}, {"priority", "1"}}  // 3
  };
  std::string cluster_metadata = R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf1.ericsson.se:443:
      - fqdn: scp1.ericsson.se:443
        ip: 10.10.10.1:443
      - fqdn: scp2.ericsson.se:443
        ip: 10.10.10.2:443
      - fqdn: scp3.ericsson.se:443
        ip: 10.10.10.3:443
)EOF";
  std::string via_hdr =
      "1.0 scp1.ericsson.se:443";
  std::vector<uint64_t> retry_params{3, 2, 1, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{2, 3}, {2, 3}, {2, 3}, {0}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf1.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params, cluster_metadata);
  testNfPoolReselection(primary_cluster, rb, expected_reselects, via_hdr);
  ENVOY_LOG(trace, printCounters(test_server_, "cluster."));
}

TEST_P(FailoverLoopPreventionTest, TestRoundRobin1) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "2"}}, // 3
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "2"}}, // 4
      {{"hostname", "scp3.ericsson.se:443"}, {"priority", "3"}}, // 5
  };
  std::string via_hdr =
      "1.0 scp1.ericsson.se:443, 1.1 scp2.ericsson.se:443, HTTP/2.0 scp3.ericsson.se:443";
  std::vector<uint64_t> retry_params{5, 0, 5, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {1, 2}, {1, 2}};
  auto rb = RoutingBehaviourWrapper();
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects, via_hdr);
  // ENVOY_LOG(trace,printCounters(test_server_, "cluster."));
}

TEST_P(FailoverLoopPreventionTest, TestRoundRobin2) {
  // the scenario that does not work with the current solution: scp alone in the first prio that
  // should be
  // skipped from the first try
  // GTEST_SKIP();
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}}, // 2
  };
  std::string via_hdr =
      "1.0 scp1.ericsson.se:443, 1.1 scp2.ericsson.se:443, HTTP/2.0 scp3.ericsson.se:443";
  std::vector<uint64_t> retry_params{2, 0, 2, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{1, 2}, {1, 2}};
  auto rb = RoutingBehaviourWrapper();
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects, via_hdr);
  // ENVOY_LOG(trace,printCounters(test_server_, "cluster."));
}

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy