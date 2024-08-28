#include "base_failover.h"
#include <cstddef>
#include <ostream>
#include <unistd.h>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class ReselectionWithOutlierDetectionTest : public EricProxyFailoverTestBase {
public:
  ReselectionWithOutlierDetectionTest() : EricProxyFailoverTestBase(true, false){};

  // Common function for nf pool reselection tests with different scenarios
  void testNfPoolReselection(std::string target_cluster, RoutingBehaviourWrapper rb,
                             const std::vector<std::vector<uint64_t>> expected_hosts_list) {

    Http::TestRequestHeaderMapImpl headers{
        {":method", "GET"}, {":path", "/"}, {":authority", "scp.ericsson.se"}};

    if (rb.preferredHost()) {
      headers.addCopy("3gpp-Sbi-target-apiRoot",
                      fmt::format("http://{}", rb.preferredHost().value()));
    }

    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(headers);

    // Extracting and testing the expected producers from the expected list in a sequence
    for (const auto& per_try_indx : expected_hosts_list) {

      auto upstream_idx = waitForNextUpstreamRequest(per_try_indx);

      // Send fake 500 status upstream response
      upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "500"}}, true);

      ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
      ASSERT_TRUE(fake_upstream_connection_->close());
      ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
      fake_upstream_connection_.reset();

      // Verify upstream request
      EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
      EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", target_cluster));
      if (!rb.isRoundRobin() && rb.preferredHost()) {
        // TODO: remove me later
        EXPECT_THAT(upstream_request_->headers(),
                    Http::HeaderValueOf("x-host", rb.preferredHost().value()));
      }

      if (per_try_indx.size() > 1 && upstream_idx.value() > 0) {
        break;
      }
    }

    // ENVOY_LOG(debug, "{}", fmt::format("tried hosts?->{}\n", tried_hosts));
    // Verify downstream response

    // Wait for the response and close the fake upstream connection

    ASSERT_TRUE(response->waitForEndStream());
    // ASSERT_TRUE(fake_upstream_connection_->close());

    // EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "500"));
    // std::replace(target_cluster.begin(), target_cluster.end(), ':', '_');
    // EXPECT_EQ(
    //     1, test_server_->counter("cluster." + target_cluster +
    //     ".upstream_rq_retry_limit_exceeded")
    //            ->value());
    // EXPECT_EQ(expected_hosts_list.size() - 1,
    //           test_server_->counter("cluster." + target_cluster +
    //           ".upstream_rq_retry")->value());

    codec_client_->close();
  }

  void testReselectionManyReqs(
      std::string target_cluster, RoutingBehaviourWrapper rb,
      const std::vector<std::vector<std::vector<uint64_t>>> expected_hosts_per_req,
      bool succeed_last_req) {

    Http::TestRequestHeaderMapImpl headers{
        {":scheme","http"},
        {":method", "GET"},
        {":path", "/"},
        {":authority", "scp.ericsson.se"}};

    if (rb.preferredHost()) {
      headers.addCopy("3gpp-Sbi-target-apiRoot",
                      fmt::format("https://{}", rb.preferredHost().value()));
    }

    codec_client_ = makeHttpConnection(lookupPort("http"));
    absl::optional<unsigned long> upstream_idx;
    for (size_t i = 0; i < expected_hosts_per_req.size(); i++) {
      ENVOY_LOG(debug,
                "======================= CHARDOU: Sending request {} =======================", i);
      auto response = codec_client_->makeHeaderOnlyRequest(headers);

      for (const auto& per_try_vector : expected_hosts_per_req[i]) {

        upstream_idx = waitForNextUpstreamRequest(per_try_vector);
        if (succeed_last_req &&
            (&per_try_vector == &expected_hosts_per_req[i].back())) { // last reselect
          ENVOY_LOG(debug, "This is the last reselect");
          upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "200"}},
                                           true);
        } else {
          // Send fake 500 status upstream response
          upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "500"}},
                                           true);
        }
         ENVOY_LOG(debug, "Sent req to index: {}", per_try_vector.at(upstream_idx.value()));
         ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
         ASSERT_TRUE(fake_upstream_connection_->close());
         ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
         fake_upstream_connection_.reset();

         // Verify upstream request
         EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
         EXPECT_THAT(upstream_request_->headers(),
                     Http::HeaderValueOf("x-cluster", target_cluster));
         // todo: remove me later
         if (!rb.isRoundRobin() && rb.preferredHost()) {

           EXPECT_THAT(upstream_request_->headers(),
                       Http::HeaderValueOf("x-host", rb.preferredHost().value()));
        }
      }
      // Wait for the response and close the fake upstream connection
      ASSERT_TRUE(response->waitForEndStream());
      if (succeed_last_req && !rb.isRoundRobin() && rb.preferredHost()) { // last reselect
        // verify that the last successful reply has the correct TaR attached
        EXPECT_THAT(response->headers(),
                    Http::HeaderValueOf(
                        "3gpp-Sbi-target-apiRoot",
                        absl::StrCat("http://chf",
                                     expected_hosts_per_req[i].back().at(upstream_idx.value()),
                                     ".ericsson.se:443")));
      }
      EXPECT_TRUE(response->complete());
      sleep(1);
    }

    codec_client_->close();
  }

  // Get specific all cluster configuration from common
  std::string
  getConfigForCluster(const std::string all_cluster,
                      std::vector<std::map<std::string, std::string>> all_hosts,
                      const std::string& cluster_metadata="") override {

    std::string config_without_outlier =
        EricProxyFailoverTestBase::getConfigForCluster(all_cluster, all_hosts, cluster_metadata);
    absl::StrAppend(&config_without_outlier, outlier_detection);
    return config_without_outlier;
  }
};

//------------------------------------------------------------------------
//-------------BEGIN TEST SUITES---------------------
//------------------------------------------------------------------------

//------------------------------------------------------------------------
//----------------------- Preferred Host ---------------------------------
//------------------------------------------------------------------------

// Scenario: preferred routing, temp blocking after 2 5xx, preferred host is tried twice
// instead of 3 times
INSTANTIATE_TEST_SUITE_P(IpVersions, ReselectionWithOutlierDetectionTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

using BigVector = std::vector<std::vector<std::vector<uint64_t>>>;

TEST_P(ReselectionWithOutlierDetectionTest, TestPreferred1) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}};

  std::vector<uint64_t> retry_params{3, 2, 1, 0};
  // For the third try include both indices but do check
  // that by the fourth try host 0 is blocked and if
  // reselection happens in third try then do not
  // proceed with fourth try
  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {0}, {0, 1}, {1}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
}
TEST_P(ReselectionWithOutlierDetectionTest, TestPreferred2) {
  int tries = 3;
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "2"}},
  };
  BigVector all_reselects(tries);
  std::vector<uint64_t> retry_params{5, 2, 3, 0};
  std::vector<std::vector<uint64_t>> first_req = {{0}, {0}, {1}, {2}};
  std::vector<std::vector<uint64_t>> second_req = {{1}, {2}};
  all_reselects = {first_req, second_req, {{2}}};

  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testReselectionManyReqs(primary_cluster, rb, all_reselects, true);
}

// prefer and block host in a prio of its own
// TODO: there is a dependency here with the overprovisioning factor
// until decision is taken on how to handle that, skip tc
TEST_P(ReselectionWithOutlierDetectionTest, TestPreferred3) {
  // GTEST_SKIP();
  int tries = 3;
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "3"}},

  };
  BigVector all_reselects(tries);
  std::vector<uint64_t> retry_params{6, 2, 4, 0};
  std::vector<std::vector<uint64_t>> first_req = {{2}, {2}, {0, 1}, {0, 1}, {3}, {4}};
  std::vector<std::vector<uint64_t>> second_req = {{0, 1}, {0, 1}, {3}, {4}};
  all_reselects = {first_req, second_req, {{4}}};

  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf2.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testReselectionManyReqs(primary_cluster, rb, all_reselects, true);
}

TEST_P(ReselectionWithOutlierDetectionTest, TestRoundRobin1) {
  int tries = 3;
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "1"}},
  };
  BigVector all_reselects(tries);
  std::vector<uint64_t> retry_params{3, 0, 3, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {
      {0, 1, 2, 3}, {0, 1, 2, 3}, {0, 1, 2, 3}, {0, 1, 2, 3}};
  all_reselects = {expected_reselects, expected_reselects, {{4}}};

  auto rb = RoutingBehaviourWrapper();
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testReselectionManyReqs(primary_cluster, rb, all_reselects, false);
}

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy