#include "base_failover.h"
#include <algorithm>
#include <cstdint>
#include <iterator>
#include <numeric>
#include <ostream>
#include <string>
#include <vector>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterNfPoolReselectionOverrideHostTest : public EricProxyFailoverTestBase {
public:
  EricProxyFilterNfPoolReselectionOverrideHostTest() : EricProxyFailoverTestBase(false, false){};
  // Common function for nf pool reselection tests with different scenarios
  void testNfPoolReselection(std::string target_cluster, RoutingBehaviourWrapper rb,
                             const std::vector<std::vector<uint64_t>> expected_hosts_list) {

    Http::TestRequestHeaderMapImpl headers{{":method", "GET"},
                                           {":scheme","http"},
                                           {":path", "/"},
                                           {":authority", "scp.ericsson.se"},
                                           {"via", "1.0 fred, HTTP/1.1 p.example.net"}};

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

    // ENVOY_LOG(debug, "{}", fmt::format("tried hosts?->{}\n", tried_hosts));
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
    const auto contains  = [](const std::string& name, const std::vector<std::string>& tags) -> bool {
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
    const auto sum = std::accumulate(
        v.cbegin(), v.cend(), 0, [&tags, &contains](uint64_t acc, const Stats::CounterSharedPtr stat) {
          return contains(stat->name(), tags) ? acc + stat->value() : acc;
        });
    EXPECT_EQ(sum, value);
  }
};

//------------------------------------------------------------------------
//-------------BEGIN TEST SUITES---------------------
//------------------------------------------------------------------------

//------------------------------------------------------------------------
//----------------------- Preferred Host ---------------------------------
//------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterNfPoolReselectionOverrideHostTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestPreferred1) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}}};

  std::vector<uint64_t> retry_params{3, 2, 1, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {0}, {0}, {1}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
  
  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));
  
  // from retry_params preffered host: e0735e6ce309
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 3); // 3 times try to e0735e6ce309
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 3);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_after_retry_per_nf", 2); // 2 times retry 

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 1);

  checkCounters("upstream_rq_total_per_nf", 4);
  checkCounters("upstream_rq_5xx_per_nf", 4);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestPreferredUppercaseTar2) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "Chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "Chf1.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}}};

  std::vector<uint64_t> retry_params{2, 1, 1, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{1}, {1}, {0}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "Chf1.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

   // preffered host: e0735e6ce310
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 2); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 2);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_after_retry_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_after_reselect_per_nf", 1);

  checkCounters("upstream_rq_total_per_nf", 3);
  checkCounters("upstream_rq_5xx_per_nf", 3);
  checkCounters("upstream_rq_after_retry_per_nf", 1);
  checkCounters("upstream_rq_after_reselect_per_nf", 1);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestPreferred3) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce313"}}

  };

  std::vector<uint64_t> retry_params{6, 2, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0},    {0},    {0},   {1, 2},
                                                           {2, 1}, {3, 4}, {4, 3}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 7);
  checkCounters("upstream_rq_after_reselect_per_nf", 4);
  checkCounters("upstream_rq_5xx_per_nf", 7);
  checkCounters("upstream_rq_after_retry_per_nf", 2);

  // preffered host: e0735e6ce309
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_total_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_5xx_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_after_reselect_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_5xx_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_after_reselect_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_total_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_5xx_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_after_reselect_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_after_reselect_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 3);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 3); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_after_retry_per_nf", 2);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestPreferred4a) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce313"}}

  };

  std::vector<uint64_t> retry_params{4, 0, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{1}, {0}, {2}, {4, 3}, {3, 4}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf1.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 5);
  checkCounters("upstream_rq_after_reselect_per_nf", 4);
  checkCounters("upstream_rq_5xx_per_nf", 5);

  // preffered host: e0735e6ce310
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_total_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_5xx_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_total_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_total_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_5xx_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 1); 
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestPreferred4b) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce313"}}

  };

  std::vector<uint64_t> retry_params{4, 0, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{2}, {0, 1}, {0, 1}, {4, 3}, {3, 4}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf2.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 5);
  checkCounters("upstream_rq_after_reselect_per_nf", 4);
  checkCounters("upstream_rq_5xx_per_nf", 5);

  // preffered host: e0735e6ce311
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_total_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_5xx_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_total_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_5xx_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 1);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestPreferred5) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce313"}}

  };

  std::vector<uint64_t> retry_params{6, 2, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{1}, {1}, {1}, {0}, {2}, {4, 3}, {3, 4}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf1.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 7);
  checkCounters("upstream_rq_after_reselect_per_nf", 4);
  checkCounters("upstream_rq_after_retry_per_nf", 2);
  checkCounters("upstream_rq_5xx_per_nf", 7);

  // preffered host: e0735e6ce310
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_total_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_5xx_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_total_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_5xx_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 3); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_after_retry_per_nf", 2);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 3);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 1);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestPreferred6) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce313"}},
  };

  std::vector<uint64_t> retry_params{4, 0, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {
      {4}, {0, 1, 2, 3}, {0, 1, 2, 3}, {0, 1, 2, 3}, {0, 1, 2, 3}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf4.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 5);
  checkCounters("upstream_rq_after_reselect_per_nf", 4);
  checkCounters("upstream_rq_5xx_per_nf", 5);

  // preffered host: e0735e6ce313
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_total_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_5xx_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_total_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_5xx_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 1); 
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 1);
}

// tests first_host interraction
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, SinglePrio) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
  };

  std::vector<uint64_t> retry_params{3, 2, 1, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {0}, {0}, {1, 2}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 4);
  checkCounters("upstream_rq_after_reselect_per_nf", 1);
  checkCounters("upstream_rq_after_retry_per_nf", 2);
  checkCounters("upstream_rq_5xx_per_nf", 4);

  // preffered host: e0735e6ce309
  checkCountersByTags({"chf_primary", "upstream_rq_total_per_nf"}, 4);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 3);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_after_retry_per_nf", 2);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 3);

}

// tar does not correspond to a host
// verify that hosts are tried in RR fashion and retries are ignored, doing 1 try
// and 4 reselects
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, PreferredInvalidTar1) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce313"}},

  };

  std::vector<uint64_t> retry_params{6, 2, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0, 1}, {0, 1}, {2}, {3, 4}, {3, 4}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "doken13:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 5);
  checkCounters("upstream_rq_after_reselect_per_nf", 4);
  checkCounters("upstream_rq_5xx_per_nf", 5);

  // preffered host: ---
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_5xx_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_5xx_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 1);
}

// Similar to the previous one but with less reselects than available hosts
// tar does not correspond to a host
// verify that hosts are tried in RR fashion and retries are ignored, doing 1 try
// and 4 reselects
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, PreferredInvalidTar2) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce313"}},

  };

  std::vector<uint64_t> retry_params{6, 3, 3, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0, 1}, {0, 1}, {2}, {3, 4}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "doken13:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCountersByTags({"chf_primary", "upstream_rq_total_per_nf"}, 4);
  checkCountersByTags({"chf_primary", "upstream_rq_after_reselect_per_nf"}, 3);
  checkCountersByTags({"chf_primary", "upstream_rq_5xx_per_nf"}, 4);
}

// This works after instantiating the prio predicate before the first 3
// Only one host on the cluster so we just do one try
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, PreferredInvalidTar3) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
  };

  std::vector<uint64_t> retry_params{6, 3, 3, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "doken13:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 1);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, PreferredIssue) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},

  };

  std::vector<uint64_t> retry_params{4, 1, 3, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {0}, {1}, {2}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 4);
  checkCounters("upstream_rq_after_reselect_per_nf", 2);
  checkCounters("upstream_rq_after_retry_per_nf", 1);
  checkCounters("upstream_rq_5xx_per_nf", 4);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_5xx_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 2);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_after_retry_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 2);
}

//------------------------------------------------------------------------
//---------------------------- Strict ------------------------------------
//------------------------------------------------------------------------
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, Strict01) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
  };

  std::vector<uint64_t> retry_params{3, 3, 0, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{3}, {3}, {3}, {3}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::STRICT, "chf3.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_total_per_nf", 4);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_after_retry_per_nf", 3);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_5xx_per_nf", 4);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, Strict02) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
  };

  std::vector<uint64_t> retry_params{2, 2, 0, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{1}, {1}, {1}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::STRICT, "chf1.ericsson.se:443");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 3);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_after_retry_per_nf", 2);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 3);
}
// tar does not correspond to a host
// verify not even the initial try goes through and that none healthy is stepped
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, Strict03) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce3010"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
  };

  std::vector<uint64_t> retry_params{2, 2, 0, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::STRICT, "doken13");
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);
  
  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));
  checkCounters("upstream_rq_total_per_nf", 0);

}
//------------------------------------------------------------------------
//-------------------------- Round Robin ---------------------------------
//------------------------------------------------------------------------
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestNfPoolReselection7) {

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce313"}},
  };

  std::vector<uint64_t> retry_params{4, 0, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {
      {0, 1, 2, 3}, {0, 1, 2, 3}, {0, 1, 2, 3}, {0, 1, 2, 3}, {4}};
  auto rb = RoutingBehaviourWrapper();
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 5);
  checkCounters("upstream_rq_after_reselect_per_nf", 4);
  checkCounters("upstream_rq_5xx_per_nf", 5);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_total_per_nf", 1);
  //checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_total_per_nf", 1);
  //checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_total_per_nf", 1);
  //checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_5xx_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 1);
  //checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 1);
  //checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 1);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, RoundRobinSamePrio) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
  };

  std::vector<uint64_t> retry_params{4, 0, 3, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0, 1, 2}, {0, 1, 2}, {0, 1, 2}};
  auto rb = RoutingBehaviourWrapper();
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 3);
  checkCounters("upstream_rq_5xx_per_nf", 3);
  checkCounters("upstream_rq_after_reselect_per_nf", 2);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_5xx_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 1);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestNfPoolReselection8) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "3"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce313"}},
  };

  std::vector<uint64_t> retry_params{4, 0, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {1, 2}, {1, 2}, {3}, {4}};
  auto rb = RoutingBehaviourWrapper();
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 5);
  checkCounters("upstream_rq_after_reselect_per_nf", 4);
  checkCounters("upstream_rq_5xx_per_nf", 5);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_5xx_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 1);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, TestNfPoolReselection9) {
  // GTEST_SKIP();

  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "3"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce313"}},
  };

  std::vector<uint64_t> retry_params{7, 0, 7, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {1, 2}, {1, 2}, {3}, {4}};
  auto rb = RoutingBehaviourWrapper();
  initConfig(primary_cluster, primary_hosts, rb, retry_params);
  testNfPoolReselection(primary_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 5);
  checkCounters("upstream_rq_after_reselect_per_nf", 4);
  checkCounters("upstream_rq_5xx_per_nf", 5);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_5xx_per_nf", 1);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 1);
}

//------------------------------------------------------------------------
//----------------------- Aggregate Cluster (LRP) ------------------------
//------------------------------------------------------------------------

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, PreferredLrpCi419) {
  std::string aggregate_cluster = "Pool_NfUdm#!_#LRP:Universal_Pool_NfUdm";
  std::string primary_cluster = "Pool_NfUdm";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "nfudm2.mnc.567.mcc.765.ericsson.de:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "nfudm2.mnc.567.mcc.765.ericsson.de:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "nfudm1.mnc.567.mcc.765.ericsson.de:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}}};
  std::string last_resort_cluster = "Universal_Pool_NfUdm";

  std::vector<std::map<std::string, std::string>> last_resort_hosts = {

      {{"hostname", "lr01.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
      {{"hostname", "lr02.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce313"}},
  };

  std::vector<uint64_t> retry_params{4, 1, 1, 2};

  std::vector<std::vector<uint64_t>> expected_reselects = {{2}, {2}, {0}, {3}, {4}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED,
                                    "nfudm1.mnc.567.mcc.765.ericsson.de:443");
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params);
  testNfPoolReselection(aggregate_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 5);
  checkCounters("upstream_rq_after_reselect_per_nf", 3);
  checkCounters("upstream_rq_after_retry_per_nf", 1);
  checkCounters("upstream_rq_5xx_per_nf", 5);

  checkCountersByTags({"Universal_Pool_NfUdm", "_per_nf"}, 6);
  checkCountersByTags({"Universal_Pool_NfUdm", "2ec8ac0b-265e-4165-86e9-e0735e6ce313"}, 3);
  checkCountersByTags({"Universal_Pool_NfUdm", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}, 3);
  checkCountersByTags({"Pool_NfUdm", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}, 5);
  checkCountersByTags({"Pool_NfUdm", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}, 3);

  checkCounter("Universal_Pool_NfUdm.n10d.2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_total_per_nf", 1);
  checkCounter("Universal_Pool_NfUdm.n10d.2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("Universal_Pool_NfUdm.n10d.2ec8ac0b-265e-4165-86e9-e0735e6ce313.upstream_rq_5xx_per_nf", 1);

  checkCounter("Universal_Pool_NfUdm.n10d.2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_total_per_nf", 1);
  checkCounter("Universal_Pool_NfUdm.n10d.2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("Universal_Pool_NfUdm.n10d.2ec8ac0b-265e-4165-86e9-e0735e6ce312.upstream_rq_5xx_per_nf", 1);

  checkCounter("Pool_NfUdm.n10d.2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_total_per_nf", 2);
  checkCounter("Pool_NfUdm.n10d.2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_after_retry_per_nf", 1);
  checkCounter("Pool_NfUdm.n10d.2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_5xx_per_nf", 2);

  checkCounter("Pool_NfUdm.n10d.2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 1);
  checkCounter("Pool_NfUdm.n10d.2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("Pool_NfUdm.n10d.2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 1);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, LastResortRR) {
  std::string aggregate_cluster = "chf_primary#!_#LRP:chf_lr_pool#!_#aggr:";
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
  };
  std::string last_resort_cluster = "chf_lr_pool";

  std::vector<std::map<std::string, std::string>> last_resort_hosts = {

      {{"hostname", "lr01.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "lr02.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
  };

  std::vector<uint64_t> retry_params{3, 0, 1, 2};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {1}, {2}, {3}};
  auto rb = RoutingBehaviourWrapper();
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params);
  testNfPoolReselection(aggregate_cluster, rb, expected_reselects);
  
  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));
  
  checkCounters("upstream_rq_total_per_nf", 4);
  checkCounters("upstream_rq_after_reselect_per_nf", 3);
  checkCounters("upstream_rq_5xx_per_nf", 4);
 
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce310", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce309", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "2ec8ac0b-265e-4165-86e9-e0735e6ce312", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "2ec8ac0b-265e-4165-86e9-e0735e6ce311", "upstream_rq_total_per_nf"}, 1);
  
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce310", "upstream_rq_after_reselect_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "2ec8ac0b-265e-4165-86e9-e0735e6ce312", "upstream_rq_after_reselect_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "2ec8ac0b-265e-4165-86e9-e0735e6ce311", "upstream_rq_after_reselect_per_nf"}, 1);
  
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce310", "upstream_rq_5xx_per_nf"}, 1);
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce309", "upstream_rq_5xx_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "2ec8ac0b-265e-4165-86e9-e0735e6ce312", "upstream_rq_5xx_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "2ec8ac0b-265e-4165-86e9-e0735e6ce311", "upstream_rq_5xx_per_nf"}, 1);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, LastResortRRJumpPrio) {
  std::string aggregate_cluster = "chf_primary#!_#LRP:chf_lr_pool#!_#aggr:";
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "chf3.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
      {{"hostname", "chf4.ericsson.se:443"}, {"priority", "3"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce313"}},
  };
  std::string last_resort_cluster = "chf_lr_pool";

  std::vector<std::map<std::string, std::string>> last_resort_hosts = {

      {{"hostname", "lr01.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce314"}},
      {{"hostname", "lr02.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce315"}},
  };

  std::vector<uint64_t> retry_params{4, 0, 2, 2};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {1, 2}, {1, 2}, {5, 6}, {5, 6}};
  auto rb = RoutingBehaviourWrapper();
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params);
  testNfPoolReselection(aggregate_cluster, rb, expected_reselects);
  
  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 5);
  checkCounters("upstream_rq_after_reselect_per_nf", 4);
  checkCounters("upstream_rq_5xx_per_nf", 5);
 
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce311", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce310", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce309", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "2ec8ac0b-265e-4165-86e9-e0735e6ce315", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "2ec8ac0b-265e-4165-86e9-e0735e6ce314", "upstream_rq_total_per_nf"}, 1);
  
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce311", "upstream_rq_after_reselect_per_nf"}, 1);
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce310", "upstream_rq_after_reselect_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "2ec8ac0b-265e-4165-86e9-e0735e6ce315", "upstream_rq_after_reselect_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "2ec8ac0b-265e-4165-86e9-e0735e6ce314", "upstream_rq_after_reselect_per_nf"}, 1);
  
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce311", "upstream_rq_5xx_per_nf"}, 1);
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce310", "upstream_rq_5xx_per_nf"}, 1);
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce309", "upstream_rq_5xx_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "2ec8ac0b-265e-4165-86e9-e0735e6ce315", "upstream_rq_5xx_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "2ec8ac0b-265e-4165-86e9-e0735e6ce314", "upstream_rq_5xx_per_nf"}, 1);

}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, CtFailedTc) {
  std::string aggregate_cluster = "chf_primary#!_#LRP:chf_lr_pool#!_#aggr:";
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
  };
  std::string last_resort_cluster = "chf_lr_pool";

  std::vector<std::map<std::string, std::string>> last_resort_hosts = {

      {{"hostname", "lr01.ericsson.se:443"}, {"priority", "0"}},
  };

  std::vector<uint64_t> retry_params{1, 0, 0, 1};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0, 1, 2}, {3}};
  auto rb = RoutingBehaviourWrapper();
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params);
  testNfPoolReselection(aggregate_cluster, rb, expected_reselects);
  
  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 1);
  checkCounters("upstream_rq_5xx_per_nf", 1);

  checkCountersByTags({"chf_primary", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"chf_primary", "upstream_rq_5xx_per_nf"}, 1);
}

// preferred host from primary cluster, don't fallback to last resort cluster since no
// last resort reselects are configured
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, LastResortPreferred1) {
  std::string aggregate_cluster = "chf_primary#!_#LRP:chf_lr_pool#!_#aggr:";
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
  };
  std::string last_resort_cluster = "chf_lr_pool";

  std::vector<std::map<std::string, std::string>> last_resort_hosts = {

      {{"hostname", "lr01.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
      {{"hostname", "lr02.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
  };

  std::vector<uint64_t> retry_params{4, 2, 2, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{1}, {1}, {1}, {0}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf1.ericsson.se:443");
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params);
  testNfPoolReselection(aggregate_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 4);
  checkCounters("upstream_rq_5xx_per_nf", 4);
  checkCounters("upstream_rq_after_retry_per_nf", 2);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 3);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_after_retry_per_nf", 2);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 3);
  
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 1);
}
// preferred host from primary cluster
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, LastResortPreferred2) {
  std::string aggregate_cluster = "Pool_NfUdm#!_#LRP:Universal_Pool_NfUdm#!_#aggr:";
  std::string primary_cluster = "Pool_NfUdm";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "nfUdm1.mnc.567.mcc.765.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},

  };
  std::string last_resort_cluster = "Universal_Pool_NfUdm";

  std::vector<std::map<std::string, std::string>> last_resort_hosts = {

      {{"hostname", "lr01.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
  };

  std::vector<uint64_t> retry_params{3, 1, 1, 1};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {1}, {3}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "lalalala:443");
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params);
  testNfPoolReselection(aggregate_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 3);
  checkCounters("upstream_rq_5xx_per_nf", 3);
  checkCounters("upstream_rq_after_reselect_per_nf", 2);

  checkCountersByTags({"Universal_Pool_NfUdm", "2ec8ac0b-265e-4165-86e9-e0735e6ce312", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"Universal_Pool_NfUdm", "2ec8ac0b-265e-4165-86e9-e0735e6ce312", "upstream_rq_after_reselect_per_nf"}, 1);
  checkCountersByTags({"Universal_Pool_NfUdm", "2ec8ac0b-265e-4165-86e9-e0735e6ce312", "upstream_rq_5xx_per_nf"}, 1);
  
  checkCountersByTags({"Pool_NfUdm", "2ec8ac0b-265e-4165-86e9-e0735e6ce310", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"Pool_NfUdm", "2ec8ac0b-265e-4165-86e9-e0735e6ce310", "upstream_rq_after_reselect_per_nf"}, 1);
  checkCountersByTags({"Pool_NfUdm", "2ec8ac0b-265e-4165-86e9-e0735e6ce310", "upstream_rq_5xx_per_nf"}, 1);
  
  checkCountersByTags({"Pool_NfUdm", "2ec8ac0b-265e-4165-86e9-e0735e6ce309", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"Pool_NfUdm", "2ec8ac0b-265e-4165-86e9-e0735e6ce309", "upstream_rq_5xx_per_nf"}, 1);
}

TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, LastResortPreferred3) {
  std::string aggregate_cluster = "chf_primary#!_#LRP:chf_lr_pool#!_#aggr:";
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},

  };
  std::string last_resort_cluster = "chf_lr_pool";

  std::vector<std::map<std::string, std::string>> last_resort_hosts = {

      {{"hostname", "lr01.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
      {{"hostname", "lr02.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce313"}},
  };

  std::vector<uint64_t> retry_params{5, 2, 2, 1};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {0}, {0}, {1, 2}, {1, 2}, {3, 4}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params);
  testNfPoolReselection(aggregate_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounters("upstream_rq_total_per_nf", 6);
  checkCounters("upstream_rq_5xx_per_nf", 6);
  checkCounters("upstream_rq_after_reselect_per_nf", 3);
  checkCounters("upstream_rq_after_retry_per_nf", 2);

  //e0735e6ce309 - PREFERRED
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce309", "upstream_rq_total_per_nf"}, 3);
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce309", "upstream_rq_after_retry_per_nf"}, 2);
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce309", "upstream_rq_5xx_per_nf"}, 3);

  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce311", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce311", "upstream_rq_after_reselect_per_nf"}, 1);
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce311", "upstream_rq_5xx_per_nf"}, 1);

  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce310", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce310", "upstream_rq_after_reselect_per_nf"}, 1);
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce310", "upstream_rq_5xx_per_nf"}, 1);

  checkCountersByTags({"chf_lr_pool", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "upstream_rq_after_reselect_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "upstream_rq_5xx_per_nf"}, 1);
}

// do not reselect on primary cluster at all
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, LastResortPreferred4) {
  //"fix falling back to lrp if no reselects are configured after retries"
  std::string aggregate_cluster = "chf_primary#!_#LRP:chf_lr_pool#!_#aggr:";
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},

  };
  std::string last_resort_cluster = "chf_lr_pool";

  std::vector<std::map<std::string, std::string>> last_resort_hosts = {

      {{"hostname", "lr01.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
  };

  std::vector<uint64_t> retry_params{2, 1, 0, 1};

  std::vector<std::vector<uint64_t>> expected_reselects = {{1}, {1}, {3}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf1.ericsson.se:443");
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params);
  testNfPoolReselection(aggregate_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce310", "upstream_rq_total_per_nf"}, 2);
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce310", "upstream_rq_after_retry_per_nf"}, 1);
  checkCountersByTags({"chf_primary", "2ec8ac0b-265e-4165-86e9-e0735e6ce310", "upstream_rq_5xx_per_nf"}, 2);

  checkCountersByTags({"chf_lr_pool", "2ec8ac0b-265e-4165-86e9-e0735e6ce312", "upstream_rq_total_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "2ec8ac0b-265e-4165-86e9-e0735e6ce312", "upstream_rq_after_reselect_per_nf"}, 1);
  checkCountersByTags({"chf_lr_pool", "2ec8ac0b-265e-4165-86e9-e0735e6ce312", "upstream_rq_5xx_per_nf"}, 1);

  checkCounters("upstream_rq_after_reselect_per_nf", 1);
  checkCounters("upstream_rq_total_per_nf", 3);

}

// invalid tar so we fallback to RR without going to the LR cluster since no lrp reselects are
// configred
// many reselects, validate we don't retry into the lrp
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, LastResortPreferredInvalidTar1) {
  std::string aggregate_cluster = "chf_primary#!_#LRP:chf_lr_pool#!_#aggr:";
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "2"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},

  };
  std::string last_resort_cluster = "chf_lr_pool";

  std::vector<std::map<std::string, std::string>> last_resort_hosts = {

      {{"hostname", "lr01.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce312"}},
      {{"hostname", "lr02.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce313"}},
  };

  std::vector<uint64_t> retry_params{6, 2, 4, 0};

  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {1}, {2}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "doken13:443");
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params);
  testNfPoolReselection(aggregate_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce311.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_after_reselect_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce310.upstream_rq_5xx_per_nf", 1);

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 1);
}
// invalid tar so we fallback to RR without going to the LR cluster since no lrp reselects are
// configred
// TODO: Discuss what the desired result is here as it's a  conrner case
// Could be fixed by invoking determinePrioLoad() for the first try
TEST_P(EricProxyFilterNfPoolReselectionOverrideHostTest, LastResortPreferredInvalidTar2) {
  // // GTEST_SKIP();
  std::string aggregate_cluster = "chf_primary#!_#LRP:chf_lr_pool#!_#aggr:";
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce309"}},
  };
  std::string last_resort_cluster = "chf_lr_pool";

  std::vector<std::map<std::string, std::string>> last_resort_hosts = {

      {{"hostname", "lr01.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce310"}},
      {{"hostname", "lr02.ericsson.se:443"}, {"priority", "0"}, {"nf_instance_id", "2ec8ac0b-265e-4165-86e9-e0735e6ce311"}},
  };

  std::vector<uint64_t> retry_params{6, 2, 4, 0};

  // std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {1, 2}};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0}};

  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "doken13:443");
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params);
  testNfPoolReselection(aggregate_cluster, rb, expected_reselects);

  ENVOY_LOG(trace, getCounters(test_server_->counters(), {"cluster.", "_per_nf"}));

  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_total_per_nf", 1);
  checkCounter("2ec8ac0b-265e-4165-86e9-e0735e6ce309.upstream_rq_5xx_per_nf", 1);
}
//------------------------------------------------------------------------
//-------------END TEST SUITES---------------------
//------------------------------------------------------------------------

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
