#include "base_failover.h"
#include <cstdint>
#include <ostream>
#include "fmt/core.h"
#include "fmt/format.h"

// TODO(enaidev): Extend from Pluggable Configurators 
namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

using namespace fmt::literals;

class EricProxyDualStackOutlierIntegrationTest : public EricProxyFailoverTestBase {
public:
EricProxyDualStackOutlierIntegrationTest() : EricProxyFailoverTestBase(true,false) {};

std::string getPrefIpFamFromIpVersions()
{
  switch(GetParam()){
    case Network::Address::IpVersion::v4:
      return "IPv4";
    case Network::Address::IpVersion::v6:
      return "IPv6";
  }
}

using BigVector = std::vector<std::vector<std::vector<uint64_t>>>;

void testDualStackRetryOptions(std::string target_cluster, RoutingBehaviourWrapper rb,
                        const BigVector exp_host_list_per_req,
                        std::vector<std::vector<uint32_t>> exp_preferred_host_retry_indices_per_req,
                        const std::vector<uint32_t> preferred_host_retries_per_req,
                        bool pref_host_retries_validate = true) {

  
    Http::TestRequestHeaderMapImpl headers {
        {":scheme","http"},
        {":method", "GET"},
        {":path","/"},
        {":authority","scp.ericsson.se"},
      };

    // If preferred host set TaR if Opt C or generic Delegated routing

    if(rb.preferredHost()){
        headers.addCopy("3gpp-sbi-target-apiroot",
            fmt::format("https://{}",rb.preferredHost().value()));

    }

    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(headers);
    std::vector<uint32_t> retried_host_indices = {};

    if(exp_host_list_per_req.empty()){
        // Local reply case
        ASSERT_TRUE(response->waitForEndStream());
        EXPECT_THAT(response->headers(),Http::HeaderValueOf(":status","503"));
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
    for(size_t i = 0; i< exp_host_list_per_req.size() ; i++) {
      uint32_t count = 0;
      std::cout << "======================== Sending request "<<i+1<<"=========================" << std::endl;
      for (const auto& per_try_indx : exp_host_list_per_req[i]) {

        auto idx = waitForNextUpstreamRequest(per_try_indx);
        if(idx.has_value() && rb.preferredHost().has_value() && count < preferred_host_retries_per_req[i]+1)
        { ENVOY_LOG(debug,"Index value:{} , exp_host :{}",idx.value(),exp_host_list_per_req[i].at(0)
                                                                        .at(*idx));
          retried_host_indices.push_back(exp_host_list_per_req[i].at(0).at(*idx));
        }
        
        // Send fake 500 status upstream response
        upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "500"}}, true);

        ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
        ASSERT_TRUE(fake_upstream_connection_->close());
        ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
        fake_upstream_connection_.reset();

        // Verify upstream request
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
        EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", target_cluster));
        count ++;
      }

      // Verify downstream response

      // Wait for the response and close the fake upstream connection
      ASSERT_TRUE(response->waitForEndStream());
      // Create a unique vector of retried indices
      // and check if retry across multiple preferred host endpoints work
      if(rb.preferredHost().has_value() && pref_host_retries_validate && preferred_host_retries_per_req[i] >0) {
        sort(retried_host_indices.begin(),retried_host_indices.end());
        retried_host_indices.erase(unique(retried_host_indices.begin(), retried_host_indices.end()),
                                      retried_host_indices.end());
        sort(exp_preferred_host_retry_indices_per_req[i].begin(),
                  exp_preferred_host_retry_indices_per_req[i].end());
        EXPECT_EQ(retried_host_indices.size(),exp_preferred_host_retry_indices_per_req[i].size());
        EXPECT_TRUE(retried_host_indices == exp_preferred_host_retry_indices_per_req[i]);
      } else if(!pref_host_retries_validate && preferred_host_retries_per_req[i] > 0) {
        // pref_host_retries is disabled, so retried_host_indices should only have one unique entry
        // and it should be contained in exp_pref_host_retry_indices
        sort(retried_host_indices.begin(),retried_host_indices.end());
        retried_host_indices.erase(unique(retried_host_indices.begin(), retried_host_indices.end()),
                                      retried_host_indices.end());
        EXPECT_TRUE(retried_host_indices.size() == 1);
        const auto it = std::find(exp_preferred_host_retry_indices_per_req[i].begin(),
                exp_preferred_host_retry_indices_per_req[i].end(),
                    retried_host_indices.at(0));
        EXPECT_TRUE(it != exp_preferred_host_retry_indices_per_req[i].end());
      }

      // ASSERT_TRUE(fake_upstream_connection_->close());

      EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "500"));
      std::replace(target_cluster.begin(), target_cluster.end(), ':', '_');
      // Check if retry
      EXPECT_EQ(
          1, test_server_->counter("cluster." + target_cluster + ".upstream_rq_retry_limit_exceeded")
                ->value());
      EXPECT_EQ(exp_host_list_per_req[i].size() - 1,
                test_server_->counter("cluster." + target_cluster + ".upstream_rq_retry")->value());
      EXPECT_TRUE(response->complete());
      sleep(1);
      std::cout << "========================= Finished request "<<i+1<<"=========================" << std::endl;
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
//-------------BEGIN TEST SUITES------------------------------------------
//------------------------------------------------------------------------


INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyDualStackOutlierIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

// Send one request, retried to all endpoints of pref host and 3 reselects
// Temporary blocking the first endpoint of preferred host after exhausting 
// all the preferred host retries
TEST_P(EricProxyDualStackOutlierIntegrationTest, TestPreferred1) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}}, // 3
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "2"}}  // 4 fake ipv6
  };

  
  std::vector<uint64_t> retry_params{5, 2, 3, 0};
  BigVector expected_reselects = {{{1,4},{1,4},{1,4},{0},{2,3},{3,2}}}; // only one request
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "true";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      endpoint_policy:
        preferred_ip_family: {pref_ip_fam}
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{{1,4}},{2},true);
}

// Send one request, retried to one endpoint of pref host and 3 reselects
// Temporary blocking the chosen endpoint of preferred host before exhausting 
// all the preferred host retries
// Test fails sometimes because of 
// determinePrioLoad sometimes returning [0,93,7] on reselect after {0} entry 
// thereby making 4 a likely candidate for target endpoint Could be an issue ??

TEST_P(EricProxyDualStackOutlierIntegrationTest, TestPreferred2) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}}, // 3
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "2"}}  // 4 fake ipv6
  };

  
  std::vector<uint64_t> retry_params{5, 2, 3, 0};                 
  // it picks 4 because prio load is  [0,93,7] and Lb picks prio 2
  BigVector expected_reselects = {{{1,4},{1,4},{0},{1,2,3,4},{1,2,3,4}}}; // only one request
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "false";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      endpoint_policy:
        preferred_ip_family: {pref_ip_fam}
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{{1,4}},{1},false);
}

// Send two requests both of them do preferred host retries on all 
// available endpoints and get temporary blocked after two consecutive failures
TEST_P(EricProxyDualStackOutlierIntegrationTest, TestPreferred3) {
  GTEST_SKIP();
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}}, // 3
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "2"}}  // 4 fake ipv6
  };

  
  std::vector<uint64_t> retry_params{5, 2, 3, 0};
  BigVector expected_reselects = {{{1,4},{1,4},{0},{1,2,3},{1,2,3}} , // first request
                                      {{},{}}};                       // second request
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "false";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      endpoint_policy:
        preferred_ip_family: {pref_ip_fam}
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{{1,4}},{2},true);
}

// Send one request, retried to all endpoints of pref host and 3 reselects
// Temporary blocking the first endpoint of preferred host after exhausting 
// all the preferred host retries
// Skipped for now as all relevant use cases are tested in the other 3
// tests
TEST_P(EricProxyDualStackOutlierIntegrationTest, TestPreferred4) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}}, // 3
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "2"}}, // 4 fake ipv6
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "3"}}  // 5 fake ipv6
  };

  
  std::vector<uint64_t> retry_params{9, 6, 3, 0};       
                                       //1     //4   //5    //1      //4     //5      //4       
  BigVector expected_reselects = {{{1,4,5},{1,4,5},{1,4,5},{1,4,5},{1,4,5},{1,4,5},
                                                    {0},{2,3},{3,2}}}; // only one request
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "true";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      endpoint_policy:
        preferred_ip_family: {pref_ip_fam}
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{{1,4,5}},{5},true);
}







} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy