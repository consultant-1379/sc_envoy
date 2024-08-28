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

class EricProxyDualStackIntegrationTest : public EricProxyFailoverTestBase {
public:
EricProxyDualStackIntegrationTest() : EricProxyFailoverTestBase(false,false) {};

std::string getPrefIpFamFromIpVersions()
{
  switch(GetParam()){
    case Network::Address::IpVersion::v4:
      return "IPv4";
    case Network::Address::IpVersion::v6:
      return "IPv6";
  }
}

void testDualStackRetryOptions(std::string target_cluster, RoutingBehaviourWrapper rb,
                        const std::vector<std::vector<uint64_t>> exp_host_list,
                        std::vector<uint32_t> exp_preferred_host_retry_indices,
                        const uint32_t preferred_host_retries,
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

    if(exp_host_list.empty()){
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
    uint32_t count = 0;
    for (const auto& per_try_indx : exp_host_list) {

      auto idx = waitForNextUpstreamRequest(per_try_indx);
      if(idx.has_value() && rb.preferredHost().has_value() && count < preferred_host_retries+1)
      {
        retried_host_indices.push_back(exp_host_list.at(0).at(*idx));
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

    // ENVOY_LOG(debug, "{}", fmt::format("tried hosts?->{}\n", tried_hosts));
    // Verify downstream response

    // Wait for the response and close the fake upstream connection
    ASSERT_TRUE(response->waitForEndStream());
    // Create a unique vector of retried indices
    // and check if retry across multiple preferred host endpoints work
    if(rb.preferredHost().has_value() && pref_host_retries_validate && preferred_host_retries >0) {
      sort(retried_host_indices.begin(),retried_host_indices.end());
      retried_host_indices.erase(unique(retried_host_indices.begin(), retried_host_indices.end()),
                                    retried_host_indices.end());
      sort(exp_preferred_host_retry_indices.begin(),exp_preferred_host_retry_indices.end());
      EXPECT_EQ(retried_host_indices.size(),exp_preferred_host_retry_indices.size());
      EXPECT_TRUE(retried_host_indices == exp_preferred_host_retry_indices);
    } else if(!pref_host_retries_validate && preferred_host_retries > 0) {
      // pref_host_retries is disabled, so retried_host_indices should only have one unique entry
      // and it should be contained in exp_pref_host_retry_indices
      sort(retried_host_indices.begin(),retried_host_indices.end());
      retried_host_indices.erase(unique(retried_host_indices.begin(), retried_host_indices.end()),
                                    retried_host_indices.end());
      EXPECT_TRUE(retried_host_indices.size() == 1);
      const auto it = std::find(exp_preferred_host_retry_indices.begin(),exp_preferred_host_retry_indices.end(),
                  retried_host_indices.at(0));
      EXPECT_TRUE(it != exp_preferred_host_retry_indices.end());
    }

    // ASSERT_TRUE(fake_upstream_connection_->close());

    EXPECT_THAT(response->headers(), Http::HeaderValueOf(":status", "500"));
    std::replace(target_cluster.begin(), target_cluster.end(), ':', '_');
    // Check if retry
    EXPECT_EQ(
        1, test_server_->counter("cluster." + target_cluster + ".upstream_rq_retry_limit_exceeded")
               ->value());
    EXPECT_EQ(exp_host_list.size() - 1,
              test_server_->counter("cluster." + target_cluster + ".upstream_rq_retry")->value());

    codec_client_->close();

  }

};


//------------------------------------------------------------------------
//-------------BEGIN TEST SUITES------------------------------------------
//------------------------------------------------------------------------

// Assumption is that a dual-stack producer would be a server with two endpoints
// listening on same port and one IPv4 + one IPv6 address. This is because if the 
// producer has to be truly dual stack it should be accessible by the consumer with same
// fqdn:port , for example if UDM has v4 at 10.0.0.1:80 and v6 at [2001::99]:81 and say 
// fqdn.example.com resolves as 10.0.0.1 and [2001::99], then
// when NF Consumer tries to contact UDM it would need to pick fqdn.example.com:80 if its a
// v4 client and fqdn.example.com:81 if its av6 client which is not IP family agnostic.
 
INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyDualStackIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

//------------------------------------------------------------------------
//----------------------- Strict Routing ---------------------------------
//------------------------------------------------------------------------

//Strict Routing
TEST_P(EricProxyDualStackIntegrationTest, TestStrict1) {

  std::string primary_cluster = "chf_primary";
 
  // IPFam key was used for some experiments with setting up v4+v6 fake_upstream servers
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}};

  std::vector<uint64_t> retry_params{3, 2, 0, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {0}, {0}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::STRICT, "chf0.ericsson.se:443");
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  bool pref_host_retry = true;
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      endpoint_policy:
        preferred_ip_family: {pref_ip_fam}
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{0},2);

}

// Preferred host with 2 endpoints
// Preferred host has two endpoints and retries are distributed across 2 endpoints
TEST_P(EricProxyDualStackIntegrationTest, TestStrict2) {

  std::string primary_cluster = "chf_primary";
 
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "1"}}, 
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}};

  std::vector<uint64_t> retry_params{3, 2, 0, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0,1}, {0,1}, {0,1}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::STRICT, "chf0.ericsson.se:443");
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
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{0,1},2);

}


// Preferred host with 1 endpoint after failing on preferred host 
// attempts highest prio host of cluster
TEST_P(EricProxyDualStackIntegrationTest, TestStrict3) {

  std::string primary_cluster = "chf_primary";
 
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}}, 
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}
      };

  std::vector<uint64_t> retry_params{3, 2, 0, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{2,3}, {2,3}, {2,3}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::STRICT, "chf1.ericsson.se:443");
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
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{2,3},2);

}

// Preferred host with 2 endpoints
// Preferred host has two endpoints and retries are not distributed
TEST_P(EricProxyDualStackIntegrationTest, TestStrict4) {

  std::string primary_cluster = "chf_primary";
 
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "1"}}, 
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}};

  std::vector<uint64_t> retry_params{3, 2, 0, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0,1}, {0,1}, {0,1}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::STRICT, "chf0.ericsson.se:443");
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
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{0,1},2,false);

}


// Preferred host with 1 endpoint after failing on preferred host 
// attempts highest prio host of cluster
TEST_P(EricProxyDualStackIntegrationTest, TestStrict5) {

  std::string primary_cluster = "chf_primary";
 
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}}, 
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}
      };

  std::vector<uint64_t> retry_params{3, 2, 0, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{2,3}, {2,3}, {2,3}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::STRICT, "chf1.ericsson.se:443");
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
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{2,3},2,false);

}

//------------------------------------------------------------------------
//-------------------- TaR not present in hostmap ------------------------
//------------------------------------------------------------------------
// Invalid TaR

// Check Preferred host with garbage TaR
// There should be 1 try and 1 reselect to host in RR fashion.
// Verify that retries are ignored
TEST_P(EricProxyDualStackIntegrationTest, TestInvalidTaR1) {

  std::string primary_cluster = "chf_primary";
 
  // IPFam key was used for some experiments with setting up v4+v6 fake_upstream servers
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}};

  std::vector<uint64_t> retry_params{3, 2, 1, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0},{1,2}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "dchf0.ericsson.se:443");
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
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{0},0,false);

}

// Similar to previous but with more reselects than available host
// Preforming 1 try and 2 reselect in RR fashion although four reselections
// are available we stop here
TEST_P(EricProxyDualStackIntegrationTest, TestInvalidTaR2) {

  std::string primary_cluster = "chf_primary";
 
  // IPFam key was used for some experiments with setting up v4+v6 fake_upstream servers
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}}
      
      ;

  std::vector<uint64_t> retry_params{5, 1, 4, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0},{1,2},{1,2}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "dchf0.ericsson.se:443");
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
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{0},0,false);

}

//------------------------------------------------------------------------
//----------------------- Preferred Host ---------------------------------
//------------------------------------------------------------------------

// Check Pref host with aggr pool

TEST_P(EricProxyDualStackIntegrationTest, TestPreferred_aggr) {

  std::string primary_cluster = "chf_primary";
  std::string aggregate_cluster = "chf_primary#!_#LRP:chf_lr_pool#!_#aggr:";
  std::string last_resort_cluster = "chf_lr_pool";
 
  // IPFam key was used for some experiments with setting up v4+v6 fake_upstream servers
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "0"}}};
  std::vector<std::map<std::string, std::string>> last_resort_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}}};

  std::vector<uint64_t> retry_params{6, 1, 2, 3};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0,1}, {0,1}, {2}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf1.ericsson.se:443");
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
  // initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  initConfig(aggregate_cluster, primary_cluster, primary_hosts, last_resort_cluster,
             last_resort_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(aggregate_cluster, rb, expected_reselects,{0,1},2,true);

}


// Check Preferred Host
// Preferred host having one endpoint and failover host having two with one being 
// chosen in RR . This is just to verify default behavior works fine
// TODO : Fails when loop prevention is on because priority load is computed incorrectly
TEST_P(EricProxyDualStackIntegrationTest, TestPreferred1) {

  std::string primary_cluster = "chf_primary";
 
  // IPFam key was used for some experiments with setting up v4+v6 fake_upstream servers
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}};

  std::vector<uint64_t> retry_params{3, 2, 1, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {0}, {0}, {1,2}};
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
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{0},2,false);

}

// Preferred host with 2 endpoints
// Preferred host has two endpoints and retries are distributed across 2 endpoints
// and 1 failover  reselect
TEST_P(EricProxyDualStackIntegrationTest, TestPreferred2) {

  std::string primary_cluster = "chf_primary";
 
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "1"}}, 
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}};

  std::vector<uint64_t> retry_params{3, 2, 1, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0,1}, {0,1}, {0,1}, {2}};
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
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{0,1},2);

}


// Preferred host with 1 endpoint after failing on preferred host 
// attempts highest prio host of cluster
TEST_P(EricProxyDualStackIntegrationTest, TestPreferred3) {

  std::string primary_cluster = "chf_primary";
 
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}}, 
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}
      };

  std::vector<uint64_t> retry_params{3, 2, 1, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{2,3}, {2,3}, {2,3}, {1}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf1.ericsson.se:443");
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
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{2,3},2);

}


// Preferred host with 2 endpoints
// Preferred host has two endpoints and  2 retries are not distributed 
// and 1 failover  reselect
// Note: here the chf0 at prio 1 is a pretend host of opposite stack 
// but since that type of testing is not possible we add it in v4 list of hosts
// and when we shuffle those it may happen that a host of lower prio is chosen first 
// with same fqdn and port however that is not a problem as realistically
// we might only have 1 v4 and 1 v6 host for one example of fqdn1.com:8080 
// i.e . both v4 and v6 host listen on same port but different IP address and have
// same domain name, and then we will only choose host that corresponds to pref-ip-family
// first and then failover to the host of other ip-family which is the desired behavior
TEST_P(EricProxyDualStackIntegrationTest, TestPreferred4) {
  GTEST_SKIP() << "Indeterministic behavior not respecting priority at times";
  std::string primary_cluster = "chf_primary";
 
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "1"}}, 
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}};

  std::vector<uint64_t> retry_params{3, 2, 1, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0,1}, {0,1}, {0,1}, {0,1,2}};
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
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{0,1},2,false);

}


// Preferred host with 1 endpoint after failing on preferred host 
// attempts highest prio host of cluster
TEST_P(EricProxyDualStackIntegrationTest, TestPreferred5) {

  std::string primary_cluster = "chf_primary";
 
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}}, 
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}
      };

  std::vector<uint64_t> retry_params{3, 2, 1, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{2,3}, {2,3}, {2,3}, {1}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf1.ericsson.se:443");
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
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{2,3},2,false);

}

//------------------------------------------------------------------------
//------------------------- Round Robin  ---------------------------------
//------------------------------------------------------------------------

// Round Robin Test cases ( Just for completeness of validation )

TEST_P(EricProxyDualStackIntegrationTest, TestRR1) {

  std::string primary_cluster = "chf_primary";
 
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}}, 
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}},
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}
      };

  std::vector<uint64_t> retry_params{3, 0, 3, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{1}, {0,2,3}, {0,2,3}, {0,2,3}};
  auto rb = RoutingBehaviourWrapper();
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
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{2,3},0,false);

}


// Round Robin of host with 2 endpoints
// num_reselections(4) > number of available hosts in cluster(3)
// so should terminate after 2 failover reselects
TEST_P(EricProxyDualStackIntegrationTest, TestRR2) {

  std::string primary_cluster = "chf_primary";
 
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "0"}},
      {{"hostname", "chf0.ericsson.se:443"}, {"priority", "1"}}, 
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}};

  std::vector<uint64_t> retry_params{4, 0, 4, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {1,2}, {1,2}};
  auto rb = RoutingBehaviourWrapper();
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
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{0,1},0,false);

}


} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy