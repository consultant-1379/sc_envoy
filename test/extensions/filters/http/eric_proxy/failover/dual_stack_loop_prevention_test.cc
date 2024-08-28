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

class EricProxyDualStackLoopPreventionIntegrationTest : public EricProxyFailoverTestBase {
public:
EricProxyDualStackLoopPreventionIntegrationTest() : EricProxyFailoverTestBase(false,true){};

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
                        const std::vector<std::string> via_hdrs = {},
                        bool pref_host_retries_validate = true) {

  
    Http::TestRequestHeaderMapImpl headers {
        {":scheme","http"},
        {":method", "GET"},
        {":path","/"},
        {":authority","scp.ericsson.se"},
      };
    if(!via_hdrs.empty()){
      for(const auto & via_hdr : via_hdrs){
        headers.addCopy("via",via_hdr);
      }
    }

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
// Descriptions written from point of view of v4 test, when in v6 testing mode 
// pref_ip_fam = v6 then reinterpret the scenarios accordingly

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyDualStackLoopPreventionIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));


//------------------------------------------------------------------------
//-------------  Direct Preferred Routing --------------------------------
//------------------------------------------------------------------------

// Sanity check if default load-balancer behavior is ok even when there is 
// no loop to block
TEST_P(EricProxyDualStackLoopPreventionIntegrationTest, TestPreferred1) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "2"}}  // 3 fake ipv6
  };
  
  std::vector<uint64_t> retry_params{5, 2, 3, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{1,3},{1,3},{1,3},{0},{2}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf1.ericsson.se:443");
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "true";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      endpoint_policy:  
        preferred_ip_family: '{pref_ip_fam}'
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{1,3},2,{},true);
}

// Sanity check if default load-balancer behavior is ok even when there is 
// no loop to block, indeterminancy of {1,3} is due to test-scope limitations
// not functional faults
TEST_P(EricProxyDualStackLoopPreventionIntegrationTest, TestPreferred2) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "chf1.ericsson.se:443"}, {"priority", "2"}}  // 3 fake ipv6
  };
  
  std::vector<uint64_t> retry_params{5, 2, 3, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{1,3},{1,3},{1,3},{0},{2,1},{3,2,1}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf1.ericsson.se:443");
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "false";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      endpoint_policy:  
        preferred_ip_family: '{pref_ip_fam}'
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{1,3},2,{},false);
}


//------------------------------------------------------------------------
//-------------  Indirect Preferred Routing ------------------------------
//------------------------------------------------------------------------

// Indirect Routing
// Via header not having entry of target proxy also distributing
// retries for the middle proxy - not loop prevented for preferred
// host , however scp2 is loop prevented.
TEST_P(EricProxyDualStackLoopPreventionIntegrationTest, TestIndirectPreferred1) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "2"}}  // 3 fake ipv6
  };

  std::string via_hdr =
      "1.1 SCP-scp2.ericsson.se:443, HTTP/2.0 scp3.ericsson.se:443";
  std::vector<uint64_t> retry_params{5, 2, 3, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{1,3}, {1,3}, {1,3},{0}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "true";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf0.ericsson.se:443: 
      - fqdn: 'scp1.ericsson.se:443'
        ip: '10.10.10.1:443'
        ip_family: 'IPv4' 
      - fqdn: 'scp1.ericsson.se:443'
        ip: '[2001::aab]:443'
        ip_family: 'IPv6' 
      chf3.ericsson.se:443:
      - fqdn: 'scp2.ericsson.se:443'
        ip: '10.10.10.3:443'
        ip_family: 'IPv4'
      endpoint_policy:  
        preferred_ip_family: '{pref_ip_fam}'
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{1,3},2,{via_hdr},true);
}


// Indirect Routing
// Via header having entry of target proxy-  loop prevented for preferred
// host. So effectively a garbage TaR or
// override host not set
TEST_P(EricProxyDualStackLoopPreventionIntegrationTest, TestIndirectPreferred2) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "2"}}  // 3 fake ipv6
  };

  std::string via_hdr =
      "HTTP/2.0 SCP-scp1.ericsson.se:443";
  std::vector<uint64_t> retry_params{5, 2, 3, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {2}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "true";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf0.ericsson.se:443:
      - fqdn: 'scp1.ericsson.se:443'
        ip: '10.10.10.1:443'
        ip_family: 'IPv4'
      - fqdn: 'scp1.ericsson.se:443'
        ip: '[2001::aab]:443'
        ip_family: 'IPv6'
      chf3.ericsson.se:443:
      - fqdn: 'scp2.ericsson.se:443'
        ip: '10.10.10.3:443'
        ip_family: 'IPv4'
      endpoint_policy:
        preferred_ip_family: '{pref_ip_fam}'
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{0},0,{via_hdr},false);
}

// Indirect Routing
// Via header not having entry of target proxy - retries are not distributed 
// to diff endpoints of the proxy, scp2 is loop prevented, here because we cannot 
// simulate hosts of different IP family at same time we have first try and retries 
// indeterministic between host1 and host3 , however in practice it would be
// deterministic and first try and retry would be at host1.
TEST_P(EricProxyDualStackLoopPreventionIntegrationTest, TestIndirectPreferred3) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "2"}}  // 3 fake ipv6
  };

  std::string via_hdr =
      "HTTP/2.0 SCP-scp2.ericsson.se:443";
  std::vector<uint64_t> retry_params{5, 2, 3, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{1,3}, {1,3},{1,3} ,{0} ,{1,3}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "false";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf0.ericsson.se:443:
      - fqdn: 'scp1.ericsson.se:443'
        ip: '10.10.10.1:443'
        ip_family: 'IPv4'
      - fqdn: 'scp1.ericsson.se:443'
        ip: '[2001::aab]:443'
        ip_family: 'IPv6'
      chf3.ericsson.se:443:
      - fqdn: 'scp2.ericsson.se:443'
        ip: '10.10.10.3:443'
        ip_family: 'IPv4'
      endpoint_policy:
        preferred_ip_family: '{pref_ip_fam}'
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{1,3},2,{via_hdr},false);
}

// Indirect Routing
// Via header not having entry of target proxy - retries are not distributed 
// to diff endpoints of the proxy, scp2 is loop prevented, 
// first attempt of selection takes scp9 but since thats absent from hostmap
// it will try to find IP which will also fail so it will pick a proxy from
// other IP family which is scp1 but it has one endpoints in hostmap, which
// is pretend v6 and its the host thats succesfully selected 
TEST_P(EricProxyDualStackLoopPreventionIntegrationTest, TestIndirectPreferred4) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp8.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "2"}}  // 3 fake ipv6
  };

  std::string via_hdr =
      "HTTP/2.0 SCP-scp2.ericsson.se:443";
  std::vector<uint64_t> retry_params{5, 2, 3, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{3},{3},{3},{0},{1}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::PREFERRED, "chf0.ericsson.se:443");
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "false";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf0.ericsson.se:443:
      - fqdn: 'scp9.ericsson.se:443'
        ip: '10.10.10.1:443'
        ip_family: 'IPv4'
      - fqdn: 'scp1.ericsson.se:443'
        ip: '[2001::aab]:443'
        ip_family: 'IPv6'
      chf3.ericsson.se:443:
      - fqdn: 'scp2.ericsson.se:443'
        ip: '10.10.10.3:443'
        ip_family: 'IPv4'
      endpoint_policy:
        preferred_ip_family: '{pref_ip_fam}'
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{3},2,{via_hdr},false);
}


//------------------------------------------------------------------------
//----------------------- Indirect Strict Routing ------------------------
//------------------------------------------------------------------------


// Indirect Routing
// Via header not having entry of target proxy also distributing
// retries for the middle proxy - not loop prevented for preferred
// host , however scp2 is loop prevented.
TEST_P(EricProxyDualStackLoopPreventionIntegrationTest, TestIndirectStrict1) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "2"}}  // 3 fake ipv6
  };

  std::string via_hdr =
      "1.1 SCP-scp2.ericsson.se:443, HTTP/2.0 scp3.ericsson.se:443";
  std::vector<uint64_t> retry_params{2, 2, 0, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{1,3}, {1,3}, {1,3}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::STRICT, "chf0.ericsson.se:443");
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "true";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf0.ericsson.se:443: 
      - fqdn: 'scp1.ericsson.se:443'
        ip: '10.10.10.1:443'
        ip_family: 'IPv4' 
      - fqdn: 'scp1.ericsson.se:443'
        ip: '[2001::aab]:443'
        ip_family: 'IPv6' 
      chf3.ericsson.se:443:
      - fqdn: 'scp2.ericsson.se:443'
        ip: '10.10.10.3:443'
        ip_family: 'IPv4'
      endpoint_policy:  
        preferred_ip_family: '{pref_ip_fam}'
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{1,3},2,{via_hdr},true);
}


// Indirect Routing
// Via header having entry of target proxy-  loop prevented for preferred
// host. So effectively a garbage TaR or
// override host not set, so a local reply
TEST_P(EricProxyDualStackLoopPreventionIntegrationTest, TestIndirectStrict2) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "2"}}  // 3 fake ipv6
  };

  std::string via_hdr =
      "HTTP/2.0 SCP-scp1.ericsson.se:443";
  std::vector<uint64_t> retry_params{2, 2, 0, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::STRICT, "chf0.ericsson.se:443");
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "true";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf0.ericsson.se:443:
      - fqdn: 'scp1.ericsson.se:443'
        ip: '10.10.10.1:443'
        ip_family: 'IPv4'
      - fqdn: 'scp1.ericsson.se:443'
        ip: '[2001::aab]:443'
        ip_family: 'IPv6'
      chf3.ericsson.se:443:
      - fqdn: 'scp2.ericsson.se:443'
        ip: '10.10.10.3:443'
        ip_family: 'IPv4'
      endpoint_policy:
        preferred_ip_family: '{pref_ip_fam}'
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{0},0,{via_hdr},false);
}

// Indirect Routing
// Via header not having entry of target proxy - retries are not distributed 
// to diff endpoints of the proxy, scp2 is loop prevented, here because we cannot 
// simulate hosts of different IP family at same time we have first try and retries 
// indeterministic between host1 and host3 , however in practice it would be
// deterministic and first try and retry would be at host1.
TEST_P(EricProxyDualStackLoopPreventionIntegrationTest, TestIndirectStrict3) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "2"}}  // 3 fake ipv6
  };

  std::string via_hdr =
      "HTTP/2.0 SCP-scp2.ericsson.se:443";
  std::vector<uint64_t> retry_params{2, 2, 0, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{1,3},{1,3},{1,3}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::STRICT, "chf0.ericsson.se:443");
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "false";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf0.ericsson.se:443:
      - fqdn: 'scp1.ericsson.se:443'
        ip: '10.10.10.1:443'
        ip_family: 'IPv4'
      - fqdn: 'scp1.ericsson.se:443'
        ip: '[2001::aab]:443'
        ip_family: 'IPv6'
      chf3.ericsson.se:443:
      - fqdn: 'scp2.ericsson.se:443'
        ip: '10.10.10.3:443'
        ip_family: 'IPv4'
      endpoint_policy:
        preferred_ip_family: '{pref_ip_fam}'
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{1,3},2,{via_hdr},false);
}

// Indirect Routing
// Via header not having entry of target proxy - retries are not distributed 
// to diff endpoints of the proxy, scp2 is loop prevented, 
// first attempt of selection takes scp9 but since thats absent from hostmap
// it will try to find IP which will also fail so it will pick a proxy from
// other IP family which is scp1 but it has one endpoints in hostmap, which
// is pretend v6 and its the host thats succesfully selected 
TEST_P(EricProxyDualStackLoopPreventionIntegrationTest, TestIndirectStrict4) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp8.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "2"}}  // 3 fake ipv6
  };

  std::string via_hdr =
      "HTTP/2.0 SCP-scp2.ericsson.se:443";
  std::vector<uint64_t> retry_params{2, 2, 0, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{3},{3},{3}};
  auto rb = RoutingBehaviourWrapper(RoutingBehaviour::STRICT, "chf0.ericsson.se:443");
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "false";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf0.ericsson.se:443:
      - fqdn: 'scp9.ericsson.se:443'
        ip: '10.10.10.1:443'
        ip_family: 'IPv4'
      - fqdn: 'scp1.ericsson.se:443'
        ip: '[2001::aab]:443'
        ip_family: 'IPv6'
      chf3.ericsson.se:443:
      - fqdn: 'scp2.ericsson.se:443'
        ip: '10.10.10.3:443'
        ip_family: 'IPv4'
      endpoint_policy:
        preferred_ip_family: '{pref_ip_fam}'
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{3},2,{via_hdr},false);
}


//------------------------------------------------------------------------
//-------------------  Indirect Round Robin ------------------------------
//------------------------------------------------------------------------

// Indirect Routing
// scp2 is loop prevented.
TEST_P(EricProxyDualStackLoopPreventionIntegrationTest, TestIndirectRR1) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "2"}}  // 3 fake ipv6
  };

  std::string via_hdr =
      "1.1 SCP-scp2.ericsson.se:443, HTTP/2.0 scp3.ericsson.se:443";
  std::vector<uint64_t> retry_params{5, 0, 5, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {1}, {3}};
  auto rb = RoutingBehaviourWrapper();
  // shouldnt influence selection as its fully done by Load Balancer
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "false";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf0.ericsson.se:443: 
      - fqdn: 'scp1.ericsson.se:443'
        ip: '10.10.10.1:443'
        ip_family: 'IPv4' 
      - fqdn: 'scp1.ericsson.se:443'
        ip: '[2001::aab]:443'
        ip_family: 'IPv6' 
      chf3.ericsson.se:443:
      - fqdn: 'scp2.ericsson.se:443'
        ip: '10.10.10.3:443'
        ip_family: 'IPv4'
      endpoint_policy:  
        preferred_ip_family: '{pref_ip_fam}'
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{0},0,{via_hdr},false);
}


// Indirect Routing

TEST_P(EricProxyDualStackLoopPreventionIntegrationTest, TestIndirectRR2) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "2"}}  // 3 fake ipv6
  };

  std::string via_hdr =
      "HTTP/2.0 SCP-scp1.ericsson.se:443";
  std::vector<uint64_t> retry_params{5, 0, 5, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0}, {2}};
  auto rb = RoutingBehaviourWrapper();
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "true";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf0.ericsson.se:443:
      - fqdn: 'scp1.ericsson.se:443'
        ip: '10.10.10.1:443'
        ip_family: 'IPv4'
      - fqdn: 'scp1.ericsson.se:443'
        ip: '[2001::aab]:443'
        ip_family: 'IPv6'
      chf3.ericsson.se:443:
      - fqdn: 'scp2.ericsson.se:443'
        ip: '10.10.10.3:443'
        ip_family: 'IPv4'
      endpoint_policy:
        preferred_ip_family: '{pref_ip_fam}'
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{0},0,{via_hdr},false);
}

// Indirect Routing
TEST_P(EricProxyDualStackLoopPreventionIntegrationTest, TestIndirectRR3) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "2"}}  // 3 fake ipv6
  };

  std::string via_hdr =
      "HTTP/2.0 scp2.ericsson.se:443";
  std::vector<uint64_t> retry_params{5,0,5,0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0},{1},{3}};
  auto rb = RoutingBehaviourWrapper();
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "false";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf0.ericsson.se:443:
      - fqdn: 'scp1.ericsson.se:443'
        ip: '10.10.10.1:443'
        ip_family: 'IPv4'
      - fqdn: 'scp1.ericsson.se:443'
        ip: '[2001::aab]:443'
        ip_family: 'IPv6'
      chf3.ericsson.se:443:
      - fqdn: 'scp2.ericsson.se:443'
        ip: '10.10.10.3:443'
        ip_family: 'IPv4'
      endpoint_policy:
        preferred_ip_family: '{pref_ip_fam}'
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{0},0,{via_hdr},false);
}

// Indirect Routing
TEST_P(EricProxyDualStackLoopPreventionIntegrationTest, TestIndirectRR4) {
  std::string primary_cluster = "chf_primary";
  std::vector<std::map<std::string, std::string>> primary_hosts = {
      {{"hostname", "chf2.ericsson.se:443"}, {"priority", "0"}}, // 0
      {{"hostname", "scp8.ericsson.se:443"}, {"priority", "1"}}, // 1
      {{"hostname", "scp2.ericsson.se:443"}, {"priority", "1"}}, // 2
      {{"hostname", "scp1.ericsson.se:443"}, {"priority", "2"}}  // 3 fake ipv6
  };

  std::string via_hdr =
      "HTTP/2.0 SCP-scp2.ericsson.se:443";
  std::vector<uint64_t> retry_params{5, 0, 5, 0};
  std::vector<std::vector<uint64_t>> expected_reselects = {{0},{1},{3}};
  auto rb = RoutingBehaviourWrapper();
  const auto& preferred_ip_fam = getPrefIpFamFromIpVersions();
  std::string pref_host_retry = "false";
  std::string cluster_metadata = fmt::format(R"EOF(
metadata:
  filter_metadata:
    envoy.eric_proxy.cluster:
      chf0.ericsson.se:443:
      - fqdn: 'scp9.ericsson.se:443'
        ip: '10.10.10.1:443'
        ip_family: 'IPv4'
      - fqdn: 'scp1.ericsson.se:443'
        ip: '[2001::aab]:443'
        ip_family: 'IPv6'
      chf3.ericsson.se:443:
      - fqdn: 'scp2.ericsson.se:443'
        ip: '10.10.10.3:443'
        ip_family: 'IPv4'
      endpoint_policy:
        preferred_ip_family: '{pref_ip_fam}'
        preferred_host_retry_multiple_address: '{pref_retry_address}'
)EOF","pref_ip_fam"_a = preferred_ip_fam, "pref_retry_address"_a = pref_host_retry);
  initConfig(primary_cluster, primary_hosts, rb, retry_params,cluster_metadata);
  testDualStackRetryOptions(primary_cluster, rb, expected_reselects,{0},0,{via_hdr},false);
}


} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy