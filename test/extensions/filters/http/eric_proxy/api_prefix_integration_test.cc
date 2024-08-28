#include "config_utils/pluggable_configurator.h"
#include "config_utils/endpoint_md_cluster_md_configurator.h"
#include <chrono>
#include <cstdint>


namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

using namespace fmt::literals;

class EricProxyFilterApiPrefixIntegrationTest : public PluggableConfigurator {

public:
    EricProxyFilterApiPrefixIntegrationTest() : 
            PluggableConfigurator(Http::CodecClient::Type::HTTP2,absl::nullopt) {};
    void SetUp() override {}
    void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Common route configuration
  std::string config_common_route = R"EOF(
name: local_route
virtual_hosts:
- name: local_service
  domains: ["*"]
  routes:
  - name: route0
    match:
      prefix: "/"
      headers:
        - name: x-cluster
          string_match:
            exact: {cluster}
    route:
      cluster: {cluster}
      retry_policy:
        retry_on: retriable-status-codes
        retriable_status_codes:
        - 500
        - 501
        - 502
        - 503
        retry_host_predicate:
        - name: envoy.retry_host_predicates.previous_hosts
        host_selection_retry_max_attempts: 3
        num_retries: {num_retries}
        retry_priority:
          name: envoy.retry_priorities.eric_reselect_priorities
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.retry.priority.eric_reselect_priorities.v3.EricReselectPrioritiesConfig
            preferred_host_retries: {num_pref_host_retries}
            failover_reselects: {num_reselects}
            last_resort_reselects: {num_lrp_reselects}
)EOF"; 


    std::string sepp_pr = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  own_internal_port: 80
  own_fqdn: sepp.own_plmn.com
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: route_to_sepp_pool
        condition:
          term_boolean: true
        actions:
        - action_route_to_roaming_partner:
            roaming_partner_name: rp_no_tar
            routing_behaviour: PREFERRED
            preserve_if_indirect: {indirect_header}
  roaming_partners:
    - name: rp_no_tar
      pool_name: {cluster}

)EOF";

    std::string scp_pr = R"EOF(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: scp_router
  node_type: SCP
  own_internal_port: 80
  own_fqdn: scp.own_plmn.com
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: route_to_nf_pool
        condition:
          term_boolean: true
        actions:
          - action_route_to_pool:
              pool_name:
                term_string: {cluster}
              routing_behaviour: PREFERRED
              preserve_if_indirect: {indirect_header}
              preferred_target:
                term_header: 3gpp-sbi-target-apiroot

)EOF";

struct RetryParams {

    uint64_t num_retries_;
    uint64_t num_preferred_host_retries_;
    uint64_t num_failover_reselects_;
    uint64_t num_lrp_reselects_;

};

std::string applyRetryParams(const std::string cluster,const RetryParams retry_params){
    return fmt::format(config_common_route,"cluster"_a = cluster,
                                    "num_retries"_a = retry_params.num_retries_,
                                    "num_pref_host_retries"_a = retry_params.num_preferred_host_retries_,
                                    "num_reselects"_a = retry_params.num_failover_reselects_,
                                    "num_lrp_reselects"_a = retry_params.num_lrp_reselects_);
}

void testDirectRoutingScenarios(const std::string& cluster_name,
                                const RetryParams retry_params,
                                const std::vector<std::string> hostname_per_host,
                                const std::vector<std::vector<std::string>> support_md_per_host,
                                const std::vector<std::string> prefix_per_host,
                                const std::string& filter_config,
                                const std::map<std::string,std::string> request_headers,
                                const std::vector<std::map<std::string,std::string>> response_headers,
                                const std::vector<uint64_t> exp_host_list,
                                const std::vector<std::map<std::string,std::string>> exp_upstream_request_per_host,
                                const std::map<std::string,std::string> exp_downstream_resp) {


    ClusterBuilder cluster = ClusterBuilder().withName(cluster_name);
    uint16_t idx = 0;
    std::for_each( support_md_per_host.begin(),
                    support_md_per_host.end(),
                    [&](const auto& support_md_vector) {
                        prefix_per_host.at(idx).empty() ? 
                        
                        cluster.withEndpoint(EndpointBuilder()
                                                .withHostName(hostname_per_host.at(idx))
                                                .withHostMd({{"support",support_md_vector}})
                                                .withHostScheme(true))
                        :
                        cluster.withEndpoint(EndpointBuilder()
                                                .withHostName(hostname_per_host.at(idx))
                                                .withHostMd({{"support",support_md_vector}},
                                                            {{"prefix",prefix_per_host.at(idx)}})
                                                .withHostScheme(true));
                        idx ++;
                    });
    EndpointMetadataClusterConfigurator cluster_config = 
            EndpointMetadataClusterConfigurator()
                .withClusterBuilder(cluster);
    initConfig(std::vector<std::string>{fmt::format(filter_config,"cluster"_a = cluster_name,
                                                                    "indirect_header"_a = "TARGET_API_ROOT",
                                                                    "node_type"_a = "SCP")},
                        cluster_config,applyRetryParams(cluster_name,retry_params));

    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    Http::TestRequestHeaderMapImpl req_headers;
    std::for_each(request_headers.begin(),
                    request_headers.end(),
                    [&](const auto& it) {
                        req_headers.addCopy(Http::LowerCaseString(it.first),it.second);
                    });
    
    auto response = codec_client_->makeHeaderOnlyRequest(req_headers);
    for(std::size_t i = 0; i < exp_host_list.size(); i++) {
        waitForNextUpstreamRequest(exp_host_list.at(i));
        Http::TestResponseHeaderMapImpl resp_headers;
        std::for_each(response_headers.at(i).begin(),
                        response_headers.at(i).end(),
                        [&](const auto& it) {
                            resp_headers.addCopy(Http::LowerCaseString(it.first),it.second);
                        });

        upstream_request_->encodeHeaders(resp_headers,true);
        ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
        ASSERT_TRUE(fake_upstream_connection_->close());
        ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
        fake_upstream_connection_.reset();

        // Verify Upstream Request
        std::for_each(exp_upstream_request_per_host.at(i).begin(),
                        exp_upstream_request_per_host.at(i).end(),
            [&](const auto& it) 
            {  EXPECT_THAT(upstream_request_->headers(),Http::HeaderValueOf(it.first,it.second)) ;}

        );


    }

    ASSERT_TRUE(response->waitForEndStream());

    // Verify Response headers
    std::for_each(exp_downstream_resp.begin(),
                    exp_downstream_resp.end(),
                    [&](const auto& it) { EXPECT_THAT(response->headers(),Http::HeaderValueOf(it.first,it.second)) ;});

    codec_client_->close();
  }



void testIndirectRoutingScenarios(const std::string& cluster_name,
                                ClusterMd cluster_md,
                                const std::string& preserve_header,
                                const RetryParams retry_params,
                                const std::vector<std::string> hostname_per_host,
                                const std::vector<std::vector<std::string>> support_md_per_host,
                                const std::vector<std::string> prefix_per_host,
                                const std::string& filter_config,
                                const std::map<std::string,std::string> request_headers,
                                const std::vector<std::map<std::string,std::string>> response_headers,
                                const std::vector<std::vector<uint64_t>> exp_host_list,
                                //      attempt   // choice  // headers
                                const std::vector<std::vector<std::map<std::string,std::string>>> exp_upstream_request_per_host,
                                const std::map<std::string,std::string> exp_downstream_resp) {

    ClusterBuilder cluster = ClusterBuilder().withName(cluster_name)
                                                .withClusterMd(std::move(cluster_md));

    uint16_t idx = 0;
    std::for_each( support_md_per_host.begin(),
                    support_md_per_host.end(),
                    [&](const auto& support_md_vector) {
                        prefix_per_host.at(idx).empty() ? 
                        
                        cluster.withEndpoint(EndpointBuilder()
                                                .withHostName(hostname_per_host.at(idx))
                                                .withHostMd({{"support",support_md_vector}})
                                                .withHostScheme(true))
                        :
                        cluster.withEndpoint(EndpointBuilder()
                                                .withHostName(hostname_per_host.at(idx))
                                                .withHostMd({{"support",support_md_vector}},
                                                            {{"prefix",prefix_per_host.at(idx)}})
                                                .withHostScheme(true));
                        idx ++;
                    });
    EndpointMetadataClusterConfigurator cluster_config = 
            EndpointMetadataClusterConfigurator()
                .withClusterBuilder(cluster);
    initConfig(std::vector<std::string>{fmt::format(filter_config,"cluster"_a = cluster_name,
                                                                    "indirect_header"_a = preserve_header)},
                    cluster_config,applyRetryParams(cluster_name,retry_params));

    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
    Http::TestRequestHeaderMapImpl req_headers;
    std::for_each(request_headers.begin(),
                    request_headers.end(),
                    [&](const auto& it) {
                        req_headers.addCopy(Http::LowerCaseString(it.first),it.second);
                    });
    
    auto response = codec_client_->makeHeaderOnlyRequest(req_headers);
    for(std::size_t i = 0; i < exp_host_list.size(); i++) {
        auto index = waitForNextUpstreamRequest(exp_host_list.at(i));
        Http::TestResponseHeaderMapImpl resp_headers;
        std::for_each(response_headers.at(i).begin(),
                        response_headers.at(i).end(),
                        [&](const auto& it) {
                            resp_headers.addCopy(Http::LowerCaseString(it.first),it.second);
                        });

        upstream_request_->encodeHeaders(resp_headers,true);
        ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
        ASSERT_TRUE(fake_upstream_connection_->close());
        ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
        fake_upstream_connection_.reset();

        // Verify Upstream Request
        std::for_each(exp_upstream_request_per_host.at(i).at(*index).begin(),
                        exp_upstream_request_per_host.at(i).at(*index).end(),
            [&](const auto& it) 
            {  EXPECT_THAT(upstream_request_->headers(),Http::HeaderValueOf(it.first,it.second)) ;}

        );


    }

    ASSERT_TRUE(response->waitForEndStream());

    // Verify Response headers
    std::for_each(exp_downstream_resp.begin(),
                    exp_downstream_resp.end(),
                    [&](const auto& it) { EXPECT_THAT(response->headers(),Http::HeaderValueOf(it.first,it.second)) ;});

    codec_client_->close();
  }


};





INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterApiPrefixIntegrationTest,
                         testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest())));


// Begin Test Cases

// Service Request Cases
// Direct Routing
// Scenario: Request from Consumer with api-prefix in TaR with Preferred Routing
//           2xx on first attempt
// Expected: :path header with api prefix of preferred host in upstream request
TEST_P(EricProxyFilterApiPrefixIntegrationTest,DirectService1) {

const std::string cluster_name = "chf_pool";
RetryParams retry_params; 
retry_params.num_retries_ = 3;
retry_params.num_preferred_host_retries_ = 2;
retry_params.num_failover_reselects_ = 1;
retry_params.num_lrp_reselects_ = 0;
const std::vector<std::string> hostname_per_host = {"chf1.ericsson.com:80","chf2.ericsson.com:80"};
const std::vector<std::vector<std::string>> support_md_per_host = {{"NF","TFQDN"},{"NF","TFQDN"}};
const std::vector<std::string> prefix_per_host = {"/one/prefix","/two/prefix"};
const std::string filter_config = scp_pr;
const std::map<std::string,std::string> request_headers = {
    {":scheme","http"},
    {":path","/nchf-convergedcharging/v2/char_ctx/1"},
    {":method","POST"},
    {":authority","host"},
    {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/one/prefix"}
};
const std::vector<std::map<std::string,std::string>> response_headers = { 
    {{":status","201"}},
};
const std::vector<uint64_t> exp_host_list = {0};
const std::vector<std::map<std::string,std::string>> exp_upstream_request_per_host = {
    {
        {":scheme","http"},
        {":path","/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
        {":authority","chf1.ericsson.com:80"},
    },
};
const std::map<std::string,std::string> exp_downstream_resp = {
    {":status","201"},
};

testDirectRoutingScenarios(cluster_name,
                                retry_params,
                                hostname_per_host,
                                support_md_per_host,
                                prefix_per_host,
                                filter_config,
                                request_headers,
                                response_headers,
                                exp_host_list,
                                exp_upstream_request_per_host,
                                exp_downstream_resp);

}

// Service Request Cases
// Direct Routing
// Scenario: Request from Consumer with no api-prefix in TaR with Preferred Routing
//           2xx on first attempt
// Expected: Standard succesful routing (Compatibility check for absent endpoint MD)
TEST_P(EricProxyFilterApiPrefixIntegrationTest,DirectService2) {

const std::string cluster_name = "chf_pool";
RetryParams retry_params; 
retry_params.num_retries_ = 3;
retry_params.num_preferred_host_retries_ = 2;
retry_params.num_failover_reselects_ = 1;
retry_params.num_lrp_reselects_ = 0;
const std::vector<std::string> hostname_per_host = {"chf1.ericsson.com:80","chf2.ericsson.com:80"};
const std::vector<std::vector<std::string>> support_md_per_host = {{"NF","TFQDN"},{"NF","TFQDN"}};
const std::vector<std::string> prefix_per_host = {"","/two/prefix"};
const std::string filter_config = scp_pr;
const std::map<std::string,std::string> request_headers = {
    {":scheme","http"},
    {":path","/nchf-convergedcharging/v2/char_ctx/1"},
    {":method","POST"},
    {":authority","host"},
    {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/one/prefix"}
};
const std::vector<std::map<std::string,std::string>> response_headers = { 
    {{":status","201"}},
};
const std::vector<uint64_t> exp_host_list = {0};
const std::vector<std::map<std::string,std::string>> exp_upstream_request_per_host = {
    {
        {":scheme","http"},
        {":path","/nchf-convergedcharging/v2/char_ctx/1"},
        {":authority","chf1.ericsson.com:80"},
    },
};
const std::map<std::string,std::string> exp_downstream_resp = {
    {":status","201"},
};

testDirectRoutingScenarios(cluster_name,
                                retry_params,
                                hostname_per_host,
                                support_md_per_host,
                                prefix_per_host,
                                filter_config,
                                request_headers,
                                response_headers,
                                exp_host_list,
                                exp_upstream_request_per_host,
                                exp_downstream_resp);

}

// Service Request Cases
// Direct Routing
// Scenario: Request from Consumer with api-prefix in TaR with Preferred Routing
//           2xx on retry attempt, both hosts have api Prefix in host MD
//           Expected: :path header with api prefix of preferred host on both attempts in upstream request
TEST_P(EricProxyFilterApiPrefixIntegrationTest,DirectService3) {

const std::string cluster_name = "chf_pool";
RetryParams retry_params; 
retry_params.num_retries_ = 3;
retry_params.num_preferred_host_retries_ = 2;
retry_params.num_failover_reselects_ = 1;
retry_params.num_lrp_reselects_ = 0;
const std::vector<std::string> hostname_per_host = {"chf1.ericsson.com:80","chf2.ericsson.com:80"};
const std::vector<std::vector<std::string>> support_md_per_host = {{"NF","TFQDN"},{"NF","TFQDN"}};
const std::vector<std::string> prefix_per_host = {"/one/prefix","/two/prefix"};
const std::string filter_config = scp_pr;
const std::map<std::string,std::string> request_headers = {
    {":scheme","http"},
    {":path","/nchf-convergedcharging/v2/char_ctx/1"},
    {":method","POST"},
    {":authority","host"},
    {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/one/prefix"}
};
const std::vector<std::map<std::string,std::string>> response_headers = { 
    {{":status","501"}},
    {{":status","201"}},
};
const std::vector<uint64_t> exp_host_list = {0,0};
const std::vector<std::map<std::string,std::string>> exp_upstream_request_per_host = {
    {
        {":scheme","http"},
        {":path","/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
        {":authority","chf1.ericsson.com:80"},
    },
    {
        {":scheme","http"},
        {":path","/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
        {":authority","chf1.ericsson.com:80"},       
    },
};
const std::map<std::string,std::string> exp_downstream_resp = {
     {":status","201"},
};

testDirectRoutingScenarios(cluster_name,
                                retry_params,
                                hostname_per_host,
                                support_md_per_host,
                                prefix_per_host,
                                filter_config,
                                request_headers,
                                response_headers,
                                exp_host_list,
                                exp_upstream_request_per_host,
                                exp_downstream_resp);

}

// Service Request Cases
// Direct Routing
// Scenario: Request from Consumer with api-prefix in TaR with Preferred Routing
//           5xx on preferred host and 2xx on reselected host
//           Expected: :path header with api prefix of preferred host on reselections
//                      and first try in upstream request and TaR in response having TaR
//                      of reselected host
TEST_P(EricProxyFilterApiPrefixIntegrationTest,DirectService4) {

const std::string cluster_name = "chf_pool";
RetryParams retry_params; 
retry_params.num_retries_ = 3;
retry_params.num_preferred_host_retries_ = 2;
retry_params.num_failover_reselects_ = 1;
retry_params.num_lrp_reselects_ = 0;
const std::vector<std::string> hostname_per_host = {"chf1.ericsson.com:80","chf2.ericsson.com:80"};
const std::vector<std::vector<std::string>> support_md_per_host = {{"NF","TFQDN"},{"NF","TFQDN"}};
const std::vector<std::string> prefix_per_host = {"/one/prefix","/two/prefix"};
const std::string filter_config = scp_pr;
const std::map<std::string,std::string> request_headers = {
    {":scheme","http"},
    {":path","/nchf-convergedcharging/v2/char_ctx/1"},
    {":method","POST"},
    {":authority","host"},
    {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/one/prefix"}
};
const std::vector<std::map<std::string,std::string>> response_headers = { 
    {{":status","501"}},
    {{":status","501"}},
    {{":status","501"}},
    {{":status","201"}},
};
const std::vector<uint64_t> exp_host_list = {0,0,0,1};
const std::vector<std::map<std::string,std::string>> exp_upstream_request_per_host = {
    {
        {":scheme","http"},
        {":path","/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
        {":authority","chf1.ericsson.com:80"},
    },
    {
        {":scheme","http"},
        {":path","/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
        {":authority","chf1.ericsson.com:80"},       
    },
    {
        {":scheme","http"},
        {":path","/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
        {":authority","chf1.ericsson.com:80"},
    },
    {
        {":scheme","http"},
        {":path","/two/prefix/nchf-convergedcharging/v2/char_ctx/1"},
        {":authority","chf2.ericsson.com:80"},       
    },
};
const std::map<std::string,std::string> exp_downstream_resp = {
    {":status","201"},    
    {"3gpp-sbi-target-apiroot","http://chf2.ericsson.com:80/two/prefix"},
};

testDirectRoutingScenarios(cluster_name,
                                retry_params,
                                hostname_per_host,
                                support_md_per_host,
                                prefix_per_host,
                                filter_config,
                                request_headers,
                                response_headers,
                                exp_host_list,
                                exp_upstream_request_per_host,
                                exp_downstream_resp);

}

// Service Request Cases
// Direct Routing
// Scenario: Request from Consumer with api-prefix in TaR with Preferred Routing
//           5xx on all attempts, TaR doesnt have port and outgoing request has 
//           :authority with fqdn:port, with default port 80 for http scheme
//           Expected: :path header with api prefix of preferred host on upstream request
TEST_P(EricProxyFilterApiPrefixIntegrationTest,DirectService5) {

const std::string cluster_name = "chf_pool";
RetryParams retry_params; 
retry_params.num_retries_ = 3;
retry_params.num_preferred_host_retries_ = 2;
retry_params.num_failover_reselects_ = 1;
retry_params.num_lrp_reselects_ = 0;
const std::vector<std::string> hostname_per_host = {"chf1.ericsson.com:80","chf2.ericsson.com:80"};
const std::vector<std::vector<std::string>> support_md_per_host = {{"NF","TFQDN"},{"NF","TFQDN"}};
const std::vector<std::string> prefix_per_host = {"/one/prefix","/two/prefix"};
const std::string filter_config = scp_pr;
const std::map<std::string,std::string> request_headers = {
    {":scheme","http"},
    {":path","/nchf-convergedcharging/v2/char_ctx/1"},
    {":method","POST"},
    {":authority","host"},
    {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com/one/prefix"}
};
const std::vector<std::map<std::string,std::string>> response_headers = { 
    {{":status","501"},{"foo","bar"}},
    {{":status","501"}},
    {{":status","501"}},
    {{":status","501"},{"foo2","bar3"}},
};
const std::vector<uint64_t> exp_host_list = {0,0,0,1};
const std::vector<std::map<std::string,std::string>> exp_upstream_request_per_host = {
  {
        {":scheme","http"},
        {":path","/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
        {":authority","chf1.ericsson.com:80"},
    },
    {
        {":scheme","http"},
        {":path","/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
        {":authority","chf1.ericsson.com:80"},       
    },
    {
        {":scheme","http"},
        {":path","/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
        {":authority","chf1.ericsson.com:80"},
    },
    {
        {":scheme","http"},
        {":path","/two/prefix/nchf-convergedcharging/v2/char_ctx/1"},
        {":authority","chf2.ericsson.com:80"},       
    },
};
const std::map<std::string,std::string> exp_downstream_resp = {
    {":status","501"}
};

testDirectRoutingScenarios(cluster_name,
                                retry_params,
                                hostname_per_host,
                                support_md_per_host,
                                prefix_per_host,
                                filter_config,
                                request_headers,
                                response_headers,
                                exp_host_list,
                                exp_upstream_request_per_host,
                                exp_downstream_resp);

}

// Service Request Cases
// Indirect Routing
// Scenario: Request from Consumer to a producer behind a peer SCP 
//           Expected: TaR with Identifier for NF Producer and :path header with 
//                     with prefix of peer SCP
TEST_P(EricProxyFilterApiPrefixIntegrationTest,IndirectService1){

const std::string cluster_name = "chf_pool";
ClusterMd cluster_md {
    {
        "chf1.ericsson.com:80",
        {
            {{"fqdn", "scp1.ericsson.com:80"},
            {"ip", "192.168.1.1:80"}},
        }
    },
    {
        "chf2.ericsson.com:80",
        {
            {{"fqdn", "scp2.ericsson.com:80"},
            {"ip", "192.168.2.1:80"}},
        }
    }
};
RetryParams retry_params; 
retry_params.num_retries_ = 3;
retry_params.num_preferred_host_retries_ = 2;
retry_params.num_failover_reselects_ = 1;
retry_params.num_lrp_reselects_ = 0;
const std::string preserve_header = "TARGET_API_ROOT" ;// or could be "ABSOLUTE_PATH"
const std::vector<std::string> hostname_per_host = {"scp1.ericsson.com:80","scp2.ericsson.com:80"};
const std::vector<std::vector<std::string>> support_md_per_host = {{"Indirect"},{"Indirect"}};
const std::vector<std::string> prefix_per_host = {"/scp/one/prefix","/scp/two/prefix"};
const std::string filter_config = scp_pr;
const std::map<std::string,std::string> request_headers = {
    {":scheme","http"},
    {":path","/nchf-convergedcharging/v2/char_ctx/1"},
    {":method","POST"},
    {":authority","host"},
    {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/nf/one/prefix"}
};
const std::vector<std::map<std::string,std::string>> response_headers = { 
    {{":status","201"}},
};
const std::vector<std::vector<uint64_t>> exp_host_list = {{0}};
        // attempt  // choice   // headers
const std::vector<std::vector<std::map<std::string,std::string>>> exp_upstream_request_per_host = {
    {    
        {  
            {":scheme","http"}, 
            {":path","/scp/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
            {":authority","scp1.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/nf/one/prefix"}
        }
    },
};
const std::map<std::string,std::string> exp_downstream_resp = {
    {":status","201"},
};
testIndirectRoutingScenarios(cluster_name,
                                cluster_md,
                                preserve_header,
                                retry_params,
                                hostname_per_host,
                                support_md_per_host,
                                prefix_per_host,
                                filter_config,
                                request_headers,
                                response_headers,
                                exp_host_list,
                                exp_upstream_request_per_host,
                                exp_downstream_resp);

}

// Service Request Cases
// Indirect Routing
// Scenario: Request from Consumer to a producer behind a peer SCP first response is 5xx, 1st retry 
//                     is 2xx 
//           Expected: TaR with Identifier for NF Producer and :path header with 
//                     with prefix of peer SCP, expect :path to be consistent on retries 
TEST_P(EricProxyFilterApiPrefixIntegrationTest,IndirectService2){

const std::string cluster_name = "chf_pool";
ClusterMd cluster_md {
    {
        "chf1.ericsson.com:80",
        {
            {{"fqdn", "scp1.ericsson.com:80"},
            {"ip", "192.168.1.1:80"}},
        }
    },
    {
        "chf2.ericsson.com:80",
        {
            {{"fqdn", "scp2.ericsson.com:80"},
            {"ip", "192.168.2.1:80"}},
        }
    }
};
RetryParams retry_params; 
retry_params.num_retries_ = 3;
retry_params.num_preferred_host_retries_ = 2;
retry_params.num_failover_reselects_ = 1;
retry_params.num_lrp_reselects_ = 0;
const std::string preserve_header = "TARGET_API_ROOT" ;// or could be "ABSOLUTE_PATH"
const std::vector<std::string> hostname_per_host = {"scp1.ericsson.com:80","scp2.ericsson.com:80"};
const std::vector<std::vector<std::string>> support_md_per_host = {{"Indirect"},{"Indirect"}};
const std::vector<std::string> prefix_per_host = {"/scp/one/prefix","/scp/two/prefix"};
const std::string filter_config = scp_pr;
const std::map<std::string,std::string> request_headers = {
    {":scheme","http"},
    {":path","/nchf-convergedcharging/v2/char_ctx/1"},
    {":method","POST"},
    {":authority","host"},
    {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/nf/one/prefix"}
};
const std::vector<std::map<std::string,std::string>> response_headers = { 
    {{":status","501"}},
    {{":status","201"}},
};
const std::vector<std::vector<uint64_t>> exp_host_list = {{0},{0}};
        // attempt  // choice   // headers
const std::vector<std::vector<std::map<std::string,std::string>>> exp_upstream_request_per_host = {
    {    
        {  
            {":scheme","http"}, 
            {":path","/scp/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
            {":authority","scp1.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/nf/one/prefix"}
        }
    },
      {    
        {  
            {":scheme","http"}, 
            {":path","/scp/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
            {":authority","scp1.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/nf/one/prefix"}
        }
    },
};
const std::map<std::string,std::string> exp_downstream_resp = {
    {":status","201"},
};

testIndirectRoutingScenarios(cluster_name,
                                cluster_md,
                                preserve_header,
                                retry_params,
                                hostname_per_host,
                                support_md_per_host,
                                prefix_per_host,
                                filter_config,
                                request_headers,
                                response_headers,
                                exp_host_list,
                                exp_upstream_request_per_host,
                                exp_downstream_resp);

}

// Service Request Cases
// Indirect Routing
// Scenario: Request from Consumer to a producer behind a peer SCP first scp retruns 5xx, reselected scp 
//                     returns 2xx 
//           Expected: TaR with Identifier for NF Producer and :path header with 
//                     with prefix of reselected peer SCP, expect :path to be consistent on all tries 
TEST_P(EricProxyFilterApiPrefixIntegrationTest,IndirectService3){

const std::string cluster_name = "chf_pool";
ClusterMd cluster_md {
    {
        "chf1.ericsson.com:80",
        {
            {{"fqdn", "scp1.ericsson.com:80"},
            {"ip", "192.168.1.1:80"}},
            {{"fqdn", "scp2.ericsson.com:80"},
            {"ip", "192.168.2.1:80"}},
        }
    },
    {
        "chf2.ericsson.com:80",
        {
            {{"fqdn", "scp2.ericsson.com:80"},
            {"ip", "192.168.2.1:80"}},
            {{"fqdn", "scp1.ericsson.com:80"},
            {"ip", "192.168.1.1:80"}},
        }
    }
};
RetryParams retry_params; 
retry_params.num_retries_ = 3;
retry_params.num_preferred_host_retries_ = 2;
retry_params.num_failover_reselects_ = 1;
retry_params.num_lrp_reselects_ = 0;
const std::string preserve_header = "TARGET_API_ROOT" ;// or could be "ABSOLUTE_PATH"
const std::vector<std::string> hostname_per_host = {"scp1.ericsson.com:80","scp2.ericsson.com:80"};
const std::vector<std::vector<std::string>> support_md_per_host = {{"Indirect"},{"Indirect"}};
const std::vector<std::string> prefix_per_host = {"/scp/one/prefix","/scp/two/prefix"};
const std::string filter_config = scp_pr;
const std::map<std::string,std::string> request_headers = {
    {":scheme","http"},
    {":path","/nchf-convergedcharging/v2/char_ctx/1"},
    {":method","POST"},
    {":authority","host"},
    {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/nf/one/prefix"}
};
const std::vector<std::map<std::string,std::string>> response_headers = { 
    {{":status","501"}},
    {{":status","501"}},
    {{":status","501"}},
    {{":status","201"}},
};
const std::vector<std::vector<uint64_t>> exp_host_list = {{0,1},{0,1},{0,1},{1,0}};
        // attempt  // choice   // headers
const std::vector<std::vector<std::map<std::string,std::string>>> exp_upstream_request_per_host = {
    {    
        {  
            {":scheme","http"}, 
            {":path","/scp/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
            {":authority","scp1.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/nf/one/prefix"}
        },
        {  
            {":scheme","http"}, 
            {":path","/scp/two/prefix/nchf-convergedcharging/v2/char_ctx/1"},
            {":authority","scp2.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/nf/one/prefix"}
        }

    },
    {    
        {  
            {":scheme","http"}, 
            {":path","/scp/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
            {":authority","scp1.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/nf/one/prefix"}
        },
        {  
            {":scheme","http"}, 
            {":path","/scp/two/prefix/nchf-convergedcharging/v2/char_ctx/1"},
            {":authority","scp2.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/nf/one/prefix"}
        }

    },
    {    
        {  
            {":scheme","http"}, 
            {":path","/scp/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
            {":authority","scp1.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/nf/one/prefix"}
        },
        {  
            {":scheme","http"}, 
            {":path","/scp/two/prefix/nchf-convergedcharging/v2/char_ctx/1"},
            {":authority","scp2.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/nf/one/prefix"}
        }

    },
    {    
        {  
            {":scheme","http"}, 
            {":path","/scp/two/prefix/nchf-convergedcharging/v2/char_ctx/1"},
            {":authority","scp2.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/nf/one/prefix"}
        },
        {  
            {":scheme","http"}, 
            {":path","/scp/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
            {":authority","scp1.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/nf/one/prefix"}
        }

    },
    
    
    
    
};
const std::map<std::string,std::string> exp_downstream_resp = {
    {":status","201"},
};

testIndirectRoutingScenarios(cluster_name,
                                cluster_md,
                                preserve_header,
                                retry_params,
                                hostname_per_host,
                                support_md_per_host,
                                prefix_per_host,
                                filter_config,
                                request_headers,
                                response_headers,
                                exp_host_list,
                                exp_upstream_request_per_host,
                                exp_downstream_resp);

}

// Service Request Cases
// Indirect Routing
// Scenaio: Request from Consumer to a producer behind a RP SEPP , the chosen SEPP doesnt support TaR
//           Expected: api prefix for NF Producer and peer SEPP in :path header in order <sepp-prefix>/<nf-cons-prefix>/remaining path
TEST_P(EricProxyFilterApiPrefixIntegrationTest,IndirectService4){

GTEST_SKIP() << "Something wrong with absolute path handling ";
const std::string cluster_name = "chf_pool";
ClusterMd cluster_md {
    {
        "chf3.ericsson.com:80",
        {
            {{"fqdn", "scp5.ericsson.com:80"},
            {"ip", "192.168.1.1:80"}},
            {{"fqdn", "scp6.ericsson.com:80"},
            {"ip", "192.168.2.1:80"}},
        }
    },
    {
        "chf4.ericsson.com:80",
        {
            {{"fqdn", "scp21.ericsson.com:80"},
            {"ip", "192.168.2.1:80"}},
            {{"fqdn", "scp12.ericsson.com:80"},
            {"ip", "192.168.1.1:80"}},
        }
    }
};
RetryParams retry_params; 
retry_params.num_retries_ = 3;
retry_params.num_preferred_host_retries_ = 2;
retry_params.num_failover_reselects_ = 1;
retry_params.num_lrp_reselects_ = 0;
const std::string preserve_header = "ABSOLUTE_PATH" ;// or could be "ABSOLUTE_PATH"
const std::vector<std::string> hostname_per_host = {"sepp1.ext_ericsson.com:80"};
const std::vector<std::vector<std::string>> support_md_per_host = {{"Indirect"}};
const std::vector<std::string> prefix_per_host = {"/sepp/one/prefix"};
const std::string filter_config = sepp_pr;
const std::map<std::string,std::string> request_headers = {
    {":scheme","http"},
    {":path","/nchf-convergedcharging/v2/char_ctx/1"},
    {":method","POST"},
    {":authority","host"},
    {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80/nf/one/prefix"}
};
const std::vector<std::map<std::string,std::string>> response_headers = { 
    {{":status","501"}},
    {{":status","501"}},
    {{":status","201"}},
};
const std::vector<std::vector<uint64_t>> exp_host_list = {{0},{0},{0}};
        // attempt  // choice   // headers
const std::vector<std::vector<std::map<std::string,std::string>>> exp_upstream_request_per_host = {
    {    
        {  
            {":scheme","http"}, 
            {":path","/sepp/one/prefix/nf/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
            {":authority","chf1.ericsson.com:80"},
        }
    },
    {    
        {  
            {":scheme","http"}, 
            {":path","/sepp/one/prefix/nf/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
            {":authority","chf1.ericsson.com:80"},
        }

    },
    {    
        {  
            {":scheme","http"}, 
            {":path","/sepp/one/prefix/nf/one/prefix/nchf-convergedcharging/v2/char_ctx/1"},
            {":authority","chf1.ericsson.com:80"}
        }

    }
    
    
    
};
const std::map<std::string,std::string> exp_downstream_resp = {
    {":status","201"},
};

testIndirectRoutingScenarios(cluster_name,
                                cluster_md,
                                preserve_header,
                                retry_params,
                                hostname_per_host,
                                support_md_per_host,
                                prefix_per_host,
                                filter_config,
                                request_headers,
                                response_headers,
                                exp_host_list,
                                exp_upstream_request_per_host,
                                exp_downstream_resp);

}

// Notification Request Cases
// Direct Routing
// Scenairo: Request from Producer to a notification context of NF Consumer with preferred routing
//           the preferred host has a different api prefix in its endpoint MD than the one mentioned in the callback uri 
//           within subscription request, 2xx on first try
//           Expected: :path header does not contain api prefix contained in endpoint MD of preferred host
TEST_P(EricProxyFilterApiPrefixIntegrationTest,DirectNotification1) {

const std::string cluster_name = "chf_pool";
RetryParams retry_params; 
retry_params.num_retries_ = 3;
retry_params.num_preferred_host_retries_ = 2;
retry_params.num_failover_reselects_ = 1;
retry_params.num_lrp_reselects_ = 0;
const std::vector<std::string> hostname_per_host = {"chf1.ericsson.com:80","chf2.ericsson.com:80"};
const std::vector<std::vector<std::string>> support_md_per_host = {{"NF","TFQDN"},{"NF","TFQDN"}};
const std::vector<std::string> prefix_per_host = {"/one/chf1prefix","/two/chf2prefix"};
const std::string filter_config = scp_pr;
const std::map<std::string,std::string> request_headers = {
    {":scheme","http"},
    {":path","/some/prefix/to/callback/uri/123"},
    {":method","POST"},
    {":authority","host"},
    {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80"},
    {"3gpp-sbi-callback","CHF_NOTIFY"}
};
const std::vector<std::map<std::string,std::string>> response_headers = { 
    {{":status","201"}},
};
const std::vector<uint64_t> exp_host_list = {0};
const std::vector<std::map<std::string,std::string>> exp_upstream_request_per_host = {
    {
        {":scheme","http"},
        {":path","/some/prefix/to/callback/uri/123"},
        {":authority","chf1.ericsson.com:80"},
    },
};
const std::map<std::string,std::string> exp_downstream_resp = {
    {":status","201"},
};

testDirectRoutingScenarios(cluster_name,
                                retry_params,
                                hostname_per_host,
                                support_md_per_host,
                                prefix_per_host,
                                filter_config,
                                request_headers,
                                response_headers,
                                exp_host_list,
                                exp_upstream_request_per_host,
                                exp_downstream_resp);


}

// Notification Request Cases
// Direct Routing
// Scenairo: Request from Producer to a notification context of NF Consumer with preferred routing
//           the preferred host has a different api prefix in its endpoint MD than the one mentioned in the callback uri 
//           within subscription request, 5xx on first preferred host try+retries 2xx on reselection
//           Expected: :path header does not contain api prefix contained in endpoint MD of preferred host
//                      on any of the attempts and on reselection picks the correct api prefix from endpoint
//                      MD and puts it in prefix of path
TEST_P(EricProxyFilterApiPrefixIntegrationTest,DirectNotification2) {

const std::string cluster_name = "chf_pool";
RetryParams retry_params; 
retry_params.num_retries_ = 3;
retry_params.num_preferred_host_retries_ = 2;
retry_params.num_failover_reselects_ = 1;
retry_params.num_lrp_reselects_ = 0;
const std::vector<std::string> hostname_per_host = {"chf1.ericsson.com:80","chf2.ericsson.com:80"};
const std::vector<std::vector<std::string>> support_md_per_host = {{"NF","TFQDN"},{"NF","TFQDN"}};
const std::vector<std::string> prefix_per_host = {"/one/chf1prefix","/two/chf2prefix"};
const std::string filter_config = scp_pr;
const std::map<std::string,std::string> request_headers = {
    {":scheme","http"},
    {":path","/some/prefix/to/callback/uri/123"},
    {":method","POST"},
    {":authority","host"},
    {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80"},
    {"3gpp-sbi-callback","CHF_NOTIFY"}
};
const std::vector<std::map<std::string,std::string>> response_headers = { 
    {{":status","501"}},
    {{":status","501"}},
    {{":status","501"}},
    {{":status","201"}},
};
const std::vector<uint64_t> exp_host_list = {0,0,0,1};
const std::vector<std::map<std::string,std::string>> exp_upstream_request_per_host = {
    {
        {":scheme","http"},
        {":path","/some/prefix/to/callback/uri/123"},
        {":authority","chf1.ericsson.com:80"},
    },
    {
        {":scheme","http"},
        {":path","/some/prefix/to/callback/uri/123"},
        {":authority","chf1.ericsson.com:80"},
    },
    {
        {":scheme","http"},
        {":path","/some/prefix/to/callback/uri/123"},
        {":authority","chf1.ericsson.com:80"},
    },
    {
        {":scheme","http"},
        {":path","/two/chf2prefix/some/prefix/to/callback/uri/123"},
        {":authority","chf2.ericsson.com:80"},
    },
};
const std::map<std::string,std::string> exp_downstream_resp = {
    {":status","201"},
};

testDirectRoutingScenarios(cluster_name,
                                retry_params,
                                hostname_per_host,
                                support_md_per_host,
                                prefix_per_host,
                                filter_config,
                                request_headers,
                                response_headers,
                                exp_host_list,
                                exp_upstream_request_per_host,
                                exp_downstream_resp);


}


// Notification Request Cases
// Direct Routing
// Scenairo: Request from Producer to a notification context of NF Consumer with preferred routing
//           the preferred host has same api prefix in its endpoint MD as the one mentioned in the callback uri 
//           within subscription request, 5xx on first preferred host try+retries 2xx on reselection
//           Expected: :path header contain api prefix contained in endpoint MD of preferred host
//                      on all of the attempts and on reselection strips the old host's api prefix 
//                      picks the correct api prefix from endpoint
//                      MD and puts it in prefix of path
TEST_P(EricProxyFilterApiPrefixIntegrationTest,DirectNotification3) {

const std::string cluster_name = "chf_pool";
RetryParams retry_params; 
retry_params.num_retries_ = 3;
retry_params.num_preferred_host_retries_ = 2;
retry_params.num_failover_reselects_ = 1;
retry_params.num_lrp_reselects_ = 0;
const std::vector<std::string> hostname_per_host = {"chf1.ericsson.com:80","chf2.ericsson.com:80"};
const std::vector<std::vector<std::string>> support_md_per_host = {{"NF","TFQDN"},{"NF","TFQDN"}};
const std::vector<std::string> prefix_per_host = {"/some/prefix","/two/chf2prefix"};
const std::string filter_config = scp_pr;
const std::map<std::string,std::string> request_headers = {
    {":scheme","http"},
    {":path","/some/prefix/to/callback/uri/123"},
    {":method","POST"},
    {":authority","host"},
    {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80"},
    {"3gpp-sbi-callback","CHF_NOTIFY"}
};
const std::vector<std::map<std::string,std::string>> response_headers = { 
    {{":status","501"}},
    {{":status","501"}},
    {{":status","501"}},
    {{":status","201"}},
};
const std::vector<uint64_t> exp_host_list = {0,0,0,1};
const std::vector<std::map<std::string,std::string>> exp_upstream_request_per_host = {
    {
        {":scheme","http"},
        {":path","/some/prefix/to/callback/uri/123"},
        {":authority","chf1.ericsson.com:80"},
    },
    {
        {":scheme","http"},
        {":path","/some/prefix/to/callback/uri/123"},
        {":authority","chf1.ericsson.com:80"},
    },
    {
        {":scheme","http"},
        {":path","/some/prefix/to/callback/uri/123"},
        {":authority","chf1.ericsson.com:80"},
    },
    {
        {":scheme","http"},
        {":path","/two/chf2prefix/to/callback/uri/123"},
        {":authority","chf2.ericsson.com:80"},
    },
};
const std::map<std::string,std::string> exp_downstream_resp = {
    {":status","201"},
};

testDirectRoutingScenarios(cluster_name,
                                retry_params,
                                hostname_per_host,
                                support_md_per_host,
                                prefix_per_host,
                                filter_config,
                                request_headers,
                                response_headers,
                                exp_host_list,
                                exp_upstream_request_per_host,
                                exp_downstream_resp);


}


// Notification Request Cases
// Direct Routing
// Scenairo: Request from Producer to a notification context of NF Consumer with preferred routing
//           the preferred host has a TaR not present in host map, so jump straight to reselections
//           Expected: :path header contain api prefix from endpoint
//                      MD and puts it in prefix of path for reselections, preferred host 
//                      try+retries dont take place and upstreamOverrideHost is not set
TEST_P(EricProxyFilterApiPrefixIntegrationTest,DirectNotification4) {

const std::string cluster_name = "chf_pool";
RetryParams retry_params; 
retry_params.num_retries_ = 4;
retry_params.num_preferred_host_retries_ = 2;
retry_params.num_failover_reselects_ = 2;
retry_params.num_lrp_reselects_ = 0;
const std::vector<std::string> hostname_per_host = {"chf1.ericsson.com:80"};
const std::vector<std::vector<std::string>> support_md_per_host = {{"NF","TFQDN"}};
const std::vector<std::string> prefix_per_host = {"/one/chf1prefix"};
const std::string filter_config = scp_pr;
const std::map<std::string,std::string> request_headers = {
    {":scheme","http"},
    {":path","/some/prefix/to/callback/uri/123"},
    {":method","POST"},
    {":authority","host"},
    {"3gpp-sbi-target-apiroot","http://chf12.ericsson.com:80"},
    {"3gpp-sbi-callback","CHF_NOTIFY"}
};
const std::vector<std::map<std::string,std::string>> response_headers = { 
    {
        {":status","501"},
        {"foo","bar"}
    }
};
const std::vector<uint64_t> exp_host_list = {0};
// No retries
const std::vector<std::map<std::string,std::string>> exp_upstream_request_per_host = {
    {
        {":scheme","http"},
        {":path","/one/chf1prefix/some/prefix/to/callback/uri/123"},
        {":authority","chf1.ericsson.com:80"},
    }
};
const std::map<std::string,std::string> exp_downstream_resp = {
    {":status","501"},
    {"foo","bar"}
};

testDirectRoutingScenarios(cluster_name,
                                retry_params,
                                hostname_per_host,
                                support_md_per_host,
                                prefix_per_host,
                                filter_config,
                                request_headers,
                                response_headers,
                                exp_host_list,
                                exp_upstream_request_per_host,
                                exp_downstream_resp);


}

// Notification Request Cases
// Indirect Routing
// Scenairo: Request from Producer to a notification context of NF Consumer with indirect routing
//           the preferred host has a TaR associated with two scps, the first scp retrurn 501 on
//           all tries and retries and reselected scp retruns a 201
//           Expected: :path header contain api prefix from SCP endpoint
//                      MD and puts it in prefix of path for reselections in preferred host 
//                      try+retries and reselection
TEST_P(EricProxyFilterApiPrefixIntegrationTest,IndirectNotification1) {

// GTEST_SKIP();
const std::string cluster_name = "chf_pool";
ClusterMd cluster_md {
    {
        "chf1.ericsson.com:80",
        {
            {{"fqdn", "scp1.ericsson.com:80"},
            {"ip", "192.168.1.1:80"}},
            {{"fqdn", "scp2.ericsson.com:80"},
            {"ip", "192.168.2.1:80"}},
        }
    }
};
RetryParams retry_params; 
retry_params.num_retries_ = 3;
retry_params.num_preferred_host_retries_ = 2;
retry_params.num_failover_reselects_ = 1;
retry_params.num_lrp_reselects_ = 0;
const std::string preserve_header = "TARGET_API_ROOT" ;// or could be "ABSOLUTE_PATH"
const std::vector<std::string> hostname_per_host = {"scp1.ericsson.com:80","scp2.ericsson.com:80"};
const std::vector<std::vector<std::string>> support_md_per_host = {{"Indirect"},{"Indirect"}};
const std::vector<std::string> prefix_per_host = {"/scp/one/prefix","/scp/two/prefix"};
const std::string filter_config = scp_pr;
const std::map<std::string,std::string> request_headers = {
    {":scheme","http"},
    {":path","/some/path/to/callback/ctx/123"},
    {":method","POST"},
    {":authority","host"},
    {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80"},
    {"3gpp-sbi-callback","SBI_NOTIFY"}
};
const std::vector<std::map<std::string,std::string>> response_headers = { 
    {{":status","501"}},
    {{":status","501"}},
    {{":status","501"}},
    {{":status","201"}},
};
const std::vector<std::vector<uint64_t>> exp_host_list = {{0,1},{0,1},{0,1},{1,0}};
        // attempt  // choice   // headers
const std::vector<std::vector<std::map<std::string,std::string>>> exp_upstream_request_per_host = {
    {    
        {  
            {":scheme","http"}, 
            {":path","/scp/one/prefix/some/path/to/callback/ctx/123"},
            {":authority","scp1.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80"}
        },
        {  
            {":scheme","http"}, 
            {":path","/scp/two/prefix/some/path/to/callback/ctx/123"},
            {":authority","scp2.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80"}
        }

    },
    {    
        {  
            {":scheme","http"}, 
            {":path","/scp/one/prefix/some/path/to/callback/ctx/123"},
            {":authority","scp1.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80"}
        },
        {  
            {":scheme","http"}, 
            {":path","/scp/two/prefix/some/path/to/callback/ctx/123"},
            {":authority","scp2.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80"}
        }

    },
    {    
        {  
            {":scheme","http"}, 
            {":path","/scp/one/prefix/some/path/to/callback/ctx/123"},
            {":authority","scp1.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80"}
        },
        {  
            {":scheme","http"}, 
            {":path","/scp/two/prefix/some/path/to/callback/ctx/123"},
            {":authority","scp2.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80"}
        }

    },
    {    
        {  
            {":scheme","http"}, 
            {":path","/scp/two/prefix/some/path/to/callback/ctx/123"},
            {":authority","scp2.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80"}
        },
        {  
            {":scheme","http"}, 
            {":path","/scp/one/prefix/some/path/to/callback/ctx/123"},
            {":authority","scp1.ericsson.com:80"},
            {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80"}
        }

    },
    
    
    
    
};
const std::map<std::string,std::string> exp_downstream_resp = {
    {":status","201"},
};

testIndirectRoutingScenarios(cluster_name,
                                cluster_md,
                                preserve_header,
                                retry_params,
                                hostname_per_host,
                                support_md_per_host,
                                prefix_per_host,
                                filter_config,
                                request_headers,
                                response_headers,
                                exp_host_list,
                                exp_upstream_request_per_host,
                                exp_downstream_resp);


}

// Preferred Host routing with pref_host_retries set to 0
// So on first attempt for direct notifications it should not execute addApiPrefix()
// routine on reselections api prefix must be modified depending on endpoint MD
TEST_P(EricProxyFilterApiPrefixIntegrationTest, DirectNotification5) {

const std::string cluster_name = "chf_pool";
RetryParams retry_params; 
retry_params.num_retries_ = 4;
retry_params.num_preferred_host_retries_ = 0;
retry_params.num_failover_reselects_ = 4;
retry_params.num_lrp_reselects_ = 0;
const std::vector<std::string> hostname_per_host = {"chf1.ericsson.com:80","chf2.ericsson.com:80"};
const std::vector<std::vector<std::string>> support_md_per_host = {{"NF","TFQDN"},{"NF","TFQDN"}};
const std::vector<std::string> prefix_per_host = {"/one/chf1prefix","/two/chf2prefix"};
const std::string filter_config = scp_pr;
const std::map<std::string,std::string> request_headers = {
    {":scheme","http"},
    {":path","/some/prefix/to/callback/uri/123"},
    {":method","POST"},
    {":authority","host"},
    {"3gpp-sbi-target-apiroot","http://chf1.ericsson.com:80"},
    {"3gpp-sbi-callback","CHF_NOTIFY"}
};
const std::vector<std::map<std::string,std::string>> response_headers = { 
    {{":status","501"}},
    {{":status","201"}},
};
const std::vector<uint64_t> exp_host_list = {0,1};
// No retries
const std::vector<std::map<std::string,std::string>> exp_upstream_request_per_host = {
    {
        {":scheme","http"},
        {":path","/some/prefix/to/callback/uri/123"},
        {":authority","chf1.ericsson.com:80"},
    },
    {
        {":scheme","http"},
        {":path","/two/chf2prefix/some/prefix/to/callback/uri/123"},
        {":authority","chf2.ericsson.com:80"},
    }
};
const std::map<std::string,std::string> exp_downstream_resp = {
    {":status","201"},
};

testDirectRoutingScenarios(cluster_name,
                                retry_params,
                                hostname_per_host,
                                support_md_per_host,
                                prefix_per_host,
                                filter_config,
                                request_headers,
                                response_headers,
                                exp_host_list,
                                exp_upstream_request_per_host,
                                exp_downstream_resp);
}



} //namespace
} //EricProxy
} //HttpFilters
} //Extensions
} //Envoy 
