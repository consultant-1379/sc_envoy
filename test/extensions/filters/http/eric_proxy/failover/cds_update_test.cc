#include "envoy/config/cluster/v3/cluster.pb.h"
#include "envoy/grpc/status.h"
#include "envoy/service/discovery/v3/discovery.pb.h"
#include "envoy/stats/scope.h"

#include "source/common/config/protobuf_link_hacks.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"

#include "test/common/grpc/grpc_client_integration.h"
#include "test/config/v2_link_hacks.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"
#include "test/test_common/network_utility.h"
#include "test/test_common/resources.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/utility.h"

#include "absl/synchronization/notification.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

const char ClusterName1[] = "cluster_1";
const char ClusterName2[] = "cluster_2";
const int UpstreamIndex1 = 1;
const int UpstreamIndex2 = 2;

class EricProxyCdsUpdate : public Grpc::DeltaSotwIntegrationParamTest, public HttpIntegrationTest {
public:
  EricProxyCdsUpdate()
      : HttpIntegrationTest(Http::CodecType::HTTP2, ipVersion(),
                            ConfigHelper::discoveredClustersBootstrap(
                                sotwOrDelta() == Grpc::SotwOrDelta::Sotw ||
                                        sotwOrDelta() == Grpc::SotwOrDelta::UnifiedSotw
                                    ? "GRPC"
                                    : "DELTA_GRPC")),
        cluster_creator_(&ConfigHelper::buildStaticCluster) {
    config_helper_.addRuntimeOverride("envoy.reloadable_features.unified_mux",
                                      (sotwOrDelta() == Grpc::SotwOrDelta::UnifiedSotw ||
                                       sotwOrDelta() == Grpc::SotwOrDelta::UnifiedDelta)
                                          ? "true"
                                          : "false");
    use_lds_ = false;
    sotw_or_delta_ = sotwOrDelta();
  }

  void TearDown() override {
    if (!test_skipped_) {
      cleanUpXdsConnection();
    }
  }

  // Overridden to insert this stuff into the initialize() at the very beginning of
  // HttpIntegrationTest::testRouterHeaderOnlyRequestAndResponse().
  void initialize() override {
    use_lds_ = false;
    test_skipped_ = false;
    // Controls how many addFakeUpstream() will happen in
    // BaseIntegrationTest::createUpstreams() (which is part of initialize()).
    // Make sure this number matches the size of the 'clusters' repeated field in the bootstrap
    // config that you use!
    setUpstreamCount(1);                         // the CDS cluster
    setUpstreamProtocol(Http::CodecType::HTTP2); // CDS uses gRPC uses HTTP2.

    // HttpIntegrationTest::initialize() does many things:
    // 1) It appends to fake_upstreams_ as many as you asked for via setUpstreamCount().
    // 2) It updates your bootstrap config with the ports your fake upstreams are actually listening
    //    on (since you're supposed to leave them as 0).
    // 3) It creates and starts an IntegrationTestServer - the thing that wraps the almost-actual
    //    Envoy used in the tests.
    // 4) Bringing up the server usually entails waiting to ensure that any listeners specified in
    //    the bootstrap config have come up, and registering them in a port map (see lookupPort()).
    //    However, this test needs to defer all of that to later.
    defer_listener_finalization_ = true;
    HttpIntegrationTest::initialize();

    // Create the regular (i.e. not an xDS server) upstreams. We create them manually here after
    // initialize() because finalize() expects all fake_upstreams_ to correspond to a static
    // cluster in the bootstrap config - which we don't want since we're testing dynamic CDS!
    addFakeUpstream(upstream_codec_type_);
    addFakeUpstream(upstream_codec_type_);
    // cluster1_ = cluster_creator_(
    //     ClusterName1, fake_upstreams_[UpstreamIndex1]->localAddress()->ip()->port(),
    //     Network::Test::getLoopbackAddressString(ipVersion()), "ROUND_ROBIN");
    cluster1_ = buildCustomStaticCluster(
        ClusterName1, fake_upstreams_[UpstreamIndex1]->localAddress()->ip()->port(),
        Network::Test::getLoopbackAddressString(ipVersion()), "ROUND_ROBIN", "scp1.ericsson.se");
    cluster2_ = cluster_creator_(ClusterName2,
                                 fake_upstreams_[UpstreamIndex2]->localAddress()->ip()->port(),
                                 Network::Test::getLoopbackAddressString(ipVersion()),
                                 envoy::config::cluster::v3::Cluster::ROUND_ROBIN);

    // Let Envoy establish its connection to the CDS server.
    acceptXdsConnection();

    // Do the initial compareDiscoveryRequest / sendDiscoveryResponse for cluster_1.
    EXPECT_TRUE(compareDiscoveryRequest(Config::TypeUrl::get().Cluster, "", {}, {}, {}, true));
    sendDiscoveryResponse<envoy::config::cluster::v3::Cluster>(Config::TypeUrl::get().Cluster,
                                                               {cluster1_}, {cluster1_}, {}, "55");

    // We can continue the test once we're sure that Envoy's ClusterManager has made use of
    // the DiscoveryResponse describing cluster_1 that we sent.
    // 2 because the statically specified CDS server itself counts as a cluster.
    test_server_->waitForGaugeGe("cluster_manager.active_clusters", 2);

    // Wait for our statically specified listener to become ready, and register its port in the
    // test framework's downstream listener port map.
    test_server_->waitUntilListenersReady();
    registerTestServerPorts({"http"});
  }

// Custom static cluster builder to include metadata
envoy::config::cluster::v3::Cluster buildCustomStaticCluster(const std::string& name,
                                                             int port,
                                                             const std::string& address,
                                                             const std::string& lb_policy,
                                                             const std::string& metadata) {
  return TestUtility::parseYaml<envoy::config::cluster::v3::Cluster>(
      fmt::format(R"EOF(
      name: {}
      connect_timeout: 5s
      type: STATIC
      load_assignment:
        cluster_name: {}
        endpoints:
        - lb_endpoints:
          - endpoint:
              address:
                socket_address:
                  address: {}
                  port_value: {}
              health_check_config:
                address:
                  socket_address:
                    address: {}
                    port_value: {}
      lb_policy: {}
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http2_protocol_options: {{}}
      metadata:
        filter_metadata:
          envoy.eric_proxy.cluster:
            prod1.ericsson.com:
            - {}
    )EOF",
                  name, name, address, port, address, port, lb_policy, metadata));
}

  // Regression test to catch the code declaring a gRPC service method for {SotW,delta}
  // when the user's bootstrap config asks for the other type.
  void verifyGrpcServiceMethod() {
    EXPECT_TRUE(xds_stream_->waitForHeadersComplete());
    Envoy::Http::LowerCaseString path_string(":path");
    std::string expected_method(
        sotwOrDelta() == Grpc::SotwOrDelta::Sotw || sotwOrDelta() == Grpc::SotwOrDelta::UnifiedSotw
            ? "/envoy.service.cluster.v3.ClusterDiscoveryService/StreamClusters"
            : "/envoy.service.cluster.v3.ClusterDiscoveryService/DeltaClusters");
    EXPECT_EQ(xds_stream_->headers().get(path_string)[0]->value(), expected_method);
  }

  void acceptXdsConnection() {
    AssertionResult result = // xds_connection_ is filled with the new FakeHttpConnection.
        fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, xds_connection_);
    RELEASE_ASSERT(result, result.message());
    result = xds_connection_->waitForNewStream(*dispatcher_, xds_stream_);
    RELEASE_ASSERT(result, result.message());
    xds_stream_->startGrpcStream();
    verifyGrpcServiceMethod();
  }

  envoy::config::cluster::v3::Cluster cluster1_;
  envoy::config::cluster::v3::Cluster cluster2_;
  // True if we decided not to run the test after all.
  bool test_skipped_{true};
  Http::CodecType upstream_codec_type_{Http::CodecType::HTTP2};
  std::function<envoy::config::cluster::v3::Cluster(
      const std::string&, int, const std::string&,
      const envoy::config::cluster::v3::Cluster::LbPolicy)>
      cluster_creator_;
};

INSTANTIATE_TEST_SUITE_P(IpVersionsClientTypeDelta, EricProxyCdsUpdate,
                         DELTA_SOTW_GRPC_CLIENT_INTEGRATION_PARAMS);

// 1) Envoy starts up with no static clusters (other than the CDS-over-gRPC server).
// 2) Envoy is told of a cluster via CDS.
// 3) We send Envoy a request, which we verify is properly proxied to and served by that cluster.
// 4) Envoy is told that cluster is gone.
// 5) We send Envoy a request, which should 503.
// 6) Envoy is told that the cluster is back.
// 7) We send Envoy a request, which we verify is properly proxied to and served by that cluster.
TEST_P(EricProxyCdsUpdate, CdsClusterUpDownUp) {
  // Calls our initialize(), which includes establishing a listener, route, and cluster.
  config_helper_.addConfigModifier(configureProxyStatus());
  testRouterHeaderOnlyRequestAndResponse(nullptr, UpstreamIndex1, "/cluster1");
  test_server_->waitForCounterGe("cluster_manager.cluster_added", 1);

  // Tell Envoy that cluster_1 is gone.
  EXPECT_TRUE(compareDiscoveryRequest(Config::TypeUrl::get().Cluster, "55", {}, {}, {}));
  sendDiscoveryResponse<envoy::config::cluster::v3::Cluster>(Config::TypeUrl::get().Cluster, {}, {},
                                                             {ClusterName1}, "42");
  // We can continue the test once we're sure that Envoy's ClusterManager has made use of
  // the DiscoveryResponse that says cluster_1 is gone.
  test_server_->waitForCounterGe("cluster_manager.cluster_removed", 1);

  // Now that cluster_1 is gone, the listener (with its routing to cluster_1) should 503.
  BufferingStreamDecoderPtr response = IntegrationUtil::makeSingleRequest(
      lookupPort("http"), "GET", "/cluster1", "", downstream_protocol_, version_, "foo.com");
  ASSERT_TRUE(response->complete());
  EXPECT_EQ("503", response->headers().getStatusValue());
  EXPECT_EQ(response->headers().getProxyStatusValue(),
            "envoy; error=destination_unavailable; details=\"cluster_not_found; NC\"");

  cleanupUpstreamAndDownstream();
  ASSERT_TRUE(codec_client_->waitForDisconnect());

  cluster1_ = buildCustomStaticCluster(
    ClusterName1, fake_upstreams_[UpstreamIndex1]->localAddress()->ip()->port(),
    Network::Test::getLoopbackAddressString(ipVersion()), "ROUND_ROBIN", "scp2.ericsson.se");

  // Tell Envoy that cluster_1 is back.
  EXPECT_TRUE(compareDiscoveryRequest(Config::TypeUrl::get().Cluster, "42", {}, {}, {}));
  sendDiscoveryResponse<envoy::config::cluster::v3::Cluster>(Config::TypeUrl::get().Cluster,
                                                             {cluster1_}, {cluster1_}, {}, "413");

  // We can continue the test once we're sure that Envoy's ClusterManager has made use of
  // the DiscoveryResponse describing cluster_1 that we sent. Again, 2 includes CDS server.
  test_server_->waitForGaugeGe("cluster_manager.active_clusters", 2);

  // Does *not* call our initialize().
  testRouterHeaderOnlyRequestAndResponse(nullptr, UpstreamIndex1, "/cluster1");

  cleanupUpstreamAndDownstream();
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy