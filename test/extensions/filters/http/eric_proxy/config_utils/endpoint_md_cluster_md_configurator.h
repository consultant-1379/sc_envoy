#include "cluster_configurator.h"
#include "metadata_builder.h"

using namespace fmt::literals;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using ClusterMd = std::map<std::string, std::vector<std::map<std::string, std::string>>>;
using HostListMd = std::map<std::string, std::vector<std::string>>;

class EndpointBuilder {
public:
  EndpointBuilder& withHostName(const std::string& hostname) {
    hostname_ = hostname;
    return *this;
  }
  EndpointBuilder& withHostMd(HostListMd&& host_list_md_map = {},
                              std::map<std::string, std::string>&& md_map = {}) {
    host_md_ = MetadataBuilder::getMetadata("envoy.eric_proxy", std::move(host_list_md_map),
                                            std::move(md_map));
    return *this;
  }
  EndpointBuilder& withHostScheme(bool is_http = true){
    if(is_http) {
      int pre_padding = 10;
      absl::StrAppend(&host_md_, std::string(pre_padding,' '),"envoy.transport_socket_match", ":\n");
      int padding = 12;
      absl::StrAppend(&host_md_, std::string(padding, ' '), "matchTLS", ": ",
                      fmt::format("[\"{}\"]", "false"), "\n");
   

    } else {
      int pre_padding = 10;
      absl::StrAppend(&host_md_, std::string(pre_padding,' '),"envoy.transport_socket_match", ":\n");
      int padding = 12;
      absl::StrAppend(&host_md_, std::string(padding, ' '), "matchTLS", ": ",
                      fmt::format("[\"{}\"]", "true"), "\n");
    }

    return *this;
  }

  std::string getEndpointConfig(const std::string& ip_version) {
    return absl::StrCat(endpointConfig(hostname_, ip_version), host_md_);
  }

private:
  // Common cluster endpoint configuration
  static std::string endpointConfig(const std::string& hostname, const std::string& ip_address) {
    return fmt::format(R"EOF(
  - priority: 0
    lb_endpoints:
    - endpoint:
        address:
          socket_address:
            address: {ip_address}
            port_value: 0
        hostname: {hostname}
      )EOF",
                       "hostname"_a = hostname, "ip_address"_a = ip_address);
  }

  std::string hostname_;
  std::string host_md_;
};

class ClusterBuilder {
public:
  ClusterBuilder& withName(const std::string& name) {
    cluster_name_ = name;
    return *this;
  }
  ClusterBuilder& withClusterMd(ClusterMd&& md_map) {
    cluster_md_ =
        MetadataBuilder::getClusterMetadata("envoy.eric_proxy.cluster", std::move(md_map));
    return *this;
  }

  ClusterBuilder& withEndpoint(EndpointBuilder endpoint) {
    endpoints_.push_back(endpoint);
    return *this;
  }

  std::string getConfigForCluster(const std::string& ip_version) {
    auto cluster_config = clusterConfig(cluster_name_);
    for (auto& host : endpoints_) {

      absl::StrAppend(&cluster_config, host.getEndpointConfig(ip_version));
    }
    absl::StrAppend(&cluster_config, cluster_md_);
    return cluster_config;
  }
  uint32_t getEndpointsSize() { return endpoints_.size(); }

private:
  // Common cluster configuration
  static std::string clusterConfig(const std::string& name) {
    return fmt::format(R"EOF(
name: '{name}'
connect_timeout: 15s
load_assignment:
  cluster_name: '{name}'
  endpoints:
)EOF",
                       "name"_a = name);
  }

  std::string cluster_name_;
  std::string cluster_md_;
  std::vector<EndpointBuilder> endpoints_;
};

class EndpointMetadataClusterConfigurator : public ClusterConfigurator {
public:
  EndpointMetadataClusterConfigurator& withClusterBuilder(ClusterBuilder cb) {
    clusters_.push_back(cb);
    return *this;
  }
  EndpointMetadataClusterConfigurator&
  withAggregateCluster(std::vector<std::string>&& aggr_cluster) {
    aggregate_cluster_ = std::move(aggr_cluster);
    return *this;
  }
  const std::vector<std::string>& getConfigForClusters(const std::string& ip_version) override {
    for (auto& cluster : clusters_) {
      cluster_configs_.push_back(cluster.getConfigForCluster(ip_version));
      upstream_count_ += cluster.getEndpointsSize();
    }
    if (!aggregate_cluster_.empty()) {
      cluster_configs_.push_back(aggregateClusterConfig(
          aggregate_cluster_.at(0), aggregate_cluster_.at(1), aggregate_cluster_.at(2)));
    }
    return cluster_configs_;
  }

  uint32_t upstreamCount() override { return upstream_count_; }

private:
  // Common aggregate cluster configuration
  static std::string aggregateClusterConfig(const std::string& aggregate_cluster,
                                            const std::string& primary_cluster,
                                            const std::string& last_resort_cluster) {
    return fmt::format(R"EOF(
name: '{aggregate_cluster}'
connect_timeout: 15s
lb_policy: CLUSTER_PROVIDED
cluster_type:
  name: envoy.clusters.aggregate
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
    clusters:
    - '{primary_cluster}'
    - '{last_resort_cluster}'
)EOF",
                       "aggregate_cluster"_a = aggregate_cluster,
                       "primary_cluster"_a = primary_cluster,
                       "last_resort_cluster"_a = last_resort_cluster);
  }

  uint32_t upstream_count_;
  std::vector<ClusterBuilder> clusters_;
  std::vector<std::string> aggregate_cluster_;
  std::vector<std::string> cluster_configs_;
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy