#include "cluster_configurator.h"

using namespace fmt::literals;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using ClusterDefinition = std::vector<std::pair<std::string, std::vector<std::pair<std::string, std::vector<std::string>>>>>;

class EndpointMetadataClusterConfigurator : public ClusterConfigurator {
public:
  EndpointMetadataClusterConfigurator(ClusterDefinition&& cluster_def)
    : cluster_def_(std::move(cluster_def)) {
    cluster_configs_.reserve(cluster_def_.size());
  }

  EndpointMetadataClusterConfigurator(
    ClusterDefinition&& cluster_def, std::vector<std::string>&& aggregate_cluster
  ) : cluster_def_(std::move(cluster_def)), aggregate_cluster_(std::move(aggregate_cluster)){
    cluster_configs_.reserve(cluster_def_.size() + 1);
  }

  EndpointMetadataClusterConfigurator(
    ClusterDefinition&& cluster_def, std::vector<std::string>& cluster_mds) :
      cluster_def_(std::move(cluster_def)), 
      cluster_mds_(cluster_mds)
    {
      cluster_configs_.reserve(cluster_def_.size());

    }

  const std::vector<std::string>&
  getConfigForClusters(const std::string& ip_version) override {
    int i = 0;
    for (auto& cluster_entry : cluster_def_) {
      if(cluster_mds_.size() != cluster_def_.size()) {
        cluster_configs_.push_back(getConfigForCluster(cluster_entry, ip_version,""));
      } else {
        cluster_configs_.push_back(getConfigForCluster(cluster_entry, ip_version,cluster_mds_[i]));
        i++;
      }
      upstream_count_ += cluster_entry.second.size();
    }
    if (!aggregate_cluster_.empty()) {
      cluster_configs_.push_back(aggregateClusterConfig(
        aggregate_cluster_.at(0), aggregate_cluster_.at(1),
        aggregate_cluster_.at(2)
      ));
    }
    return cluster_configs_;
  }
  

  uint32_t upstreamCount() override { return upstream_count_; }

private:
  // Create and return the configuration for one cluster including all endpoints
  // and metadata.
  // First element of the pair is the cluster name, second element is a list of pair
  // of endpoint and its list of support metadata
  static std::string getConfigForCluster(
    std::pair<std::string, std::vector<std::pair<std::string, std::vector<std::string>>>>& cluster_entry,
    const std::string& ip_version,
     std::string metadata = ""
  ) {
    auto cluster = clusterConfig(cluster_entry.first);
    for (auto& host : cluster_entry.second) {
      auto endpoint = endpointConfig(host.first, ip_version);
      for (auto& support_md : host.second) {
        auto support = endpointSupportMetadataConfig(support_md);
        absl::StrAppend(&endpoint, support);
      }
      absl::StrAppend(&cluster, endpoint);
    }
    if(!metadata.empty()) {

     absl::StrAppend(&cluster,metadata) ;
    } 

    return cluster;
  }

  // Common cluster configuration
  static std::string clusterConfig(const std::string& name) {
    
    auto cluster = fmt::format(R"EOF(
name: '{name}'
connect_timeout: 15s
load_assignment:
  cluster_name: '{name}'
  endpoints:
)EOF",
      "name"_a = name
    );
    return cluster;
  }

  // Common cluster endpoint configuration
  static std::string endpointConfig(
    const std::string& hostname, const std::string& ip_address
  ) {
    return fmt::format(R"EOF(
  - priority: 0
    lb_endpoints:
    - endpoint:
        address:
          socket_address:
            address: {ip_address}
            port_value: 0
        hostname: {hostname}
      metadata:
        filter_metadata:
          envoy.eric_proxy:
            support:
)EOF",
      "hostname"_a = hostname, "ip_address"_a = ip_address
    );
  }

  // Common endpoint metadata for "support"
  static std::string endpointSupportMetadataConfig(std::string& support) {
    return fmt::format(R"EOF(
            - {support}
)EOF", "support"_a = support);
  }

  // Common aggregate cluster configuration
  static std::string aggregateClusterConfig(
    const std::string& aggregate_cluster,
    const std::string& primary_cluster,
    const std::string& last_resort_cluster
  ) {
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
    "aggregate_cluster"_a = aggregate_cluster, "primary_cluster"_a = primary_cluster,
    "last_resort_cluster"_a = last_resort_cluster
    );
  }

  ClusterDefinition cluster_def_;
  std::vector<std::string> aggregate_cluster_;
  std::vector<std::string> cluster_configs_;
  std::vector<std::string> cluster_mds_;
  uint32_t upstream_count_{0};
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy