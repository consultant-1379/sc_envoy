#include "cluster_configurator.h"

using namespace fmt::literals;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using ClusterDefinition = std::vector<std::pair<std::string, std::vector<std::string>>>;

class BasicClusterConfigurator : public ClusterConfigurator {
public:
  BasicClusterConfigurator(ClusterDefinition&& cluster_def)
    : cluster_def_(std::move(cluster_def)) {
    cluster_configs_.reserve(cluster_def_.size());
  }

  const std::vector<std::string>&
  getConfigForClusters(const std::string& ip_version) override {
    for (auto& cluster_entry : cluster_def_) {
      cluster_configs_.push_back(getConfigForCluster(cluster_entry, ip_version));
      upstream_count_ += cluster_entry.second.size();
    }
    return cluster_configs_;
  }

  uint32_t upstreamCount() override { return upstream_count_; }

private:
  // Create and return the configuration for one cluster including all endpoints
  // First element of the pair is the cluster name, second element a list of endpoints
  static std::string getConfigForCluster(
    std::pair<std::string, std::vector<std::string>>& cluster_entry,
    const std::string& ip_version
  ) {
    auto cluster = clusterConfig(cluster_entry.first);
    for (auto& host : cluster_entry.second) {
      auto endpoint = endpointConfig(host, ip_version);
      absl::StrAppend(&cluster, endpoint);
    }
    return cluster;
  }

  // Beginning of a cluster configuration
  static std::string clusterConfig(const std::string& name) {
    return fmt::format(R"EOF(
name: '{name}'
connect_timeout: 15s
load_assignment:
  cluster_name: '{name}'
  endpoints:
)EOF",
      "name"_a = name
    );
  }

  // Common  cluster endpoint configuration
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
      "hostname"_a = hostname, "ip_address"_a = ip_address
    );
  }

  ClusterDefinition cluster_def_;
  std::vector<std::string> cluster_configs_;
  uint32_t upstream_count_{0};
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy