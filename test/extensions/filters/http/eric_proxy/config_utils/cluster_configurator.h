#pragma once

#include <string>
#include <vector>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

class ClusterConfigurator {

public:
  virtual ~ClusterConfigurator() = default;

  virtual const std::vector<std::string>& getConfigForClusters(const std::string& ip_version) = 0;
  virtual uint32_t upstreamCount() = 0;
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy