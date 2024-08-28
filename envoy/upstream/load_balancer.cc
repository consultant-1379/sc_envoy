#include "load_balancer.h"
namespace Envoy {
namespace Upstream {

void LoadBalancer::analyzePrioritySet(LoadBalancerContext*) {
  ENVOY_LOG_MISC(debug, "analyzePrioritySet default impl");
};

void LoadBalancerContext::finalizePreferredHostRetries(){};

void LoadBalancerContext::setSniFromHostName(const absl::string_view) {};
void LoadBalancerContext::setAutoSanValidation(const absl::string_view) {};

} // namespace Upstream
} // namespace Envoy