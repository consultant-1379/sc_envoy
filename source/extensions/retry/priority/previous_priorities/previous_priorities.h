#pragma once

#include "envoy/upstream/retry.h"

#include "source/common/upstream/load_balancer_impl.h"
#include <cstdint>

namespace Envoy {
namespace Extensions {
namespace Retry {
namespace Priority {

class PreviousPrioritiesRetryPriority : public Upstream::RetryPriority {
public:
  PreviousPrioritiesRetryPriority(google::protobuf::RepeatedField<google::protobuf::uint32> update_frequency, uint32_t max_retries)
      : update_frequency_(update_frequency) {
    attempted_hosts_.reserve(max_retries);
  }

  const Upstream::HealthyAndDegradedLoad&
  determinePriorityLoad(const Upstream::PrioritySet& priority_set,
                        const Upstream::HealthyAndDegradedLoad& original_priority_load,
                        const PriorityMappingFunc& priority_mapping_func,
                        const std::vector<absl::string_view>&) override;

  void onHostAttempted(Upstream::HostDescriptionConstSharedPtr attempted_host) override {
    attempted_hosts_.emplace_back(attempted_host);
  }

  // these three functions only apply for the eric_reselect_priorities predicate
  // and are just default interface implementations
  uint32_t& preferredHostRetries() override { return preferred_host_retries_; }
  bool shouldRetry() const override { return true; }

private:
  void recalculatePerPriorityState(uint32_t priority, const Upstream::PrioritySet& priority_set) {
    // Recalculate health and priority the same way the load balancer does it.
    Upstream::LoadBalancerBase::recalculatePerPriorityState(
        priority, priority_set, per_priority_load_, per_priority_health_, per_priority_degraded_,
        total_healthy_hosts_);
  }

  uint32_t adjustedAvailability(std::vector<uint32_t>& per_priority_health,
                                std::vector<uint32_t>& per_priority_degraded) const;

  // Distributes priority load between priorities that should be considered after
  // excluding attempted priorities.
  // @return whether the adjustment was successful. If not, the original priority load should be
  // used.
  bool adjustForAttemptedPriorities(const Upstream::PrioritySet& priority_set);

  const google::protobuf::RepeatedField<google::protobuf::uint32> update_frequency_;
  std::vector<Upstream::HostDescriptionConstSharedPtr> attempted_hosts_;
  std::vector<bool> excluded_priorities_;
  Upstream::HealthyAndDegradedLoad per_priority_load_;
  Upstream::HealthyAvailability per_priority_health_;
  Upstream::DegradedAvailability per_priority_degraded_;
  uint32_t total_healthy_hosts_;
  uint32_t preferred_host_retries_{0};
  // The current priority level used to track the correct update frequency list element
  int32_t current_priority_level_ = 0;
};

} // namespace Priority
} // namespace Retry
} // namespace Extensions
} // namespace Envoy
