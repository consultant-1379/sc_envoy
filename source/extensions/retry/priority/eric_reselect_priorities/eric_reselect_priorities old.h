#pragma once

#include "envoy/upstream/retry.h"
#include "source/common/upstream/load_balancer_impl.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace Envoy {
namespace Extensions {
namespace Retry {
namespace Priority {

class EricReselectRetryPriority : public Upstream::RetryPriority,
                                  public Logger::Loggable<Logger::Id::upstream> {
public:
  EricReselectRetryPriority(google::protobuf::uint32 preferred_host_retries,
                            google::protobuf::uint32 failover_reselects,
                            google::protobuf::uint32 last_resort_reselects,
                            bool support_temporary_blocking, bool support_loop_prevention, uint32_t)
      : preferred_host_retries_(preferred_host_retries + 1),
        failover_reselects_(failover_reselects), last_resort_reselects_(last_resort_reselects),
        support_temporary_blocking_(support_temporary_blocking),
        support_loop_prevention_(support_loop_prevention) {}
  class PrioritiesContext {
  public:
    void
    instantiatePrioritiesContext(const Upstream::PrioritySet& priority_set,
                                 const Upstream::HealthyAndDegradedLoad& original_priority_load,
                                 const PriorityMappingFunc& priority_mapping_func,
                                 const std::set<std::string>& via_header_hosts,
                                 EricReselectRetryPriority* parent);

    uint32_t currentPriority() { return current_priority_level_; };
    void adjustPriorityIndexForNextIteration() {

      if (current_priority_level_ == next_priority_level_) {
        // no indermediate jumps have been performed
        // increase prio index by one
        next_priority_level_ = ++current_priority_level_;
      } else {
        // we have jumped priorities in the last processing
        current_priority_level_ = next_priority_level_;
      }
    }

    // jumps a priority level because only the preferred host resides on the next one,
    //  respecting boundaries calculated in instantiatePrioritiesContext
    // effectively this means if there are vacant priorities in the
    // primary cluster, jump to the start prio of the lr cluster
    //   |-----|-----|----|----
    //   sp    ep    sl   el
    void jumpPriorityLevel() {
      auto new_prio = next_priority_level_ + 2;
      if (new_prio <= end_prio_primary_) {
        next_priority_level_ = new_prio;

      } else if (hasLastResortHosts()) {
        if (new_prio <= *start_prio_last_resort_) {
          next_priority_level_ = *start_prio_last_resort_;
        } else if (new_prio <= *end_prio_last_resort_) {
          next_priority_level_ = new_prio;
        }
      }
    }
    uint32_t getEndPrioPrimary() { return end_prio_primary_; };
    // void adjustConfiguredReselects(const Upstream::PrioritySet& priority_set);

    // Atempts to find a host belonging to a different cluster (the second cluster member in
    // aggregate
    // cluster configuration) If found, marks all priorities up to its priorities level as excluded
    // and returns the new 'current_priority_' level
    void excludePriosUptoLastResort(std::vector<bool>& excluded_priorities);

    bool hasLastResortHosts() const { return start_prio_last_resort_.has_value(); };

    bool isLastPriorityReached() const {
      if (hasLastResortHosts()) {
        return current_priority_level_ == *end_prio_last_resort_;
      } else {
        return current_priority_level_ == end_prio_primary_;
      }
    }

    // flag to indicate priority levels have been adjusted for last resort cluster, i.e. a jump in
    // priorites was made when failover_reselects exhausted
    bool prios_adjusted_for_last_resort_{false};

  private:
    uint32_t current_priority_level_;
    uint32_t next_priority_level_;

    absl::optional<uint32_t> start_prio_last_resort_ = absl::nullopt;
    absl::optional<uint32_t> end_prio_last_resort_ = absl::nullopt;

    uint32_t end_prio_primary_;
  };

  const Upstream::HealthyAndDegradedLoad&
  determinePriorityLoad(const Upstream::PrioritySet& priority_set,
                        const Upstream::HealthyAndDegradedLoad& original_priority_load,
                        const PriorityMappingFunc& priority_mapping_func) override;

  void determineNextPriority(const Upstream::PrioritySet& priority_set,
                             const Upstream::HealthyAndDegradedLoad& original_priority_load,
                             const PriorityMappingFunc& priority_mapping_func,
                             const std::set<std::string>& via_header_hosts) override;

  uint32_t& preferredHostRetries() override { return preferred_host_retries_; }

  /*
   * onHostAttempted() is called by the router regardless if it's a retry or not so we also need to
   * cater for the first try by adding an extra try
   */
  void onHostAttempted(Upstream::HostDescriptionConstSharedPtr attempted_host) override;

  // keep going as long as:
  // - there are either pref retries failover reselects or lrp reselects left
  // -  not all priorities are exhausted i.e. if we are in the last prio it has hosts left
  // due to the call sequence we need to know if the last prio has been exhausted prior
  // to determinePriorityLoad() being invoked by the retry_state.
  // that's where the remaining_hosts_in_curr_prio_level_ comes into play
  bool shouldRetry() const override {

    auto should_retry =
        (preferred_host_retries_ | last_resort_reselects_ | failover_reselects_ > 0) &&
        (!isLastPriorityReached() || (remaining_hosts_in_curr_prio_level_ > 0));

    auto current_prio = prio_context_ ? prio_context_->currentPriority() : 0;
    ENVOY_LOG(debug,
              "CHARDOU: shouldRetry(): {}, isLastPriorityReached(): {}, remaining hosts "
              "in prio {} : {}",
              should_retry, isLastPriorityReached(), current_prio,
              remaining_hosts_in_curr_prio_level_);
    return should_retry;
  }

private:
  void recalculatePerPriorityState(uint32_t priority, const Upstream::PrioritySet& priority_set) {
    // Recalculate health and priority the same way the load balancer does it.
    Upstream::LoadBalancerBase::recalculatePerPriorityState(
        priority, priority_set, per_priority_load_, per_priority_health_, per_priority_degraded_,
        total_healthy_hosts_);
  }

  uint32_t adjustedAvailability(std::vector<uint32_t>& per_priority_health,
                                std::vector<uint32_t>& per_priority_degraded) const;

  bool isLastPriorityReached() const {
    if (prio_context_) {

      return prio_context_->isLastPriorityReached();
    }
    return false;
  }

  bool isLastPriorityExhausted() const {
    return isLastPriorityReached() && excluded_priorities_[prio_context_->currentPriority()];
  }

  // this exists to cater for edge case where retries>0 failover_reselects_=0 and lrp reselects >0
  // and in the first iteration of determinePriorityLoad() a jump needs to happen
  bool maybeSkipToLastResort() const {
    return ((!prio_context_->prios_adjusted_for_last_resort_) && (last_resort_reselects_ > 0) &&
            (failover_reselects_ == 0));
  }

  // Distributes priority load between priorities that should be considered after
  // excluding attempted priorities.
  // @return whether the adjustment was successful. If not, the original priority load should be
  // used.
  bool adjustForAttemptedPriorities(const Upstream::PrioritySet& priority_set);

  // Atempts to find a host belonging to a different cluster (the second cluster member in aggregate
  // cluster configuration) If found, marks all priorities up to its priorities level as excluded
  // and returns the new 'current_priority_' level
  uint32_t excludePriosUptoLastResort(const Upstream::PrioritySet& priority_set,
                                      const PriorityMappingFunc& priority_mapping_func);

  // wrapper function that checks if the pre-computed per_priority_load_ is valid,
  // otherwise returns the original
  const Upstream::HealthyAndDegradedLoad& getPrecomputedOrOriginalPriorityLoad(
      const Upstream::HealthyAndDegradedLoad& original_priority_load);

  uint32_t countHostsOnPrioLevel(const Envoy::Upstream::HostVector& hosts,
                                 const std::set<std::string>& via_header_hosts);

  std::string vectorToStr(Upstream::HealthyAndDegradedLoad);
  uint32_t preferred_host_retries_;
  uint32_t failover_reselects_;
  uint32_t last_resort_reselects_;

  absl::optional<Upstream::HostDescriptionConstSharedPtr> first_host_ = absl::nullopt;
  uint32_t remaining_hosts_in_curr_prio_level_;
  std::vector<uint32_t> healthy_hosts_per_prio_;
  std::vector<bool> excluded_priorities_;
  std::vector<std::vector<Upstream::HostDescriptionConstSharedPtr>> attempted_hosts_per_priority_;
  Upstream::HealthyAndDegradedLoad per_priority_load_;
  Upstream::HealthyAvailability per_priority_health_;
  Upstream::DegradedAvailability per_priority_degraded_;
  uint32_t total_healthy_hosts_;
  bool invoked_once_{false};
  bool support_temporary_blocking_;
  bool support_loop_prevention_;
  std::unique_ptr<PrioritiesContext> prio_context_;
};

} // namespace Priority
} // namespace Retry
} // namespace Extensions
} // namespace Envoy