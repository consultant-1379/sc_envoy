#pragma once

#include "envoy/upstream/retry.h"
#include "source/common/upstream/load_balancer_impl.h"
#include <algorithm>
#include <bitset>
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
      : preferred_host_retries_(preferred_host_retries), failover_reselects_(failover_reselects),
        last_resort_reselects_(last_resort_reselects),
        support_temporary_blocking_(support_temporary_blocking),
        support_loop_prevention_(support_loop_prevention) {}

  const Upstream::HealthyAndDegradedLoad&
  determinePriorityLoad(const Upstream::PrioritySet& priority_set,
                        const Upstream::HealthyAndDegradedLoad& original_priority_load,
                        const PriorityMappingFunc& priority_mapping_func,
                        const std::vector<absl::string_view>& via_header_hosts) override;

  // void analyzePrioritySet(const Upstream::PrioritySet& priority_set,
  //                         const Upstream::HealthyAndDegradedLoad& original_priority_load,
  //                         const PriorityMappingFunc& priority_mapping_func) override;

  uint32_t& preferredHostRetries() override { return preferred_host_retries_; }

  /*
   * onHostAttempted() is called by the router regardless if it's a retry or not so we also need to
   * cater for the first try by adding an extra try
   */
  void onHostAttempted(Upstream::HostDescriptionConstSharedPtr attempted_host) override;

  bool shouldRetry() const override;

private:
  void determineNextPriority(const Upstream::PrioritySet& priority_set,
                             const PriorityMappingFunc& priority_mapping_func, bool skip_to_lrp);

  uint32_t findNextPriority(const Upstream::PrioritySet& priority_set,
                            const PriorityMappingFunc& priority_mapping_func, uint32_t start_index,
                            uint32_t& remaining_hosts_on_prio, bool skip_to_lrp);

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

  uint32_t countHostsOnPrioLevel(const Envoy::Upstream::HostVector& hosts);

  uint32_t alreadyTriedHostsOnPrioLevel(const Upstream::PrioritySet& priority_set,
                                        const PriorityMappingFunc& priority_mapping_func,
                                        uint32_t prio_level);
  bool shouldSkipToLastResort() const {
    // if it's the first try do not skip to last resort (which would happen if configured
    // failover_reselects ==0)
    if (!invoked_once_) {
      return false;
    }
    return (!preferred_host_retries_ && (!prio_context_->prios_adjusted_for_last_resort) &&
            (last_resort_reselects_ > 0) && (failover_reselects_ == 0));
  }

  bool configuredReselectsRemainingForPrio(const uint32_t& prio_lvl) const {
    if (prio_context_ && prio_context_->lrp_priority.has_value()) {
      // there is a last resort pool and its priority range is investigated
      if (prio_lvl >= prio_context_->lrp_priority.value()) {
        return last_resort_reselects_ > 0;
      } else {
        return failover_reselects_ > 0;
      }
    }
    // TODO: this means the lrp priority is not encountered yet and has to be taken care of
    // in a better way. For now trust config input that if there are lrp reselects configured
    // there is also a pool
    return (failover_reselects_ | last_resort_reselects_);
  }

  std::string vectorToStr(Upstream::HealthyAndDegradedLoad);
  uint32_t preferred_host_retries_;
  uint32_t failover_reselects_;
  uint32_t last_resort_reselects_;
  uint32_t remaining_hosts_in_curr_prio_level_ = 0;
  uint32_t remaining_hosts_in_next_prio_level_ = 0;

  uint32_t current_priority_level_ = 0;
  absl::optional<uint32_t> next_priority_level_ = absl::nullopt;

  std::vector<bool> excluded_priorities_;
  Upstream::HealthyAndDegradedLoad per_priority_load_;
  Upstream::HealthyAvailability per_priority_health_;
  Upstream::DegradedAvailability per_priority_degraded_;
  uint32_t total_healthy_hosts_;
  bool invoked_once_{false};
  bool support_temporary_blocking_;
  bool support_loop_prevention_;
  const std::vector<absl::string_view>* via_header_hosts_{nullptr};

  class PrefHostHander {

    using elem_t = std::pair<Upstream::HostDescriptionConstSharedPtr, std::bitset<2>>;

  public:
    PrefHostHander() { pref_hosts_.reserve(1); }
    void insert(Upstream::HostDescriptionConstSharedPtr h) {
      if (std::none_of(pref_hosts_.begin(), pref_hosts_.end(),
                       [h](elem_t i) { return i.first == h; })) {
        pref_hosts_.push_back(std::make_pair(h, std::bitset<2>{0b00}));
      }
    }

    std::string toString() const {
      std::ostringstream oss;
      oss << "preferred hosts: [\n";
      for (const auto& i : pref_hosts_) {
        oss << i.first << ", status(unhealthy, processed): [" << i.second.to_string() << "]\n";
      }
      oss << "]\n";
      return oss.str();
    }

    bool isEmpty() const { return pref_hosts_.empty(); }

    std::vector<elem_t>::const_iterator end() const { return pref_hosts_.end(); }

    std::vector<Upstream::HostDescriptionConstSharedPtr>
    hostsInPrioLevel(const uint32_t prio_level, const PriorityMappingFunc& priority_mapping_func) {
      std::vector<Upstream::HostDescriptionConstSharedPtr> ret;
      for (auto& h : pref_hosts_) {
        absl::optional<uint32_t> host_priority = priority_mapping_func(*h.first);
        if (host_priority && *host_priority == prio_level) {
          // mark host as encountered
          h.second.set(0);
          ret.push_back(h.first);
        }
      }
      return ret;
    }

    std::vector<elem_t>::iterator find(Upstream::HostDescriptionConstSharedPtr val) {
      for (auto it = pref_hosts_.begin(); it != pref_hosts_.end(); it++) {
        if (it->second[0]) {
          // already processed
          continue;
        }
        if (it->first == val) {
          // found, exclude it
          it->second.set(0);
          // check health and set it
          return it;
        }
      }
      return pref_hosts_.end();
    }

    bool healthy(std::vector<elem_t>::iterator it) { return !it->second[1]; }

    bool allExcluded() {
      if (all_excluded_) {
        return all_excluded_;
      }
      for (auto it = pref_hosts_.begin(); it != pref_hosts_.end(); it++) {
        if (!it->second[0]) {
          return false;
        }
      }
      all_excluded_ = !all_excluded_;
      return all_excluded_;
    }

    bool noneHealthy() {
      for (auto it = pref_hosts_.begin(); it != pref_hosts_.end(); it++) {
        if (!it->second[1]) {
          return false;
        }
      }
      return true;
    }

  private:
    // stores the hosts tried during preferred host retries. By default it's one (the same host)
    // but can be different when in dual stack mode and the preferred host is searched via fqdn
    // The bitset's LSB signifies if this host has already been seen when processing the priority
    // levels and does not need to be considered for further processing and the MSB if it was found
    // unhealthy or not due to outlier detection
    std::vector<elem_t> pref_hosts_;
    bool all_excluded_{false};
  };

  PrefHostHander ph_handler_;

  struct PriorityContext {
    PriorityContext(uint32_t priority_set_size) : last_primary_priority(priority_set_size - 1) {}
    // absl::string_view primary_cluster_name; maybe used in the future
    // absl::string_view lrp_cluster_name;  maybe used in the future
    absl::optional<uint32_t> lrp_priority = absl::nullopt;
    uint32_t last_primary_priority;
    bool prios_adjusted_for_last_resort{false};
  };
  std::unique_ptr<PriorityContext> prio_context_;
};

} // namespace Priority
} // namespace Retry
} // namespace Extensions
} // namespace Envoy