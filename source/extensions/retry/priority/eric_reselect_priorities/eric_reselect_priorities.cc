#include "source/extensions/retry/priority/eric_reselect_priorities/eric_reselect_priorities.h"
#include <algorithm>
#include <cstdint>
#include <iterator>
#include <memory>
#include <sstream>
#include <utility>

namespace Envoy {
namespace Extensions {
namespace Retry {
namespace Priority {

/**
 * Determines the next priority where a host is to be selected from.
 * Also, attempts to determine the next valid priority after that. That way shouldRetry() knows if
 * more retries should take place without the need of extra callbacks
 * @param priority_set current priority set.
 * @param priority_mapping_func see @Upstream::RetryPriority::PriorityMappingFunc.
 */
void EricReselectRetryPriority::determineNextPriority(
    const Upstream::PrioritySet& priority_set, const PriorityMappingFunc& priority_mapping_func,
    bool skip_to_lrp) {

  // we have analyzed the next valid priority already. However if  we have to skip to lrp prio,
  // don't use the cached value
  if (next_priority_level_.has_value() && !skip_to_lrp) {
    remaining_hosts_in_curr_prio_level_ = remaining_hosts_in_next_prio_level_;
    current_priority_level_ = *next_priority_level_;
    next_priority_level_.reset();
  } else {
    // for the first invocation, the starting prio needs to be considered
    current_priority_level_ =
        findNextPriority(priority_set, priority_mapping_func,
                         invoked_once_ ? current_priority_level_ + 1 : current_priority_level_,
                         remaining_hosts_in_curr_prio_level_, skip_to_lrp);
  }
  std::fill(excluded_priorities_.begin(), excluded_priorities_.begin() + current_priority_level_,
            true);

  // attempt to find the next valid prio
  remaining_hosts_in_next_prio_level_ = 0;
  next_priority_level_ =
      findNextPriority(priority_set, priority_mapping_func, current_priority_level_ + 1,
                       remaining_hosts_in_next_prio_level_, false);
}

/**
 * Given a priority index to start from, returns the index of the next valid priority and the number
 * of eligble hosts found. In case a skip to the last resort priority is required, the provided
 * start index is ignored, And either the cached value of the last resort prio is used (if found) or
 * the search starts from the current priority
 * @param priority_set current priority set.
 * @param priority_mapping_func see @Upstream::RetryPriority::PriorityMappingFunc.
 * @param start_index The priority to start looking from
 * @param remaining_hosts_in_prio is updated with the number of eligible hosts found for the next
 * valid priority found
 * @param skip_to_lrp Bolean indicating that the returning priority index should belong to the last
 * resort pool
 * @return the index of the next valid priority found
 */
uint32_t EricReselectRetryPriority::findNextPriority(
    const Upstream::PrioritySet& priority_set, const PriorityMappingFunc& priority_mapping_func,
    uint32_t start_index, uint32_t& remaining_hosts_on_prio, bool skip_to_lrp) {
  ASSERT(remaining_hosts_on_prio == 0);
  // proceed with analyzing the current prio level
  // DND-61812 Envoy crashes because hosSetsPerPriority() returns an empty array (happening probably because of 
  // a race condition of the state and accessing a host is causing segmentation fault
  if (priority_set.hostSetsPerPriority()[0] != nullptr &&
      !priority_set.hostSetsPerPriority()[0]->hosts().empty() &&
      priority_set.hostSetsPerPriority()[0]->hosts().back() != nullptr) {
    const auto primary_cluster_host = priority_set.hostSetsPerPriority()[0]->hosts().back();
    Upstream::HostDescriptionConstSharedPtr lrp_cluster_host;
    if (primary_cluster_host) {
      if (skip_to_lrp) {
        if (prio_context_->lrp_priority.has_value()) {
          start_index = prio_context_->lrp_priority.value();
        } else {
          start_index = current_priority_level_;
        }
      }
      while (remaining_hosts_on_prio == 0 &&
            start_index < priority_set.hostSetsPerPriority().size()) {
        if (priority_set.hostSetsPerPriority()[start_index]->hosts().empty()) {
          // an eds update can leave a priority level without hosts. These empty priorities do not get
          // removed when the priority set is updated. Skip this prio level but mark the previous one
          // as the last priority to be considered for the primary cluster
          prio_context_->last_primary_priority = start_index;
          start_index++;
          continue;
        }

        // if failover_reselects are done but lrp_reselects are configured, jump to the first priority
        // of the last resort pool
        if (!prio_context_->lrp_priority.has_value()) {
          lrp_cluster_host = priority_set.hostSetsPerPriority()[start_index]->hosts().back();
          // prio level belongs to last resort cluster. Mark the last, non empty prio level as the end
          // priority for the primary cluster and the level we are looking at as the start priority
          // for the last resort cluster
          if (lrp_cluster_host &&
              (&lrp_cluster_host->cluster() != &primary_cluster_host->cluster())) {
            for (auto i = start_index - 1; i >= 0; i--) {
              if (!priority_set.hostSetsPerPriority()[i]->hosts().empty()) {
                prio_context_->last_primary_priority = i;
                break;
              }
            }
            prio_context_->lrp_priority = start_index;
          } else if (skip_to_lrp) {
            start_index++;
            continue;
          }
        }
        remaining_hosts_on_prio = std::max<int32_t>(
            countHostsOnPrioLevel(priority_set.hostSetsPerPriority()[start_index]->hosts()) -
                alreadyTriedHostsOnPrioLevel(priority_set, priority_mapping_func, start_index),
            0);

        ENVOY_LOG(debug, "Number of eligible hosts on prio level {} : {}", start_index,
                  remaining_hosts_on_prio);
        // if there are eligible hosts for this prio level, exit otherwise proceed to investigate the
        // next level
        if (!remaining_hosts_on_prio) {
          start_index++;
        }
      }
    }
  }
  if (skip_to_lrp && prio_context_->lrp_priority && start_index >= *prio_context_->lrp_priority) {
    failover_reselects_ = 0;
    prio_context_->prios_adjusted_for_last_resort = true;
  }
  return start_index;
}

const Upstream::HealthyAndDegradedLoad& EricReselectRetryPriority::determinePriorityLoad(
    const Upstream::PrioritySet& priority_set,
    const Upstream::HealthyAndDegradedLoad& original_priority_load,
    const PriorityMappingFunc& priority_mapping_func,
    const std::vector<absl::string_view>& via_header_hosts) {

  if (!invoked_once_) {
    // The following only need to happen in the first invocation of determinePriorityLoad()
    // so at the first retry that's actually a reselect
    // * Adjust preferred host retries !! THIS IS GONE FOR NOW TO onhostattempted()
    // * resize excluded priorities vector
    // * Find the first valid priority

    excluded_priorities_.resize(priority_set.hostSetsPerPriority().size());
    // when this function is called, either pref_host_retries well performed and are over and we
    // are doing first reselect or no pref host retries were supplied and this is the first try

    prio_context_ = std::make_unique<PriorityContext>(priority_set.hostSetsPerPriority().size());
    // figure out starting prio based on original prio load
    const auto first_valid_prio =
        std::find_if_not(original_priority_load.healthy_priority_load_.get().begin(),
                         original_priority_load.healthy_priority_load_.get().end(),
                         [](uint32_t x) { return x == 0; });
    if (first_valid_prio != original_priority_load.healthy_priority_load_.get().end()) {
      current_priority_level_ =
          first_valid_prio - original_priority_load.healthy_priority_load_.get().begin();
      ENVOY_LOG(debug, "found start priority {}", current_priority_level_);
    } else {
      // this should never happen and the whole cluster is out. DeterminePrioLoad() should just
      // return the originally supplied load
      ENVOY_LOG(debug,
                "The Original priority load vector is filled with 0s, returning original "
                "priority load: {}",
                vectorToStr(original_priority_load));
      invoked_once_ = true;

      return original_priority_load;
    }

    if (priority_set.hostSetsPerPriority()[0]->hosts().empty()) {
      // This effectively means the cluster has no hosts. Again return the original prio load as
      // we can't really do much
      ENVOY_LOG(debug,
                "No hosts found on selected priority level 0, returning original priority load: {}",
                vectorToStr(original_priority_load));
      invoked_once_ = true;
      return original_priority_load;
    }
    if (support_loop_prevention_) {
      // if the supplied via header contents are empty even when supporting loop prevention
      // don't bother with it but don't leave the point dangling
      if (via_header_hosts.empty()) {
        support_loop_prevention_ = false;
      }
      via_header_hosts_ = &via_header_hosts;
    }
  }

  // If there are eligible remaining hosts in this prio level,
  //  AND there are reselects available, return the precomputed/original
  // load
  bool skip_to_lrp = shouldSkipToLastResort();
  if (remaining_hosts_in_curr_prio_level_ > 0 && !skip_to_lrp) {
    // Returning per_priority_load_ is safe as in the first invocation,
    // remaining_hosts_in_curr_prio_level_ is initialized to 0
    ENVOY_LOG(debug, "ReselectPriorities returning priority load : {}",
              vectorToStr(per_priority_load_));
    return per_priority_load_;
  } else {
    // tried all hosts in this priority level, the procedure to calculate
    // the next priority level starts
    if (invoked_once_) {
      ENVOY_LOG(debug, "ReselectPriorities tried all hosts in  prio level: {}",
                current_priority_level_);
    }
    remaining_hosts_in_curr_prio_level_ = 0;
    determineNextPriority(priority_set, priority_mapping_func, skip_to_lrp);
    ENVOY_LOG(debug, "excluded_priorities->{}", fmt::format("{}", excluded_priorities_));
    invoked_once_ = true;

    if (!adjustForAttemptedPriorities(priority_set)) {
      ENVOY_LOG(debug, "ReselectPriorities returning original load");
      return original_priority_load;
    }

    ENVOY_LOG(debug, "ReselectPriorities returning priority load : {}",
              vectorToStr(per_priority_load_));
    return per_priority_load_;
  }
}

uint32_t EricReselectRetryPriority::adjustedAvailability(
    std::vector<uint32_t>& adjusted_per_priority_health,
    std::vector<uint32_t>& adjusted_per_priority_degraded) const {
  // Create an adjusted view of the priorities, where attempted priorities are given a zero
  // load. Create an adjusted health view of the priorities, where attempted priorities are
  // given a zero weight.
  uint32_t total_availability = 0;

  ASSERT(per_priority_health_.get().size() == per_priority_degraded_.get().size());

  for (size_t i = 0; i < per_priority_health_.get().size(); ++i) {
    if (!excluded_priorities_[i]) {
      adjusted_per_priority_health[i] = per_priority_health_.get()[i];
      adjusted_per_priority_degraded[i] = per_priority_degraded_.get()[i];
      total_availability += per_priority_health_.get()[i];
      total_availability += per_priority_degraded_.get()[i];
    } else {
      adjusted_per_priority_health[i] = 0;
      adjusted_per_priority_degraded[i] = 0;
    }
  }

  return std::min(total_availability, 100u);
}

bool EricReselectRetryPriority::adjustForAttemptedPriorities(
    const Upstream::PrioritySet& priority_set) {
  for (auto& host_set : priority_set.hostSetsPerPriority()) {
    recalculatePerPriorityState(host_set->priority(), priority_set);
  }

  std::vector<uint32_t> adjusted_per_priority_health(per_priority_health_.get().size(), 0);
  std::vector<uint32_t> adjusted_per_priority_degraded(per_priority_degraded_.get().size(), 0);
  auto total_availability =
      adjustedAvailability(adjusted_per_priority_health, adjusted_per_priority_degraded);

  // If there are no available priorities left, we reset the attempted priorities and
  // recompute the adjusted availability. This allows us to fall back to the unmodified
  // priority load when we run out of priorities instead of failing to route requests.
  if (total_availability == 0) {
    for (auto excluded_priority : excluded_priorities_) {
      excluded_priority = false;
    }
    total_availability =
        adjustedAvailability(adjusted_per_priority_health, adjusted_per_priority_degraded);
  }

  // If total availability is still zero at this point, it must mean that all clusters are
  // completely unavailable. If so, fall back to using the original priority loads. This
  // maintains whatever handling the default LB uses when all priorities are unavailable.
  if (total_availability == 0) {
    return false;
  }

  std::fill(per_priority_load_.healthy_priority_load_.get().begin(),
            per_priority_load_.healthy_priority_load_.get().end(), 0);
  std::fill(per_priority_load_.degraded_priority_load_.get().begin(),
            per_priority_load_.degraded_priority_load_.get().end(), 0);

  // TODO(snowp): This code is basically distributeLoad from load_balancer_impl.cc, should
  // probably reuse that.

  // We then adjust the load by rebalancing priorities with the adjusted availability
  // values.
  size_t total_load = 100;
  // The outer loop is used to eliminate rounding errors: any remaining load will be
  // assigned to the first availability priority.
  while (total_load != 0) {
    for (size_t i = 0; i < adjusted_per_priority_health.size(); ++i) {
      // Now assign as much load as possible to the high priority levels and cease assigning
      // load when total_load runs out.
      const auto delta = std::min<uint32_t>(total_load, adjusted_per_priority_health[i] * 100 /
                                                            total_availability);
      per_priority_load_.healthy_priority_load_.get()[i] += delta;
      total_load -= delta;
    }

    for (size_t i = 0; i < adjusted_per_priority_degraded.size(); ++i) {
      // Now assign as much load as possible to the high priority levels and cease assigning
      // load when total_load runs out.
      const auto delta = std::min<uint32_t>(total_load, adjusted_per_priority_degraded[i] * 100 /
                                                            total_availability);
      per_priority_load_.degraded_priority_load_.get()[i] += delta;
      total_load -= delta;
    }
  }

  return true;
}

void EricReselectRetryPriority::onHostAttempted(
    Upstream::HostDescriptionConstSharedPtr attempted_host) {
  ENVOY_LOG(trace,
            "EricReselectPriorities:onHostAttempted(), host: {} (ip:{}), pref host retries: {}",
            attempted_host->hostname(), attempted_host->address()->asStringView(),
            preferred_host_retries_);

  if (ph_handler_.isEmpty()) {
    // this is the first try
    ph_handler_.insert(attempted_host);
    if (!preferred_host_retries_ && remaining_hosts_in_curr_prio_level_) {
      remaining_hosts_in_curr_prio_level_--;
    }
    return;
  } else if (preferred_host_retries_ > 0) {
    // cache the host as preferred
    ph_handler_.insert(attempted_host);
    preferred_host_retries_--;
    ENVOY_LOG(debug, "pref host retries remaining: {}", preferred_host_retries_);
    return;
  }

  if (remaining_hosts_in_curr_prio_level_ > 0) {
    // this was a reselect, reduce the number of remaining hosts in the current prio
    remaining_hosts_in_curr_prio_level_--;
  }

  // reselect
  if (failover_reselects_ > 0) {
    failover_reselects_--;
    if (failover_reselects_ > 0 && remaining_hosts_in_curr_prio_level_ == 0 &&
        current_priority_level_ == prio_context_->last_primary_priority) {
      // checking for the existence of the prio_context_ ptr is not required since for
      // remaining_hosts to be >0
      // a prio level has been counted, meaning determinePriorityLoad() has been called at least
      // once
      // If the last priority of the primary cluster has been exhausted but there are still
      // failover_reselects, make them zero.
      failover_reselects_ = 0;
    }
  } else if (last_resort_reselects_ > 0) {
    // reselects are over, LR reselects have been configured and we've been called by an
    // aggregate cluster
    last_resort_reselects_--;
  }
}

// Called by RetryState when the router needs to know if it should arm a retry.
// Keep going as long as:
// - There are either pref retries failover reselects or lrp reselects left AND remaining hosts
// -  not all priorities are exhausted i.e. if we are in the last prio it has hosts left
// due to the call sequence we need to know if the last prio has been exhausted prior
// to determinePriorityLoad() being invoked by the retry_state.
// that's where the remaining_hosts_in_next_prio_level_ comes into play
bool EricReselectRetryPriority::shouldRetry() const {

  ENVOY_LOG(debug,
            "shouldRetry() params: \npreferred_host_retries_: {},\nfailover_reselects_: {},\n"
            "last_resort_reselects_: {}\nremaining hosts in current prio ({}): {}",
            preferred_host_retries_, failover_reselects_, last_resort_reselects_,
            current_priority_level_, remaining_hosts_in_curr_prio_level_);
  if (next_priority_level_) {
    ENVOY_LOG(debug, "remaining hosts in next prio ({}): {}", *next_priority_level_,
              remaining_hosts_in_next_prio_level_);
  } else {
    ENVOY_LOG(debug, "next prio not analyzed");
  }

  bool verdict{false};
  if (preferred_host_retries_ > 0 /* && !ph_handler_.noneHealthy()*/) {
    verdict = true;
  }

  if (remaining_hosts_in_curr_prio_level_ &&
      configuredReselectsRemainingForPrio(current_priority_level_)) {
    verdict = true;
  }

  if (remaining_hosts_in_next_prio_level_ && next_priority_level_ &&
      configuredReselectsRemainingForPrio(*next_priority_level_)) {
    verdict = true;
  }

  ENVOY_LOG(debug, "shouldRetry()? {}", verdict);
  return verdict;
}

// Counts eligible hosts on a priority level
// Host counting is different and more resource intensive depending if temp blocking or/and
// loop prevention is supported
uint32_t
EricReselectRetryPriority::countHostsOnPrioLevel(const Envoy::Upstream::HostVector& hosts) {
  if (support_temporary_blocking_ && support_loop_prevention_) {
    // a "good" host is not blocked and not in the via header
    return std::count_if(hosts.begin(), hosts.end(), [&](const Upstream::HostSharedPtr& host) {
      bool found_in_via = std::find_if(via_header_hosts_->begin(), via_header_hosts_->end(),
                                       [&](const absl::string_view via_host) {
                                         return host->hostname() == via_host ||
                                                host->address()->asStringView() == via_host;
                                       }) == via_header_hosts_->end();
      if (!found_in_via) {
        return (host->coarseHealth() == Upstream::Host::Health::Healthy);
      }
      return found_in_via;
    });
  } else if (support_temporary_blocking_) {
    return std::count_if(hosts.begin(), hosts.end(), [&](const Upstream::HostSharedPtr& host) {
      return (host->coarseHealth() == Upstream::Host::Health::Healthy);
    });
  } else if (support_loop_prevention_) {
    return std::count_if(hosts.begin(), hosts.end(), [&](const Upstream::HostSharedPtr& host) {
      // find_if finds the host on the via header. If not found, this host should be counted as
      // eligible
      return std::find_if(via_header_hosts_->begin(), via_header_hosts_->end(),
                          [&](const absl::string_view via_host) {
                            return host->hostname() == via_host ||
                                   host->address()->asStringView() == via_host;
                          }) == via_header_hosts_->end();
    });
  } else {
    return hosts.size();
  }
}

// returns how many of the preferred hosts (or just the first host in the simple case) belong to the
// supplied priority level. Hosts are marked as processed internally by the preferred_host_handler
uint32_t EricReselectRetryPriority::alreadyTriedHostsOnPrioLevel(
    const Upstream::PrioritySet& priority_set, const PriorityMappingFunc& priority_mapping_func,
    uint32_t prio_level) {
  if (ph_handler_.isEmpty() || ph_handler_.allExcluded()) {
    return 0;
  }
  // if the first host tried has been tried  already, and belongs in this priority level, check its
  // health
  // and adjust remaining_hosts_in_curr_prio_level accordingly
  auto tried_hosts_in_prio = ph_handler_.hostsInPrioLevel(prio_level, priority_mapping_func);
  auto ret = tried_hosts_in_prio.size();

  if (support_temporary_blocking_) {
    for (const auto& pref_host : tried_hosts_in_prio) {
      const auto& found =
          std::find_if(priority_set.hostSetsPerPriority()[prio_level]->hosts().begin(),
                       priority_set.hostSetsPerPriority()[prio_level]->hosts().end(),
                       [&](const Upstream::HostSharedPtr& host) {
                         return ((host->coarseHealth() != Upstream::Host::Health::Healthy) &&
                                 pref_host->address()->asString() == host->address()->asString());
                       });
      if (found != priority_set.hostSetsPerPriority()[prio_level]->hosts().end()) {
        ENVOY_LOG(debug, "First/pref host {} {} on prio level {} found unhealthy",
                  pref_host->hostname(), pref_host->address()->asStringView(), prio_level);
        ret--;
      }
    }
  }
  return ret;
}

std::string EricReselectRetryPriority::vectorToStr(Upstream::HealthyAndDegradedLoad load) {
  std::ostringstream oss;
  oss << "healthy load: [";
  std::copy(load.healthy_priority_load_.get().begin(), load.healthy_priority_load_.get().end() - 1,
            std::ostream_iterator<int>(oss, ","));
  oss << load.healthy_priority_load_.get().back() << "] , degraded load:[";
  std::copy(load.degraded_priority_load_.get().begin(),
            load.degraded_priority_load_.get().end() - 1, std::ostream_iterator<int>(oss, ","));
  oss << load.degraded_priority_load_.get().back() << "]";
  return oss.str();
}

} // namespace Priority
} // namespace Retry
} // namespace Extensions
} // namespace Envoy