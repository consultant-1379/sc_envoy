#include "source/extensions/retry/priority/eric_reselect_priorities/eric_reselect_priorities_old.h"
#include <algorithm>
#include <cstdint>
#include <iterator>
#include <memory>
#include <sstream>

namespace Envoy {
namespace Extensions {
namespace Retry {
namespace Priority {

void EricReselectRetryPriority::determineNextPriority(
    const Upstream::PrioritySet& priority_set,
    const Upstream::HealthyAndDegradedLoad& original_priority_load,
    const PriorityMappingFunc& priority_mapping_func,
    const std::set<std::string>& via_header_hosts) {
  if (!prio_context_) {
    ENVOY_LOG(debug, "CHARDOU: determineNextPriority()");
    if (attempted_hosts_per_priority_.empty()) {
      attempted_hosts_per_priority_.resize(priority_set.hostSetsPerPriority().size());
    }
    prio_context_ = std::make_unique<PrioritiesContext>();
    prio_context_->instantiatePrioritiesContext(priority_set, original_priority_load,
                                                priority_mapping_func, via_header_hosts, this);
    remaining_hosts_in_curr_prio_level_ = healthy_hosts_per_prio_[prio_context_->currentPriority()];
    // when this function is called, there retries are either over or no preferred host has been
    // supplied
    // if (preferred_host_retries_ > 0) {
    //   // TODO: document what i was thinking possibly go away from the =1 notation
    //   preferred_host_retries_ = 1;
    // }
  }
}

const Upstream::HealthyAndDegradedLoad& EricReselectRetryPriority::determinePriorityLoad(
    const Upstream::PrioritySet& priority_set,
    const Upstream::HealthyAndDegradedLoad& original_priority_load,
    const PriorityMappingFunc& priority_mapping_func) {
  // If we've not seen enough retries to modify the priority load, just
  // return the original.
  // If this retry should trigger an update, recalculate the priority load by excluding attempted
  // priorities.

  // first time this function is called, attempted_hosts_pre_priority is uninitialized and only
  // one host has been tried (either the preferred or at random from p0 if RR)
  // if (attempted_hosts_per_priority_.empty()) {
  //   attempted_hosts_per_priority_.resize(priority_set.hostSetsPerPriority().size());
  // }

  // The following only need to happen in the first invocation of determinePriorityLoad()
  // so at the first retry that's actually a reselect
  // * make preferred host retries = 0
  // * mark the already tried host (first try + pref retries) as attempted
  if (!invoked_once_) {
    // when this function is called, the retries are either over or no preferred host has been
    // supplied
    preferred_host_retries_ = 0;
    // remaining_hosts_in_curr_prio_level_ =
    //     healthy_hosts_per_prio_.at(prio_context_->currentPriority());

    // TODO: remove me if I keep this solution
    // mark the first host that has been tried, up to preferred retries num of times as attempted
    // if the first host is on prio level 0, adjust remaining hosts on curr prio accordingly
    // this is taken care in instantiate now
    if (first_host_.has_value()) {
      absl::optional<uint32_t> mapped_host_priority = priority_mapping_func(*first_host_.value());
      // perform insertion only once. Preferred is tried first so the container is empty
      if (mapped_host_priority.has_value() &&
          attempted_hosts_per_priority_[mapped_host_priority.value()].empty()) {
        attempted_hosts_per_priority_[mapped_host_priority.value()].emplace_back(
            first_host_.value());
        // it's the first call of determinePriorityLoad() so first reselect
        // if the host attempted on the initial try (plus potential retries) is on prio level 0
        // adjust remaining_hosts_in_curr_prio_level_
        // if (mapped_host_priority.value() == prio_context_->currentPriority()) {
        //   remaining_hosts_in_curr_prio_level_--;
        // }
      }
    }

    invoked_once_ = true;
  }
  const auto current_priority = prio_context_->currentPriority();
  const auto& hosts_in_prio_level = priority_set.hostSetsPerPriority()[current_priority]
                                        ->hosts()
                                        .size(); // num of hosts in current prio level
  ENVOY_LOG(debug,
            "CHARDOU: determinePriorityLoad() start, curr prio level: {}, Hosts in current prio "
            "level: {}, remaining hosts in current prio level: {}",
            current_priority, hosts_in_prio_level, remaining_hosts_in_curr_prio_level_);

  // TODO: resize excluded prios up to final prio
  if (excluded_priorities_.size() < priority_set.hostSetsPerPriority().size()) {
    excluded_priorities_.resize(priority_set.hostSetsPerPriority().size());
  }

  // If there are eligible remaining hosts in this prio level,
  //  AND there are reselects available, return the precomputed/original
  // load
  if (remaining_hosts_in_curr_prio_level_ > 0 && !maybeSkipToLastResort()) {
    // if we are on the first prio level return the prio load given to us
    // as the internally kept per_prio_load_ is uninitialized
    return getPrecomputedOrOriginalPriorityLoad(original_priority_load);
  } else {
    // tried all hosts in this priority level, the procedure to calculate
    // the next priority level starts
    ENVOY_LOG(debug, "CHARDOU: ReselectPriorities tried all hosts in  prio level: {}",
              current_priority);

    for (const auto& host : attempted_hosts_per_priority_[current_priority]) {
      absl::optional<uint32_t> mapped_host_priority = priority_mapping_func(*host);
      if (mapped_host_priority.has_value()) {
        excluded_priorities_[mapped_host_priority.value()] = true;
      }
    }
    // If we are not on the last prio level, take a peek in the next priority.
    // If it has been tried for preferred host and only contains
    // one host it needs to be skipped and marked excluded
    if (current_priority < prio_context_->getEndPrioPrimary()) {
      const auto& attempted_from_next_level = attempted_hosts_per_priority_[current_priority + 1];
      // we can only have tried up to 1 host from a next priority level so basically == 1
      if (!attempted_from_next_level.empty() &&
          attempted_from_next_level.size() ==
              priority_set.hostSetsPerPriority()[current_priority + 1]->hosts().size()) {
        absl::optional<uint32_t> mapped_host_priority =
            priority_mapping_func(*attempted_from_next_level[0]);
        if (mapped_host_priority.has_value()) {
          excluded_priorities_[mapped_host_priority.value()] = true;
          prio_context_->jumpPriorityLevel();
        }
      }
    }

    // called from aggregate cluster who previously supplied the start prios per cluster member &&
    // reselects are over jump to the priority level of the last resort hosts
    // this procedure needs to happen once as afterwards priorities are processed sequentially
    if (failover_reselects_ == 0 && last_resort_reselects_ > 0) {
      prio_context_->excludePriosUptoLastResort(excluded_priorities_);
    }

    ENVOY_LOG(debug, "CHARDOU: excluded_priorities->{}", fmt::format("{}", excluded_priorities_));

    // if all the priorities have been exhausted
    // don't modify the priority load
    if (isLastPriorityExhausted()) {
      ENVOY_LOG(debug, "CHARDOU: Available Priorities have been exhausted)");

      return getPrecomputedOrOriginalPriorityLoad(original_priority_load);
    }

    if (!adjustForAttemptedPriorities(priority_set)) {
      ENVOY_LOG(debug, "CHARDOU: ReselectPriorities returning original load");
      return original_priority_load;
    }

    prio_context_->adjustPriorityIndexForNextIteration();

    // save the number of available hosts in the new priority level. This is modified when we jump
    // to a new priority and when onHostAttempted is called. When it falls down to 0 and we are on
    // the last priority, the shouldRetry() function call invoked by the retry_state returns false
    remaining_hosts_in_curr_prio_level_ =
        healthy_hosts_per_prio_.at(prio_context_->currentPriority());
    //-attempted_hosts_per_priority_[prio_context_->currentPriority()].size();
  }
  return getPrecomputedOrOriginalPriorityLoad(original_priority_load);
}

uint32_t EricReselectRetryPriority::adjustedAvailability(
    std::vector<uint32_t>& adjusted_per_priority_health,
    std::vector<uint32_t>& adjusted_per_priority_degraded) const {
  // Create an adjusted view of the priorities, where attempted priorities are given a zero load.
  // Create an adjusted health view of the priorities, where attempted priorities are
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
// TODO(chardou) this probably interracts with temp blocking
bool EricReselectRetryPriority::adjustForAttemptedPriorities(
    const Upstream::PrioritySet& priority_set) {
  for (auto& host_set : priority_set.hostSetsPerPriority()) {
    recalculatePerPriorityState(host_set->priority(), priority_set);
  }

  std::vector<uint32_t> adjusted_per_priority_health(per_priority_health_.get().size(), 0);
  std::vector<uint32_t> adjusted_per_priority_degraded(per_priority_degraded_.get().size(), 0);
  auto total_availability =
      adjustedAvailability(adjusted_per_priority_health, adjusted_per_priority_degraded);

  // If there are no available priorities left, we reset the attempted priorities and recompute the
  // adjusted availability.
  // This allows us to fall back to the unmodified priority load when we run out of priorities
  // instead of failing to route requests.
  if (total_availability == 0) {
    for (auto excluded_priority : excluded_priorities_) {
      excluded_priority = false;
    }
    attempted_hosts_per_priority_.clear();
    total_availability =
        adjustedAvailability(adjusted_per_priority_health, adjusted_per_priority_degraded);
  }

  // If total availability is still zero at this point, it must mean that all clusters are
  // completely unavailable. If so, fall back to using the original priority loads. This maintains
  // whatever handling the default LB uses when all priorities are unavailable.
  if (total_availability == 0) {
    return false;
  }

  std::fill(per_priority_load_.healthy_priority_load_.get().begin(),
            per_priority_load_.healthy_priority_load_.get().end(), 0);
  std::fill(per_priority_load_.degraded_priority_load_.get().begin(),
            per_priority_load_.degraded_priority_load_.get().end(), 0);

  // TODO(snowp): This code is basically distributeLoad from load_balancer_impl.cc, should probably
  // reuse that.

  // We then adjust the load by rebalancing priorities with the adjusted availability values.
  size_t total_load = 100;
  // The outer loop is used to eliminate rounding errors: any remaining load will be assigned to the
  // first availability priority.
  while (total_load != 0) {
    for (size_t i = 0; i < adjusted_per_priority_health.size(); ++i) {
      // Now assign as much load as possible to the high priority levels and cease assigning load
      // when total_load runs out.
      const auto delta = std::min<uint32_t>(total_load, adjusted_per_priority_health[i] * 100 /
                                                            total_availability);
      per_priority_load_.healthy_priority_load_.get()[i] += delta;
      total_load -= delta;
    }

    for (size_t i = 0; i < adjusted_per_priority_degraded.size(); ++i) {
      // Now assign as much load as possible to the high priority levels and cease assigning load
      // when total_load runs out.
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
  ENVOY_LOG(debug,
            "CHARDOU: EricReselectPriorities:onHostAttempted(), host: {}, pref host retries: {}",
            attempted_host->hostname(), std::to_string(preferred_host_retries_));
  if (!first_host_) {
    first_host_.emplace(attempted_host);
  }

  if (preferred_host_retries_ > 0) {
    // either first try or retrying the preferred host
    preferred_host_retries_--;
    ENVOY_LOG(debug, "CHARDOU: pref host retries remaining: {}",
              std::to_string(preferred_host_retries_));

    return;
  }
  // reselect
  attempted_hosts_per_priority_[prio_context_->currentPriority()].emplace_back(attempted_host);
  if (failover_reselects_ > 0) {
    failover_reselects_--;
  } else if (last_resort_reselects_ > 0) {
    // reselects are over, LR reselects have been configured and we've been called by an aggregate
    // cluster
    last_resort_reselects_--;
  }
  if (remaining_hosts_in_curr_prio_level_ > 0) {
    // this was a reselect, reduce the number of remaining hosts in the current prio
    remaining_hosts_in_curr_prio_level_--;
  }
}

// Fills in all the parameters required by the PriorityContext to perform reselects.
// * Given the original priority load, determines the starting priority level
// * Given a priority set of hosts, determines how many reselects should actually happen
//   which is min(failover_reselects_, sum of healthy hosts across priorities of the primary
//   cluster)
// * Figure out if the target cluster is aggregate and if so adjust last_resort_reselects_
// accordingly
// * Find the priority borders of primary and last resort pools, taking into account that priority
//   levels within a cluster can be empty due to an eds update
//
void EricReselectRetryPriority::PrioritiesContext::instantiatePrioritiesContext(
    const Upstream::PrioritySet& priority_set,
    const Upstream::HealthyAndDegradedLoad& original_priority_load,
    const PriorityMappingFunc& priority_mapping_func, const std::set<std::string>& via_header_hosts,
    EricReselectRetryPriority* const parent) {
  // just for the unused var warning
  via_header_hosts.find("");
  // resize the healthy_hosts_per_prio_vector to the size of total priorities (including possible
  // vacant ones)
  // and fill it with 0s. That way vacant priorities where we don't count healthy hosts later on
  // will contain 0s.
  parent->healthy_hosts_per_prio_.resize(priority_set.hostSetsPerPriority().size(), 0);
  // find the starting priority level from the original priority load supplied. If outlier detection
  // has
  // kicked in, it can be different from 0
  const auto first_valid_prio = std::find_if_not(
      original_priority_load.healthy_priority_load_.get().begin(),
      original_priority_load.healthy_priority_load_.get().end(), [](uint32_t x) { return x == 0; });
  if (first_valid_prio != original_priority_load.healthy_priority_load_.get().end()) {
    // ENVOY_LOG(debug, "found start priority {}", *first_valid_prio );
    current_priority_level_ =
        first_valid_prio - original_priority_load.healthy_priority_load_.get().begin();
  } else {
    ENVOY_LOG(debug, "The Original priority load vector is filled with 0s");
    current_priority_level_ = 0;
  }
  if (priority_set.hostSetsPerPriority()[0]->hosts().empty()) {
    // This effectively means the cluster has no hosts
    parent->failover_reselects_ = 0;
    parent->last_resort_reselects_ = 0;
    parent->remaining_hosts_in_curr_prio_level_ = 0;
    return;
  }

  int sum_primary_hosts = 0;
  bool vacant_prio_level_found = false;
  bool lrp_cluster_host_found = false;

  // get a host from the first priority
  const auto& primary_cluster_host = priority_set.hostSetsPerPriority()[0]->hosts().back();
  Upstream::HostDescriptionConstSharedPtr lrp_cluster_host;
  if (primary_cluster_host) {
    const auto& primary_cluster_name = primary_cluster_host->cluster().name();
    uint32_t indx;
    for (indx = current_priority_level_; indx < priority_set.hostSetsPerPriority().size(); indx++) {
      if (priority_set.hostSetsPerPriority()[indx]->hosts().empty()) {
        // an eds update can leave a priority level without hosts. These empty priorities do not get
        // removed when the priority set is updated. Mark previous index as the last valid priority
        // level for the primary cluster and continue until and if you find a host belonging to the
        // lrp
        if (!vacant_prio_level_found) {
          end_prio_primary_ = indx - 1;
          vacant_prio_level_found = !vacant_prio_level_found;
        }
        continue;
      }
      lrp_cluster_host = priority_set.hostSetsPerPriority()[indx]->hosts().back();
      // prio level belongs to last resort cluster
      if (lrp_cluster_host && lrp_cluster_host->cluster().name() != primary_cluster_name) {
        lrp_cluster_host_found = true;
        if (!vacant_prio_level_found) { // no vacant priorities have been encountered so the
                                        // previous index
          end_prio_primary_ = indx - 1; // marks the end of the primary cluster priorities
        }
        start_prio_last_resort_ = indx;
        break;
      } else {
        // prio level belongs to primary cluster
        const auto healthy_hosts = parent->countHostsOnPrioLevel(
            priority_set.hostSetsPerPriority()[indx]->hosts(), via_header_hosts);
        ENVOY_LOG(debug, "CHARDOU: Number of eligible hosts on prio level {} : {}", indx,
                  healthy_hosts);
        sum_primary_hosts += healthy_hosts;
        parent->healthy_hosts_per_prio_.at(indx) = healthy_hosts;

        // no lrp found, no empty last priorities, fix end prio primary index
        if (indx == priority_set.hostSetsPerPriority().size() - 1) {
          end_prio_primary_ = indx;
        }
      }
    }

    // at this point, either there is a last resort cluster, with its starting prio level stored on
    // indx or all prio levels belong to the primary cluster or we encountered a vacant priority.
    // In both scenarios, sum_primary_hosts holds the number of reselects If there is a last resort
    // cluster, adapt failover_reselects as well
    if (lrp_cluster_host_found) {
      int sum_last_resort_hosts = 0;
      // same logic for LRP. Check remaining priorities, summing up lrp hosts, until you encounter
      // the first empty prio
      for (indx = *start_prio_last_resort_;
           indx < priority_set.hostSetsPerPriority().size() &&
           !priority_set.hostSetsPerPriority()[indx]->hosts().empty();
           indx++) {
        const auto healthy_hosts = parent->countHostsOnPrioLevel(
            priority_set.hostSetsPerPriority()[indx]->hosts(), via_header_hosts);
        ENVOY_LOG(debug, "CHARDOU: Number of eligible hosts on prio level {} : {}", indx,
                  healthy_hosts);
        sum_last_resort_hosts += healthy_hosts;
        parent->healthy_hosts_per_prio_.at(indx) = healthy_hosts;
      }
      end_prio_last_resort_ = indx;

      parent->last_resort_reselects_ =
          std::min<uint32_t>(parent->last_resort_reselects_, sum_last_resort_hosts);
      ENVOY_LOG(
          debug,
          "CHARDOU: Adjusted last_resort_reselects to {}, start prio for last resort cluster: {}",
          parent->last_resort_reselects_, start_prio_last_resort_.value());
    } else {
      parent->last_resort_reselects_ = 0; // no lrp is configured
    }

    // Adjust healthy_hosts_per_prio_ and failover reselects based on the first host's health
    // Naturally, reselections upper limit is hosts - 1 to accommodate for the first
    // try, unless the firstly tried hosts became blocked in the process. A common
    // scenario for this is outlier detection kicking in during retries
    // if we are on the priority level of the first host && we are processing a temp
    // blocked host mark it as found and adjust failover_reselects accordingly.
    // We take a peek in the prio level of the first tried host to see if it's blocked
    if (parent->first_host_.has_value()) {
      absl::optional<uint32_t> first_host_priority =
          priority_mapping_func(*parent->first_host_.value());
      if (first_host_priority) {
        auto first_host_unhealthy =
            priority_set.hostSetsPerPriority()[*first_host_priority]->hosts().end();
        if (parent->support_temporary_blocking_) {
          first_host_unhealthy = std::find_if(
              priority_set.hostSetsPerPriority()[*first_host_priority]->hosts().begin(),
              priority_set.hostSetsPerPriority()[*first_host_priority]->hosts().end(),
              [&](const Upstream::HostSharedPtr& host) {
                return (host->healthFlagGet(Upstream::Host::HealthFlag::FAILED_OUTLIER_CHECK) &&
                        parent->first_host_.value()->address()->asString() ==
                            host->address()->asString());
              });
        }
        if (first_host_unhealthy ==
            std::end(priority_set.hostSetsPerPriority()[*first_host_priority]->hosts())) {

          // first tried host is healthy and should not be included when calculating minimum
          // reselects (it's tried already)
          // Also adjust `healthy_hosts_per_prio_(first_host_prio_)` accordingly
          parent->failover_reselects_ =
              std::min<uint32_t>(parent->failover_reselects_, sum_primary_hosts - 1);
          parent->healthy_hosts_per_prio_.at(*first_host_priority)--;
          ENVOY_LOG(debug,
                    "First host is healthy, Adjusted failover_reselects_ to {}, end prio for "
                    "primary cluster: {}",
                    parent->failover_reselects_, end_prio_primary_);
          return;
        }
      }
    }
    // first tried host is unhealthy, meaning all hosts counted on that prio level should be
    // included
    // when calculating minimum reselects.
    parent->failover_reselects_ =
        std::min<uint32_t>(parent->failover_reselects_, sum_primary_hosts);
    ENVOY_LOG(debug,
              "First host is unhealthy, Adjusted failover_reselects_ to {}, end prio for primary "
              "cluster: {}",
              parent->failover_reselects_, end_prio_primary_);
  }
}
// wrapper function to facilitate host counting on a prio level, performed by
// instantiatePrioritiesContext().
// Host counting is different and more resource intensive depending if temp blocking or/and loop
// prevention is supported
uint32_t
EricReselectRetryPriority ::countHostsOnPrioLevel(const Envoy::Upstream::HostVector& hosts,
                                                  const std::set<std::string>& via_header_hosts) {
  if (support_temporary_blocking_ && support_loop_prevention_) {
    // a "good" host is not blocked and not in the via header
    return std::count_if(hosts.begin(), hosts.end(), [&](const Upstream::HostSharedPtr& host) {
      return via_header_hosts.find(host->hostname()) == via_header_hosts.end() &&
             via_header_hosts.find(host->address()->asString()) == via_header_hosts.end() &&
             !host->healthFlagGet(Upstream::Host::HealthFlag::FAILED_OUTLIER_CHECK);
    });
  } else if (support_temporary_blocking_) {
    return std::count_if(hosts.begin(), hosts.end(), [&](const Upstream::HostSharedPtr& host) {
      return !host->healthFlagGet(Upstream::Host::HealthFlag::FAILED_OUTLIER_CHECK);
    });
  } else if (support_loop_prevention_) {
    return std::count_if(hosts.begin(), hosts.end(), [&](const Upstream::HostSharedPtr& host) {
      return via_header_hosts.find(host->hostname()) == via_header_hosts.end() &&
             via_header_hosts.find(host->address()->asString()) == via_header_hosts.end();
    });
  } else {
    return hosts.size();
  }
}

void EricReselectRetryPriority::PrioritiesContext::excludePriosUptoLastResort(
    std::vector<bool>& excluded_priorities) {
  if (start_prio_last_resort_ && !prios_adjusted_for_last_resort_) {
    std::fill(excluded_priorities.begin(), excluded_priorities.begin() + *start_prio_last_resort_,
              true);
    next_priority_level_ = *start_prio_last_resort_;
  }
  prios_adjusted_for_last_resort_ = !prios_adjusted_for_last_resort_;
}

const Upstream::HealthyAndDegradedLoad&
EricReselectRetryPriority::getPrecomputedOrOriginalPriorityLoad(
    const Upstream::HealthyAndDegradedLoad& original_priority_load) {
  if (per_priority_load_.healthy_priority_load_.get().empty()) {
    ENVOY_LOG(debug, "CHARDOU: ReselectPriorities returning original load : {}",
              vectorToStr(original_priority_load));
    return original_priority_load;
  } else {
    ENVOY_LOG(debug, "CHARDOU: ReselectPriorities returning pre computed load : {}",
              vectorToStr(per_priority_load_));
    return per_priority_load_;
  }
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