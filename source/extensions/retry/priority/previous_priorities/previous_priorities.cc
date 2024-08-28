#include "source/extensions/retry/priority/previous_priorities/previous_priorities.h"
#include <algorithm>
#include <cstdint>

namespace Envoy {
namespace Extensions {
namespace Retry {
namespace Priority {

const Upstream::HealthyAndDegradedLoad& PreviousPrioritiesRetryPriority::determinePriorityLoad(
    const Upstream::PrioritySet& priority_set,
    const Upstream::HealthyAndDegradedLoad& original_priority_load,
    const PriorityMappingFunc& priority_mapping_func, const std::vector<absl::string_view>&) {
  // If we've not seen enough retries to modify the priority load, just
  // return the original.
  // If this retry should trigger an update, recalculate the priority load by excluding attempted
  // priorities.

  // Initialize the 'exclude' attribute of all priority levels to 'false' at the beginning of a
  // request (the beginning of a new request is sometimes when the exclude_priorities size
  // differentiates to the number of priority levels)
  if (excluded_priorities_.size() != priority_set.hostSetsPerPriority().size()) {
    for (size_t i = 0; i < priority_set.hostSetsPerPriority().size(); ++i) {
      priority_set.hostSetsPerPriority()[i]->exclude_ = false;
    }
    excluded_priorities_.resize(priority_set.hostSetsPerPriority().size());
  }

  // Another attempt to initialize the 'exclude' attribute of all priority levels to 'false' at the
  // beginning of a request. This attempt checks whether we are at the highest priority level (0) and if
  // we have as of now only tried 0 or 1 host. Both attempts are there because of the following
  // issue: Sometimes Envoy reuses old objects for subsequent requests, which means that the
  // 'exclude' attribute remains 'true', which is then not correct for new requests, so it must be
  // initialized to 'false' again.
  if (current_priority_level_ == 0 && attempted_hosts_.size() < 2) {
    for (size_t i = 0; i < priority_set.hostSetsPerPriority().size(); ++i) {
      priority_set.hostSetsPerPriority()[i]->exclude_ = false;
    }
  }

  // Go through every entry in the Update Frequency list and check for 0s.
  // If an entry is 0, then exclude this priority level (i.e. set 'exclude'
  // to 'true' so that it is skipped later)
  for (int i = 0; i < update_frequency_.size(); ++i) {
    if (update_frequency_.at(i) == 0) {
      if (static_cast<std::uint32_t>(i) < excluded_priorities_.size()) {
        excluded_priorities_[i] = true;
      }
      if (static_cast<std::uint32_t>(i) < priority_set.hostSetsPerPriority().size()) {
        if (priority_set.hostSetsPerPriority()[i]) {
          priority_set.hostSetsPerPriority()[i]->exclude_ = true;
        }
      }
    }
  }

  // This is just for safety reasons. Set the current priority level we are currently
  // checking for to the priority level of the attempted host (they should always have
  // the same value, except when we are in the very first try of a priority level,
  // then the attempted_host list is empty and this is skipped)
  for (const auto& host : attempted_hosts_) {
    absl::optional<uint32_t> mapped_host_priority = priority_mapping_func(*host);
    if (mapped_host_priority.has_value()) {
      current_priority_level_ = mapped_host_priority.value();
    }
  }

  // This is for safety reasons. The current priority level shouldn't be bigger than the number of
  // update frequency list elements
  if (current_priority_level_ >= update_frequency_.size()) {
    current_priority_level_ = 0;
  }

  // This is for safety reasons. The current priority level shouldn't be bigger than the number of
  // Host Sets per priority
  if (static_cast<uint32_t>(current_priority_level_) >= priority_set.hostSetsPerPriority().size()) {
    current_priority_level_ = priority_set.hostSetsPerPriority().size() - 1;
  }

  // If we have set 'exclude' to 'true' for this priority level, then set the
  // corresponding excluded_priorities for this priority level to 'true' as well.
  // While priority_set.hostSetsPerPriority()[current_priority_level_]->exclude_ is our
  // parameter used to determine whether to skip a priority or not,
  // excluded_priorities_[current_priority_level_] is an internal parameter used then for actual
  // priority availability percentage calculation in adjustedAvailability().
  if (priority_set.hostSetsPerPriority()[current_priority_level_]->exclude_) {
    excluded_priorities_[current_priority_level_] = true;
  }

  // If we have reached the last try for this priority level, mark it as excluded for the next try.
  if (attempted_hosts_.size() == update_frequency_.at(current_priority_level_)) {
    priority_set.hostSetsPerPriority()[current_priority_level_]->exclude_ = true;
    excluded_priorities_[current_priority_level_] = true;
  }

  // This is the actual check whether we go with this priority level or if we skip it.
  // If this priority level is not marked to be excluded and the number of host attempts are still
  // lower than the corresponding Update Frequency entry value, i.e. there are still retries
  // available for this priority level, go with this priority level and return the unmodified
  // priority availbility percentage (priority load) list in order to choose a host from this
  // priority level again.
  if (!priority_set.hostSetsPerPriority()[current_priority_level_]->exclude_ &&
      update_frequency_.at(current_priority_level_) > 0) {

    if (!per_priority_load_.healthy_priority_load_.get().empty()) {
      return per_priority_load_;
    }
    return original_priority_load;

  } else {
    // If we have exceeded the number of tries for this priority level or the priority level has
    // been marked as excluded, this priority level will be skipped.
    // Go through the list of attempted hosts and set their priority levels to be excluded.
    // Increment our current_priority_level_ tracker parameter for the next reselection.
    // Then, internally under adjustForAttemptedPriorities() and consequenlty in
    // adjustedAvailability(), set its priority availbility percentage (priority load) list entry
    // for this priority level to 0, and recalculate the remaining percentages of the remaining
    // priority levels accordingly. Return the modified priority availbility percentage (priority
    // load) list for host selection.
    ++current_priority_level_;

    for (const auto& host : attempted_hosts_) {
      absl::optional<uint32_t> mapped_host_priority = priority_mapping_func(*host);
      if (mapped_host_priority.has_value()) {
        excluded_priorities_[mapped_host_priority.value()] = true;
      }
    }

    if (!adjustForAttemptedPriorities(priority_set)) {
      return original_priority_load;
    }
  }
  attempted_hosts_.clear();

  return per_priority_load_;
}

bool PreviousPrioritiesRetryPriority::adjustForAttemptedPriorities(
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
    attempted_hosts_.clear();
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

uint32_t PreviousPrioritiesRetryPriority::adjustedAvailability(
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

} // namespace Priority
} // namespace Retry
} // namespace Extensions
} // namespace Envoy
