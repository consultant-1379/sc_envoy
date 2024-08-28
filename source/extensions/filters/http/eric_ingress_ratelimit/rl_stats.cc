#include "source/extensions/filters/http/eric_ingress_ratelimit/rl_stats.h"
#include <iostream>
#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IngressRateLimitFilter {

RateLimitStats::RateLimitStats(const std::shared_ptr<EricIngressRateLimitConfig> config,
                               Stats::Scope& scope, const std::string& fetched_prefix)
    : scope_(scope), stat_name_set_(scope.symbolTable().makeSet("EricIngressRatelimit")),
      stats_prefix_(stat_name_set_->add(absl::string_view("http.eirl"))),
      fetched_prefix_(fetched_prefix), n8e_(stat_name_set_->add(absl::string_view("n8e"))),
      g3p_(stat_name_set_->add(absl::string_view("g3p"))),
      s6a6_(stat_name_set_->add(absl::string_view("s6a6"))),
      r12r_(stat_name_set_->add(absl::string_view("r12r"))),
      n5k_(stat_name_set_->add(absl::string_view("n5k"))),
      ingress_(stat_name_set_->add(absl::string_view("ingress"))),
      per_rp_accepted_(stat_name_set_->add(absl::string_view("global_rate_limit_accepted_per_roaming_partner"))),
      per_rp_rejected_(stat_name_set_->add(absl::string_view("global_rate_limit_rejected_per_roaming_partner"))),
      per_rp_dropped_(stat_name_set_->add(absl::string_view("global_rate_limit_dropped_per_roaming_partner"))),

      per_nw_accepted_(stat_name_set_->add(absl::string_view("global_rate_limit_accepted_per_network"))),
      per_nw_rejected_(stat_name_set_->add(absl::string_view("global_rate_limit_rejected_per_network"))),
      per_nw_dropped_(stat_name_set_->add(absl::string_view("global_rate_limit_dropped_per_network"))),

      total_accepted_(stat_name_set_->add(absl::string_view("global_rate_limit_accepted"))),
      total_rejected_(stat_name_set_->add(absl::string_view("global_rate_limit_rejected"))),
      total_dropped_(stat_name_set_->add(absl::string_view("global_rate_limit_dropped"))),
      unknown_name_(stat_name_set_->add(absl::string_view("unknownName"))),

      nf_instance_name_(stat_name_set_->add(extractNfInstance())),
      rlf_lookup_failure_(stat_name_set_->add("rlf_lookup_failure")) {

  if (config != nullptr) {
    // remember namespace for n8e
    stat_name_set_->rememberBuiltin(config->nameSpace());

    for (const auto& limit : config->limits()) {
      if (limit.has_network()) {
        const auto& name = getNameFromBucketName(limit.network().bucket_action().bucket_name());
        // remember Networks
        stat_name_set_->rememberBuiltin(name);        
        ENVOY_LOG(trace, "Network name: {}", name);
        // [Christian] has a problem with formulas, we need to create counters
        initializeNetworkCounters(name);
      } else if (limit.has_roaming_partner()) {
        // remember RP names
        for (const auto& kv : limit.roaming_partner().rp_bucket_action_table()) {
          ENVOY_LOG(trace, "RP name: {}", kv.second.rp_name());
          stat_name_set_->rememberBuiltin(kv.second.rp_name());
          // [Christian] has a problem with formulas, we need to create counters
          initializeRoamingPartnerCounters(kv.second.rp_name());
        }
      } else {
        continue;
      }
    }
  }
  // [Christian] has a problem with formulas, we need to create counters
  initializeGlobalCounters();
}

void RateLimitStats::incCounterPerRP(const Stats::StatName& r12r, const CounterType& flavor) {
  Stats::ElementVec names_with_prefix;

  names_with_prefix.reserve(8);

  names_with_prefix.push_back(stats_prefix_);
  names_with_prefix.push_back(n8e_);
  names_with_prefix.push_back(nf_instance_name_);
  names_with_prefix.push_back(g3p_);
  names_with_prefix.push_back(ingress_);
  names_with_prefix.push_back(r12r_);
  names_with_prefix.push_back(r12r);
  switch (flavor) {

  case CounterType::PASSED:
    names_with_prefix.push_back(per_rp_accepted_);
    break;
  case CounterType::REJECTED:
    names_with_prefix.push_back(per_rp_rejected_);
    break;
  case CounterType::DROPPED:
    names_with_prefix.push_back(per_rp_dropped_);
    break;
  }

  Stats::Utility::counterFromElements(scope_, names_with_prefix).inc();
}

void RateLimitStats::incCounterPerNetwork(
    /*const Stats::StatName& s6a6, */ const Stats::StatName& n5k, const CounterType& flavor) {
  Stats::ElementVec names_with_prefix;

  names_with_prefix.reserve(8);

  names_with_prefix.push_back(stats_prefix_);
  names_with_prefix.push_back(n8e_);
  names_with_prefix.push_back(nf_instance_name_);
  names_with_prefix.push_back(g3p_);
  names_with_prefix.push_back(ingress_);
  // names_with_prefix.push_back(s6a6_);
  // names_with_prefix.push_back(s6a6);
  names_with_prefix.push_back(n5k_);
  names_with_prefix.push_back(n5k);
  switch (flavor) {

  case CounterType::PASSED:
    names_with_prefix.push_back(per_nw_accepted_);
    break;
  case CounterType::REJECTED:
    names_with_prefix.push_back(per_nw_rejected_);
    break;
  case CounterType::DROPPED:
    names_with_prefix.push_back(per_nw_dropped_);
    break;
  }

  Stats::Utility::counterFromElements(scope_, names_with_prefix).inc();
}

void RateLimitStats::incCounter(const Stats::ElementVec& names) {
  Stats::Utility::counterFromElements(scope_, addPrefix(names)).inc();
}

// NB! Should be called AFTER rememberBuiltin
void RateLimitStats::initializeNetworkCounters(const std::string& name) {
  Stats::ElementVec names_with_prefix;

  names_with_prefix.reserve(8);

  names_with_prefix.push_back(stats_prefix_);
  names_with_prefix.push_back(n8e_);
  names_with_prefix.push_back(nf_instance_name_);
  names_with_prefix.push_back(g3p_);
  names_with_prefix.push_back(ingress_);
  names_with_prefix.push_back(n5k_);
  names_with_prefix.push_back(getBuiltin(name, unknown_name_));

  names_with_prefix.push_back(per_nw_accepted_);
  Stats::Utility::counterFromElements(scope_, names_with_prefix);

  names_with_prefix.pop_back();

  names_with_prefix.push_back(per_nw_rejected_);
  Stats::Utility::counterFromElements(scope_, names_with_prefix);

  names_with_prefix.pop_back();

  names_with_prefix.push_back(per_nw_dropped_);
  Stats::Utility::counterFromElements(scope_, names_with_prefix);
}

// NB! Should be called AFTER rememberBuiltin
void RateLimitStats::initializeRoamingPartnerCounters(const std::string& name) {
  Stats::ElementVec names_with_prefix;

  names_with_prefix.reserve(8);

  names_with_prefix.push_back(stats_prefix_);
  names_with_prefix.push_back(n8e_);
  names_with_prefix.push_back(nf_instance_name_);
  names_with_prefix.push_back(g3p_);
  names_with_prefix.push_back(ingress_);
  names_with_prefix.push_back(r12r_);
  names_with_prefix.push_back(getBuiltin(name, unknown_name_));

  names_with_prefix.push_back(per_rp_accepted_);
  Stats::Utility::counterFromElements(scope_, names_with_prefix);

  names_with_prefix.pop_back();

  names_with_prefix.push_back(per_rp_rejected_);
  Stats::Utility::counterFromElements(scope_, names_with_prefix);

  names_with_prefix.pop_back();

  names_with_prefix.push_back(per_rp_dropped_);
  Stats::Utility::counterFromElements(scope_, names_with_prefix);
}

void RateLimitStats::initializeGlobalCounters() {
  Stats::Utility::counterFromElements(
      scope_, addPrefix({n8e_, nf_instance_name_, g3p_, ingress_, total_accepted_}));
  Stats::Utility::counterFromElements(
      scope_, addPrefix({n8e_, nf_instance_name_, g3p_, ingress_, total_rejected_}));
  Stats::Utility::counterFromElements(
      scope_, addPrefix({n8e_, nf_instance_name_, g3p_, ingress_, total_dropped_}));
}

Stats::ElementVec RateLimitStats::addPrefix(const Stats::ElementVec& names) {
  Stats::ElementVec names_with_prefix;
  names_with_prefix.reserve(1 + names.size());
  names_with_prefix.push_back(stats_prefix_);
  names_with_prefix.insert(names_with_prefix.end(), names.begin(), names.end());
  return names_with_prefix;
}

std::string RateLimitStats::getNameFromBucketName(const std::string& bucket_name) {

  std::size_t found = bucket_name.rfind('=');
  if (found != std::string::npos) {
    return bucket_name.substr(found + 1, bucket_name.length());
  }
  PANIC("Configured bucket name does not follow the correct format");
}

std::string RateLimitStats::extractNfInstance() {
  std::smatch m;
  std::regex_search(fetched_prefix_, m, SpecifierConstants::get().PATTERN);
  return m.empty()? "null" : m.str(1);
}

} // namespace IngressRateLimitFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
