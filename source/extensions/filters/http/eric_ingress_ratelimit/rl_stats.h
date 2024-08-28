#pragma once

#include <memory>
#include <regex>
#include <string>
#include "envoy/stats/scope.h"
#include "source/common/stats/symbol_table.h"
#include "source/common/stats/utility.h"
#include "source/extensions/filters/http/eric_ingress_ratelimit/ingress_ratelimit_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IngressRateLimitFilter {
enum class CounterType {
  PASSED,
  DROPPED,
  REJECTED
};
class RateLimitStats : public Logger::Loggable<Logger::Id::eric_proxy> {
private:
  Stats::Scope& scope_;

  Stats::StatNameSetPtr stat_name_set_;
  const Stats::StatName prefix_;

  Stats::ElementVec addPrefix(const Stats::ElementVec& names);
  std::string extractNfInstance();
  
  // NB! Should be called AFTER rememberBuiltin
  void initializeNetworkCounters(const std::string& name);
  void initializeRoamingPartnerCounters(const std::string& name);
  void initializeGlobalCounters();
public:
  RateLimitStats(const std::shared_ptr<EricIngressRateLimitConfig> config, Stats::Scope& scope, const std::string& fetched_prefix);

  void incCounter(const Stats::ElementVec& names);
  void incCounterPerRP(const Stats::StatName& r12r,
                       const CounterType&);
  void incCounterPerNetwork(/*const Stats::StatName& s6a6,*/
                            const Stats::StatName& n5k, const CounterType&);

  const Stats::StatName stats_prefix_;
  const std::string fetched_prefix_;

  const Stats::StatName n8e_;
  const Stats::StatName g3p_;
  const Stats::StatName s6a6_;
  const Stats::StatName r12r_;
  const Stats::StatName n5k_;
  const Stats::StatName ingress_;
  
  const Stats::StatName per_rp_accepted_;
  const Stats::StatName per_rp_rejected_;
  const Stats::StatName per_rp_dropped_;

  const Stats::StatName per_nw_accepted_;
  const Stats::StatName per_nw_rejected_;
  const Stats::StatName per_nw_dropped_;

  const Stats::StatName total_accepted_;
  const Stats::StatName total_rejected_;
  const Stats::StatName total_dropped_;

  const Stats::StatName unknown_type_;
  const Stats::StatName unknown_name_;
  const Stats::StatName nf_instance_name_;
  const Stats::StatName rlf_lookup_failure_;

  Stats::StatName getBuiltin(const std::string& str, Stats::StatName fallback) {
    return stat_name_set_->getBuiltin(str, fallback);
  }

  // Get network or RP name from bucket namme
  // bucket_name: ingress=GRLnamme.rp=rp_A
  // return name: rp_A
  static std::string getNameFromBucketName(const std::string& bucket_name);
  static bool hasRP(const std::string& bucket_name);
  static bool hasNetwork(const std::string& bucket_name);
  static std::string externalOrInternalNetwork(const std::string& bucket_name);
};

// using this const singleton to have initialized once and have it available for any matching after
class ConstantValues {
public:
    const std::regex PATTERN{"n8e\\.(.+?)\\.", std::regex::optimize};
};

using SpecifierConstants = ConstSingleton<ConstantValues>;
using RateLimitStatsSharedPtr = std::shared_ptr<RateLimitStats>;

} // namespace IngressRateLimitFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy