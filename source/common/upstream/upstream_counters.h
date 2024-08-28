#pragma once
#include "envoy/upstream/upstream_counters_interface.h"
#include "envoy/stats/scope.h"

#include "source/common/stats/symbol_table.h"
#include "envoy/config/cluster/v3/cluster.pb.h"
#include <string>


namespace Envoy {
namespace Upstream {

class ClusterTrafficPerNfStats : public ClusterTrafficPerNfStatsInt {
public:
  ClusterTrafficPerNfStats(Stats::Scope& scope,
                           const envoy::config::core::v3::Metadata* metadata);
  // Should be protected by Mutex!
  void updateMeta(const envoy::config::core::v3::Metadata* metadata);
private:
  Stats::Scope& scope_;
  mutable Stats::StatNameSetPtr stat_name_set_;

  const Stats::StatName stats_prefix_;
  const Stats::StatName n10d_;
  const Stats::StatName upstream_rq_total_per_nf_;
  const Stats::StatName upstream_rq_timeout_per_nf_;
  const Stats::StatName upstream_rq_rx_reset_per_nf_;
  const Stats::StatName upstream_rq_tx_reset_per_nf_;
  const Stats::StatName upstream_rq_pending_failure_eject_per_nf_;
  const Stats::StatName upstream_rq_after_retry_per_nf_;
  const Stats::StatName upstream_rq_after_reselect_per_nf_;
  const Stats::StatName upstream_rq_1xx_per_nf_;
  const Stats::StatName upstream_rq_2xx_per_nf_;
  const Stats::StatName upstream_rq_3xx_per_nf_;
  const Stats::StatName upstream_rq_4xx_per_nf_;
  const Stats::StatName upstream_rq_5xx_per_nf_;
  const Stats::StatName unknown_id_;

  bool is_activated_ = false;
  std::string nf_inctance_id_;

  // Should be protected by Mutex! Or should becalled on object creation
  void rememberInstanceIds(const envoy::config::core::v3::Metadata* metadata);
  Stats::StatNameVec addPrefix(const Stats::StatNameVec& names) const;

public:
  void upstreamRqTotalPerNfInc() const override;
  void upstreamRqTimeoutPerNfInc() const override;
  void upstreamRqRxResetPerNfInc() const override;
  void upstreamRqTxResetPerNfInc() const override;
  void upstreamRqPendingFailureEjectPerNfInc() const override;
  void upstreamRqAfterRetryPerNfInc() const override;
  void upstreamRqAfterReselectPerNfInc() const override;
  void upstreamRq1xxPerNfInc() const override;
  void upstreamRq2xxPerNfInc() const override;
  void upstreamRq3xxPerNfInc() const  override;
  void upstreamRq4xxPerNfInc() const  override;
  void upstreamRq5xxPerNfInc() const  override;

};

} // namespace Upstream
} // namespace Envoy