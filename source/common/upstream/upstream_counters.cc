#include "source/common/upstream/upstream_counters.h"
#include "source/common/config/metadata.h"
#include "source/common/config/well_known_names.h"

namespace Envoy {
namespace Upstream {
ClusterTrafficPerNfStats::ClusterTrafficPerNfStats(
    Stats::Scope& scope, const envoy::config::core::v3::Metadata* metadata)
    : scope_(scope), stat_name_set_(scope.symbolTable().makeSet("EricProxy")),
      // stats_prefix_(stat_name_set_->add(absl::string_view("http.eric_proxy"))),
      n10d_(stat_name_set_->add(absl::string_view("n10d"))),
      upstream_rq_total_per_nf_(stat_name_set_->add(absl::string_view("upstream_rq_total_per_nf"))),
      upstream_rq_timeout_per_nf_(
          stat_name_set_->add(absl::string_view("upstream_rq_timeout_per_nf"))),
      upstream_rq_rx_reset_per_nf_(
          stat_name_set_->add(absl::string_view("upstream_rq_rx_reset_per_nf"))),
      upstream_rq_tx_reset_per_nf_(
          stat_name_set_->add(absl::string_view("upstream_rq_tx_reset_per_nf"))),
      upstream_rq_pending_failure_eject_per_nf_(
          stat_name_set_->add(absl::string_view("upstream_rq_pending_failure_eject_per_nf"))),
      upstream_rq_after_retry_per_nf_(
          stat_name_set_->add(absl::string_view("upstream_rq_after_retry_per_nf"))),
      upstream_rq_after_reselect_per_nf_(
          stat_name_set_->add(absl::string_view("upstream_rq_after_reselect_per_nf"))),
      upstream_rq_1xx_per_nf_(stat_name_set_->add("upstream_rq_1xx_per_nf")),
      upstream_rq_2xx_per_nf_(stat_name_set_->add("upstream_rq_2xx_per_nf")),
      upstream_rq_3xx_per_nf_(stat_name_set_->add("upstream_rq_3xx_per_nf")),
      upstream_rq_4xx_per_nf_(stat_name_set_->add("upstream_rq_4xx_per_nf")),
      upstream_rq_5xx_per_nf_(stat_name_set_->add("upstream_rq_5xx_per_nf")),
      unknown_id_(stat_name_set_->add(absl::string_view("unknown_id"))) {
  is_activated_ = Config::Metadata::metadataValue(
                      metadata, Config::MetadataFilters::get().ENVOY_ERIC_PROXY, "pernfcounter")
                      .bool_value();
  if (is_activated_) {
    rememberInstanceIds(metadata);
  }
}

void ClusterTrafficPerNfStats::updateMeta(const envoy::config::core::v3::Metadata* metadata) {
  is_activated_ = Config::Metadata::metadataValue(
                      metadata, Config::MetadataFilters::get().ENVOY_ERIC_PROXY, "pernfcounter")
                      .bool_value();
  if (is_activated_) {
    rememberInstanceIds(metadata);
  }
}

void ClusterTrafficPerNfStats::rememberInstanceIds(
    const envoy::config::core::v3::Metadata* metadata) {
  const auto& value = Envoy::Config::Metadata::metadataValue(
      metadata, Config::MetadataFilters::get().ENVOY_ERIC_PROXY, "nfInstanceId");
  if (value.kind_case() != ProtobufWkt::Value::kListValue) {
    // error
  } else {
    nf_inctance_id_ = value.list_value().values(0).string_value();
    stat_name_set_->rememberBuiltin(nf_inctance_id_);
  }
}

Stats::StatNameVec ClusterTrafficPerNfStats::addPrefix(const Stats::StatNameVec& names) const {
  Stats::StatNameVec names_with_prefix;
  names_with_prefix.reserve(1 + names.size());
  names_with_prefix.push_back(stats_prefix_);
  names_with_prefix.insert(names_with_prefix.end(), names.begin(), names.end());
  return names_with_prefix;
}

void ClusterTrafficPerNfStats::upstreamRqTotalPerNfInc() const {
  if (is_activated_ && !nf_inctance_id_.empty()) {
    const auto id = stat_name_set_->getBuiltin(nf_inctance_id_, unknown_id_);
    Stats::Utility::counterFromStatNames(scope_, addPrefix({n10d_, id, upstream_rq_total_per_nf_}))
        .inc();
  }
}

void ClusterTrafficPerNfStats::upstreamRqTimeoutPerNfInc() const {
  if (is_activated_ && !nf_inctance_id_.empty()) {
    const auto id = stat_name_set_->getBuiltin(nf_inctance_id_, unknown_id_);
    Stats::Utility::counterFromStatNames(scope_,
                                         addPrefix({n10d_, id, upstream_rq_timeout_per_nf_}))
        .inc();
  }
}

void ClusterTrafficPerNfStats::upstreamRqRxResetPerNfInc() const {
  if (is_activated_ && !nf_inctance_id_.empty()) {
    const auto id = stat_name_set_->getBuiltin(nf_inctance_id_, unknown_id_);
    Stats::Utility::counterFromStatNames(scope_,
                                         addPrefix({n10d_, id, upstream_rq_rx_reset_per_nf_}))
        .inc();
  }
}

void ClusterTrafficPerNfStats::upstreamRqTxResetPerNfInc() const {
  if (is_activated_ && !nf_inctance_id_.empty()) {
    const auto id = stat_name_set_->getBuiltin(nf_inctance_id_, unknown_id_);
    Stats::Utility::counterFromStatNames(scope_,
                                         addPrefix({n10d_, id, upstream_rq_tx_reset_per_nf_}))
        .inc();
  }
}

void ClusterTrafficPerNfStats::upstreamRqPendingFailureEjectPerNfInc() const {
  if (is_activated_ && !nf_inctance_id_.empty()) {
    const auto id = stat_name_set_->getBuiltin(nf_inctance_id_, unknown_id_);
    Stats::Utility::counterFromStatNames(scope_,
                                         addPrefix({n10d_, id, upstream_rq_pending_failure_eject_per_nf_}))
        .inc();
  }
}

void ClusterTrafficPerNfStats::upstreamRqAfterRetryPerNfInc() const {
  if (is_activated_ && !nf_inctance_id_.empty()) {
    const auto id = stat_name_set_->getBuiltin(nf_inctance_id_, unknown_id_);
    Stats::Utility::counterFromStatNames(scope_,
                                         addPrefix({n10d_, id, upstream_rq_after_retry_per_nf_}))
        .inc();
  }
}

void ClusterTrafficPerNfStats::upstreamRqAfterReselectPerNfInc() const {
  if (is_activated_ && !nf_inctance_id_.empty()) {
    const auto id = stat_name_set_->getBuiltin(nf_inctance_id_, unknown_id_);
    Stats::Utility::counterFromStatNames(scope_,
                                         addPrefix({n10d_, id, upstream_rq_after_reselect_per_nf_}))
        .inc();
  }
}

void ClusterTrafficPerNfStats::upstreamRq1xxPerNfInc() const {
  if (is_activated_ && !nf_inctance_id_.empty()) {
    const auto id = stat_name_set_->getBuiltin(nf_inctance_id_, unknown_id_);
    Stats::Utility::counterFromStatNames(scope_, addPrefix({n10d_, id, upstream_rq_1xx_per_nf_}))
        .inc();
  }
}

void ClusterTrafficPerNfStats::upstreamRq2xxPerNfInc() const {
  if (is_activated_ && !nf_inctance_id_.empty()) {
    const auto id = stat_name_set_->getBuiltin(nf_inctance_id_, unknown_id_);
    Stats::Utility::counterFromStatNames(scope_, addPrefix({n10d_, id, upstream_rq_2xx_per_nf_}))
        .inc();
  }
}

void ClusterTrafficPerNfStats::upstreamRq3xxPerNfInc() const {
  if (is_activated_ && !nf_inctance_id_.empty()) {
    const auto id = stat_name_set_->getBuiltin(nf_inctance_id_, unknown_id_);
    Stats::Utility::counterFromStatNames(scope_, addPrefix({n10d_, id, upstream_rq_3xx_per_nf_}))
        .inc();
  }
}

void ClusterTrafficPerNfStats::upstreamRq4xxPerNfInc() const {
  if (is_activated_ && !nf_inctance_id_.empty()) {
    const auto id = stat_name_set_->getBuiltin(nf_inctance_id_, unknown_id_);
    Stats::Utility::counterFromStatNames(scope_, addPrefix({n10d_, id, upstream_rq_4xx_per_nf_}))
        .inc();
  }
}

void ClusterTrafficPerNfStats::upstreamRq5xxPerNfInc() const {
  if (is_activated_ && !nf_inctance_id_.empty()) {
    const auto id = stat_name_set_->getBuiltin(nf_inctance_id_, unknown_id_);
    Stats::Utility::counterFromStatNames(scope_, addPrefix({n10d_, id, upstream_rq_5xx_per_nf_}))
        .inc();
  }
}

} // namespace Upstream
} // namespace Envoy