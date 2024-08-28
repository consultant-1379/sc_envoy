#include "source/common/upstream/host_utility.h"

#include <string>

#include "source/common/config/well_known_names.h"
#include "source/common/runtime/runtime_features.h"

namespace Envoy {
namespace Upstream {
namespace {

void setHealthFlag(Upstream::Host::HealthFlag flag, const Host& host, std::string& health_status) {
  switch (flag) {
  case Host::HealthFlag::FAILED_ACTIVE_HC: {
    if (host.healthFlagGet(Host::HealthFlag::FAILED_ACTIVE_HC)) {
      health_status += "/failed_active_hc";
    }
    break;
  }

  case Host::HealthFlag::FAILED_OUTLIER_CHECK: {
    if (host.healthFlagGet(Host::HealthFlag::FAILED_OUTLIER_CHECK)) {
      health_status += "/failed_outlier_check";
    }
    break;
  }

  case Host::HealthFlag::FAILED_EDS_HEALTH: {
    if (host.healthFlagGet(Host::HealthFlag::FAILED_EDS_HEALTH)) {
      health_status += "/failed_eds_health";
    }
    break;
  }

  case Host::HealthFlag::DEGRADED_ACTIVE_HC: {
    if (host.healthFlagGet(Host::HealthFlag::DEGRADED_ACTIVE_HC)) {
      health_status += "/degraded_active_hc";
    }
    break;
  }

  case Host::HealthFlag::DEGRADED_EDS_HEALTH: {
    if (host.healthFlagGet(Host::HealthFlag::DEGRADED_EDS_HEALTH)) {
      health_status += "/degraded_eds_health";
    }
    break;
  }

  case Host::HealthFlag::PENDING_DYNAMIC_REMOVAL: {
    if (host.healthFlagGet(Host::HealthFlag::PENDING_DYNAMIC_REMOVAL)) {
      health_status += "/pending_dynamic_removal";
    }
    break;
  }

  case Host::HealthFlag::PENDING_ACTIVE_HC: {
    if (host.healthFlagGet(Host::HealthFlag::PENDING_ACTIVE_HC)) {
      health_status += "/pending_active_hc";
    }
    break;
  }

  case Host::HealthFlag::EXCLUDED_VIA_IMMEDIATE_HC_FAIL: {
    if (host.healthFlagGet(Host::HealthFlag::EXCLUDED_VIA_IMMEDIATE_HC_FAIL)) {
      health_status += "/excluded_via_immediate_hc_fail";
    }
    break;
  }

  case Host::HealthFlag::ACTIVE_HC_TIMEOUT: {
    if (host.healthFlagGet(Host::HealthFlag::ACTIVE_HC_TIMEOUT)) {
      health_status += "/active_hc_timeout";
    }
    break;
  }
  }
}

} // namespace

std::string HostUtility::healthFlagsToString(const Host& host) {
  std::string health_status;

  // Invokes setHealthFlag for each health flag.
#define SET_HEALTH_FLAG(name, notused)                                                             \
  setHealthFlag(Upstream::Host::HealthFlag::name, host, health_status);
  HEALTH_FLAG_ENUM_VALUES(SET_HEALTH_FLAG)
#undef SET_HEALTH_FLAG

  if (health_status.empty()) {
    return "healthy";
  } else {
    return health_status;
  }
}

HostUtility::HostStatusSet HostUtility::createOverrideHostStatus(
    const envoy::config::cluster::v3::Cluster::CommonLbConfig& common_config) {
  HostStatusSet override_host_status;

  if (!common_config.has_override_host_status()) {
    // No override host status and [UNKNOWN, HEALTHY, DEGRADED] will be applied by default.
    override_host_status.set(static_cast<uint32_t>(envoy::config::core::v3::HealthStatus::UNKNOWN));
    override_host_status.set(static_cast<uint32_t>(envoy::config::core::v3::HealthStatus::HEALTHY));
    override_host_status.set(
        static_cast<uint32_t>(envoy::config::core::v3::HealthStatus::DEGRADED));
    return override_host_status;
  }

  for (auto single_status : common_config.override_host_status().statuses()) {
    switch (static_cast<envoy::config::core::v3::HealthStatus>(single_status)) {
      PANIC_ON_PROTO_ENUM_SENTINEL_VALUES;
    case envoy::config::core::v3::HealthStatus::UNKNOWN:
    case envoy::config::core::v3::HealthStatus::HEALTHY:
    case envoy::config::core::v3::HealthStatus::UNHEALTHY:
    case envoy::config::core::v3::HealthStatus::DRAINING:
    case envoy::config::core::v3::HealthStatus::TIMEOUT:
    case envoy::config::core::v3::HealthStatus::DEGRADED:
      override_host_status.set(static_cast<uint32_t>(single_status));
      break;
    }
  }
  return override_host_status;
}

HostConstSharedPtr HostUtility::selectOverrideHost(const HostMap* host_map, HostStatusSet status,
                                                   LoadBalancerContext* context) {
  if (context == nullptr) {
    return nullptr;
  }
  const auto override_host = context->overrideHostToSelect();
  const auto host_retry_vect = context->overrideHostRetryIndices();
  const auto host_idx = context->getOverrideHostRetryIndexToChoose();
  if (!override_host.has_value()) {
    ENVOY_LOG(debug, "No Overriden host supplied by eric_proxy");
    return nullptr;
  }
  ENVOY_LOG(debug, "override_host: {}", override_host.value());
  if (host_map == nullptr) {
    return nullptr;
  }

  // For host_utility_test to work
  // since there is no overloaded implementation of
  // overrideHostRetryIndices() for MockLoadBalancerContext
  // Uncomment following lines
  // if(host_retry_vect.empty()){
  //   host_retry_vect = {0};
  // }

  const auto host_iter = host_map->find(override_host.value().first);

  // The override host cannot be found in the host map.
  if (host_iter == host_map->end()) {
    ENVOY_LOG(debug, "Can't find overriden host: {} in host map", override_host.value());
    return nullptr;
  }
  ENVOY_LOG(debug, "Found overriden host: {} in host map", override_host.value());
  std::size_t i =0;
  while(i < host_retry_vect.size()){
    int vect_idx = 0;
    vect_idx = ((host_idx + i)%host_retry_vect.size());
    HostConstSharedPtr host = host_iter->second[host_retry_vect[vect_idx]]
                                  .first;
    ASSERT(host != nullptr);
    // Checked for SC
    if (status[static_cast<uint32_t>(host->healthStatus())]) {
      context->setOverrideHostRetryIndexChosen(vect_idx);
      ENVOY_LOG(debug,"finally chosen host after health_check:'{}'['{}']",host->hostname(),host->address()->asStringView());
      return host;
    } else {
      // Comment out following lines if you wanna run
      // host_utility_test
      ENVOY_LOG(debug, "Host {}, endpoint:{} failed healthstatus check, status {}", host->hostname(),
            host->address()->asStringView(),host->healthStatus());
      i++;
    }
  }

  //set the Retry index counter to 0
  context->setOverrideHostRetryIndexChosen(0);
  return nullptr;
}

bool HostUtility::allowLBChooseHost(LoadBalancerContext* context) {
  if (context == nullptr) {
    return true;
  }

  auto override_host = context->overrideHostToSelect();
  if (!override_host.has_value()) {
    return true;
  }

  // Return opposite value to "strict" setting.
  return !override_host.value().second;
}

void HostUtility::forEachHostMetric(
    const ClusterManager& cluster_manager,
    const std::function<void(Stats::PrimitiveCounterSnapshot&& metric)>& counter_cb,
    const std::function<void(Stats::PrimitiveGaugeSnapshot&& metric)>& gauge_cb) {
  for (const auto& [unused_name, cluster_ref] : cluster_manager.clusters().active_clusters_) {
    Upstream::ClusterInfoConstSharedPtr cluster_info = cluster_ref.get().info();
    if (cluster_info->perEndpointStatsEnabled()) {
      const std::string cluster_name =
          Stats::Utility::sanitizeStatsName(cluster_info->observabilityName());

      const Stats::TagVector& fixed_tags = cluster_info->statsScope().store().fixedTags();

      for (auto& host_set : cluster_ref.get().prioritySet().hostSetsPerPriority()) {
        for (auto& host : host_set->hosts()) {

          Stats::TagVector tags;
          tags.reserve(fixed_tags.size() + 3);
          tags.insert(tags.end(), fixed_tags.begin(), fixed_tags.end());
          tags.emplace_back(Stats::Tag{Envoy::Config::TagNames::get().CLUSTER_NAME, cluster_name});
          tags.emplace_back(Stats::Tag{"envoy.endpoint_address", host->address()->asString()});

          const auto& hostname = host->hostname();
          if (!hostname.empty()) {
            tags.push_back({"envoy.endpoint_hostname", hostname});
          }

          auto set_metric_metadata = [&](absl::string_view metric_name,
                                         Stats::PrimitiveMetricMetadata& metric) {
            metric.setName(
                absl::StrCat("cluster.", cluster_name, ".endpoint.",
                             Stats::Utility::sanitizeStatsName(host->address()->asStringView()),
                             ".", metric_name));
            metric.setTagExtractedName(absl::StrCat("cluster.endpoint.", metric_name));
            metric.setTags(tags);

            // Validate that all components were sanitized.
            ASSERT(metric.name() == Stats::Utility::sanitizeStatsName(metric.name()));
            ASSERT(metric.tagExtractedName() ==
                   Stats::Utility::sanitizeStatsName(metric.tagExtractedName()));
          };

          for (auto& [metric_name, primitive] : host->counters()) {
            Stats::PrimitiveCounterSnapshot metric(primitive.get());
            set_metric_metadata(metric_name, metric);

            counter_cb(std::move(metric));
          }

          auto gauges = host->gauges();

          // Add synthetic "healthy" gauge.
          Stats::PrimitiveGauge healthy_gauge;
          healthy_gauge.set((host->coarseHealth() == Host::Health::Healthy) ? 1 : 0);
          gauges.emplace_back(absl::string_view("healthy"), healthy_gauge);

          for (auto& [metric_name, primitive] : gauges) {
            Stats::PrimitiveGaugeSnapshot metric(primitive.get());
            set_metric_metadata(metric_name, metric);
            gauge_cb(std::move(metric));
          }
        }
      }
    }
  }
}

} // namespace Upstream
} // namespace Envoy