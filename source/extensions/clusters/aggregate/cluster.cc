#include "source/extensions/clusters/aggregate/cluster.h"

#include "envoy/config/cluster/v3/cluster.pb.h"
#include "envoy/event/dispatcher.h"
#include "envoy/extensions/clusters/aggregate/v3/cluster.pb.h"
#include "envoy/extensions/clusters/aggregate/v3/cluster.pb.validate.h"

#include "source/common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace Clusters {
namespace Aggregate {

Cluster::Cluster(const envoy::config::cluster::v3::Cluster& cluster,
                 const envoy::extensions::clusters::aggregate::v3::ClusterConfig& config,
                 Upstream::ClusterFactoryContext& context)
    : Upstream::ClusterImplBase(cluster, context), cluster_manager_(context.clusterManager()),
      runtime_(context.serverFactoryContext().runtime()),
      random_(context.serverFactoryContext().api().randomGenerator()),
      clusters_(std::make_shared<ClusterSet>(config.clusters().begin(), config.clusters().end())) {}

AggregateClusterLoadBalancer::AggregateClusterLoadBalancer(
    const Upstream::ClusterInfoConstSharedPtr& parent_info,
    Upstream::ClusterManager& cluster_manager, Runtime::Loader& runtime,
    Random::RandomGenerator& random, const ClusterSetConstSharedPtr& clusters)
    : parent_info_(parent_info), cluster_manager_(cluster_manager), runtime_(runtime),
      random_(random), clusters_(clusters) {
  for (const auto& cluster : *clusters_) {
    auto tlc = cluster_manager_.getThreadLocalCluster(cluster);
    // It is possible when initializing the cluster, the included cluster doesn't exist. e.g., the
    // cluster could be added dynamically by xDS.
    if (tlc == nullptr) {
      continue;
    }

    // Add callback for clusters initialized before aggregate cluster.
    addMemberUpdateCallbackForCluster(*tlc);
  }
  refresh();
  handle_ = cluster_manager_.addThreadLocalClusterUpdateCallbacks(*this);
}

void AggregateClusterLoadBalancer::addMemberUpdateCallbackForCluster(
    Upstream::ThreadLocalCluster& thread_local_cluster) {
  member_update_cbs_[thread_local_cluster.info()->name()] =
      thread_local_cluster.prioritySet().addMemberUpdateCb(
          [this, target_cluster_info = thread_local_cluster.info()](const Upstream::HostVector&,
                                                                    const Upstream::HostVector&) {
            ENVOY_LOG(debug, "member update for cluster '{}' in aggregate cluster '{}'",
                      target_cluster_info->name(), parent_info_->name());
            refresh();
          });
}

PriorityContextPtr
AggregateClusterLoadBalancer::linearizePrioritySet(OptRef<const std::string> excluded_cluster) {
  PriorityContextPtr priority_context = std::make_unique<PriorityContext>();
  uint32_t next_priority_after_linearizing = 0;

  // Linearize the priority set. e.g. for clusters [C_0, C_1, C_2] referred in aggregate cluster
  //    C_0 [P_0, P_1, P_2]
  //    C_1 [P_0, P_1]
  //    C_2 [P_0, P_1, P_2, P_3]
  // The linearization result is:
  //    [C_0.P_0, C_0.P_1, C_0.P_2, C_1.P_0, C_1.P_1, C_2.P_0, C_2.P_1, C_2.P_2, C_2.P_3]
  // and the traffic will be distributed among these priorities.
  for (const auto& cluster : *clusters_) {
    if (excluded_cluster.has_value() && excluded_cluster.value().get() == cluster) {
      continue;
    }
    auto tlc = cluster_manager_.getThreadLocalCluster(cluster);
    // It is possible that the cluster doesn't exist, e.g., the cluster could be deleted or the
    // cluster hasn't been added by xDS.
    if (tlc == nullptr) {
      ENVOY_LOG(debug, "refresh: cluster '{}' absent in aggregate cluster '{}'", cluster,
                parent_info_->name());
      continue;
    } else {
      ENVOY_LOG(debug, "refresh: cluster '{}' found in aggregate cluster '{}'", cluster,
                parent_info_->name());
    }

    uint32_t priority_in_current_cluster = 0;
    for (const auto& host_set : tlc->prioritySet().hostSetsPerPriority()) {
      if (!host_set->hosts().empty()) {
        priority_context->priority_set_.updateHosts(
            next_priority_after_linearizing, Upstream::HostSetImpl::updateHostsParams(*host_set),
            host_set->localityWeights(), host_set->hosts(), {}, host_set->weightedPriorityHealth(),
            host_set->overprovisioningFactor());
        priority_context->priority_to_cluster_.emplace_back(
            std::make_pair(priority_in_current_cluster, tlc));

        priority_context->cluster_and_priority_to_linearized_priority_[std::make_pair(
            cluster, priority_in_current_cluster)] = next_priority_after_linearizing;
        next_priority_after_linearizing++;
      }
      priority_in_current_cluster++;
    }
  }
  return priority_context;
}

void AggregateClusterLoadBalancer::refresh(OptRef<const std::string> excluded_cluster) {
  PriorityContextPtr priority_context = linearizePrioritySet(excluded_cluster);
  if (!priority_context->priority_set_.hostSetsPerPriority().empty()) {
    load_balancer_ = std::make_unique<LoadBalancerImpl>(
        *priority_context, parent_info_->lbStats(), runtime_, random_, parent_info_->lbConfig(), this);
  } else {
    load_balancer_ = nullptr;
  }
  priority_context_ = std::move(priority_context);
}

void AggregateClusterLoadBalancer::onClusterAddOrUpdate(
    absl::string_view cluster_name, Upstream::ThreadLocalClusterCommand& get_cluster) {
  if (std::find(clusters_->begin(), clusters_->end(), cluster_name) != clusters_->end()) {
    ENVOY_LOG(debug, "adding or updating cluster '{}' for aggregate cluster '{}'", cluster_name,
              parent_info_->name());
    auto& cluster = get_cluster();
    refresh();
    addMemberUpdateCallbackForCluster(cluster);
  }
}

void AggregateClusterLoadBalancer::onClusterRemoval(const std::string& cluster_name) {
  //  The onClusterRemoval callback is called before the thread local cluster is removed. There
  //  will be a dangling pointer to the thread local cluster if the deleted cluster is not skipped
  //  when we refresh the load balancer.
  if (std::find(clusters_->begin(), clusters_->end(), cluster_name) != clusters_->end()) {
    ENVOY_LOG(debug, "removing cluster '{}' from aggregate cluster '{}'", cluster_name,
              parent_info_->name());
    refresh(cluster_name);
  }
}

absl::optional<uint32_t> AggregateClusterLoadBalancer::LoadBalancerImpl::hostToLinearizedPriority(
    const Upstream::HostDescription& host) const {
  auto it = priority_context_.cluster_and_priority_to_linearized_priority_.find(
      std::make_pair(host.cluster().name(), host.priority()));

  if (it != priority_context_.cluster_and_priority_to_linearized_priority_.end()) {
    return it->second;
  } else {
    // The HostSet can change due to CDS/EDS updates between retries.
    return absl::nullopt;
  }
}

void AggregateClusterLoadBalancer::analyzePrioritySet(Upstream::LoadBalancerContext* context) {
  if (load_balancer_) {
    load_balancer_->analyzePrioritySet(context);
  }
}

void AggregateClusterLoadBalancer::LoadBalancerImpl::analyzePrioritySet(
    Upstream::LoadBalancerContext* context) {
  if (context != nullptr) {
    context->determinePriorityLoad(priority_set_, per_priority_load_, [this](const auto& host) {
      return hostToLinearizedPriority(host);
    });
  }
}

Upstream::HostConstSharedPtr
AggregateClusterLoadBalancer::LoadBalancerImpl::chooseHost(Upstream::LoadBalancerContext* context) {
  const Upstream::HealthyAndDegradedLoad* priority_loads = nullptr;
  // ENVOY_LOG(debug, "AggregateClusterLoadBalancer::LoadBalancerImpl::chooseHost() calling "
  //                 "determinePriorityLoad(), choosePriority() ");

  if (context != nullptr) {
    priority_loads = &context->determinePriorityLoad(
        priority_set_, per_priority_load_,
        [this](const auto& host) { return hostToLinearizedPriority(host); });
  } else {
    priority_loads = &per_priority_load_;
  }

  const auto priority_pair =
      choosePriority(random_.random(), priority_loads->healthy_priority_load_,
                     priority_loads->degraded_priority_load_);

  AggregateLoadBalancerContext aggregate_context(
      context, priority_pair.second,
      priority_context_.priority_to_cluster_[priority_pair.first].first);

  Upstream::ThreadLocalCluster* cluster =
      priority_context_.priority_to_cluster_[priority_pair.first].second;
  // ENVOY_LOG(debug, "AggregateClusterLoadBalancer Calling underlying cluster's "
  //                 "chooseHost() with aggregate context ");

  return cluster->loadBalancer().chooseHost(&aggregate_context);
}

// This is the aggregated cluster. Goal is to first find the next priority level
// that is not excluded and with that the "real" cluster (inside this aggregate
// cluster) to which we delegate the choose-host and return the chosen host.
// Since we once had a bug with infinite recursion that we couldn't fix, we
// have added a recursion-depth-protection that exits before crashing.
Upstream::HostConstSharedPtr
AggregateClusterLoadBalancer::LoadBalancerImpl::chooseHostRec(Upstream::LoadBalancerContext* context, int num_rec) {
  const Upstream::HealthyAndDegradedLoad* priority_loads = nullptr;

  ENVOY_LOG(debug, "AggrCluster: START chooseHostRec(recursion-level: {})", num_rec);
  // DND-30832
  // We want debug printouts from the last few recursions and then terminate at level 100
  bool excessive_recursion_detected = (num_rec >= 90);

  if(excessive_recursion_detected){
    ENVOY_LOG(error, "Excessive recursion detected in chooseHost()");
    ENVOY_LOG(error, "Number of recursion: {}", num_rec);
    ENVOY_LOG(error, "Printing debug information:");
  }

  if (context != nullptr) {
    priority_loads = &context->determinePriorityLoad(
        priority_set_, per_priority_load_,
        [this](const auto& host) { return hostToLinearizedPriority(host); });
  } else {
    priority_loads = &per_priority_load_;
  }

  // If there are num_retries left only continue if there are still priority levels that
  // are not marked as excluded (i.e. have not yet been tried). If all priority levels are marked as
  // excluded, i.e. we tried every priority level the corresponding update frequency number
  // of times, return a nullptr as host, which results in Envoy replying with a 503.
  bool found_prio_level{false};
  for (size_t i = 0; i < priority_set_.hostSetsPerPriority().size(); ++i) {
    if (!priority_set_.hostSetsPerPriority()[i]->exclude_) {
      ENVOY_LOG(debug, "AggrCluster: Non-exluded prio level {} is candidate", i);
      found_prio_level = true;
      break;
    }
  }
  // We tried the all priority level, but all were excluded.
  // Reset 'exclude' of all priority levels to 'false' for the next request
  if (!found_prio_level) {
    // TODO(eedala): Is resetting all levels really necessary? It's also done in previous_priorities.cc
    for (size_t i = 0; i < priority_set_.hostSetsPerPriority().size(); ++i) {
      priority_set_.hostSetsPerPriority()[i]->exclude_ = false;
    }
    ENVOY_LOG(
        debug,
        "AggrCluster: RETURN No host found because all prio levels are excluded -> status 503");
    return nullptr;
  }

  const auto priority_pair =
      choosePriority(random_.random(), priority_loads->healthy_priority_load_,
                     priority_loads->degraded_priority_load_);

  if (priority_pair.first == 0) {
    ENVOY_LOG(debug, "AggrCluster: Preferred host is not set yet (or invalid)", preferred_host_);
  } else {
    ENVOY_LOG(debug, "AggrCluster: Preferred host is: '{}'", preferred_host_);
  }

  // DND-24934: Skip this priority level (set the exclude attribute of this priority level to
  // 'true') if :
  // 1. The current priority level must be greater than 0, so that we don't skip the first
  // (preferred) priority level
  // 2. The priority level only contains 1 host
  // 3. Either the omit-host-metadata 'shouldSelectAnotherHost' funtion returns 'true'
  //    **or** the previously stored preferred hostname equals the current hostname (which is
  //    the only one on this prio-level)
  if (priority_pair.first > 0 &&
      priority_set_.hostSetsPerPriority()[priority_pair.first]->hosts().size() == 1) {
    // prio > 0 and only one host on this level
    bool should_select_another_host = context->shouldSelectAnotherHost(
        *priority_set_.hostSetsPerPriority()[priority_pair.first]->hosts().at(0).get());
    if (should_select_another_host) {
      ENVOY_LOG(debug,
                "AggrCluster: Excluding prio level {} because shouldSelectAnotherHost() "
                "returned 'true' for the only host ({}) on this prio level",
                priority_pair.first,
                priority_set_.hostSetsPerPriority()[priority_pair.first]
                    ->hosts()
                    .at(0)
                    .get()
                    ->hostname());
    }
    bool only_host_is_the_preferred_host = (preferred_host_ == priority_set_.hostSetsPerPriority()[priority_pair.first]
      ->hosts().at(0).get()->hostname());
    if (only_host_is_the_preferred_host) {
      ENVOY_LOG(
          debug,
          "AggrCluster: Excluding prio level {} because the only host ({}) is the preferred host",
          priority_pair.first, preferred_host_);
    }
    if (should_select_another_host || only_host_is_the_preferred_host) {
      priority_set_.hostSetsPerPriority()[priority_pair.first]->exclude_ = true;
      if (excessive_recursion_detected) {
        // Print information for debugging
        ENVOY_LOG(error, "Current priority level: '{}'", priority_pair.first);
        ENVOY_LOG(error, "Priority level '{}' number of hosts: '{}'", priority_pair.first, priority_set_.hostSetsPerPriority()[priority_pair.first]->hosts().size());
        for(auto const& host: priority_set_.hostSetsPerPriority()[priority_pair.first]->hosts()){
          ENVOY_LOG(error, "Priority level '{}' containing host: '{}'", priority_pair.first, host.get()->hostname());
        }
        ENVOY_LOG(error, "Preferred Host: '{}'", preferred_host_);
        ENVOY_LOG(error, "Current hostname: '{}'", priority_set_.hostSetsPerPriority()[priority_pair.first]->hosts().at(0).get()->hostname());
        ENVOY_LOG(error, "Current host configured in omit-host-metadata?: '{}'", context->shouldSelectAnotherHost(
              *priority_set_.hostSetsPerPriority()[priority_pair.first]->hosts().at(0).get()));

        // Terminate when we reach 100 levels of recursion depth:
        if(num_rec == 100) {
          ENVOY_LOG(trace, "AggrCluster: RETURN chooseHostRec() because max. recursion depth is reached: No host found -> status 503");
          // Envoy replies with a 503
          return nullptr;
        }
      }
      // We are going into the recursion and try the next prio level
      ENVOY_LOG(debug,
                "AggrCluster: (return) Trying next prio level because this level is excluded");
      return AggregateClusterLoadBalancer::LoadBalancerImpl::chooseHostRec(context, num_rec + 1);
    }
  }
  // If we make it here, we have found a not-excluded prio level in the aggregate cluster.
  ENVOY_LOG(debug, "AggrCluster: Selected prio level {}", priority_pair.first);

  AggregateLoadBalancerContext aggregate_context(
      context, priority_pair.second,
      priority_context_.priority_to_cluster_[priority_pair.first].first);

  // Given the priority-level in the aggregate cluster, select the "real" cluster
  // that will receive the request:
  Upstream::ThreadLocalCluster* cluster =
      priority_context_.priority_to_cluster_[priority_pair.first].second;

  // That "real" cluster will choose the host that receives the request.
  // In other words, we are delegating it to the "real" host.

  auto host_descr = cluster->loadBalancer().chooseHost(&aggregate_context);

  // DND-26881: In scenarios where the Endpoint host metadata is not set to the hostname (i.e. it
  // differs from the configured omit-host-metadata), we still want the preferred host to be skipped
  // in reselections, i.e. we still want the functionality of omit-host-metadata. For that we manually
  // store the hostname of the host in the highest priority level (0) in order to later compare it
  // to the hostname of the currently selected host in lower priority levels.
  if (priority_pair.first == 0) {
    preferred_host_ = host_descr->hostname();
    ENVOY_LOG(debug,
              "AggrCluster: Storing the preferred host '{}' in prio level 0 to exclude "
              "higher levels that only contain this preferred host",
              preferred_host_);
  }

  ENVOY_LOG(debug, "AggrCluster: RETURN chooseHost() => Chosen host is: '{}'",
            host_descr->hostname());
  return host_descr;
}

Upstream::HostConstSharedPtr
AggregateClusterLoadBalancer::chooseHost(Upstream::LoadBalancerContext* context) {

  if (load_balancer_) {
    Upstream::HostConstSharedPtr host;
    ENVOY_LOG(debug, "aggrCluster->chooseHost() delegating to cluster member lb");
    return load_balancer_->chooseHost(context);
  }
  return nullptr;
}

Upstream::HostConstSharedPtr
AggregateClusterLoadBalancer::peekAnotherHost(Upstream::LoadBalancerContext* context) {
  if (load_balancer_) {
    return load_balancer_->peekAnotherHost(context);
  }
  return nullptr;
}

absl::optional<Upstream::SelectedPoolAndConnection>
AggregateClusterLoadBalancer::selectExistingConnection(Upstream::LoadBalancerContext* context,
                                                       const Upstream::Host& host,
                                                       std::vector<uint8_t>& hash_key) {
  if (load_balancer_) {
    return load_balancer_->selectExistingConnection(context, host, hash_key);
  }
  return absl::nullopt;
}

OptRef<Envoy::Http::ConnectionPool::ConnectionLifetimeCallbacks>
AggregateClusterLoadBalancer::lifetimeCallbacks() {
  if (load_balancer_) {
    return load_balancer_->lifetimeCallbacks();
  }
  return {};
}

absl::StatusOr<std::pair<Upstream::ClusterImplBaseSharedPtr, Upstream::ThreadAwareLoadBalancerPtr>>
ClusterFactory::createClusterWithConfig(
    const envoy::config::cluster::v3::Cluster& cluster,
    const envoy::extensions::clusters::aggregate::v3::ClusterConfig& proto_config,
    Upstream::ClusterFactoryContext& context) {
  auto new_cluster = std::make_shared<Cluster>(cluster, proto_config, context);
  auto lb = std::make_unique<AggregateThreadAwareLoadBalancer>(*new_cluster);
  return std::make_pair(new_cluster, std::move(lb));
}

REGISTER_FACTORY(ClusterFactory, Upstream::ClusterFactory);

} // namespace Aggregate
} // namespace Clusters
} // namespace Extensions
} // namespace Envoy
