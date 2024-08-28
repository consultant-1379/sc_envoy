#include "source/extensions/filters/http/eric_proxy/config.h"

#include <memory>

#include "envoy/common/exception.h"
#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "envoy/http/filter.h"
#include "envoy/registry/registry.h"
#include "envoy/server/factory_context.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {


Http::FilterFactoryCb EricProxyFilterFactory::createFilterFactoryFromProtoTyped(const envoy::extensions::filters::http::eric_proxy::v3::EricProxyConfig& proto_config, const std::string& stats_prefix, Server::Configuration::FactoryContext& context) {
  auto config = std::make_shared<EricProxyFilterConfig>(proto_config, context.serverFactoryContext().clusterManager());
  auto stats = std::make_shared<EricProxyStats>(config, context.scope(), stats_prefix);
  auto notifier = std::make_shared<AlarmNotifier>(proto_config.event_log_path(),context.serverFactoryContext().accessLogManager());
  const std::chrono::time_point<std::chrono::system_clock> config_updated_at =
  std::chrono::system_clock::now();
  return [config, config_updated_at, &context, stats, notifier](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamFilter(std::make_shared<EricProxyFilter>(
        config, config_updated_at, context.serverFactoryContext().api().randomGenerator(), stats, notifier));
  };
}

REGISTER_FACTORY(EricProxyFilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);

REGISTER_FACTORY(EricProxyClusterTypedMetadataFactory, Upstream::ClusterTypedMetadataFactory);

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
