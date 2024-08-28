#include "source/extensions/filters/http/eric_ingress_ratelimit/config.h"
#include "source/extensions/filters/http/eric_ingress_ratelimit/ingress_ratelimit_config.h"
#include "envoy/extensions/filters/http/eric_ingress_ratelimit/v3/eric_ingress_ratelimit.pb.h"
#include "source/extensions/filters/http/eric_ingress_ratelimit/ratelimit.h"
#include <algorithm>
#include <iterator>
#include <memory>
#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IngressRateLimitFilter {

Http::FilterFactoryCb RateLimitFilterConfig::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::eric_ingress_ratelimit::v3::IngressRateLimit&
        proto_config,
    const std::string& stats_prefix, Server::Configuration::FactoryContext& context) {

  auto config =
      std::make_shared<EricIngressRateLimitConfig>(proto_config, context.serverFactoryContext().clusterManager());

  const std::chrono::milliseconds timeout =
      std::chrono::milliseconds(PROTOBUF_GET_MS_OR_DEFAULT(proto_config, timeout, 20));

  // a timestamp of when a configuration update was received
  const std::chrono::time_point<std::chrono::system_clock> config_updated_at =
      std::chrono::system_clock::now();
  // the 32 3gpp priorities mapped to token bucket watermarks
  auto watermarks = std::make_shared<std::vector<float>>();
  std::for_each(std::begin(proto_config.watermarks()), std::end(proto_config.watermarks()),
                [&](auto i) { watermarks->push_back(i); });
  auto stats = std::make_shared<RateLimitStats>(config, context.scope(), stats_prefix);
  return [config, config_updated_at, timeout, watermarks,
          stats](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamFilter(std::make_shared<EricIngressRateLimitFilter>(
        config, config_updated_at, timeout, watermarks, stats));
  };
}

/**
 * Static registration for the rate limit filter. @see RegisterFactory.
 */
REGISTER_FACTORY(RateLimitFilterConfig, Server::Configuration::NamedHttpFilterConfigFactory){
    "envoy.eric_ingress_ratelimit"};

} // namespace IngressRateLimitFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy