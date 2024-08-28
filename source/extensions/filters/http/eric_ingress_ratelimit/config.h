#pragma once

#include <string>
#include "envoy/http/filter.h"
#include "envoy/server/factory_context.h"
#include "envoy/extensions/filters/http/eric_ingress_ratelimit/v3/eric_ingress_ratelimit.pb.h"
#include "envoy/extensions/filters/http/eric_ingress_ratelimit/v3/eric_ingress_ratelimit.pb.validate.h"

#include "source/extensions/filters/http/common/factory_base.h"


namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IngressRateLimitFilter {


/**
 * Config registration for the rate limit filter.
 */

class RateLimitFilterConfig
    : public Common::FactoryBase<
          envoy::extensions::filters::http::eric_ingress_ratelimit::v3::IngressRateLimit> {

public:
  RateLimitFilterConfig() : FactoryBase("envoy.filters.http.eric_ingress_ratelimit") {}

private:
    Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
        const envoy::extensions::filters::http::eric_ingress_ratelimit::v3::IngressRateLimit& config,
        const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;

};

} // namespace IngressRateLimitFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy