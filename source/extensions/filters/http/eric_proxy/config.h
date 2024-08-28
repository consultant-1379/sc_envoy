#pragma once

#include <string>

#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.validate.h"
#include "envoy/http/filter.h"
#include "envoy/server/factory_context.h"

#include "source/extensions/filters/http/common/factory_base.h"
#include "source/extensions/filters/http/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

class EricProxyFilterFactory
    : public Common::FactoryBase<
          envoy::extensions::filters::http::eric_proxy::v3::EricProxyConfig> {
public:
  EricProxyFilterFactory() : FactoryBase(HttpFilterNames::get().EricProxy) {}

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::eric_proxy::v3::EricProxyConfig& config,
      const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
