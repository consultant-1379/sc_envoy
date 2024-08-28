#pragma once

#include "source/extensions/filters/http/eric_proxy/condition.h"
#include "source/extensions/filters/http/eric_proxy/proxy_filter_config.h"
#include "source/extensions/filters/http/eric_proxy/contexts.h"
#include <memory>


namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy{

std::unique_ptr<Operator> setUpCondition(RootContext& root_ctx, const ConditionProtoConfig& pe,
                                       std::set<ValueIndex>& var_req,
                                       std::set<ValueIndex>& hdr_req,
                                       std::set<ValueIndex>& query_param_req);


} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
