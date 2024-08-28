#include "envoy/http/header_map.h"
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/header_utility.h"
#include "source/common/http/utility.h"
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <tuple>
#include <vector>

// Methods in this file are all in the EricProxyFilter class.
// They are stored in a separate file to keep action processing
// separate.

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

//-------- Query-Parameter Actions ---------------------------------------------------------------
// Modify Query-Parameter
ActionResultTuple EricProxyFilter::actionModifyQueryParam(const ActionModifyQueryParamWrapper& action) {
  const auto& proto_config = action.protoConfig().action_modify_query_param();
  const auto& key_name = proto_config.key_name();

  // If run_ctx_ was not populated with query param value
  // then check if you are going to modify it.
  // If yes, then populate run_ctx_ after modification
  // so that run_ctx_ update only happens once.
  if (run_ctx_.rootContext()->hasQueryParamName(key_name) && run_ctx_.isRequest()) {
    const auto& path_hdr = run_ctx_.getReqHeaders()->get(Http::LowerCaseString(":path"));
    if (path_hdr.empty()) {
      return std::make_tuple(ActionResult::Next, false, std::nullopt);
    }

    auto req_query_params = Http::Utility::QueryParamsMulti::parseQueryString(
      path_hdr[0]->value().getStringView()
    );
    const auto query_param = req_query_params.getFirstValue(key_name);
    if (!query_param.has_value()) {
      // Cannot find relevant query param in
      // path header -> jump to next action as it's not
      // an error case
      return std::make_tuple(ActionResult::Next, false, std::nullopt);
    }

    if (proto_config.has_replace_value()) {
      const auto new_val = varHeaderConstValueAsString(proto_config.replace_value(), true);
      req_query_params.overwrite(key_name, new_val);
      // Populate run_ctx_ with new query_param value
      run_ctx_.setQueryParamValue(key_name, new_val);
      // Set :path header with new query string
      const auto& new_path = req_query_params.replaceQueryString(path_hdr[0]->value());
      run_ctx_.getReqHeaders()->setCopy(Http::LowerCaseString(":path"), new_path);
      ENVOY_STREAM_LOG(trace, "Replacing query param:'{}', new value: '{}'",
                       *decoder_callbacks_, key_name, new_val);
    } else if (
      proto_config.has_use_string_modifiers() &&
      !proto_config.use_string_modifiers().string_modifiers().empty()
    ) {
      auto string_modifiers = proto_config.use_string_modifiers().string_modifiers();

      const auto query_param_idx = run_ctx_.rootContext()->findOrInsertQueryParamName(key_name);
      std::string query_param_val =
          run_ctx_.hasQueryParamValue(query_param_idx)
              ? std::string(run_ctx_.queryParamValue(query_param_idx))
              : query_param.value();

      ENVOY_STREAM_LOG(trace, "Modifying query param:'{}', current value: '{}'",
                       *decoder_callbacks_, key_name, query_param_val);

      for (const auto& string_modifier : string_modifiers) {
        const auto& modifier_function = prepareStringModifier(string_modifier, run_ctx_, decoder_callbacks_);
        try {
          query_param_val = modifier_function(query_param_val);
        } catch (const std::string& e) {
          ENVOY_STREAM_LOG(trace, "string modifier exception in actionModifyQueryParam: '{}'", *decoder_callbacks_, e);
          if (run_ctx_.stringModifierContext()) {
            if (!run_ctx_.stringModifierContext()->getMappingUnsuccessfulFilterCase().empty()) {
              std::string fc_unsuccessful_operation = run_ctx_.stringModifierContext()->getMappingUnsuccessfulFilterCase();
              ENVOY_STREAM_LOG(trace, "unsuccessful operation filter case for string modifier: '{}'",
                              *decoder_callbacks_, fc_unsuccessful_operation);
              return std::make_tuple(ActionResult::GotoFC, false, fc_unsuccessful_operation);
            }
            if (!run_ctx_.stringModifierContext()->getScramblingUnsuccessfulFilterCase().empty()) {
              std::string fc_unsuccessful_operation = run_ctx_.stringModifierContext()->getScramblingUnsuccessfulFilterCase();
              ENVOY_STREAM_LOG(trace, "unsuccessful operation filter case for string modifier: '{}'",
                              *decoder_callbacks_, fc_unsuccessful_operation);
              return std::make_tuple(ActionResult::GotoFC, false, fc_unsuccessful_operation);
            }
          }
          ENVOY_STREAM_LOG(trace, "no unsuccessful operation filter case found for string modifier", *decoder_callbacks_);
          return std::make_tuple(ActionResult::Next, false, std::nullopt);
        } catch (...) {
          ENVOY_STREAM_LOG(trace, "unknown exception in actionModifyQueryParam", *decoder_callbacks_);
          return std::make_tuple(ActionResult::Next, false, std::nullopt);
        }
      }

      // Populate run_ctx_ with new query_param value
      req_query_params.overwrite(key_name, query_param_val);
      run_ctx_.setQueryParamValue(key_name, query_param_val);
      // Set :path header with new query string
      const auto new_path = req_query_params.replaceQueryString(path_hdr[0]->value());
      run_ctx_.getReqHeaders()->setCopy(Http::LowerCaseString(":path"), new_path);
      ENVOY_STREAM_LOG(trace, "Modifying query param:'{}', new value: '{}'", *decoder_callbacks_,
                       key_name, query_param_val);
      ENVOY_STREAM_LOG(trace, "query parameter modification successful", *decoder_callbacks_);
    }

    return std::make_tuple(ActionResult::Next, true, std::nullopt);
  }

  return std::make_tuple(ActionResult::Next, false, std::nullopt);
}

ActionResultTuple EricProxyFilter::actionRemoveQueryParam(const FilterActionWrapper& action) {
  const auto& path_hdr = run_ctx_.getReqHeaders()->get(Http::LowerCaseString(":path"));
  if(path_hdr.empty()) {
    return std::make_tuple(ActionResult::Next, false, std::nullopt);
  }

  const auto& key_name = action.protoConfig().action_remove_query_param().key_name();
  auto req_query_params =
      Http::Utility::QueryParamsMulti::parseQueryString(path_hdr[0]->value().getStringView());
  const auto query_param = req_query_params.getFirstValue(key_name);
  if (!query_param.has_value()) {
    return std::make_tuple(ActionResult::Next, false, std::nullopt);
  }
  req_query_params.remove(key_name);
  const auto& new_path = req_query_params.replaceQueryString(path_hdr[0]->value());
  run_ctx_.getReqHeaders()->setCopy(Http::LowerCaseString(":path"), new_path);

  // Update run_ctx_
  if(run_ctx_.rootContext()->hasQueryParamName(key_name)) {
    auto var_idx = run_ctx_.rootContext()->findOrInsertQueryParamName(key_name);
    if(run_ctx_.hasQueryParamValue(var_idx)) {
      // FIXME: There should be run_ctx->removeQueryParam()
      // to remove the query param value and key from run_ctx
      run_ctx_.setQueryParamValue(key_name, "");
    }
  }

  return std::make_tuple(ActionResult::Next, true, std::nullopt);
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
