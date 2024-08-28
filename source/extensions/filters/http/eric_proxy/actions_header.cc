#include "envoy/http/header_map.h"
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/extensions/filters/http/eric_proxy/wrappers.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/header_utility.h"
#include "source/common/http/utility.h"
#include <cstddef>
#include <stdexcept>
#include <tuple>
#include <vector>
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_request_meta.h"

// Methods in this file are all in the EricProxyFilter class.
// They are stored in a separate file to keep action processing
// separate.

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

//-------- Header Actions ---------------------------------------------------------------
// Add Header
ActionResultTuple EricProxyFilter::actionAddHeader(const ActionAddHeaderWrapper& action) {
  const auto proto_config = action.protoConfig().action_add_header();
  const auto& name = proto_config.name();
  const auto name_lc = Http::LowerCaseString(name);
  auto values = varHeaderConstValueAsVector(proto_config.value(), false);
  auto hdr = run_ctx_.getReqOrRespHeaders()->get(name_lc);
  if (hdr.empty()) {
    ENVOY_STREAM_LOG(debug, "Adding new header: {}", *decoder_callbacks_, name);
    for(const auto& value: values){
      ENVOY_STREAM_LOG(debug, "{}: {}", *decoder_callbacks_, name, value);
      run_ctx_.getReqOrRespHeaders()->addCopy(name_lc, value);
    }
    return std::make_tuple(ActionResult::Next, /*headers changed:*/true, std::nullopt);
  }
  // Header exists, act according to configured value for "if_exists"
  switch (proto_config.if_exists()) {
  case NO_ACTION:
    ENVOY_STREAM_LOG(debug, "Header exists -> no action", *decoder_callbacks_);
    return std::make_tuple(ActionResult::Next, /* headers changed: */false, std::nullopt);
  case ADD:
    for(const auto& value: values){
      ENVOY_STREAM_LOG(debug, "Adding header instance {}: {}", *decoder_callbacks_, name, value);
      run_ctx_.getReqOrRespHeaders()->addCopy(name_lc, value);
    }
    return std::make_tuple(ActionResult::Next, /*headers changed:*/true, std::nullopt);
    break;
  case REPLACE:
    ENVOY_STREAM_LOG(debug, "Replacing header: {}", *decoder_callbacks_, name);
    run_ctx_.getReqOrRespHeaders()->remove(name_lc);
    for(const auto& value: values){
      ENVOY_STREAM_LOG(debug, "  -> new value: {}", *decoder_callbacks_, value);
      run_ctx_.getReqOrRespHeaders()->addCopy(name_lc, value);
    }
    return std::make_tuple(ActionResult::Next, /*headers changed:*/true, std::nullopt);
    break;
  default:
    ENVOY_STREAM_LOG(debug, "Unknown \"if_exists\" option", *decoder_callbacks_);
    return std::make_tuple(ActionResult::Next, /*headers changed:*/false, std::nullopt);
  }
}

// Remove Header
ActionResultTuple EricProxyFilter::actionRemoveHeader(const FilterActionWrapper& action) {
  const auto proto_config = action.protoConfig().action_remove_header();
  const auto& name = proto_config.name();
  // for 3gpp sbi peer info header to remove it from router
  // TODO[ekhrart]: think of better solution
  if (absl::EqualsIgnoreCase(name, "3gpp-Sbi-NF-Peer-Info")) {
    SbiNfPeerInfoHeaderRequestMetadata::markSbiPeerInfoHeaderForDeletion(decoder_callbacks_);
  }
  const auto hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(proto_config.name()));
  if (!hdr.empty()) {
    ENVOY_STREAM_LOG(debug, "Removing header: {}", *decoder_callbacks_, name);
    run_ctx_.getReqOrRespHeaders()->remove(Http::LowerCaseString(name));
  }
  return std::make_tuple(ActionResult::Next, true, std::nullopt);
}

// Modify Header
ActionResultTuple EricProxyFilter::actionModifyHeader(const ActionModifyHeaderWrapper& action) {
  const auto proto_config = action.protoConfig().action_modify_header();
  const auto& name = proto_config.name();
  auto header_to_be_modified = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(name));
  if (!header_to_be_modified.empty()) {
    // Is it "replace"?
    if (proto_config.has_replace_value()) {
      auto values = varHeaderConstValueAsVector(proto_config.replace_value(), false);
      if (!values.empty()) {
        ENVOY_STREAM_LOG(debug, "Replacing value in header: {}", *decoder_callbacks_, name);
        run_ctx_.getReqOrRespHeaders()->remove(Http::LowerCaseString(name));
        for(const auto& value: values){
          ENVOY_STREAM_LOG(debug, "{}: {}", *decoder_callbacks_, name, value);
          run_ctx_.getReqOrRespHeaders()->addCopy(Http::LowerCaseString(name), value);
        }
      }
    } else if (proto_config.has_append_value() || proto_config.has_prepend_value()) {
      // Append and/or prepend
      // The value to be appended is always a single string. If it is a header with multiple values,
      // then we combine the header values with "," as per RFC7230.
      // If the header does not exist in the request/response, then do nothing.
      auto appendValue = varHeaderConstValueAsString(proto_config.append_value(), false);
      auto prependValue = varHeaderConstValueAsString(proto_config.prepend_value(), false);
      // If the original header has only one value:
      if (header_to_be_modified.size() == 1) {
        std::string newHdrVal = std::string(header_to_be_modified[0]->value().getStringView());
        if (!prependValue.empty()) {
          ENVOY_STREAM_LOG(debug, "Prepending value: {} in header: {} with value: '{}'",
                    *decoder_callbacks_, header_to_be_modified[0]->value().getStringView(), name, prependValue);
          newHdrVal = newHdrVal.insert(0, prependValue);
        }
        if (!appendValue.empty()) {
          ENVOY_STREAM_LOG(debug, "Appending value: {} in header: {} with value: '{}'",
                    *decoder_callbacks_, header_to_be_modified[0]->value().getStringView(), name, appendValue);
          newHdrVal = newHdrVal.append(appendValue);
        }
        ENVOY_STREAM_LOG(trace, "Setting header: {} to value: '{}'", *decoder_callbacks_, name, newHdrVal);
        run_ctx_.getReqOrRespHeaders()->setCopy(Http::LowerCaseString(name), newHdrVal);
      }
      // The original header had multiple values:
      // -> Append/prepend to all instances of the header
      // DND-26377
      else if (header_to_be_modified.size() > 1){
        // HeaderMap implementation modifies only the first occurrence of the header (see setCopy method doc).
        // So, we do a temporary deep copy of the values, remove the header, and add each value again.
        // It is a bit costly and that's why we do it only for multple header values.
        absl::InlinedVector<std::string, 3> hdrValues; // is this better than std::vector?
        hdrValues.reserve(header_to_be_modified.size());
        for (size_t i = 0; i < header_to_be_modified.size(); i++) {
          hdrValues.push_back(std::string(header_to_be_modified[i]->value().getStringView()));
        }

        ENVOY_STREAM_LOG(debug, "Removing header: {}", *decoder_callbacks_, name);
        run_ctx_.getReqOrRespHeaders()->remove(Http::LowerCaseString(name)); // header_to_be_modified is gone

        for (auto newHdrVal : hdrValues) {
           if (!prependValue.empty()) {
            ENVOY_STREAM_LOG(debug, "Prepending value: {} with value: '{}'",
                      *decoder_callbacks_, newHdrVal, prependValue);
            newHdrVal = newHdrVal.insert(0, prependValue);
          }
          if (!appendValue.empty()) {
            ENVOY_STREAM_LOG(debug, "Appending value: {} with value: '{}'",
                      *decoder_callbacks_, newHdrVal, appendValue);
            newHdrVal = newHdrVal.append(appendValue);
          }
          run_ctx_.getReqOrRespHeaders()->addCopy(Http::LowerCaseString(name), newHdrVal);
        }
      }
    } else if (
      proto_config.has_use_string_modifiers() &&
      !proto_config.use_string_modifiers().string_modifiers().empty()
    ) {
      auto string_modifiers = proto_config.use_string_modifiers().string_modifiers();
      if (header_to_be_modified.size() == 1) {
        std::string hdr_to_be_modified_val = std::string(header_to_be_modified[0]->value().getStringView());
        std::string *hdr_ptr = &hdr_to_be_modified_val;

        for (const auto& string_modifier : string_modifiers) {
          const auto& modifier_function = prepareStringModifier(string_modifier, run_ctx_, decoder_callbacks_);
          ENVOY_STREAM_LOG(trace, "header value before applying string modifier: {}", *decoder_callbacks_, *hdr_ptr);
          try {
            *hdr_ptr = modifier_function(*hdr_ptr);
          } catch (const std::string& e) {
            ENVOY_STREAM_LOG(trace, "string modifier exception in actionModifyHeader: '{}'", *decoder_callbacks_, e);
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
            ENVOY_STREAM_LOG(trace, "unknown exception in actionModifyHeader", *decoder_callbacks_);
            return std::make_tuple(ActionResult::Next, false, std::nullopt);
          }
          ENVOY_STREAM_LOG(trace, "header value after applying string modifier: {}", *decoder_callbacks_, *hdr_ptr);
        }
        run_ctx_.getReqOrRespHeaders()->setCopy(Http::LowerCaseString(name), *hdr_ptr);
      } else if (header_to_be_modified.size() > 1) {
        // HeaderMap implementation modifies only the first occurrence of the header (see setCopy method doc).
        // So, we do a temporary deep copy of the values, remove the header, and add each value again.
        // It is a bit costly and that's why we do it only for multple header values.
        absl::InlinedVector<std::string, 3> hdr_values; // is this better than std::vector?
        hdr_values.reserve(header_to_be_modified.size());
        for (size_t i = 0; i < header_to_be_modified.size(); i++) {
          hdr_values.push_back(std::string(header_to_be_modified[i]->value().getStringView()));
        }

        ENVOY_STREAM_LOG(debug, "Removing header: {}", *decoder_callbacks_, name);
        run_ctx_.getReqOrRespHeaders()->remove(Http::LowerCaseString(name)); // header_to_be_modified is gone

        for (std::string hdr_value : hdr_values) {
          std::string *hdr_ptr = &hdr_value;
          for (const auto& string_modifier : string_modifiers) {
            const auto& modifier_function = prepareStringModifier(string_modifier, run_ctx_, decoder_callbacks_);
            ENVOY_STREAM_LOG(trace, "header value before applying string modifier: {}", *decoder_callbacks_, *hdr_ptr);
            try {
              *hdr_ptr = modifier_function(*hdr_ptr);
            } catch (const std::string& e) {
              ENVOY_STREAM_LOG(trace, "string modifier exception in actionModifyHeader: '{}'", *decoder_callbacks_, e);
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
              ENVOY_STREAM_LOG(trace, "unknown exception in actionModifyHeader", *decoder_callbacks_);
              return std::make_tuple(ActionResult::Next, false, std::nullopt);
            }
            ENVOY_STREAM_LOG(trace, "header value after applying string modifier: {}", *decoder_callbacks_, *hdr_ptr);
          }
          run_ctx_.getReqOrRespHeaders()->addCopy(Http::LowerCaseString(name), *hdr_ptr);
        }
      }
      ENVOY_STREAM_LOG(trace, "header modification successful", *decoder_callbacks_);
    }
    return std::make_tuple(ActionResult::Next, true, std::nullopt);
  }
  return std::make_tuple(ActionResult::Next, false, std::nullopt);
}


// Return the resulting string value for a VarHeaderConstValue protobuf-parameter.
// If the referenced variable or header can not be found and empty string is returned.
// First tries to read a header from the variable run-context, if it's not there, read
// it from the headers directly. 
// If the parameter force_use_req_hdrs is set to false, the headers of the request or of 
// the response will be considered respectively. If it is set to true, it will only 
// consider the request headers, regardless if it is a request or a response.
std::string EricProxyFilter::varHeaderConstValueAsString(
  const VarHeaderConstValue& header_value_ref, bool force_use_req_hdrs, 
  RunContext& run_ctx, Http::StreamDecoderFilterCallbacks* decoder_callbacks
) {
  // TERM_STRING
  if (!header_value_ref.term_string().empty()) {
    return header_value_ref.term_string();
  // TERM_VAR
  } else if (!header_value_ref.term_var().empty()) {
    const auto& var_name = header_value_ref.term_var();
    if (!run_ctx.rootContext()->hasVarName(var_name)) {
      ENVOY_STREAM_LOG(trace, "Variable: {} not found in rootContext", *decoder_callbacks, var_name);
      return "";
    }
    auto var_value_idx = run_ctx.rootContext()->findOrInsertVarName(var_name, decoder_callbacks);
    if (run_ctx.varValueIsEmpty(var_value_idx)) {
      ENVOY_STREAM_LOG(trace, "Variable: {} is not set in runContext", *decoder_callbacks, var_name);
      return "";
    } else {
      return run_ctx.varValueAsString(var_value_idx);
    }
  // TERM_HEADER
  } else if (!header_value_ref.term_header().empty()) {
    auto header_values = varHeaderConstValueAsVector(header_value_ref, force_use_req_hdrs, run_ctx, decoder_callbacks);
    // Combine into a single value (= join with "," as per RFC7230)
    std::string combined_header = absl::StrJoin(header_values, ",");
    return combined_header;
  } else {  // Header not found -> return empty string
    // This is allowed because appendValue or prependValue can be empty
    return "";
  }
}

std::vector<std::string> EricProxyFilter::varHeaderConstValueAsVector(
  const VarHeaderConstValue& header_value_ref, bool force_use_req_hdrs,
  RunContext& run_ctx, Http::StreamDecoderFilterCallbacks* decoder_callbacks
) {
  // TERM_STRING
  if (header_value_ref.has_term_string()) {
    ENVOY_STREAM_LOG(trace, "Found term_string: '{}'", *decoder_callbacks, header_value_ref.term_string());
    std::vector<std::string> ret;
    //auto ret = std::vector<std::string>();
    ret.push_back(header_value_ref.term_string());
    return ret;
  // TERM_VAR
  } else if (!header_value_ref.term_var().empty()) {
    const auto& var_name = header_value_ref.term_var();
    ENVOY_STREAM_LOG(trace, "Found term_var, variable name: '{}'", *decoder_callbacks, header_value_ref.term_var());
    if (!run_ctx.rootContext()->hasVarName(var_name)) {
      ENVOY_STREAM_LOG(trace, "Variable: {} not found in rootContext", *decoder_callbacks, var_name);
      return std::vector<std::string>();
    }
    auto var_value_idx = run_ctx.rootContext()->findOrInsertVarName(var_name, decoder_callbacks);
    if (run_ctx.varValueIsEmpty(var_value_idx)) {
      ENVOY_STREAM_LOG(trace, "Variable: {} is not set in runContext", *decoder_callbacks, var_name);
      return std::vector<std::string>();
    } else {
      // Using "auto val" does not work because that results in std::string and a copy of varValue()'s
      // return value. Since  the local variable "var" will be released as soon as we return from this
      // function, the caller will overwrite the memory of var.
      const std::string& val = run_ctx.varValueAsString(var_value_idx);
      auto ret = std::vector<std::string>();
      ret.push_back(val);
      return ret;
    }
  // TERM_HEADER
  } else if (!header_value_ref.term_header().empty()) {
    const auto& header_name = header_value_ref.term_header();
    ENVOY_STREAM_LOG(trace, "Found term_header, header name: '{}'", *decoder_callbacks, header_value_ref.term_header());
    if (run_ctx.rootContext()->hasHeaderName(header_name)) {
      auto header_value_idx = run_ctx.rootContext()->findOrInsertHeaderName(header_name);
      if (!run_ctx.hasHeaderValue(header_value_idx, run_ctx.getReqOrResp())) {
        ENVOY_STREAM_LOG(trace, "Header: {} ist not set in runContext", *decoder_callbacks, header_name);
        return std::vector<std::string>();
      } else {
        return run_ctx.headerValueStrings(header_value_idx, run_ctx.getReqOrResp());
        //auto ret = std::vector<std::string>(std::string(run_ctx_.headerValue(header_value_idx)));
        //return ret;
      }
    } else {
      ENVOY_STREAM_LOG(trace, "Header: {} not found in rootContext, reading from headers directly",
          *decoder_callbacks, header_name);
      
      auto hdr = !force_use_req_hdrs ? run_ctx.getReqOrRespHeaders()->get(Http::LowerCaseString(header_name)) : 
                                run_ctx.getReqHeaders()->get(Http::LowerCaseString(header_name));
      if (!hdr.empty()) {
        auto ret = std::vector<std::string>(hdr.size());
        for(size_t i = 0; i < hdr.size(); i++){
          ret.at(i) = std::string(hdr[i]->value().getStringView());
        }
        return ret;
      } else { // Header is not present in message -> return empty string
        return std::vector<std::string>();
      }
    }
  } else {  // Header not found -> return empty string
    // This is allowed because appendValue or prependValue can be empty
    return std::vector<std::string>();
  }
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
