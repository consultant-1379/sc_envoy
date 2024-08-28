#include <algorithm>
#include <memory>
#include <tuple>
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/extensions/filters/http/eric_proxy/json_operations.h"
#include "source/common/common/logger.h"
#include "absl/strings/string_view.h"
#include "absl/strings/str_format.h"
#include "source/common/stream_info/eric_proxy_state.h"


// Methods in this file are all in the EricProxyFilter class.
// They are stored in a separate file to keep action processing
// separate.

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using Json = nlohmann::json;

//-------- Body Actions ---------------------------------------------------------------
// Modify Body
ActionResultTuple EricProxyFilter::actionModifyJsonBody(const ActionModifyJsonBodyWrapper& action) {
  // Only do something if there is a message body:
  if (body_->isBodyPresent()) {
    // absl::StatusOr<std::string> modified_body;
    // modified_body = absl::StatusOr<std::string>(body_str);

    const auto proto_config = action.protoConfig().action_modify_json_body();
    if (!proto_config.name().empty()) {
      ENVOY_STREAM_LOG(trace, "Action-Modify-JSON-Body, applying action: '{}'", *decoder_callbacks_,
                       proto_config.name());
    }

    const auto status = body_->executeJsonOperation(proto_config, decoder_callbacks_, run_ctx_);
    if (status.ok()) {
      ENVOY_STREAM_LOG(trace, "JSON body modification succeeded", *decoder_callbacks_);
      ENVOY_STREAM_LOG(trace, "The body is now: '{}'", *decoder_callbacks_,
                       body_->getBodyAsString());
    } else if (status.code() == absl::StatusCode::kAborted) {
      // DND-32766 specific status code used to send back a local reply indicating
      // a request buffer overflow after a json body modification
      const std::string message = R"({"status": 413, "title": "Payload Too Large", "detail": "request_payload_too_large"})";
      sendLocalReplyWithSpecificContentType(
        413, "application/problem+json", message,
        StreamInfo::ResponseCodeDetails::get().RequestPayloadTooLarge
      );
      return std::make_tuple(ActionResult::StopIteration, true, std::nullopt);
    } else {
      ENVOY_STREAM_LOG(trace, "JSON operation failed: '{}'", *decoder_callbacks_, status.message());

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

      if (run_ctx_.isRequest()) {
        const std::string s = absl::StrFormat(
            R"({"status": %d, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_json_operation_failed"})",
            400);
        sendLocalReplyWithSpecificContentType(
            400, "application/problem+json", s,
            StreamInfo::ResponseCodeDetails::get().DirectResponse);
        return std::make_tuple(ActionResult::StopIteration, true, std::nullopt);
      } else {
        const std::string s = absl::StrFormat(
          R"({"status": %d, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_json_operation_failed"})",
          500);
        sendLocalReplyWithSpecificContentType(
            500, "application/problem+json", s,
            StreamInfo::ResponseCodeDetails::get().DirectResponse);
        return std::make_tuple(ActionResult::StopIteration, true, std::nullopt);
      }
    }

    // If there is a (T-FQDN modified) body in dyn. MD, we have to apply the JSON operation
    // on that modified body as well
    const auto& filter_state = decoder_callbacks_->streamInfo().filterState();
    const auto& eric_sepp_state = filter_state->getDataMutable<StreamInfo::EricProxySeppState>(StreamInfo::EricProxySeppState::key());
    if(eric_sepp_state && 
        eric_sepp_state->getModifiedBodyLen() != 0) {

      const auto sepp_tfqdn_modified_body = eric_sepp_state->getModifiedBody();

      auto sepp_tfqdn_modified_body_json = Json::parse(sepp_tfqdn_modified_body);

      auto json_operation =
        EricProxy::JsonOpWrapper(proto_config.json_operation(),
            sepp_tfqdn_modified_body_json, decoder_callbacks_, run_ctx_);

      ENVOY_STREAM_LOG(trace, "Executing JSON operation on T-FQDN mod. body in dyn. MD",
                       *decoder_callbacks_);

      auto modified_body_json = json_operation.execute();

      if (modified_body_json.ok()) {
        ENVOY_STREAM_LOG(trace, "JSON body modification succeeded", *decoder_callbacks_);

        ProtobufWkt::Struct metadata;
        auto mod_tfqdn_body_str_dyn_md = modified_body_json.value()->dump();
        ENVOY_STREAM_LOG(trace, "modified_body in dyn. MD is: {}", *decoder_callbacks_,
                         mod_tfqdn_body_str_dyn_md);

        eric_sepp_state->setModifiedBody(std::move(mod_tfqdn_body_str_dyn_md));
      } else {
        ENVOY_STREAM_LOG(trace, "JSON operation failed: {} ", *decoder_callbacks_,
                         modified_body_json.status());

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

        if (run_ctx_.isRequest()) {
          const std::string s = absl::StrFormat(
            R"({"status": %d, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_json_operation_failed"})",
            400);
          sendLocalReplyWithSpecificContentType(
              400, "application/problem+json", s,
              StreamInfo::ResponseCodeDetails::get().DirectResponse);
          return std::make_tuple(ActionResult::StopIteration, true, std::nullopt);
        } else {
          const std::string s = absl::StrFormat(
            R"({"status": %d, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_json_operation_failed"})",
            500);
          sendLocalReplyWithSpecificContentType(
              500, "application/problem+json", s,
              StreamInfo::ResponseCodeDetails::get().DirectResponse);
          return std::make_tuple(ActionResult::StopIteration, true, std::nullopt);
        }
      }
    }
  }
  return std::make_tuple(ActionResult::Next, true, std::nullopt);
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
