#include "contexts.h"
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/common/stream_info/eric_proxy_state.h"
#include "source/extensions/filters/http/eric_proxy/json_utils.h"
#include <cstddef>
#include <cstdint>
#include <elf.h>
#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// Request validation
void EricProxyFilter::populateRequestValidationConfig(const bool& is_global) {
  if (is_global && config_) {
    if (config_->protoConfig().request_validation().check_message_bytes().has_max_message_bytes()) {
      request_bytes_check_ = std::make_unique<CheckMessageBytes>(
          config_->protoConfig().request_validation().check_message_bytes());
    }
    if (config_->protoConfig().request_validation().check_json_leaves().has_max_message_leaves()) {
      request_json_leaves_check_ = std::make_unique<CheckJsonLeaves>(
          config_->protoConfig().request_validation().check_json_leaves());
    }
    if (config_->protoConfig()
            .request_validation()
            .check_json_depth()
            .has_max_message_nesting_depth()) {
      request_json_depth_check_ = std::make_unique<CheckJsonDepth>(
          config_->protoConfig().request_validation().check_json_depth());
    }
  } else if (rp_config_) {
    if (rp_config_->request_validation().has_check_headers()) {
      request_headers_check_ = std::make_unique<CheckHeaders>(rp_config_->request_validation().check_headers());
    }
    if (rp_config_->request_validation().has_check_json_syntax()) {
      request_json_syntax_check_ =
          std::make_unique<CheckJsonSyntax>(rp_config_->request_validation().check_json_syntax());
    }
    if (rp_config_->request_validation().check_message_bytes().has_max_message_bytes()) {
      request_bytes_check_ = std::make_unique<CheckMessageBytes>(
          rp_config_->request_validation().check_message_bytes());
    }
    if (rp_config_->request_validation().check_json_leaves().has_max_message_leaves()) {
      request_json_leaves_check_ =
          std::make_unique<CheckJsonLeaves>(rp_config_->request_validation().check_json_leaves());
    }
    if (rp_config_->request_validation().check_json_depth().has_max_message_nesting_depth()) {
      request_json_depth_check_ =
          std::make_unique<CheckJsonDepth>(rp_config_->request_validation().check_json_depth());
    }
    if (rp_config_->request_validation().has_check_service_operations()) {
      request_unauthorized_service_operations_check_ =
          std::make_unique<CheckServiceOperations>(rp_config_->request_validation().check_service_operations());
    }
  }
}

void EricProxyFilter::setMaxRequestBytesLimit() {
  // If configured then use configured limit otherwise use default limit
  if (request_bytes_check_) {
    decoder_callbacks_->setDecoderBufferLimit(request_bytes_check_->max_message_bytes().value());
  } else { // No limit is configured, set default limit
    decoder_callbacks_->setDecoderBufferLimit(16000000);
  }
}

bool EricProxyFilter::checkMaxRequestBytes() {
  // ULID(A21) Check for configured/default max message bytes for request body
  // We are not using "highWatermarkTriggered()" here because if buffer limit
  // is set to 0 then high watermark is not triggered
  if (decoder_callbacks_->decodingBuffer()->length() > decoder_callbacks_->decoderBufferLimit()) {
    // If configured then use configured action on failure otherwise use default local reply
    if (request_bytes_check_) {
      // ULID(A02) Check for event reporting
      if (request_bytes_check_->report_event()) {
        Json sub_spec_json;
        sub_spec_json["body"]["issues"][0]["err"] = "body_too_long";
        sub_spec_json["body"]["issues"][0]["msg"] = "Message body size limit exceeded";
        const std::string& sub_spec = sub_spec_json.dump();
        reportEvent(EricEvent::EventType::HTTP_BODY_TOO_LONG, EricEvent::EventCategory::SECURITY,
                    EricEvent::EventSeverity::WARNING,
                    absl::StrCat("Body of received HTTP request message exceeds the size limit of ",
                                 decoder_callbacks_->decoderBufferLimit(), " bytes"),
                    request_bytes_check_->action_on_failure(), ULID(A02), sub_spec);
      }
     return actionOnFailure(request_bytes_check_->action_on_failure());
    } else { // Not configured, neither through firewall rules nor globally (= legacy)
      // ULID(A31) Send default local reply for exceeding default limit since no limit was configured
      const std::string message = R"({"status": 413, "title": "Payload Too Large", "detail": "request_payload_too_large"})";
      sendLocalReplyWithSpecificContentType(
        413, "application/problem+json", message,
        StreamInfo::ResponseCodeDetails::get().RequestPayloadTooLarge
      );
      return false;
    }
  }
  return true;
}

//-------------------------------------------------------------------------------------------------
// Response validation
void EricProxyFilter::populateResponseValidationConfig(const bool& is_global) {
  if (is_global && config_) {
    if (config_->protoConfig()
            .response_validation()
            .check_message_bytes()
            .has_max_message_bytes()) {
      response_bytes_check_ = std::make_unique<CheckMessageBytes>(
          config_->protoConfig().response_validation().check_message_bytes());
    }
    if (config_->protoConfig().response_validation().check_json_leaves().has_max_message_leaves()) {
      response_json_leaves_check_ = std::make_unique<CheckJsonLeaves>(
          config_->protoConfig().response_validation().check_json_leaves());
    }
    if (config_->protoConfig()
            .response_validation()
            .check_json_depth()
            .has_max_message_nesting_depth()) {
      response_json_depth_check_ = std::make_unique<CheckJsonDepth>(
          config_->protoConfig().response_validation().check_json_depth());
    }
  } else if (rp_config_) {
    if (rp_config_->response_validation().has_check_headers()) {
      response_headers_check_ = std::make_unique<CheckHeaders>(rp_config_->response_validation().check_headers());
    }
    if (rp_config_->response_validation().has_check_json_syntax()) {
      response_json_syntax_check_ =
          std::make_unique<CheckJsonSyntax>(rp_config_->response_validation().check_json_syntax());
    }
    if (rp_config_->response_validation().check_message_bytes().has_max_message_bytes()) {
      response_bytes_check_ = std::make_unique<CheckMessageBytes>(
          rp_config_->response_validation().check_message_bytes());
    }
    if (rp_config_->response_validation().check_json_leaves().has_max_message_leaves()) {
      response_json_leaves_check_ =
          std::make_unique<CheckJsonLeaves>(rp_config_->response_validation().check_json_leaves());
    }
    if (rp_config_->response_validation().check_json_depth().has_max_message_nesting_depth()) {
      response_json_depth_check_ =
          std::make_unique<CheckJsonDepth>(rp_config_->response_validation().check_json_depth());
    }
  }
}

void EricProxyFilter::setMaxResponseBytesLimit() {
  // If configured then use configured limit otherwise use default limit
  if (response_bytes_check_) {
    encoder_callbacks_->setEncoderBufferLimit(response_bytes_check_->max_message_bytes().value());
  } else { // No limit is configured, set default limit
    encoder_callbacks_->setEncoderBufferLimit(16000000);
  }
}

bool EricProxyFilter::checkMaxResponseBytes() {
  // ULID(A29) Check for configured/default max message bytes for response body
  // We are not using "highWatermarkTriggered()" here because if buffer limit
  // is set to 0 then high watermark is not triggered
  if (encoder_callbacks_->encodingBuffer()->length() > encoder_callbacks_->encoderBufferLimit()) {
    // If configured then use configured action on failure otherwise use default local reply
    if (response_bytes_check_) {
      // ULID(A03) Check for event reporting
      if (response_bytes_check_->report_event()) {
        Json sub_spec_json;
        sub_spec_json["body"]["issues"][0]["err"] = "body_too_long";
        sub_spec_json["body"]["issues"][0]["msg"] = "Message body size limit exceeded";
        const std::string& sub_spec = sub_spec_json.dump();
        reportEvent(
            EricEvent::EventType::HTTP_BODY_TOO_LONG, EricEvent::EventCategory::SECURITY,
            EricEvent::EventSeverity::WARNING,
            absl::StrCat("Body of received HTTP response message exceeds the size limit of ",
                         encoder_callbacks_->encoderBufferLimit(), " bytes"),
            response_bytes_check_->action_on_failure(), ULID(A03), sub_spec);
      }
      return actionOnFailure(response_bytes_check_->action_on_failure());
    } else { // Not configured, neither through firewall rules nor globally (= legacy)
      // Send default local reply for exceeding default limit since no limit was configured
      const std::string message = R"({"status": 500, "title": "Internal Server Error", "cause": "INSUFFICIENT_RESOURCES", "detail": "response_payload_too_large"})";
      sendLocalReplyWithSpecificContentType(
        500, "application/problem+json", message,
        StreamInfo::ResponseCodeDetails::get().ResponsePayloadTooLarge
      );
      return false;
    }
  }
  return true;
}

//-------------------------------------------------------------------------------------------------
// Common check for syntax, configured number of leaves and
// nesting depth for both request and response JSON bodies.
// Returns true if processing can continue, and false if
// we skip everything and continue with phase 6.
bool EricProxyFilter::checkForConfiguredJsonFormat() {
  CheckJsonSyntax* syntax_check = nullptr;
  CheckJsonLeaves* leaves_check = nullptr;
  CheckJsonDepth* depth_check = nullptr;

  if (run_ctx_.isRequest()) {
    syntax_check = request_json_syntax_check_.get();
    leaves_check = request_json_leaves_check_.get();
    depth_check = request_json_depth_check_.get();
  } else {
    syntax_check = response_json_syntax_check_.get();
    leaves_check = response_json_leaves_check_.get();
    depth_check = response_json_depth_check_.get();
  }

  // If no JSON body format checks are configured then continue further processing
  if (!(syntax_check || leaves_check || depth_check)) {
    return true;
  }

  absl::optional<int> max_leaves_limit = absl::nullopt;
  absl::optional<int> max_depth_limit = absl::nullopt;

  if (leaves_check) {
    max_leaves_limit = leaves_check->max_message_leaves().value();
  }
  if (depth_check) {
    max_depth_limit = depth_check->max_message_nesting_depth().value();
  }

  // ULID(A22) Parse JSON body
  absl::StatusOr<std::shared_ptr<Json>> json_body =
      EricProxyJsonUtils::parseWithFormatCheck(std::string(body_->getBodyOrJsonBodypartAsString()),
                                               max_leaves_limit, max_depth_limit);

  if (json_body.ok()) {
    body_->setBodyFromJson(*json_body, /* is_modified = */false);
    return true;
  // ULID(A25):
  } else if (json_body.status() == absl::OutOfRangeError("Maximum JSON leaves limit crossed")) {
    if (leaves_check) {
      if (leaves_check->report_event()) {
        Json sub_spec_json;
        sub_spec_json["json_body"]["issues"][0]["err"] = "too_many_leaves";
        sub_spec_json["json_body"]["issues"][0]["msg"] = "Maximum JSON leaves limit exceeded";
        const std::string& sub_spec = sub_spec_json.dump();
        reportEvent(
            EricEvent::EventType::HTTP_JSON_BODY_TOO_MANY_LEAVES,
            EricEvent::EventCategory::SECURITY, EricEvent::EventSeverity::WARNING,
            fmt::format("JSON body in received HTTP {} message exceeds the limit of {} leaves",
                        run_ctx_.isRequest() ? "request" : "response", max_leaves_limit.value()),
            leaves_check->action_on_failure(), run_ctx_.isRequest() ? ULID(A04) : ULID(A05), sub_spec);
      }
      return actionOnFailure(leaves_check->action_on_failure());
    }
  // ULID(A26):
  } else if (json_body.status() == absl::OutOfRangeError("Maximum JSON nested depth limit crossed")) {
    if (depth_check) {
      if (depth_check->report_event()) {
        Json sub_spec_json;
        sub_spec_json["json_body"]["issues"][0]["err"] = "nesting_level_too_deep";
        sub_spec_json["json_body"]["issues"][0]["msg"] = "Maximum JSON nesting depth limit exceeded";
        const std::string& sub_spec = sub_spec_json.dump();
        reportEvent(
            EricEvent::EventType::HTTP_JSON_BODY_MAX_DEPTH_EXCEEDED,
            EricEvent::EventCategory::SECURITY, EricEvent::EventSeverity::WARNING,
            fmt::format("JSON body in received HTTP {} message exceeds the nesting depth limit of {}",
                        run_ctx_.isRequest() ? "request" : "response", max_depth_limit.value()),
            depth_check->action_on_failure(), run_ctx_.isRequest() ? ULID(A06) : ULID(A07), sub_spec);
      }
      return actionOnFailure(depth_check->action_on_failure());
    }
  // ULID(A24):
  } else { // JSON cannot be parsed
    if (syntax_check) {  // ULID(A27)
      if (syntax_check->report_event()) {
        Json sub_spec_json;
        sub_spec_json["json_body"]["issues"][0]["err"] = "syntax";
        sub_spec_json["json_body"]["issues"][0]["msg"] = "Body contains syntax error(s)";
        const std::string& sub_spec = sub_spec_json.dump();
        reportEvent(
            EricEvent::EventType::HTTP_JSON_BODY_SYNTAX_ERR, EricEvent::EventCategory::SECURITY,
            EricEvent::EventSeverity::WARNING,
            fmt::format("JSON body in received HTTP {} message could not be parsed due to syntax errors",
                        run_ctx_.isRequest() ? "request" : "response"),
            syntax_check->action_on_failure(), run_ctx_.isRequest() ? ULID(A08) : ULID(A09), sub_spec);
      }
      return actionOnFailure(syntax_check->action_on_failure());
    } else {  // ULID(A28)
      // Not configured, neither through firewall rules nor globally (= legacy)
      // Send default local reply for syntax failure since either JSON leaves or JSON depth or both
      // are configured but JSON syntax check was not configured
      const std::string message =
          run_ctx_.isRequest()
              ? R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_body"})"
              : R"({"status": 500, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_invalid_json_body"})";
      sendLocalReplyWithSpecificContentType(run_ctx_.isRequest() ? 400 : 500,
                                            "application/problem+json", message,
                                            StreamInfo::ResponseCodeDetails::get().DirectResponse);
      return false;
    }
  }
  return true;
}

// Configured action on failure (when check fails)
bool EricProxyFilter::actionOnFailure(const ActionOnFailure& action_on_failure,
                                      std::vector<absl::string_view>&& offending_headers) {
  Http::StreamFilterCallbacks* callbacks;
  if (run_ctx_.isRequest()) {
    callbacks = decoder_callbacks_;
  } else {
    callbacks = encoder_callbacks_;
  }
  switch (action_on_failure.action_specifier_case()) {
  case ActionOnFailure::ActionSpecifierCase::kRespondWithError:
    ENVOY_STREAM_LOG(trace, "Applying respond_with_error action on failure", *callbacks);
    respondWithError(action_on_failure.respond_with_error());
    return false;
    break;
  case ActionOnFailure::ActionSpecifierCase::kDropMessage:
    ENVOY_STREAM_LOG(trace, "Applying drop action on failure", *callbacks);
    actionDropMessage();
    return false;
    break;
  case ActionOnFailure::ActionSpecifierCase::kForwardUnmodifiedMessage:
    ENVOY_STREAM_LOG(trace, "Applying forward_unmodified_message action on failure", *callbacks);
    return true;
    break;
  case ActionOnFailure::ActionSpecifierCase::kRemoveDeniedHeaders:
    ENVOY_STREAM_LOG(trace, "Applying remove_denied_headers action on failure", *callbacks);
    // don't repair the message if more than 20 violations were detected, reject instead
    // different reply if we are rejecting a request or a response
    for (const auto& hdr : offending_headers) {
      run_ctx_.getReqOrRespHeaders()->remove(Http::LowerCaseString(hdr));
    }
    return true;
    break;
  default:
    ENVOY_STREAM_LOG(trace, "Invalid action on failure", *callbacks);
    return true;
    break;
  }
}

namespace {
// header check callback, to be used when allowed_headers are configured
// appends offending headers' names in the offending_headers vector
Http::HeaderMap::ConstIterateCb
checkAllowedHeaders(const Protobuf::Map<std::string, bool>& allowed_headers,
                    std::vector<absl::string_view>& offending_headers, const size_t& threshold) {
  return [&allowed_headers, &offending_headers,
          &threshold](const Http::HeaderEntry& header) -> Http::HeaderMap::Iterate {
    if (!allowed_headers.contains(header.key().getStringView())) {
      offending_headers.push_back(header.key().getStringView());
    }
    if (offending_headers.size() == threshold) {
      return Http::HeaderMap::Iterate::Break;
    }
    return Http::HeaderMap::Iterate::Continue;
  };
}
} // namespace

// Firewall Header checks: Check if denied headers/not only allowed headers are included on the
// message The threshold of header violations (don't continue checking headers after the #threshold
// violation) depends on the combination of configured action + if event reporting is enabled.
// THRES= 20
// +---------+-------+------------+
// | Action  | Event | Threshold  |
// +---------+-------+------------+
// | Drop    | True  | THRES      |
// | Drop    | False | 1          |
// | Reject  | True  | THRES      |
// | Reject  | False | 1          |
// | Repair  | True  | THRES + 1  | # 21 because then we override the action to reject
// | Repair  | False | THRES + 1  | # Up to 20 just repair the message
// | Forward | True  | THRES      |
// | Forward | False | Do nothing |
// +---------+-------+------------+
//
// Return true if processing can continue, false if processing shall stop (direct response, drop
// message)

// TODO: make denied/allowed a set of lowercaseString on configtime to avoid castings on runtime
bool EricProxyFilter::checkHeaders() {
  // ULID(S51)
  CheckHeaders* checks = nullptr;
  Http::StreamFilterCallbacks* callbacks = nullptr;
  if (run_ctx_.isRequest()) {
    checks = request_headers_check_.get();
    callbacks = decoder_callbacks_;
  } else {
    checks = response_headers_check_.get();
    callbacks = encoder_callbacks_;
  }
  if (checks) {
    size_t threshold;
    // calculate the threshold of offending headers depending on configured actions/events
    switch (checks->action_on_failure().action_specifier_case()) {
    case ActionOnFailure::ActionSpecifierCase::kRespondWithError:
    case ActionOnFailure::ActionSpecifierCase::kDropMessage:
      threshold = checks->report_event() ? USFW_HEADERS_THRESHOLD : 1;
      break;
    case ActionOnFailure::ActionSpecifierCase::kRemoveDeniedHeaders:
      threshold = USFW_HEADERS_THRESHOLD + 1;
      break;
    case ActionOnFailure::ActionSpecifierCase::kForwardUnmodifiedMessage:
      if (checks->report_event()) {
        threshold = USFW_HEADERS_THRESHOLD;
      } else {
        // if no event is to be reported and action is forward just continue
        return true;
      }
    default:
      break;
    }
    std::vector<absl::string_view> offending_headers;
    if (checks->has_allowed_headers()) {
      run_ctx_.getReqOrRespHeaders()->iterate(
          checkAllowedHeaders(checks->allowed_headers().values(), offending_headers, threshold));
    } else { // denied header
      for (const auto& hdr : checks->denied_headers().values()) {
        const auto& found = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(hdr.first));
        if (!found.empty()) {
          offending_headers.push_back(hdr.first);
          // No need to check all the headers if the threshold is reached already
          if (offending_headers.size() == threshold) {
            break;
          }
        }
      }
    }
    if (!offending_headers.empty()) {
      // just for testing
      // report up to 20 violations
      const auto end_it = offending_headers.size() == USFW_HEADERS_THRESHOLD + 1
                              ? offending_headers.begin() + USFW_HEADERS_THRESHOLD
                              : offending_headers.end();
   
      ENVOY_STREAM_LOG(debug, "offending headers found in {}: {}", *callbacks,
                       run_ctx_.isRequest() ? "request" : "response", 
                       absl::StrCat("[\"", absl::StrJoin(offending_headers.begin(), end_it, "\", \""), "\"]"));
      ActionOnFailure* override_action = nullptr;
      if (checks->action_on_failure().has_remove_denied_headers() &&
          offending_headers.size() > USFW_HEADERS_THRESHOLD) {
        // over the threshold in action repair, perform over the threshold actions
        override_action = run_ctx_.isRequest() ? &config_->request_action_after_threshold_
                                               : &config_->response_action_after_threshold_;
      }

      // report event
      if (checks->report_event()) {
        Json sub_spec_json;
        sub_spec_json["headers"]["not_allowed"] = offending_headers;
        const std::string& sub_spec = sub_spec_json.dump();
        reportEvent(EricEvent::EventType::HTTP_HEADER_NOT_ALLOWED,
                    EricEvent::EventCategory::SECURITY, EricEvent::EventSeverity::WARNING,
                    run_ctx_.isRequest() ? "Header in received HTTP request message not allowed"
                                         : "Header in received HTTP response message not allowed",
                    override_action != nullptr ? *override_action : checks->action_on_failure(),
                    run_ctx_.isRequest() ? ULID(A10) : ULID(A11), sub_spec);
      }

      return actionOnFailure(override_action != nullptr ? *override_action
                                                        : checks->action_on_failure(),
                             std::move(offending_headers));
    }
  }
  return true;
}

/**
* EricProxyFilter::isUnauthorizedServiceOperation
* 
* returns: true, if the current request is categorized unauthorized service operation
*          false, otherwise
*/
bool EricProxyFilter::isUnauthorizedServiceOperation() {
  // ULID(A30):
  CheckServiceOperations* checks = request_unauthorized_service_operations_check_.get();
  Http::StreamFilterCallbacks* callbacks = decoder_callbacks_;

  if (checks) {
    ENVOY_STREAM_UL_LOG(debug, "Check Unauthorized Service Operation", *callbacks, ULID(A30));
    auto req_api_name = run_ctx_.getServiceClassifierCtx().getApiName();

    // Detect custom allowed service operations
    if (!checks->custom_allowed_service_operations().empty()) {
      auto custom_allowed_service_operations =
          config_->getCustomAllowedServiceOperationsPerApiNameForRp(rp_config_->name(), req_api_name);
      if (custom_allowed_service_operations.empty()) {
        custom_allowed_service_operations = config_->getCustomAllowedServiceOperationsPerApiNameForRp(rp_config_->name(), "");
      }
      if (validateCurrentRequestAgainstServiceClassifiers(custom_allowed_service_operations)){
        ENVOY_STREAM_LOG(trace, "Request matches one of the custom allowed service operations", *callbacks);
        return false;
      }      
    }

    // Detect custom denied service operations
    if (!checks->custom_denied_service_operations().empty()) {
      auto custom_denied_service_operations =
          config_->getCustomDeniedServiceOperationsPerApiNameForRp(rp_config_->name(), req_api_name);
      if (custom_denied_service_operations.empty()) {
        custom_denied_service_operations = config_->getCustomDeniedServiceOperationsPerApiNameForRp(rp_config_->name(), "");
      }
      if (validateCurrentRequestAgainstServiceClassifiers(custom_denied_service_operations)){
        ENVOY_STREAM_LOG(trace, "Request matches one of the custom denied service operations", *callbacks);
        return true;
      }      
    }

    // Detect default allowed service operations
    auto default_allowed_service_operations =
        config_->getDefaultAllowedServiceOperationsPerApiName(req_api_name);
    if (default_allowed_service_operations.empty()) {
      default_allowed_service_operations = config_->getDefaultAllowedServiceOperationsPerApiName("");
    }
    if (validateCurrentRequestAgainstServiceClassifiers(default_allowed_service_operations)){
      ENVOY_STREAM_LOG(trace, "Request matches one of the default allowed service operations", *callbacks);
      return false;
    }

    // Everything else is unauthorized service operation
    ENVOY_STREAM_LOG(trace, "Request does not match any of the configured service operations", *callbacks);
    return true;
  }

  // No USFW USOC active
  return false;
}

/**
* EricProxyFilter::validateCurrentRequestAgainstServiceClassifiers
* 
* returns: true, if the current request (service context) matches any of the given service classifiers attributes
*          false, otherwise
*/
bool EricProxyFilter::validateCurrentRequestAgainstServiceClassifiers(
    const std::vector<std::shared_ptr<ServiceClassifierConfigBase>>& service_classifiers) {
  Http::StreamFilterCallbacks* callbacks = decoder_callbacks_;

  for (auto service_classifier : service_classifiers) {
    ENVOY_STREAM_LOG(trace, "Check if request matches: {}", *callbacks,
                     service_classifier->debugString());
    if (service_classifier->eval(&run_ctx_)) {
      // Match found
      return true;
    }
  }

  // No match
  return false;
}

/**
* EricProxyFilter::processUnauthorizedServiceOperation
* 
* returns: true, if the request is allowed to pass
*          false, if the request is dropped/rejected
*/
bool EricProxyFilter::processUnauthorizedServiceOperation() {
  CheckServiceOperations* checks = request_unauthorized_service_operations_check_.get();

  if (checks->report_event()) {
    // ULID(A33):
    Json sub_spec_json;
    sub_spec_json["unauthorized_service_operation"]["attributes"]["api_name"] = run_ctx_.getServiceClassifierCtx().getApiName();
    sub_spec_json["unauthorized_service_operation"]["attributes"]["api_version"] = run_ctx_.getServiceClassifierCtx().getApiVersion();
    sub_spec_json["unauthorized_service_operation"]["attributes"]["resource"] = run_ctx_.getServiceClassifierCtx().getResource();
    sub_spec_json["unauthorized_service_operation"]["attributes"]["http_method"] = run_ctx_.getServiceClassifierCtx().getMethod();
    if (run_ctx_.getServiceClassifierCtx().isNotify()) {
      sub_spec_json["unauthorized_service_operation"]["attributes"]["message_type"] = "callback";
    } else {
      sub_spec_json["unauthorized_service_operation"]["attributes"]["message_type"] = "service_request";
    }
    const std::string& sub_spec = sub_spec_json.dump();
    reportEvent(EricEvent::EventType::UNAUTHORIZED_SERVICE_OPERATION_DETECTED,
                EricEvent::EventCategory::SECURITY, EricEvent::EventSeverity::WARNING,
                "Unauthorized service operation detected", checks->action_on_failure(),
                ULID(A33), sub_spec);
  }

  return actionOnFailure(checks->action_on_failure());
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy