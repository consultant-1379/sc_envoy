#include "source/common/common/logger.h"
#include "envoy/http/header_map.h"
#include "envoy/stream_info/stream_info.h"
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/header_utility.h"
// #include "source/common/stream_info/utility.h"
#include "source/common/http/utility.h"
#include <charconv>
#include <string_view>
#include <tuple>

// Methods in this file are all in the EricProxyFilter class.
// They are stored in a separate file to keep action processing
// separate.

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {


//----- Misc Actions --------------------------------------------------------------------

// Modify Variable
// So far only kvt-lookups can modify the variable.
// + If the key is a header with multiple values, then the headers are combined with "," according
//   to RFC7230 section 3.2.2.
// - If the table does not exist, then then new value is "".
// - If the key does not exists, then the new value is "".
ActionResultTuple EricProxyFilter::actionModifyVariable(const ActionModifyVariableWrapper& action) {
  const auto proto_config = action.protoConfig().action_modify_variable();
  auto var_name = proto_config.name();
  ENVOY_STREAM_LOG(debug, "actionModifyVariable(), name='{}'", *decoder_callbacks_, var_name);

  if (proto_config.has_table_lookup()){
    const auto kvt_lookup = proto_config.table_lookup();
    const auto& kvt_table_name = kvt_lookup.table_name();
    const auto key = varHeaderConstValueAsString(kvt_lookup.key(), false);
    ENVOY_STREAM_LOG(debug, "actionModifyVariable(), key='{}'", *decoder_callbacks_, key);

    // Finally, the table lookup!
    auto modified_value = run_ctx_.rootContext()->kvtValue(kvt_table_name, key);
    if (modified_value) {
      ENVOY_STREAM_LOG(debug, "actionModifyVariable(), new variable value='{}'",
       *decoder_callbacks_, modified_value.value());
    } else {
      ENVOY_STREAM_LOG(debug, "actionModifyVariable(), Error: could not get new variable value from kvt. New value is ''.",
        *decoder_callbacks_);
      modified_value = "";
    }
    // Update variable value
    auto var_value_idx = run_ctx_.rootContext()->findOrInsertVarName(var_name, decoder_callbacks_);
    run_ctx_.updateVarValue(var_value_idx, modified_value.value(), pfcstate_filter_case_.get());
  } else {
      ENVOY_STREAM_LOG(error, "actionModifyVariable('{}'), mandatory parameter table_lookup missing",
          *decoder_callbacks_, var_name);
  }
  return std::make_tuple(ActionResult::Next, false, std::nullopt);
}

//----- Control-Flow Actions ------------------------------------------------------------
// Go-To
ActionResultTuple EricProxyFilter::actionGotoFilterCase(const FilterActionWrapper& action) {
  ENVOY_STREAM_LOG(debug, "Go to filter case {}", *decoder_callbacks_,
      action.protoConfig().action_goto_filter_case());
  return std::make_tuple(ActionResult::GotoFC, false, action.protoConfig().action_goto_filter_case());
}

// Exit filter-case
ActionResultTuple EricProxyFilter::actionExitFilterCase() {
  ENVOY_STREAM_LOG(debug, "Exit filter case", *decoder_callbacks_);
  return std::make_tuple(ActionResult::Exit, false, std::nullopt);
}

//----- Terminal Actions ------------------------------------------------------------
// Reject the request (send a direct response)
// Action Reject Message with callbacks_->sendLocalReply() should only be used in
// decoder path and not on encoder path, for the response path flush all the headers
// and relevant body to send only the error resp body and error headers

// CHECK : If actionRejectMessage can be used on response path as well
// after ASAN tests , if not then use sendLocalReplyForResponsePath helper function
// to handle error replies on response screening direction
ActionResultTuple EricProxyFilter::actionRejectMessage(const FilterActionWrapper& action) {
  const auto proto_config = action.protoConfig().action_reject_message();
  auto status_code = proto_config.status();
  std::string title;

  std::string format_name;
  std::string content_type;
  switch (proto_config.message_format()) {
  case JSON:
  {
    format_name = "JSON";
    content_type = "application/problem+json";

    // status code and title are mandatory via YANG
    // detail and cause are optional and if not present should be omitted from the body
    const auto& detail = proto_config.detail();
    const auto& cause = proto_config.cause();
    title = absl::StrCat("{\"status\": ", status_code,", \"title\": \"",
        proto_config.title(), "\"");
    if (!detail.empty()) {
      absl::StrAppend(&title, ", \"detail\": \"", detail, "\"");
    }
    if (!cause.empty()) {
      absl::StrAppend(&title, ", \"cause\": \"", cause, "\"");
    }
    absl::StrAppend(&title, "}");   
    break;
  }
  case PLAIN_TEXT:
    title = proto_config.title();
    format_name = "text";
    content_type = "text/plain";
    break;
  default:
    ENVOY_STREAM_LOG(warn, "Unknown message_format for action_reject_message", *decoder_callbacks_);
    format_name = "unknown format";
    content_type = "text/plain";
  }

  // Envoy's sendLocalReply() always adds a content-type text-plain. The ratelimit filter
  // has a way to bypass that. We copy that here.
  // See also source/extensions/filters/http/ratelimit/ratelimit.cc:252
  if (response_headers_to_add_ == nullptr) {
    response_headers_to_add_ = Http::ResponseHeaderMapImpl::create();
  }
  response_headers_to_add_->setContentType(content_type);

  ENVOY_STREAM_LOG(debug, "Reject title with status code: {} and title '{}' formatted as {}",
      *decoder_callbacks_, status_code, title, format_name);

  // The reply will go through the filter chain because no response headers have been received yet
  // (they couldn't because we don't forward the request). This means the response filter
  // will process the title.
  // This action can only be in the request path, hence "decoder_callbacks_".

  // DND-32300 add local_replied flag to dyn. MD, 
  // so that local reply config can filter it out.
  // The local reply will not be modified by local reply filter.
  ProtobufWkt::Struct local_reply_md;
  *(*local_reply_md.mutable_fields())["local_replied"].mutable_string_value() = "true";
  decoder_callbacks_->streamInfo().setDynamicMetadata("eric_filter", local_reply_md);
  internal_rejected_ = true;
  local_reply_ = true;
  decoder_callbacks_->sendLocalReply(
      static_cast<Http::Code>(status_code), title,
      [this](Http::HeaderMap& headers) { populateResponseHeaders(headers); }, absl::nullopt,
      EricProxyResponseCodeDetails::get().RejectResponseFromEricProxyFilter); 
  
  return std::make_tuple(ActionResult::StopIteration, true, std::nullopt);
}

// Drop message by resetting the HTTP/2 stream (no response is sent, only RESET_STREAM)
ActionResultTuple EricProxyFilter::actionDropMessage() {
  ENVOY_STREAM_LOG(debug, "Action drop message", *decoder_callbacks_);
  decoder_callbacks_->streamInfo().setResponseFlag(StreamInfo::ResponseFlag::LocalReset);
  decoder_callbacks_->streamInfo().setResponseCodeDetails(EricProxyResponseCodeDetails::get().DropResponseFromEricProxyFilter);
  decoder_callbacks_->resetStream();
  return std::make_tuple(ActionResult::StopIteration, false, std::nullopt);
}

// Modify Status Code
ActionResultTuple EricProxyFilter::actionModifyStatusCode(const FilterActionWrapper& action) {
  const auto proto_config = action.protoConfig().action_modify_status_code();
  // Get the configured values
  auto status_code = proto_config.status();
  auto title = proto_config.title();
  auto detail = proto_config.detail();
  auto cause = proto_config.cause();


  ENVOY_STREAM_LOG(debug, "Modify Status Code: Original headers:", *decoder_callbacks_);
  run_ctx_.getReqOrRespHeaders()->iterate([this](const Http::HeaderEntry& entry) -> Http::HeaderMap::Iterate {
    ENVOY_STREAM_LOG(debug, "  {}: {}", *decoder_callbacks_,
        entry.key().getStringView(), entry.value().getStringView());
    return Http::HeaderMap::Iterate::Continue;
  });

  // If the status code is not configured, the status code should stay the same
  if (status_code == 0) {
    auto original_status = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(":status"));
    // status_code = original status code
    bool success = absl::SimpleAtoi(original_status[0]->value().getStringView(), &status_code);
    if (!success) {
      ENVOY_STREAM_LOG(debug, "Can not convert the status code from the incoming response header to integer",
          *decoder_callbacks_);
    }
    ENVOY_STREAM_LOG(debug, "Status code is not configured. Keeping the original status code: {}",
        *decoder_callbacks_, status_code);
  } else {
    run_ctx_.getReqOrRespHeaders()->remove(Http::LowerCaseString(":status"));
    run_ctx_.getReqOrRespHeaders()->addCopy(Http::LowerCaseString(":status"), status_code);
  }
  absl::optional<std::string> content_type;

  const auto& orig_content_type_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString("content-type"));
  const auto& orig_content_type =
      !orig_content_type_hdr.empty() ? orig_content_type_hdr[0]->value().getStringView() : "";

  // If no title is configured the status in the body is
  // modified, only if the original content type is "application/problem+json"
  if (title.empty()) {
    const auto json_body = body_->getBodyAsJson();
    if (json_body && (orig_content_type == "application/problem+json")) {
      (*json_body)["status"] = status_code;

      if (!detail.empty()) {
        (*json_body)["detail"] = detail;
      }
      if (!cause.empty()) {
        (*json_body)["cause"] = cause;
      }
      body_->setBodyFromJson(json_body);
      ENVOY_STREAM_LOG(trace, "Title is not configured. Only Status (and cause) will be modified",
                       *decoder_callbacks_);
    } 
    return std::make_tuple(ActionResult::Next, true, std::nullopt);
  }

  // If the title is configured a new message with the configured details is sent
  switch (proto_config.message_format()) {
  case JSON: {
    content_type.emplace("application/problem+json");
    // status code and title are mandatory via YANG
    // detail and cause are optional and if not present should be omitted from the body
    const auto json_body = body_->getBodyAsJson();
    if (json_body && (orig_content_type == "application/problem+json")) {
      (*json_body)["status"] = status_code;
      (*json_body)["title"] = title;

      if (!detail.empty()) {
        (*json_body)["detail"] = detail;
      }
      if (!cause.empty()) {
        (*json_body)["cause"] = cause;
      }
      body_->setBodyFromJson(json_body);
    } else {
      // we have no json ("application/problem+json") body
      std::string message = absl::StrCat("{\"status\": ", status_code,", \"title\": \"", title,"\"");
      if (!detail.empty()) {
        absl::StrAppend(&message, ", \"detail\": \"", detail, "\"");
      }
      if (!cause.empty()) {
        absl::StrAppend(&message, ", \"cause\": \"", cause, "\"");
      }  
      absl::StrAppend(&message, "}");    
      body_->setBodyFromString(message);
    }
    break;
  }
  case PLAIN_TEXT:
    content_type.emplace("text/plain");
    body_->setBodyFromString(title);
    break;
  default:
    ENVOY_STREAM_LOG(error, "Unknown message_format for action_modify_status_code",
                     *decoder_callbacks_);
    content_type.emplace("text/plain");
    body_->setBodyFromString(title);
    break;
  }
  run_ctx_.getReqOrRespHeaders()->remove(Http::LowerCaseString("content-type"));
  run_ctx_.getReqOrRespHeaders()->addCopy(Http::LowerCaseString("content-type"), content_type.value_or(""));
  return std::make_tuple(ActionResult::Next, true, std::nullopt);
}

//-------------------------------------------------------------------------------------
// Helper functions for the actions above

/**
 * From extensions/filters/http/ratelimit/ratelimit.cc
 * Trick to get the right content-type header
 */
 void EricProxyFilter::populateResponseHeaders(Http::HeaderMap& response_headers) {
  if (response_headers_to_add_) {
    // If the EricProxy filter is sending back the content-type header and we're
    // populating response headers for a local reply, overwrite the existing
    // content-type header.
    //
    // We do this because sendLocalReply initially sets content-type to text/plain
    // whenever the response body is non-empty, but we want the content-type coming
    // from the EricProxy filter to be authoritative in this case.
    if (!response_headers_to_add_->getContentTypeValue().empty()) {
      response_headers.remove(Http::Headers::get().ContentType);
    }
    Http::HeaderMapImpl::copyFrom(response_headers, *response_headers_to_add_);
    response_headers_to_add_ = nullptr;

    if (internal_rejected_) {
      ProtobufWkt::Struct internal_reject_md;
      *(*internal_reject_md.mutable_fields())[md_key_internal_rejected_].mutable_string_value() =
          "true";
      *(*internal_reject_md.mutable_fields())[md_key_internal_rejected_by_].mutable_string_value() =
          this->config_->protoConfig().name();
      encoder_callbacks_->streamInfo().setDynamicMetadata("eric_proxy", internal_reject_md);
      internal_rejected_ = false ; // flag can be reset when MD is written
    }
  }
}

// Return true if the request was internally rejected
// (this is needed to pass through unwanted filter instances in the response filter chain)
bool EricProxyFilter::internalRejected() {
  if (!encoder_callbacks_->streamInfo().dynamicMetadata().filter_metadata().contains("eric_proxy")) {
    return false;
  }

  const auto dynamic_md_eric_proxy =
      encoder_callbacks_->streamInfo().dynamicMetadata().filter_metadata().find("eric_proxy");

  if (!dynamic_md_eric_proxy->second.fields().contains(md_key_internal_rejected_)) {
    return false;
  }

  const auto internal_rejected_ =
      dynamic_md_eric_proxy->second.fields().find(md_key_internal_rejected_);

  return (internal_rejected_->second.string_value() == "true"); 
}


// Send a direct response back to the requester
ActionResultTuple EricProxyFilter::sendLocalReplyWithSpecificContentType(int status_code,
    const absl::optional<std::string>& content_type,
    const std::string& message, const absl::string_view response_code_details) {
  ENVOY_STREAM_LOG(debug, "Sending local reply with status code: {}, message '{}' and content-type '{}'",
      *decoder_callbacks_, status_code, message, content_type.value_or(""));

  // DND-32300 add local_replied flag to dyn. MD,
  // so that local reply config can filter it out.
  // The local reply will not be modified by local reply filter.
  ProtobufWkt::Struct local_reply_md;
  *(*local_reply_md.mutable_fields())["local_replied"].mutable_string_value() = "true";
  decoder_callbacks_->streamInfo().setDynamicMetadata("eric_filter", local_reply_md);

  if (response_headers_to_add_ == nullptr) {
    response_headers_to_add_ = Http::ResponseHeaderMapImpl::create();
  }

  // Always copy the 3gpp-sbi-correlation-info from the request
  auto corr_header_name = Http::LowerCaseString("3gpp-sbi-correlation-info");
  auto corr_header = run_ctx_.getReqHeaders()->get(corr_header_name);
  if (! corr_header.empty()) {
    response_headers_to_add_->addCopy(corr_header_name, corr_header[0]->value().getStringView());
  }

  // Content-type:
  if (content_type) {
    response_headers_to_add_->setContentType(*content_type);
  }
  local_reply_ = true;
  encoder_callbacks_->sendLocalReply(static_cast<Http::Code>(status_code), message,
        [this](Http::HeaderMap& headers) { populateResponseHeaders(headers); }, absl::nullopt, response_code_details);
  return std::make_tuple(ActionResult::StopIteration, false, std::nullopt);
}

// Send a direct response back to the requester, only that the status code is
// given as a string_view. If the status code cannot be converted to a number,
// code 599 is used.
ActionResultTuple EricProxyFilter::sendLocalReplyWithSpecificContentType(
    absl::string_view status_code_str,
    const absl::optional<std::string>& content_type, const std::string& message,
    const absl::string_view response_code_details) {
  int status_code;
  auto [ptr, ec] { std::from_chars(status_code_str.data(),
      status_code_str.data() + status_code_str.size(), status_code) };
  if (ec != std::errc()) {  // conversion failed
    ENVOY_STREAM_LOG(error, "Status code is not numeric ({})", *decoder_callbacks_,
        status_code_str);
    status_code = 599;
  }
  return EricProxyFilter::sendLocalReplyWithSpecificContentType(status_code, content_type,
      message, response_code_details);
}


// Common code to send a local reply ***on response path***
ActionResultTuple EricProxyFilter::sendLocalReplyOnResponsePathWithContentType(int status_code,
                                    const absl::optional<std::string>& content_type ,
                                    const std::string& message ,
                                    const absl::string_view ) {

  ENVOY_STREAM_LOG(debug, "Sending local reply with status code: {}, message '{}' and content-type '{}'",
      *decoder_callbacks_, status_code, message, content_type.value_or(""));
  resp_body_.setBodyFromString(message);
  run_ctx_.getReqOrRespHeaders()->clear();
  run_ctx_.getReqOrRespHeaders()->addCopy(Http::LowerCaseString("content-type"),*content_type);
  run_ctx_.getReqOrRespHeaders()->addCopy(Http::LowerCaseString(":status"),status_code);
  // include file doesnt compile ??? check why 
  // if(encoder_callbacks_ != nullptr)
  // {
  //   absl::optional<StreamInfo::ResponseFlag> response_flag =
  //       StreamInfo::ResponseFlagUtils::toResponseFlag(response_code_details);
  //   encoder_callbacks_->streamInfo().setResponseFlag(*response_flag);
  // }
  // DND-32300 add local_replied flag to dyn. MD, 
  // so that local reply config can filter it out.
  // The local reply will not be modified by local reply filter.
  ProtobufWkt::Struct local_reply_md;
  *(*local_reply_md.mutable_fields())["local_replied"].mutable_string_value() = "true";
  decoder_callbacks_->streamInfo().setDynamicMetadata("eric_filter", local_reply_md);
  local_reply_ = true;


  return std::make_tuple(ActionResult::StopIteration, false, std::nullopt);

}


} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
