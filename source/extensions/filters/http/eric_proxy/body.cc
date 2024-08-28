#include "body.h"
#include "source/extensions/filters/http/eric_proxy/json_operations.h"
#include "source/extensions/filters/http/eric_proxy/json_utils.h"
#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include <cstddef>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using JsonUtils = Envoy::Extensions::HttpFilters::EricProxy::EricProxyJsonUtils;

// Parse a body part into its components.
// A body part consists of:
// - an optional header section
//   - one header per line (name: value)
//   - each line is terminated by \r\n (CR LF)
//   - after the end of the header section, a blank line (CR LF)
// - a mandatory body part (rest of the body section)
void BodyPart::parse() {
  // Headers are separated from the data by a blank line
  auto header_end_pos = whole_part_.find("\r\n\r\n");
  if (header_end_pos != absl::string_view::npos) {
    header_part_ = whole_part_.substr(0, header_end_pos);
    header_end_pos += 4;  // advance over \r\n\r\n
    parseHeaderSection();
  } else {
    // No headers found in body part
    header_end_pos = 0;
  }

  // The rest is the data part
  data_part_ = whole_part_.substr(header_end_pos);
}


// Parse the header section to extract only content-type and content-id.
// Ignore all others
void BodyPart::parseHeaderSection() {
  static const Http::LowerCaseString content_type_str_lc{"content-type"};
  static const Http::LowerCaseString content_id_str_lc{"content-id"};

  std::vector<absl::string_view> headers = absl::StrSplit(header_part_, "\r\n");
  for (auto header: headers) {
    // Split into name and value
    std::vector<absl::string_view> name_value = absl::StrSplit(header, ':');
    if (name_value.size() == 2) { // =2 because we need name and value
      Http::LowerCaseString name_lc{absl::StripTrailingAsciiWhitespace(name_value.at(0))};
      if (name_lc == content_type_str_lc) { // Content-type, not case-sensitive
        Http::LowerCaseString ct{absl::StripLeadingAsciiWhitespace(name_value.at(1))};
        content_type_lc_ = ct;
      } else if (name_lc == content_id_str_lc) {  // Content-ID, case-sensitive
        content_id_ = absl::StripLeadingAsciiWhitespace(name_value.at(1));
      }
    }
  }
}


//--------------------------------------------------------------------------------------
// Body class

Body::Body(const Buffer::Instance* body_buffer, absl::string_view content_type,
 Http::StreamDecoderFilterCallbacks* decoder_callbacks) :
  content_type_(content_type), decoder_callbacks_(decoder_callbacks) {
  setBodyFromBuffer(body_buffer, nullptr);
  parseContentType();
}

Body::Body() = default;


// Parse a content-type header (not the content-type in the body -> see parseHeaderSection() for
// that) to find out if it's "multipart/related". If yes also parse and set the values for
// "boundary"
void Body::parseContentType() {
  absl::string_view content_type_sv{content_type_};
  // Everything in the content-type header is case-insensitive, only the value
  // for "boundary" is case-sensitive.
  std::string content_type_lc = absl::AsciiStrToLower(content_type_);
  absl::string_view content_type_lc_sv{content_type_lc};
  // The assert is because we use the lower-case version of the content-type
  // to find the position of the boundary and start parameters and then
  // use these positions to read the value in the original string so that
  // we don't use the lowercased value.
  ASSERT(content_type_lc.length() == content_type_.length());

  size_t scan_pos = 0;
  // Skip possible whitespace at the beginning
  skipOptionalWhitespace(scan_pos, content_type_lc_sv);
  // It must start with the content-type of "multipart/related"
  if (content_type_lc_sv.compare(scan_pos, multipart_related_str_length_, multipart_related_str_) != 0) {
    if (decoder_callbacks_) {ENVOY_STREAM_UL_LOG(debug, "Body is not multipart because the content-type header is not 'multipart/related'", *decoder_callbacks_, ULID(B06)); }
    return;
  }
  scan_pos += multipart_related_str_length_;
  // Loop over all parameters
  size_t temp_pos = 0;
  absl::string_view param_name;
  absl::string_view param_value;
  int num_param_max = 20;  // Limit max. params
  while (num_param_max--) {
    // Now we are just past the content-type.
    skipOptionalWhitespace(scan_pos, content_type_lc_sv);
    // Find the semicolon between content-type and the parameters
    scan_pos = content_type_lc_sv.find(';', scan_pos);
    if (notFound(scan_pos, "Body is not multipart because no parameter-separating semicolon was found in content-type header", ULID(B22))) {
     return;
    }
    scan_pos++;
    skipOptionalWhitespace(scan_pos, content_type_lc_sv);
    //   read until ws or = -> this is the param name
    temp_pos = content_type_lc_sv.find_first_of(" \t=", scan_pos);
    if (notFound(temp_pos, "Body is not multipart because no boundary was found in content-type header", ULID(B05))) {
     return;
    }
    // Extract the parameter name
    param_name = content_type_lc_sv.substr(scan_pos, temp_pos - scan_pos);
    scan_pos = temp_pos;
    // Find the "="
    skipOptionalWhitespace(scan_pos, content_type_lc_sv);
    if ((scan_pos + 1 < content_type_lc_sv.length()) && content_type_lc_sv.at(scan_pos) != '=') {
      if (decoder_callbacks_) {
        ENVOY_STREAM_UL_LOG(debug, "Body is not multipart because the boundary is incomplete (no '=') in content-type header", *decoder_callbacks_, ULID(B23));
      }
     return;
    }
    scan_pos++; // go past the =
    skipOptionalWhitespace(scan_pos, content_type_lc_sv);
    // Parameter value
    // Is it quoted?
    if ((scan_pos + 1 < content_type_lc_sv.length()) && content_type_lc_sv.at(scan_pos) == '"') {
      // yes, quoted
      scan_pos++;
      temp_pos = content_type_lc_sv.find_first_of('"', scan_pos);
      if (notFound(temp_pos, "Body is not multipart because the boundary is incomplete (no closing quote) in content-type header", ULID(B24))) {
       return;
      }
      // Read **from original string** until next unescaped quote -> this is the value
      //param_value = content_type_.substr(scan_pos, temp_pos - scan_pos);
      param_value = content_type_sv.substr(scan_pos, temp_pos - scan_pos);
      storeBoundaryOrStart(param_name, param_value);
      // Exit loop when both boundary and start have been found
      if ((! mp_boundary_.empty()) && (! mp_start_.empty())) {
        break;
      }
      scan_pos = temp_pos + 1;
      // Exit loop when only whitespace remains or the string ends right after this parameter
      if (!skipOptionalWhitespace(scan_pos, content_type_lc_sv) || scan_pos == content_type_lc_sv.length() - 1) {
        break;  // End of string, possibly after white space
      }
    } else {
      // Un-quoted bounday -> find next white space or semicolon or end of string
     temp_pos = content_type_lc_sv.find_first_of(" \t;", scan_pos);
      if (temp_pos != absl::string_view::npos) {
        // whitespace found -> read **from original string** until the temp_pos, this is the value
        param_value = content_type_sv.substr(scan_pos, temp_pos - scan_pos);
        storeBoundaryOrStart(param_name, param_value);
        scan_pos = temp_pos;
        // Exit loop when both boundary and start have been found
        if ((!mp_boundary_.empty()) && (!mp_start_.empty())) {
          break;
        }
        // Exit loop when only whitespace remains or the string ends right after this parameter
        if (!skipOptionalWhitespace(scan_pos, content_type_lc_sv) || scan_pos == content_type_lc_sv.length() - 1) {
          break;  // End of string, possibly after white space
        }
      } else {
        // Parameter ends at the end of the string
        param_value = absl::string_view(content_type_).substr(scan_pos);
        storeBoundaryOrStart(param_name, param_value);
        // Exit the loop, we are at the end of the string
        break;
      }
    }
    // Exit the parameter-reading loop when we are at the end of the input string
    if (scan_pos >= content_type_lc_sv.length()) {
      break;
    }
  } // end of loop

  // Construct the search-strings for body parsing
  if (!mp_boundary_.empty()) {
    if (decoder_callbacks_) {
      ENVOY_STREAM_UL_LOG(trace, "Body is multipart with boundary '{}'", *decoder_callbacks_,
                          ULID(B01), mp_boundary_);
    }

    is_multipart_ = true;
    mp_boundary_delim_ = std::string("--") + mp_boundary_;
    mp_boundary_delim_len_ = mp_boundary_delim_.length();
    mp_boundary_delim_crlf_ = std::string("\r\n--") + mp_boundary_;
    mp_boundary_delim_crlf_len_ = mp_boundary_delim_crlf_.length();
  }
}


// Parse a multipart-body into its body-parts
void Body::parseMultipartBody() {
  // Use a state-machine to parse the body
  MpState state = MpState::PREAMBLE;
  absl::string_view body_sv{body_str_};

  size_t scan_pos = 0;  // position in the body
  while (state != MpState::END) {
    switch (state) {
      case MpState::PREAMBLE: {
        // Find first boundary
        auto next_b_start = body_sv.find(mp_boundary_delim_);
        // If not found -> this is not a correct multipart-body -> stop processing
        if (next_b_start == absl::string_view::npos) {
          state = MpState::NOTVALIDMULTIPART;
          break;
        }
        // If found, everything before the first boundary goes into the preamble
        if (next_b_start > 2) { // 2 because if there is a preamble, there must be CRLF before it
          mp_preamble_ = body_sv.substr(0, next_b_start -2); // -2 to not copy CRLF
          scan_pos = next_b_start + mp_boundary_delim_crlf_len_; // just after the CRLF after boundary
          state = MpState::BODYPART;
        } else if (next_b_start == 0) { // No preamble
          scan_pos += mp_boundary_delim_crlf_len_; // just after the CRLF after boundary
          state = MpState::BODYPART;
        }else { // invalid multipart body because the preamble is too short
          state = MpState::NOTVALIDMULTIPART;
        }
        break;
      }
      case MpState::BODYPART: {
        // Find next boundary
        auto next_b_start = body_sv.find(mp_boundary_delim_crlf_, scan_pos);
        // If not found -> this is not a correct multipart-body -> stop processing
        if (next_b_start == absl::string_view::npos) {
          state = MpState::NOTVALIDMULTIPART;
          break;
        }
        // If found, store the part
        auto bp_len = next_b_start - scan_pos;
        mp_body_parts_.emplace_back(body_sv.substr(scan_pos, bp_len));
        scan_pos += bp_len + mp_boundary_delim_crlf_len_;
        // Check if it is followed by "--". If yes, it's the final part.
        if (body_sv.substr(scan_pos, 2) == "--") {
          // Yes, last part -> go to epilogue
          scan_pos += 4; // go past the "--" and CRLF
          if (scan_pos >= body_sv.length()) {
            // no epilogue -> end
            state = MpState::END;
            break;
          } else { // There is an epilogue
            state = MpState::EPILOGUE;
            break;
          }
        } else {
          scan_pos += 2; // skip the CRLF after the boundary
          // Not last boundary -> stay in BODY_PARTS, no state change
        }
        break;
      }
      case MpState::EPILOGUE: {
        // If there is more data, store it into the epilogue
        mp_epilogue_ = body_sv.substr(scan_pos);
        state = MpState::END;
        break;
      }
      case MpState::NOTVALIDMULTIPART: {
        is_multipart_ = false;
        state = MpState::END;
        break;
      }
      default: {
        if (decoder_callbacks_) { ENVOY_STREAM_UL_LOG(error, "Unexpected state in multipart-body parsing", *decoder_callbacks_, ULID(B21)); }
        state = MpState::END;
      }
    }
  }
  // Find the body-part containing JSON and remember it
  setJsonBodyPartIndex();
}

// Find the body part containing the JSON and set mp_start_index.
// If the content-type header of the message contained a "start" parameter then use that.
// If it didn't, find the first body-part with a content-type header of "application/json".
void Body::setJsonBodyPartIndex() {
  // This only makes sense for multipart bodies
  if (is_multipart_) {
    // Do we have a "start" parameter in the content-type of the message?
    if (!mp_start_.empty()) {
      // Find the body-part with the content-ID matching the "start" ID
      // FIXME: implement this part (not done yet because the "start" value is
      //        not yet parsed from the content-type header either
    } else {
      // No start -> find the first JSON body (the standards say to use the
      // first body part
      for (size_t i = 0; i < mp_body_parts_.size(); i++) {
        if (mp_body_parts_.at(i).content_type_lc_ == application_json_str_) {
          mp_start_index_ = i;
          return;
        }
      }
    }
  }
}


// Copy the body from a supplied Envoy buffer into this object's body_buffer.
// Apply multipart-handling if the content-type header is multipart/related.
void Body::setBodyFromBuffer(const Buffer::Instance* body, Http::RequestOrResponseHeaderMap* headers) {
  if (content_type_.empty()) {
    content_type_ = headers->getContentTypeValue();
  }
  parseContentType();
  if (body) {
    is_body_present_ = body->length() > 0;
    // Clean/reset old JSON obj if one already exists
    if (json_body_) {
      json_body_.reset();
    }
    body_str_ = body->toString();
    //TODO: remove below, once we introduced separate objects for request/reponse body
    is_modified_ = false;
    if (decoder_callbacks_) { ENVOY_STREAM_UL_LOG(trace, "Body::setBodyFromBuffer: {}", *decoder_callbacks_, ULID(B07), body_str_); }
    if (is_body_present_ && is_multipart_) {
     parseMultipartBody();
    }
  }
}


// Update the JSON object in the body from supplied JSON object.
// Typically after the JSON has been modified by screening (is_modified = true),
// or by the firewall (is_modified = false so that the body doesn't need to be parsed again)
void Body::setBodyFromJson(std::shared_ptr<Json> json_body, bool is_modified){
  json_body_ = json_body;
  is_modified_ = is_modified;
  if (decoder_callbacks_) { ENVOY_STREAM_UL_LOG(trace, "Body::setBodyFromJson: {}", *decoder_callbacks_, ULID(B08), getBodyAsString()); }
};


// Set/replace the whole body with the supplied string.
// Typically used in direct responses
void Body::setBodyFromString(const std::string& body_str, absl::string_view content_type){
  content_type_ = content_type;
  parseContentType();
  json_body_.reset();
  body_str_ = body_str;
  if (decoder_callbacks_) { ENVOY_STREAM_UL_LOG(trace, "Body::setBodyFromString: {}", *decoder_callbacks_, ULID(B09), body_str_); }
  is_body_present_ = body_str_.length() > 0;
  is_modified_ = true;
  if (is_body_present_ && is_multipart_) {
    parseMultipartBody();
  }
};


// Return the whole body as a string. If there is a JSON part (or everything is JSON),
// serialize/dump it first.
std::string Body::getBodyAsString() const {
  // Multipart case:
  if (is_multipart_) {
    absl::Cord body_cord;
    // Preamble (if exists)
    if (!mp_preamble_.empty()) {
      body_cord.Append(mp_preamble_);
      body_cord.Append("\r\n");
    }

    // All body-parts
    for (const auto& bp: mp_body_parts_) {
      body_cord.Append(mp_boundary_delim_);
      body_cord.Append("\r\n");
      // If it's a json body, dump the JSON object into the cord
      if ((bp.content_type_lc_ == application_json_str_) && json_body_) {
        body_cord.Append(bp.header_part_);
        body_cord.Append("\r\n\r\n");
        // Dump the JSON object
        body_cord.Append(json_body_->dump());
      } else {
        // Copy the whole body-part into the Cord
        body_cord.Append(bp.whole_part_);
      }
      body_cord.Append("\r\n");
    }

    // Last boundary
    body_cord.Append(mp_boundary_delim_);
    body_cord.Append("--");

    // Epilogue (if exists)
    if (!mp_epilogue_.empty()) {
      body_cord.Append("\r\n");
      body_cord.Append(mp_epilogue_);
      // No boundary after the epilogue
    }

    absl::CopyCordToString(body_cord, &body_str_);  
  } else {
    // Non-multipart case:
    if (json_body_) {
      body_str_= json_body_->dump();
    }
  }
  return body_str_;
}


// Return the JSON-part of a body as a shared-pointer to a JSON object.
// If there is no body, return a JSON object that is empty.
// If the parsing fails, return a shared pointer to a JSON null object.
// Typically used to subsequenctly modify the JSON object
std::shared_ptr<Json> Body::getBodyAsJson() {
  // If there is already a JSON object for the body, we don't have to do anything,
  // just return it at the end.

  if (!json_body_) {
    // No JSON body object exists yet
    if (is_body_present_) {
      // Decode the body into a JSON object
      if (decoder_callbacks_) { ENVOY_STREAM_UL_LOG(trace, "body_str is: {}", *decoder_callbacks_, ULID(B10), body_str_);}
      try {
        Json json_body;
        json_body = Json::parse(getBodyOrJsonBodypartAsString());
        json_body_ = std::make_shared<Json>(json_body);
      } catch (Json::parse_error& e) {
        // TODO(eedala): step counter for malformed body
        if (decoder_callbacks_) { ENVOY_STREAM_UL_LOG(debug, "Malformed JSON body ({})", *decoder_callbacks_, ULID(B11), e.what());}
        // This leaves a JSON null object which will be returned
      }
    } else {
      // No body exists -> create an otherwise empty JSON object
      if (decoder_callbacks_) { ENVOY_STREAM_UL_LOG(trace, "Body is not present", *decoder_callbacks_, ULID(B12));}
      json_body_ = std::make_shared<Json>(Json::object());
    }
  }

  return json_body_;
}

// If the body is not multipart, return the whole body.
// However, if the body is multipart, return the first 
// body-part that has content-type application/json
// unparsed as a string. If there is no application/json
// bodypart, return the whole body.
// This function is for the firewall and for getBodyAsJson().
// All other uses should use "getBodyAsJson()" instead.
absl::string_view Body::getBodyOrJsonBodypartAsString() {
  if (is_multipart_ && mp_start_index_.has_value()) {
    return mp_body_parts_.at(mp_start_index_.value()).data_part_;
  } else {
    return body_str_;
  }
}


// Read from an element from a JSON-encoded string via a Json-Pointer.
StatusOr<Json> Body::readWithPointer(const std::string& json_pointer_str) {
  if (decoder_callbacks_) { ENVOY_STREAM_UL_LOG(trace, "readWithPointer(\"{}\")", *decoder_callbacks_, ULID(B13), json_pointer_str); }
  const auto json_body = getBodyAsJson();
  if (!json_body) {
    if (decoder_callbacks_) { ENVOY_STREAM_UL_LOG(trace, "Cannot parse message body as JSON", *decoder_callbacks_, ULID(B14)); }
    return absl::InvalidArgumentError("Cannot parse json");
  }

  Json::json_pointer json_pointer;
  try {
    json_pointer = Json::json_pointer(json_pointer_str);
  } catch (Json::parse_error& e) {
    // Shoud not happen (should have been caught in a validator)
    if (decoder_callbacks_) {
      ENVOY_STREAM_UL_LOG(info, "Malformed JSON pointer ({}: {})", *decoder_callbacks_, ULID(B15),
                          e.what(), json_pointer_str);
    }
    return absl::InvalidArgumentError("Malformed JSON pointer");
  }
  Json element;
    if (decoder_callbacks_) { ENVOY_STREAM_UL_LOG(trace, "Body: {}", *decoder_callbacks_, ULID(B16), json_body->dump());}
  try {
    element = json_body->at(json_pointer);
  } catch (std::exception& e) {
    if (decoder_callbacks_) {
      ENVOY_STREAM_UL_LOG(debug, "Element {} not found in JSON body via JSON pointer ({})",
        *decoder_callbacks_, ULID(B17), json_pointer_str, e.what());
    }
    return element; // Not found -> null type
  }
  return element;
}

absl::Status Body::executeJsonOperation(const ModifyJsonBodyAction& action,
                                        Http::StreamDecoderFilterCallbacks* decoder_callbacks,
                                        EricProxy::RunContext& run_ctx) {
  if (!is_body_present_) {
    return absl::InvalidArgumentError("Body is empty");
  }

  const auto json_body = getBodyAsJson();

  if (!json_body) {
    return absl::NotFoundError("Can not parse json");
  }

  auto json_operation =
    EricProxy::JsonOpWrapper(action.json_operation(), *json_body, decoder_callbacks, run_ctx);
  if (decoder_callbacks_) { ENVOY_STREAM_UL_LOG(trace, "Executing json operation", *decoder_callbacks, ULID(B18)); }
  absl::StatusOr<std::shared_ptr<json>> modified_body_json = json_operation.execute();
  if (modified_body_json.ok()) {
    if (decoder_callbacks_) {
      ENVOY_STREAM_UL_LOG(trace, "modified_body_json is: {}", *decoder_callbacks, ULID(B19),
        modified_body_json.value()->dump());
      if (modified_body_json.value()->dump().length() > decoder_callbacks_->decoderBufferLimit() ) {
        // DND-32766 specific status code used to send back a local reply indicating
        // a request buffer overflow after a json body modification
        return absl::Status(absl::StatusCode::kAborted, "Payload too large");      
      }
    }
    setBodyFromJson(modified_body_json.value());
    return absl::OkStatus();
  } else {
    if (decoder_callbacks_) {
      ENVOY_STREAM_UL_LOG(trace, "json operation failed: {} ", *decoder_callbacks, ULID(B20),
                       modified_body_json.status().message());
    }
    return absl::InternalError(modified_body_json.status().message());
  }
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
