#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "envoy/buffer/buffer.h"
#include "envoy/http/filter.h"
#include "include/nlohmann/json.hpp"
#include "source/common/common/statusor.h"

#include "source/extensions/filters/http/eric_proxy/proxy_filter_config.h"
#include "source/extensions/filters/http/eric_proxy/stats.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using Json = nlohmann::json;
using ModifyJsonBodyAction =
    ::envoy::extensions::filters::http::eric_proxy::v3::ModifyJsonBodyAction;

// States for the multipart-parser state-machine
enum class MpState {
  PREAMBLE,
  BODYPART,
  EPILOGUE,
  END,
  NOTVALIDMULTIPART,
};


// One body-part of a multipart body
class BodyPart : public Logger::Loggable<Logger::Id::eric_proxy> {
public:
  BodyPart(std::string_view body_part_as_stringview) : whole_part_(body_part_as_stringview),
    content_type_lc_(Http::LowerCaseString{""}) {
      parse();
    };


  absl::string_view whole_part_;
  absl::string_view header_part_;
  absl::string_view content_id_;
  Http::LowerCaseString content_type_lc_;
  absl::string_view data_part_;

private:
  // Parse the body part into headers, content-ID, content-type, and data part
  void parse();
  // Parse the header section
  void parseHeaderSection();
};


// The whole body
class Body : public Logger::Loggable<Logger::Id::eric_proxy> {
public:
  Body(const Buffer::Instance* body_buffer,
      absl::string_view content_type,
      Http::StreamDecoderFilterCallbacks* decoder_callbacks=nullptr);
  Body();

  virtual ~Body() = default;

  // Method returns body as string.
  // NB do not call it after buffer.drain()
  // Return the whole body as a string. If there is a JSON part
  // (or everything is JSON), serialize/dump it first.
  std::string getBodyAsString() const;

  // Return the parsed body as a JSON object. Handles
  // single and multipart body (first JSON body part is
  // parsed and returned.
  std::shared_ptr<Json> getBodyAsJson();
  
  // If the body is not multipart, return the whole body.
  // However, if the body is multipart, return the first 
  // body-part that has content-type application/json
  // unparsed as a string. If there is no application/json
  // bodypart, return the whole body.
  // This function is for the firewall and for getBodyAsJson().
  // All other uses should use "getBodyAsJson()" instead.
  absl::string_view getBodyOrJsonBodypartAsString();
  
  void setCallbacks(Http::StreamDecoderFilterCallbacks* decoder_callbacks) {
    decoder_callbacks_ = decoder_callbacks;
  }
  void setBodyFromBuffer(const Buffer::Instance* body_buffer, Http::RequestOrResponseHeaderMap* headermap);
  void setBodyFromJson(std::shared_ptr<Json> json_body, bool is_modified = true);
  void setBodyFromString(const std::string& body_str, absl::string_view content_type=absl::string_view());

  bool isBodyPresent() const { return is_body_present_; };
  bool isModified() const { return is_modified_; }
  bool isMultipart() const { return is_multipart_; }
  
  absl::string_view contentType() { return content_type_; }
  absl::string_view mpBoundary() { return mp_boundary_; }
  absl::string_view mpStart() { return mp_start_; }
  absl::optional<size_t> mpStartIndex() { return mp_start_index_; }
  absl::string_view mpPreamble() { return mp_preamble_; }
  absl::string_view mpEpilogue() { return mp_epilogue_; }
  std::vector<BodyPart> mpBodyParts() { return mp_body_parts_; }

  // Method checks if the body has valid JSON.
  // When a body is present and can be parsed as JSON,
  // then it returns true otherwise false.
  bool hasJson() {
    if (isBodyPresent()) {
      getBodyAsJson();
      return bool(json_body_);
    } else {
      return false;
    }
  }

  // reads from body by the pointer
  StatusOr<Json> readWithPointer(const std::string& json_pointer);

  // Executes an action on json body if the body presents
  absl::Status executeJsonOperation(const ModifyJsonBodyAction& action,
                                    Http::StreamDecoderFilterCallbacks* decoder_callbacks,
                                    EricProxy::RunContext& run_ctx);


private:
  Body(const Body&); // preventing coping
  

  bool is_body_present_ = false;
  bool is_modified_ = false;
  std::shared_ptr<Json> json_body_;
  mutable std::string body_str_ = "";

  // Multipart-related -------
  
  // Parse a content-type header into the type, and if present "boundary" and "start"
  void parseContentType();
  void parseMultipartBody();
  // Find the body part containing the JSON and set mp_start_index.
  void setJsonBodyPartIndex();

  bool is_multipart_ = false;
  std::string content_type_;
  std::string mp_boundary_;
  std::string mp_boundary_delim_;  // boundary prefixed with "--"
  size_t mp_boundary_delim_len_;
  std::string mp_boundary_delim_crlf_;  // boundary prefixed with "CRLF--"
  size_t mp_boundary_delim_crlf_len_;
  std::string mp_start_;
  absl::optional<size_t> mp_start_index_; // Index into mp_body_parts_ where the JSON body is
  std::string mp_preamble_;
  std::vector<BodyPart> mp_body_parts_;
  std::string mp_epilogue_;

  const std::string multipart_related_str_{"multipart/related"};
  const size_t multipart_related_str_length_ = 17;
  const Http::LowerCaseString application_json_str_{"application/json"};

  // Utility -------
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_ = nullptr;

  // Helper for content-type header parsing
  // Check if a search resulted in npos (= not found).
  // If yes, log the supplied error message with ULID and return true.
  // Otherwise return false
  bool notFound(size_t pos, const std::string& message, const std::string ulid) {
    if (pos == absl::string_view::npos) {
      if (decoder_callbacks_) {
        ENVOY_STREAM_UL_LOG(debug, message, *decoder_callbacks_, ulid);
      }
      return true;
    } else {
      return false;
    }
  }

  // Helper for content-type header parsing
  // Skip optional white space (space and tab)
  // -> Sets the scan_pos to the character after the white space and "true" is returned.
  //    If there is no white space, the scan_pos is unchanged and "false" is returned.
  bool skipOptionalWhitespace(size_t& scan_pos, absl::string_view str_view) {
    size_t post_ws_pos = str_view.find_first_not_of(" \t", scan_pos);
    if (post_ws_pos != absl::string_view::npos) {
      scan_pos = post_ws_pos;
      return true;
    }
    return false;
  }

  // Helper for content-type header parsing
  // Store the parameters of the content-type header in mp_boundary_ or mp_start_,
  // or ignore if any other parameter
  void storeBoundaryOrStart(absl::string_view name, absl::string_view value) {
    if (name == "boundary") {
      mp_boundary_ = value;
    } else {
      if (name == "start") {
        mp_start_ = value;
      } else {
        // nothing, we ignore all other parameters
      }
    }
  }

  // Helper for content-type header parsing
  // Debug: print the content-type header and where scan-pos and temp-pos are
  void printScanPos(const std::string& id, const absl::string_view string, size_t scan_pos, size_t temp_pos = 0) {
    const static std::string spaces{"                                                                                                                                                                           "};
    std::cout << "#### " << id << "#### " << string << std::endl
              << "#### " << id << "#### " << spaces.substr(0, scan_pos) << "S " << scan_pos << std::endl
              << "#### " << id << "#### " << spaces.substr(0, temp_pos) << "T " << temp_pos << std::endl;
  }
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
