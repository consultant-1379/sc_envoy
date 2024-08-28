#include "source/extensions/filters/http/cdn_loop/filter.h"

#include "envoy/http/codes.h"
#include "envoy/http/filter.h"
#include "envoy/http/header_map.h"

#include "source/common/common/statusor.h"
#include "source/common/http/headers.h"
#include "source/extensions/filters/http/cdn_loop/utils.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace CdnLoop {

namespace {

Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::RequestHeaders>
    cdn_loop_handle(Http::Headers::get().Via);

constexpr absl::string_view ParseErrorMessage = "Invalid via header in request.";
constexpr absl::string_view ParseErrorDetails = "invalid_via_header";
  // DND-56014 Response code has to be 400 for Loop Detection
constexpr absl::string_view LoopDetectedMessage = "{\"title\": \"Bad Request\", \"cause\": \"MSG_LOOP_DETECTED\", \"status\": 400,\"detail\":\"loop_detected\"}";
constexpr absl::string_view LoopDetectedDetails = "loop_detected";

} // namespace

Http::FilterHeadersStatus CdnLoopFilter::decodeHeaders(Http::RequestHeaderMap& headers,
                                                       bool /*end_stream*/) {

  if (const Http::HeaderEntry* header_entry = headers.getInline(cdn_loop_handle.handle());
      header_entry != nullptr) {
    StatusOr<std::vector<absl::string_view>> cdn_ids =
        parseViaHeaderContents(header_entry->value().getStringView(), cdn_id_);
    if (!cdn_ids.ok()) {
      decoder_callbacks_->streamInfo().setResponseFlag(StreamInfo::ResponseFlag::InvalidViaHeader);
      decoder_callbacks_->sendLocalReply(Http::Code::BadRequest, ParseErrorMessage, nullptr,
                                         absl::nullopt, ParseErrorDetails);
      return Http::FilterHeadersStatus::StopIteration;
    } else if (std::count(cdn_ids->begin(), cdn_ids->end(), cdn_id_) > max_allowed_occurrences_) {
      // Has to set local_replied key to true in eric_filter Dyn MD
      // to avoid being screened by local reply filter
      ProtobufWkt::Struct local_reply_md;
      *(*local_reply_md.mutable_fields())["local_replied"].mutable_string_value() = "true";
      decoder_callbacks_->streamInfo().setDynamicMetadata("eric_filter", local_reply_md);
      // DND-56014 Response Code modification aspect
      decoder_callbacks_->sendLocalReply(
          Http::Code::BadRequest, LoopDetectedMessage,
          [](Http::ResponseHeaderMap& headers) { headers.setContentType("application/problem+json"); },
          absl::nullopt, LoopDetectedDetails);
      return Http::FilterHeadersStatus::StopIteration;
    }
    if (decoder_callbacks_) {
      // change cdn_infos to not include protocol version
      // as the produced vector is also used for loop prevention
      // TS 29500 would also add SCP- or SEPP- prefixes to via headers 
      // So remove them as well if they exist

      std::vector<absl::string_view> prevented_hosts;
      prevented_hosts.reserve(cdn_ids->size());
      for (absl::string_view elem : *cdn_ids) {
        const auto& scp_idx = elem.find("SCP-");
        if(scp_idx != absl::string_view::npos){
          elem.remove_prefix(scp_idx+4);
        }
        const auto& sepp_idx = elem.find("SEPP-");
        if(sepp_idx != absl::string_view::npos){
          elem.remove_prefix(sepp_idx + 5);
        }        
        const auto& whitespace = elem.find(' ');

        if (whitespace != absl::string_view::npos) {
          prevented_hosts.push_back(elem.substr(whitespace + 1));
        } else {
          prevented_hosts.push_back(elem);
        }
      }
      decoder_callbacks_->setViaHeaderContents(std::move(prevented_hosts));
    }
  }
  // DND 60738 Move the addition of Via Header up the filter chain in
  // Eric Proxy post routing
  // headers.appendCopy(Http::Headers::get().Via, cdn_id_);
  return Http::FilterHeadersStatus::Continue;
}

} // namespace CdnLoop
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
