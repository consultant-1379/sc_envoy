#include "source/extensions/filters/http/eric_ingress_ratelimit/ratelimit.h"
#include <algorithm>
#include <cstddef>
#include <iterator>
#include <optional>
#include <string>
#include "rl_stats.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IngressRateLimitFilter {

struct RcDetailsValues {
  // This request went above the configured limits for the rate limit filter.
  const std::string RateLimited = "request_rate_limited";
  // The rate limiter encountered a failure, and was configured to fail-closed.
  const std::string RateLimitError = "rate_limiter_error";
  const std::string DropResponse = "stream_reset_by_rate_limiting";
};
using RcDetails = ConstSingleton<RcDetailsValues>;


EricIngressRateLimitFilter::EricIngressRateLimitFilter(
    std::shared_ptr<EricIngressRateLimitConfig> config,
    const std::chrono::time_point<std::chrono::system_clock> config_updated_at,
    const std::chrono::milliseconds timeout, std::shared_ptr<std::vector<float>> watermarks,
    const RateLimitStatsSharedPtr& stats)
    : config_(config), config_updated_at_(config_updated_at), timeout_(timeout),
      watermarks_(watermarks), stats_(stats) {}

EricIngressRateLimitFilter::~EricIngressRateLimitFilter() = default;

void EricIngressRateLimitFilter::onDestroy() { cleanup(); }

Http::FilterHeadersStatus EricIngressRateLimitFilter::decodeHeaders(Http::RequestHeaderMap& headers,
                                                                    bool) {
  request_headers_ = &headers;
  initiateCall();
  return (state_ == State::Calling || state_ == State::Responded)
             ? Http::FilterHeadersStatus::StopIteration
             : Http::FilterHeadersStatus::Continue;

  // ENVOY_STREAM_LOG(debug, "DecodeData , state: {}, filterStatus: {}", *decoder_callbacks_,
  // state_, return_status); return return_status;
}

Http::FilterDataStatus EricIngressRateLimitFilter::decodeData(Buffer::Instance&, bool) {
  ASSERT(state_ != State::Responded);
  if (state_ != State::Calling) {
    return Http::FilterDataStatus::Continue;
  }
  // If the request is too large, stop reading new data until the buffer drains.
  return Http::FilterDataStatus::StopIterationAndWatermark;
}

Http::FilterTrailersStatus EricIngressRateLimitFilter::decodeTrailers(Http::RequestTrailerMap&) {
  ASSERT(state_ != State::Responded);
  return state_ == State::Calling ? Http::FilterTrailersStatus::StopIteration
                                  : Http::FilterTrailersStatus::Continue;
}

void EricIngressRateLimitFilter::setDecoderFilterCallbacks(
    Http::StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

Http::Filter1xxHeadersStatus EricIngressRateLimitFilter::encode1xxHeaders(Http::ResponseHeaderMap&) {
  return Http::Filter1xxHeadersStatus::Continue;
}

Http::FilterHeadersStatus
EricIngressRateLimitFilter::encodeHeaders(Http::ResponseHeaderMap& headers, bool) {
  populateResponseHeaders(headers, /*from_local_reply=*/false);
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus EricIngressRateLimitFilter::encodeData(Buffer::Instance&, bool) {
  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus EricIngressRateLimitFilter::encodeTrailers(Http::ResponseTrailerMap&) {
  return Http::FilterTrailersStatus::Continue;
}

Http::FilterMetadataStatus EricIngressRateLimitFilter::encodeMetadata(Http::MetadataMap&) {
  return Http::FilterMetadataStatus::Continue;
}

void EricIngressRateLimitFilter::setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks&) {}

//-------------------------------------------------------------------------------------------------
// The reason there is an onDestroy() method vs. doing this type of cleanup
// in the destructor is to avoid potential data races between an async
// callback and the destructor in case the connection terminates abruptly.
void EricIngressRateLimitFilter::cleanup() {
  ENVOY_STREAM_LOG(debug, "Eric IngressRateLimitfilter destroyed.", *decoder_callbacks_);
  if (lookup_request_ != nullptr) {
    ENVOY_STREAM_LOG(debug, "Cancelling lookup request.", *decoder_callbacks_);
    lookup_request_->cancel();
    lookup_request_ = nullptr;
  }
}

void EricIngressRateLimitFilter::initiateCall() {
  for (const auto& limit : config_->limits()) {
    auto bucket_action_pair = getBucketActionPairForLimit(limit);
    if (bucket_action_pair.has_value()) {
      bucket_actions_list_.push_back(bucket_action_pair.value());
    }
  }
  if (!bucket_actions_list_.empty()) {
    initiating_call_ = true;
    contactRlfService();
    initiating_call_ = false;
  }
}

void EricIngressRateLimitFilter::contactRlfService() {
  auto headers = EricIngressRateLimitFilter::prepareRlfServiceHeaders();
  Http::RequestMessagePtr message(new Http::RequestMessageImpl(std::move(headers)));
  appendBodyToRlfServiceRequest(message);
  //message->body().add(prepareRlfServiceRequestBody());
  ENVOY_STREAM_LOG(trace, "Contacting rate limit service", *decoder_callbacks_);
  auto options = Http::AsyncClient::RequestOptions().setTimeout(timeout_);
  const auto cluster_name = config_->clusterName();
  auto thread_local_cluster = config_->clusterManager().getThreadLocalCluster(cluster_name);
  if (thread_local_cluster == nullptr) {
    ENVOY_STREAM_LOG(error, "HTTP call cluster ({}) invalid. Must be configured",
                     *decoder_callbacks_, cluster_name);
    state_ = State::Complete;
    executeAction(config_->rlfServiceUnreachableAction(), std::nullopt);
    return;
  }
  state_ = State::Calling;

  ENVOY_STREAM_LOG(debug, "Contacting rlf with headers {}", *decoder_callbacks_,
                   logHeaders(message->headers()));

  ENVOY_STREAM_LOG(debug, "Contacting rlf with body {}", *decoder_callbacks_,
                   message->body().toString());

  auto lookupRequest =
      thread_local_cluster->httpAsyncClient().send(std::move(message), lookup_callbacks_, options);
  if (lookupRequest != nullptr) {
    lookup_request_ = lookupRequest;
    ENVOY_STREAM_LOG(debug, "HTTP call sent..", *decoder_callbacks_);
  } else {
    // Could only happen if TCP connection could not be established (no healthy hosts in the rlf
    // cluster). The service unreachable Action is triggered but from the callbacks, specifically
    // onRlfLookupSuccess(), so executing another terminal action here leads to unwanted behavior
    ENVOY_STREAM_LOG(debug, "HTTP call sending failed.", *decoder_callbacks_);
    // executeAction(config_->rlfServiceUnreachableAction(), std::nullopt);
  }
}

std::unique_ptr<Http::RequestHeaderMapImpl> EricIngressRateLimitFilter::prepareRlfServiceHeaders() {
  auto headers = Http::RequestHeaderMapImpl::create();

  headers->setContentType("application/json");
  headers->addCopy(Http::LowerCaseString(":path"), config_->getRlfServicePathHeader());
  headers->addCopy(Http::LowerCaseString(":method"), "POST");
  headers->addCopy(Http::LowerCaseString(":authority"), "eric-sc-rlf");
  headers->addCopy(Http::LowerCaseString(":scheme"), "https");
  return headers;
}

// Builds the body of the request to be sent to the RLF, appending it to the request and
// also setting the contentLength header
void EricIngressRateLimitFilter::appendBodyToRlfServiceRequest(Http::RequestMessagePtr& message) {
  const auto priority = request_headers_->get(Http::LowerCaseString("3gpp-sbi-message-priority"));
  std::size_t watermark_index;
  if (priority.empty() ||
      !absl::SimpleAtoi(priority[0]->value().getStringView(), &watermark_index)) {
    ENVOY_STREAM_LOG(debug,
                     "3gpp-sbi-message-priority header not found in request or malformed, assuming "
                     "default priority (24)",
                     *decoder_callbacks_);
    watermark_index = 24;
  }
  Json body = Json::array();
  for_each(bucket_actions_list_.begin(), bucket_actions_list_.end(), [&](const auto& info) {
    Json member;
    member["name"] = info.bucket_action_pair.bucket_name();
    member["watermark"] = watermarks_->at(watermark_index);
    member["amount"] = 1;
    body.push_back(member);
  });

  message->body().add(body.dump());
  message->headers().setContentLength(message->body().length());
  
}

std::optional<EricIngressRateLimitFilter::BucketActionInfo>
EricIngressRateLimitFilter::getBucketActionPairForLimit(const RateLimit& limit) {
  if (limit.has_network()) {

    return BucketActionInfo{std::string(config_->getNetworkName()), limit.network().bucket_action(),
                            LimitType::NW};

  } else if (limit.has_roaming_partner()) {

    // retrieve rp name from connection
    std::optional<std::string> rp_opt =
        decoder_callbacks_->connection()->ssl()
            ? decoder_callbacks_->connection()->ssl()->getRoamingPartnerName(
                  config_->getDnToRpTable(), config_->getDnToRegexTable(), config_updated_at_)
            : std::nullopt;

    const auto& rpToBucketActionTable = config_->getRpBucketActionTable();
    if (rp_opt) {
      const auto& found_it = rpToBucketActionTable.find(rp_opt.value());
      if (found_it != rpToBucketActionTable.end()) {
        // found bucket action pair for this RP
        ENVOY_STREAM_LOG(debug, "Rate limit found for roaming partner {}", *decoder_callbacks_,
                         rp_opt.value());
        return BucketActionInfo{rp_opt.value(), found_it->second, LimitType::RP};
      } else {
        ENVOY_STREAM_LOG(debug, "No configured limit found for roaming partner {}",
                         *decoder_callbacks_, rp_opt.value());
      }
    } else {
      // SAN did not match any known RPs -> rp_not_found action
      ENVOY_STREAM_LOG(debug, "RP not found, executing rp_not_found_action", *decoder_callbacks_);
      executeAction(limit.roaming_partner().rp_not_found_action(), std::nullopt);
    }
  }
  return std::nullopt;
}

/** HTTP request to RLF was successful
 */
void EricIngressRateLimitFilter::onRlfLookupSuccess(Http::ResponseMessagePtr&& lookup_resp) {
  ENVOY_STREAM_LOG(debug, "onRlfLookupSuccess()", *decoder_callbacks_);
  lookup_request_ = nullptr;

  auto status = lookup_resp->headers().getStatusValue();
  auto body = lookup_resp->bodyAsString();

  ENVOY_STREAM_LOG(debug, "status: {}, body: {}", *decoder_callbacks_, status, body);
  if (status == "200") {
    processRlfLookupBodyOK(body);
  } else {
    processRlfLookupErrors(status);
  }
}

void EricIngressRateLimitFilter::processRlfLookupBodyOK(const std::string& body) {
  ENVOY_STREAM_LOG(trace, "processRlfLookupBodyOK()", *decoder_callbacks_);
  state_ = State::Complete;
  Json json_body;
  try {
    json_body = Json::parse(body);
  } catch (Json::parse_error& e) {
    ENVOY_STREAM_LOG(debug, "Malformed JSON body in RLfLookup Response ({})", *decoder_callbacks_,
                     e.what());
    // increment counter for malformed body
    stats_->incCounter({stats_->n8e_, stats_->nf_instance_name_, stats_->g3p_, stats_->ingress_,
                        stats_->rlf_lookup_failure_});
    auto pass_action = ActionProfile();
    pass_action.set_action_pass_message(true);
    executeAction(pass_action, std::nullopt);
    return;
  }
  ENVOY_STREAM_LOG(debug, "Parsed JSON body raw string: {}", *decoder_callbacks_,
                   json_body.dump(2));

  if (!json_body.is_array()) {
    ENVOY_STREAM_LOG(debug, "Parsed JSON body is not an array", *decoder_callbacks_);
    auto pass_action = ActionProfile();
    pass_action.set_action_pass_message(true);
    executeAction(pass_action, std::nullopt);
    return;
  }
  if (json_body.empty()) {
    ENVOY_STREAM_LOG(debug, "Parsed JSON array is empty", *decoder_callbacks_);
    auto pass_action = ActionProfile();
    pass_action.set_action_pass_message(true);
    executeAction(pass_action, std::nullopt);
    return;
  }
  // body is indeed a json array, process each entry.
  // If at least one 429 response is encountered, the relevant action from the VucketActionPair
  // list. In case of underlimit response (200) the next entry is processed. For  500/404/<random>
  // occurences are flagged. After the entry processing is over, if the flag is true, the
  // configured service_error_action is executed.

  bool execute_service_error_action = false;
  for (Json::iterator it = json_body.begin(); it != json_body.end(); ++it) {

    // all entries should contain rc
    if (!it->contains("rc")) {
      ENVOY_STREAM_LOG(debug, "Entry does not have a return code (rc)", *decoder_callbacks_);
      execute_service_error_action = true;
      continue;
    }
    try {
      it.value()["rc"].get<int>();
    } catch (Json::exception& e) {
      execute_service_error_action = true;
      ENVOY_STREAM_LOG(debug, "Type Error in RLfLookup Response ({})", *decoder_callbacks_,
                       e.what());
      continue;
    }
    switch (static_cast<int>(it.value()["rc"])) {
    case 200:
      // underlimit
      ENVOY_STREAM_LOG(debug, "Underlimit", *decoder_callbacks_);
      break;
    case 429: {
      // overlimit
      ENVOY_STREAM_LOG(debug, "Overlimit", *decoder_callbacks_);
      const auto& action =
          bucket_actions_list_.at(it - json_body.begin()).bucket_action_pair.over_limit_action();
      updateResponseCounters(bucket_actions_list_.at(it - json_body.begin()),
                             action.has_action_drop_message() ? CounterType::DROPPED
                                                              : CounterType::REJECTED);
      // "ra" value is use as a value on the retry-after header and is only needed when
      // rejecting the request via a local reply 
      if (action.has_action_reject_message() && action.action_reject_message().retry_after_header() != RetryAfterFormat::DISABLED
           && it->contains("ra")) {

        if (action.action_reject_message().retry_after_header() == RetryAfterFormat::SECONDS) {
          executeAction(action, RetryAfterHeaderFormat::getSecondsJsonBody(it));
        } else {
          //http date
          executeAction(action, RetryAfterHeaderFormat::getHttpDateFromJsonBody(it));
        }
      } else {
        executeAction(action, std::nullopt);
      }
    }
      // action was executed, no need to process more entries
      return;
      // break;
    case 500:
      // service error, check related action profile.
      ENVOY_STREAM_LOG(debug, "Rlf service error ", *decoder_callbacks_);
      stats_->incCounter({stats_->n8e_, stats_->nf_instance_name_, stats_->g3p_, stats_->ingress_,
                          stats_->rlf_lookup_failure_});
      execute_service_error_action = true;
      break;
    case 404:
      // Bucket not found. This should never happen and would mean an inconsistency between our
      // config and that of rlf Pass the request through
      ENVOY_STREAM_LOG(debug, "Rlf bucket not found", *decoder_callbacks_);
      stats_->incCounter({stats_->n8e_, stats_->nf_instance_name_, stats_->g3p_, stats_->ingress_,
                          stats_->rlf_lookup_failure_});
      execute_service_error_action = true;
      break;
    default:
      ENVOY_STREAM_LOG(debug, "unrecognized response code from Rlf", *decoder_callbacks_);
      stats_->incCounter({stats_->n8e_, stats_->nf_instance_name_, stats_->g3p_, stats_->ingress_,
                          stats_->rlf_lookup_failure_});
      execute_service_error_action = true;
    }
  }

  if (execute_service_error_action) {
    executeAction(config_->rlfServiceUnreachableAction(), std::nullopt);
  } else {
    // incremmenting all counters as success
    for (const auto& ba : bucket_actions_list_) {
      updateResponseCounters(ba, CounterType::PASSED);
    }
    if (!initiating_call_) {
      decoder_callbacks_->continueDecoding();
    }
  }
}

/** HTTP request to RLF was unsuccessful
 */
void EricIngressRateLimitFilter::onRlfLookupFailure(
    Http::AsyncClient::FailureReason failure_reason) {
  ENVOY_STREAM_LOG(debug, "FailureReason:{}", *decoder_callbacks_,
                   static_cast<int>(failure_reason));
  state_ = State::Complete;
  lookup_request_ = nullptr;
  executeAction(config_->rlfServiceUnreachableAction(), std::nullopt);
}

void EricIngressRateLimitFilter::processRlfLookupErrors(const absl::string_view& status) {
  ENVOY_STREAM_LOG(debug, "processRlfLookupErrors(), status code {}", *decoder_callbacks_, status);
  state_ = State::Complete;
  executeAction(config_->rlfServiceUnreachableAction(), std::nullopt);
}

void EricIngressRateLimitFilter::executeAction(const ActionProfile& action,
                                               std::optional<std::string> retry_after) {

  if (action.has_action_pass_message()) {
    if (!initiating_call_ && state_ != State::NotStarted) {
      decoder_callbacks_->continueDecoding();
    }
  } else if (action.has_action_reject_message()) {

    state_ = State::Responded;

    auto status_code = action.action_reject_message().status();
    std::string title;

    std::string format_name;
    std::string content_type;

    switch (action.action_reject_message().message_format()) {
    case RejectMessageBodyType::JSON: {
      format_name = "JSON";
      content_type = "application/problem+json";

      // status code and title are mandatory via YANG
      // detail and cuse are optional and if not present should be omitted from the body
      const auto& detail = action.action_reject_message().detail();
      const auto& cause = action.action_reject_message().cause();
      title = absl::StrCat("{\"status\": ", status_code, ", \"title\": \"",
                           action.action_reject_message().title(), "\"");
      if (!detail.empty()) {
        absl::StrAppend(&title, ", \"detail\": \"", detail, "\"");
      }
      if (!cause.empty()) {
        absl::StrAppend(&title, ", \"cause\": \"", cause, "\"");
      }
      absl::StrAppend(&title, "}");
      break;
    }
    case RejectMessageBodyType::PLAIN_TEXT:
      title = action.action_reject_message().title();
      format_name = "text";
      content_type = "text/plain";
      break;
    default:
      title = action.action_reject_message().title();
      ENVOY_STREAM_LOG(warn, "Unknown message_format for action_reject_message",
                       *decoder_callbacks_);
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
    if (retry_after.has_value()) {

      response_headers_to_add_->setCopy(Http::LowerCaseString("retry-after"), retry_after.value());
    }
    ENVOY_STREAM_LOG(debug, "Reject title with status code: {} and title '{}' formatted as {}",
                     *decoder_callbacks_, status_code, title, format_name);

    // The reply will go through the filter chain because no response headers have been received
    // yet (they couldn't because we don't forward the request). This means the response filter
    // will process the title.
    // This action can only be in the request path, hence "decoder_callbacks_".
    // internal_rejected_ = true;

    // DND-32300 add local_replied flag to dyn. MD,
    // so that local reply config can filter it
    ProtobufWkt::Struct local_reply_md;
    *(*local_reply_md.mutable_fields())["local_replied"].mutable_string_value() = "true";
    decoder_callbacks_->streamInfo().setDynamicMetadata("eric_filter", local_reply_md);

    decoder_callbacks_->sendLocalReply(
        static_cast<Http::Code>(status_code), title,
        [this](Http::HeaderMap& headers) {
          populateResponseHeaders(headers, /*from_local_reply=*/true);
        },
        absl::nullopt, RcDetails::get().RateLimited);

  } else if (action.has_action_drop_message()) {
    // drop message

    state_ = State::Responded; // silent response
    ENVOY_STREAM_LOG(debug, "Dropping request", *decoder_callbacks_);
    decoder_callbacks_->streamInfo().setResponseFlag(StreamInfo::ResponseFlag::LocalReset);
    decoder_callbacks_->streamInfo().setResponseCodeDetails(RcDetails::get().DropResponse);
    decoder_callbacks_->resetStream();

  } else {
    ENVOY_STREAM_LOG(error, "Unknown action, filter can't handle the request", *decoder_callbacks_);
  }
}

void EricIngressRateLimitFilter::populateResponseHeaders(Http::HeaderMap& response_headers,
                                                         bool from_local_reply) {
  if (response_headers_to_add_) {
    // If the ratelimit service is sending back the content-type header and we're
    // populating response headers for a local reply, overwrite the existing
    // content-type header.
    //
    // We do this because sendLocalReply initially sets content-type to text/plain
    // whenever the response body is non-empty, but we want the content-type coming
    // from the ratelimit service to be authoritative in this case.
    if (from_local_reply && !response_headers_to_add_->getContentTypeValue().empty()) {
      response_headers.remove(Http::Headers::get().ContentType);
    }
    Http::HeaderMapImpl::copyFrom(response_headers, *response_headers_to_add_);
    response_headers_to_add_ = nullptr;
  }
}

void EricIngressRateLimitFilter::updateResponseCounters(std::optional<BucketActionInfo> info,
                                                        const CounterType flavor) {

  if (!info.has_value()) {
    return;
  }
  auto& stat_info = info.value();
  switch (stat_info.type) {
  case LimitType::NW:

    stats_->incCounterPerNetwork(stats_->getBuiltin(stat_info.name, stats_->unknown_name_), flavor);
    break;

  case LimitType::RP:
    stats_->incCounterPerRP(stats_->getBuiltin(stat_info.name, stats_->unknown_name_), flavor);
    break;
  }
  // incr total counter
  switch (flavor) {

  case CounterType::PASSED:
    stats_->incCounter({stats_->n8e_, stats_->nf_instance_name_, stats_->g3p_, stats_->ingress_,
                        stats_->total_accepted_});
    break;
  case CounterType::REJECTED:
    stats_->incCounter({stats_->n8e_, stats_->nf_instance_name_, stats_->g3p_, stats_->ingress_,
                        stats_->total_rejected_});
    break;
  case CounterType::DROPPED:
    stats_->incCounter({stats_->n8e_, stats_->nf_instance_name_, stats_->g3p_, stats_->ingress_,
                        stats_->total_dropped_});
    break;
  }
}

/**
 * Returns a string containg a printout of supplied headers.
 * Can be invoked by a logger for debugging and troubleshooting purposes
 */
const std::string EricIngressRateLimitFilter::logHeaders(const Http::RequestOrResponseHeaderMap& headers) const {
  std::string log_message = "\n  ";
  headers.iterate([&](const Http::HeaderEntry& entry) -> Http::HeaderMap::Iterate {
    absl::StrAppend(&log_message, entry.key().getStringView(), ": ", entry.value().getStringView(),
                    "\n  ");
    return Http::HeaderMap::Iterate::Continue;
  });
  return log_message;
}



} // namespace IngressRateLimitFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
