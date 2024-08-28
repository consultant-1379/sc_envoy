#include <algorithm>
#include <chrono>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>
#include "absl/strings/str_format.h"
#include "proxy_filter_config.h"
#include "source/common/common/empty_string.h"
#include "source/common/common/logger.h"
#include "source/common/common/regex.h"
#include "source/common/http/utility.h"
#include "source/common/http/header_utility.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/base32.h"

#include "source/common/common/statusor.h"
#include "envoy/config/route/v3/route_components.pb.h"
#include "envoy/extensions/retry/host/previous_hosts/v3/previous_hosts.pb.h"
#include "envoy/http/header_map.h"
#include "envoy/type/matcher/v3/regex.pb.h"
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/extensions/filters/http/eric_proxy/condition.h"
#include "source/extensions/filters/http/eric_proxy/wrappers.h"
#include "source/extensions/filters/http/eric_proxy/json_utils.h"
#include "source/extensions/filters/http/eric_proxy/search_and_replace.h"
#include "source/extensions/filters/http/eric_proxy/tfqdn_codec.h"
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_local_response.h"
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_request_meta.h"
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_response_meta.h"
#include "source/common/stream_info/eric_proxy_state.h"
#include "envoy/server/filter_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using Json = nlohmann::json;
using JsonUtils = Envoy::Extensions::HttpFilters::EricProxy::EricProxyJsonUtils;

const std::vector<EricEvent::EventAction> EricProxyFilter::vec_proto_fw_action_ =
    EricProxyFilter::makeFwActionVector();

//---------------------------------------------------------------------------------------
// Constructor, Destructor, Callback-Setup
// Happens for every request

EricProxyFilter::EricProxyFilter(
    EricProxyFilterConfigSharedPtr config,
    const std::chrono::time_point<std::chrono::system_clock> config_updated_at,
    Random::RandomGenerator& random, const EricProxyStatsSharedPtr& stats,
    std::shared_ptr<AlarmNotifier> notifier)
    : config_(config), config_updated_at_(config_updated_at), random_(random),
      run_ctx_(RunContext(&config_->rootContext())), req_body_(), resp_body_(), stats_(stats),
      notifier_(*notifier) {
  routing_behaviour_str_.at(static_cast<int>(RoutingBehaviour::NOT_USED)) = "NOT_USED";
  routing_behaviour_str_.at(static_cast<int>(RoutingBehaviour::ROUND_ROBIN)) = "ROUND_ROBIN";
  routing_behaviour_str_.at(static_cast<int>(RoutingBehaviour::PREFERRED)) = "PREFERRED";
  routing_behaviour_str_.at(static_cast<int>(RoutingBehaviour::STRICT)) = "STRICT";
  routing_behaviour_str_.at(static_cast<int>(RoutingBehaviour::STRICT_DFP)) = "STRICT_DFP";
  routing_behaviour_str_.at(static_cast<int>(RoutingBehaviour::REMOTE_ROUND_ROBIN)) =
      "REMOTE_ROUND_ROBIN";
  routing_behaviour_str_.at(static_cast<int>(RoutingBehaviour::REMOTE_PREFERRED)) =
      "REMOTE_PREFERRED";

  /* Example for how to notify the sidecar of an AlarmEvent */
  // auto now = ::google::protobuf::util::TimeUtil::GetCurrentTime();
  // AlarmEvent event;
  // event.set_type(::envoy::extensions::filters::http::eric_proxy::v3::EricProxyAlarmEventType::NO_IPV4);
  // event.mutable_timestamp()->MergeFrom(now);
  // event.set_message("Dummy Alarm message");
  // auto json = MessageUtil::getJsonStringFromMessageOrError(event,/* pretty print */ false, /* set
  // primitive defaults */ true) ; ENVOY_LOG(debug,"####Notifier invoked ..");
  // notifier_.logAlarmEvent(json);
  // ENVOY_LOG(debug,"#### After access log write");
  
}

EricProxyFilter::~EricProxyFilter() = default;

void EricProxyFilter::onDestroy() {cleanup();}

void EricProxyFilter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
  run_ctx_.setDecoderCallbacks(&callbacks);
  req_body_.setCallbacks(&callbacks);
  resp_body_.setCallbacks(&callbacks);
}
void EricProxyFilter::setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks& callbacks) {
  encoder_callbacks_ = &callbacks;
}

//-------------------------------------------------------------------------------------------------
// Request processing

// Entry point for a request. Everything starts from here.
Http::FilterHeadersStatus EricProxyFilter::decodeHeaders(Http::RequestHeaderMap& headers,
                                                    bool end_stream) {
  ENVOY_STREAM_LOG(debug, "EricProxy filter '{}' invoked on request", *decoder_callbacks_,
                   config_->protoConfig().name());
  // Setting request headers in run_ctx here for providing access to
  // request headers in both request and response directions.
  run_ctx_.setReqOrRespHeaders(&headers);
  run_ctx_.setReqHeaders(&headers);
  // Remember that we're in the request direction and have to use decoder_callbacks_
  run_ctx_.setReqOrResp(ReqOrResp::Request);
  // Setting both the request and response body objects in run_ctx here for providing
  // access to request body object in both request and response directions and
  // to access response body object in response direction.
  run_ctx_.setRequestBody(&req_body_);
  run_ctx_.setResponseBody(&resp_body_);

  // We need to set body_ pointer to request body object in decode headers to allow request body
  // operations irrespective of whether the request is a header-only-request or it is a request
  // with body.
  body_ = &req_body_;

  // Populate Service Context from request
  populateServiceContext(run_ctx_, decoder_callbacks_);

  // Create a FilterState Object for General Proxy Context
  const Envoy::StreamInfo::FilterStateSharedPtr& filter_state =
              decoder_callbacks_->streamInfo().filterState();
  auto eric_proxy_state = std::make_unique<StreamInfo::EricProxyState>();
  eric_proxy_state->setEricRunContextPtr(&run_ctx_);
  filter_state->setData(StreamInfo::EricProxyState::key(), std::move(eric_proxy_state),
                                StreamInfo::FilterState::StateType::Mutable,
                                StreamInfo::FilterState::LifeSpan::Request);  
    
  // Populate request validation config for SCP and SEPP with request coming
  // from both own network and from roaming-partner in external network
  populateRequestValidationConfig(/* global config = */ true);

  // ULID(S63) Check if it is SEPP & request origin is external network
  if (config_->isSeppNode() && config_->isOriginExt()) {
    // Set originating_rp_name_ filter variable
    setOriginatingRpName();

    // Set rp_config_ filter variable
    setRpConfigFromRpName();

    // Populate request validation config for SEPP and request
    // originating from roaming-partner in external network
    populateRequestValidationConfig(/* global config = */ false);

    // Perform checks for unauthorized service operations in firewall.cc
    if (isUnauthorizedServiceOperation()) {
      if (processUnauthorizedServiceOperation()) {
        return Http::FilterHeadersStatus::StopIteration;
      }
    }

    // Perform checks for request headers in firewall.cc
    if (!checkHeaders()) {
      return Http::FilterHeadersStatus::StopIteration;
    }
  }

  // NfPeerInfo handling (indicating sender, receiver, and if indirect routing also
  // SCP/SEPP handling the message). See TS 29.500 R17 ch. 5.2.3.2.21
  if (config_->isNfPeerinfoActivated()) {
    // Store in dyn. metadata: original nf-peer-info header, own node type (scp/sepp),
    // own FQDN, and that nf-peer-info-handling is on and request-out-screening is off(?).
    // Data is used by the router code.
    // ULID(S49)
    SbiNfPeerInfoHeaderRequestMetadata::saveMetaData(config_->nodeTypeLc(), config_->ownFqdnLc(),
                                                     decoder_callbacks_,
                                                     *run_ctx_.getReqOrRespHeaders());
  }

  if (end_stream) {
    // If the HTTP/2 stream's end-flag is set, then it's a header-only-request without body.
    // Process it now:
    return processRequest();
  } else {
    // Body will follow. Remember the headers and stop filter-chain processing.
    // The body-processing in decodeData will call processRequest.
    // Set limits of max message bytes for request body
    setMaxRequestBytesLimit();
    return Http::FilterHeadersStatus::StopIteration;
  }
}

// If we need to inspect/modify the request body, we do it here.
Http::FilterDataStatus EricProxyFilter::decodeData(Buffer::Instance& data, bool end_stream) {
  ENVOY_STREAM_LOG(debug, "EricProxy filter '{}' invoked on request for body data",
                   *decoder_callbacks_, config_->protoConfig().name());
  // We need to buffer here because we are not using the buffer_filter
  decoder_callbacks_->addDecodedData(data, true);

  // Check max message bytes for request body.   ULID(A21)
  if (!checkMaxRequestBytes()) {
    // Remember for the response processing to only start in phase 6
    // and skip phase 4 and 5:
    response_start_phase_ = FCPhase::Screening6;
    return Http::FilterDataStatus::StopIterationNoBuffer;
  }

  if (end_stream) {
    // Body is complete -> process the request, then translate the result-code
    ENVOY_STREAM_LOG(trace, "Received Body with length: {}, body: '{}'", *decoder_callbacks_, decoder_callbacks_->decodingBuffer()->length(),
      decoder_callbacks_->decodingBuffer()->toString());

    body_->setBodyFromBuffer(decoder_callbacks_->decodingBuffer(), run_ctx_.getReqOrRespHeaders());
    run_ctx_.getReqOrRespHeaders()->setContentLength(decoder_callbacks_->decodingBuffer()->length());

    // Check JSON formats for request body
    if (!checkForConfiguredJsonFormat()) {
      // Remember for the response processing to only start in phase 6
      // and skip phase 4 and 5:
      response_start_phase_ = FCPhase::Screening6;
      return Http::FilterDataStatus::StopIterationNoBuffer;
    }

    // Checks passed, now process the request
    auto result = map_filter_to_data_status_.at(processRequest());
    return result;
  } else {
    // Body not complete yet
    return Http::FilterDataStatus::StopIterationAndBuffer;
  }
}

//-------------------------------------------------------------------------------------------------
// Response processing

// Entry point for a response.
Http::FilterHeadersStatus EricProxyFilter::encodeHeaders(Http::ResponseHeaderMap& headers,
                                                    bool end_stream) {
  ENVOY_STREAM_LOG(debug, "EricProxy filter '{}' invoked on response", *encoder_callbacks_,
                   config_->protoConfig().name());

  // Remember that we're in the response direction and have to use decoder_callbacks_
  run_ctx_.setReqOrResp(ReqOrResp::Response);
  // Setting response headers in run_ctx here for providing access to
  // response headers in response direction.
  run_ctx_.setReqOrRespHeaders(&headers);

  // We need to set body_ pointer to response body object in encode headers to allow response body operations
  // irrespective of whether the response is a header-only-response or it is a response with body.
  body_ = &resp_body_;

  // Populate response validation config for SCP and SEPP with response coming
  // from both own network and from roaming-partner in external network
  populateResponseValidationConfig(/* global config = */ true);

  // Check if it is SEPP & request origin is own network.
  // It means response origin is external network
  if (config_->isSeppNode() && config_->isOriginInt()) {
    // Populate response validation config for SEPP and response
    // originating from roaming-partner in external network
    populateResponseValidationConfig(/* global config = */ false);

    // Perform checks for response headers in firewall.cc
    if (!checkHeaders()) {
      return Http::FilterHeadersStatus::StopIteration;
    }
  }

  // NfPeerInfo handling
  // ULID(S50) 
  if (config_->isNfPeerinfoActivated()) {
    ENVOY_STREAM_LOG(trace, "Nf Peerinfo is activated", *encoder_callbacks_);
    std::unique_ptr<SbiNfPeerInfoInterface> sbi_nf_peer_info_pr;
    if (local_reply_) {
      ENVOY_STREAM_LOG(trace, "It's a local reply", *encoder_callbacks_);
      sbi_nf_peer_info_pr = std::make_unique<SbiNfPeerInfoHeaderLocalResponse>(
          encoder_callbacks_->streamInfo().dynamicMetadata());
    } else {
      ENVOY_STREAM_LOG(trace, "It's a standard reply", *encoder_callbacks_);
      sbi_nf_peer_info_pr = std::make_unique<SbiNfPeerInfoHeaderResponseMetadata>(
          encoder_callbacks_->streamInfo().dynamicMetadata());
    }

    sbi_nf_peer_info_pr->setOwnFqdn(config_->ownFqdnLc());
    sbi_nf_peer_info_pr->setNodeType(config_->nodeTypeLc());
    sbi_nf_peer_info_pr->setAll(headers);
  } else {
      ENVOY_STREAM_LOG(trace, "Nf Peerinfo is Deactivated", *encoder_callbacks_);
  }

  if (end_stream) {
    // If the HTTP/2 stream's end-flag is set, then it's a header-only-response without body.
    // Process it now:
    return processResponse();
  } else {
    // Body will follow. Remember the headers and stop filter-chain processing.
    // The body-processing in encodeData will call processResponse.
    // Set limits of max message bytes for response body
    setMaxResponseBytesLimit();
    return Http::FilterHeadersStatus::StopIteration;
  }
}

// If we need to inspect/modify the response body, we do it here.
Http::FilterDataStatus EricProxyFilter::encodeData(Buffer::Instance& data, bool end_stream) {
  ENVOY_STREAM_LOG(debug, "EricProxy filter '{}' invoked on response for body data",
                   *encoder_callbacks_, config_->protoConfig().name());
  // We need to buffer here because we are not using the buffer_filter
  // (From envoy/http/filter.h):
  // Add buffered body data. This method is used in advanced cases where returning
  // StopIterationAndBuffer from decodeData() is not sufficient.
  // [..]
  // 2) If a filter is going to look at all buffered data from within a data callback with end
  //    stream set, this method can be called to immediately buffer the data. This avoids having
  //    to deal with the existing buffered data and the data from the current callback.
  encoder_callbacks_->addEncodedData(data, true);

  // Check max message bytes for response body if not a local reply  ULID(A29)
  if (!local_reply_) {
    // Check max message bytes for response body
    if (!checkMaxResponseBytes()) {
      return Http::FilterDataStatus::StopIterationNoBuffer;
    }
  }

  if (end_stream) {
    // Body is complete -> process the response, then translate the result-code
    ENVOY_STREAM_LOG(trace, "Received Body with length: {}, body: '{}'", *encoder_callbacks_, encoder_callbacks_->encodingBuffer()->length(),
      encoder_callbacks_->encodingBuffer()->toString());

    body_->setBodyFromBuffer(encoder_callbacks_->encodingBuffer(), run_ctx_.getReqOrRespHeaders());
    run_ctx_.getReqOrRespHeaders()->setContentLength(encoder_callbacks_->encodingBuffer()->length());

    // Check JSON formats for response JSON body if not a local reply
    if (!local_reply_) {
      // Check JSON formats for response body
      if (!checkForConfiguredJsonFormat()) {
        return Http::FilterDataStatus::StopIterationNoBuffer;
      }
    }

    // Checks passed, now process the response
    auto result = map_filter_to_data_status_.at(processResponse());
    return result;
  } else {
    // Body not complete yet
    return Http::FilterDataStatus::StopIterationAndBuffer;
  }
}

//-------------------------------------------------------------------------------------------------
// The reason there is an onDestroy() method vs. doing this type of cleanup
// in the destructor is to avoid potential data races between an async
// callback and the destructor in case the connection terminates abruptly.
void EricProxyFilter::cleanup() {
  ENVOY_STREAM_LOG(debug, "EricProxy filter {} destroyed.", *decoder_callbacks_,
                   config_->protoConfig().name());
  if (lookup_request_ != nullptr) {
    ENVOY_STREAM_LOG(debug, "Cancelling lookup request.", *decoder_callbacks_);
    lookup_request_->cancel();
    lookup_request_ = nullptr;
    }
  }

//-------------------------------------------------------------------------------------------------
// Process a request. Called from decodeHeaders if it is a header-only request, or from
// decodeData if it is a request with header and body.
Http::FilterHeadersStatus EricProxyFilter::processRequest() {
  // Step the Ingress per RP Counters, Request Total
  if(originating_rp_name_.has_value()){
   stats_->incIngressRpRqTotal(originating_rp_name_.value());
  }
  ENVOY_STREAM_LOG(trace, "Filter_cases: {}", *decoder_callbacks_,
      config_->filterCases().size());
  ENVOY_STREAM_LOG(trace, "Original request headers: {}", *decoder_callbacks_,
                   logHeaders(*run_ctx_.getReqOrRespHeaders()));

  // Header indicating that the request has been processed in the eric-proxy filter.
  // This is used in the Envoy routing table (in the configuration loaded by the manager)
  // to determine if it's the first or second round through the Envoy routing table.
  run_ctx_.getReqOrRespHeaders()->addCopy(Envoy::Http::LowerCaseString("x-eric-proxy"), absl::string_view("///"));

  Http::FilterHeadersStatus return_value = Http::FilterHeadersStatus::Continue;

  ENVOY_STREAM_LOG(debug, "Finding start filter case(s) from FilterPhaseConfig(s)",
                    *decoder_callbacks_);
  return_value = processRequestFilterPhases();
  // Filter-cases have completed here

  // If the filter-chain execution continues (= not a reject or drop or SLF lookup),
  // then clear the cached route to make Envoy re-evaluate its routing decision.
  // If the route cache is cleared and sendLocalReply() is used, then Envoy will
  // crash.
  if (return_value != Http::FilterHeadersStatus::StopIteration) {
    if (return_value == Http::FilterHeadersStatus::Continue) {
      decoder_callbacks_->downstreamCallbacks()->clearRouteCache();
    }
  }

  if(body_->isModified()) {
    // A request body is already present in decoding buffer
    // Decode modified body into request
    if (decoder_callbacks_->decodingBuffer()) {
      decoder_callbacks_->modifyDecodingBuffer([&](auto& buffer) {
        buffer.drain(buffer.length());
        // add() copies the string (include/envoy/buffer/buffer.h)
        const auto& body_string = body_->getBodyAsString();
        buffer.add(absl::string_view(body_string));
        run_ctx_.getReqOrRespHeaders()->setContentLength(body_string.length());
        ENVOY_STREAM_LOG(trace, "new request body is set:{}", *decoder_callbacks_, body_string);
      });
    }
    // No request body is present in decoding buffer
    // Add decoded data to create a new request body
    else {
      const auto& body_string = body_->getBodyAsString();
      Buffer::OwnedImpl body(body_string);
      decoder_callbacks_->addDecodedData(body, true);
      run_ctx_.getReqOrRespHeaders()->setContentLength(body_string.length());
      ENVOY_STREAM_LOG(trace, "new request body is created:{}", *decoder_callbacks_, body_string);
    }
  }

  // Only print headers and metadata if we're not paused (e.g. due to SLF lookup):
  if (deferred_filter_case_ptr_ == nullptr && run_ctx_.getReqOrRespHeaders() != nullptr) {
    ENVOY_STREAM_LOG(debug, "Request headers: {}", *decoder_callbacks_,
                     logHeaders(*run_ctx_.getReqOrRespHeaders()));
    ENVOY_STREAM_LOG(trace, "Dyn. Metadata: {}", *decoder_callbacks_,
              decoder_callbacks_->streamInfo().dynamicMetadata().DebugString());
  }

  return return_value;
}

//-------------------------------------------------------------------------------------------------
// Process a response. Called from encodeHeaders if it is a header-only response, or from
// encodeData if it is a response with header and body.
Http::FilterHeadersStatus EricProxyFilter::processResponse() {
  ENVOY_STREAM_LOG(trace, "Filter_cases: {}", *decoder_callbacks_, config_->filterCases().size());
  ENVOY_STREAM_LOG(trace, "Original response headers:{}", *decoder_callbacks_,
                   logHeaders(*run_ctx_.getReqOrRespHeaders()));
  ENVOY_STREAM_LOG(trace, "Dyn. Metadata: {}", *decoder_callbacks_,
    encoder_callbacks_->streamInfo().dynamicMetadata().DebugString());

  if (internalRejected()) {
    // Set dyn-MD for the standard-result-code modification
    std::vector<std::string> keys({md_key_internal_rejected_, md_key_internal_rejected_by_});
    std::vector<std::string> values({"false", ""});
    setEncoderOrDecoderDynamicMetadata("eric_proxy", keys, values, false);
  }

  // Common SEPP and SCP

  // TS 29.500 R16.10 Clause 5.2.3.2.1
  // TS29.500 R16 ch 6.10.4:
  // If the SCP changed the target URI when forwarding the request from the HTTP client
  // to HTTP server and no "Location" header is included in the HTTP response (e.g.
  // subsequent service request towards a created resource), the SCP shall include a
  // "3gpp-Sbi-Target-apiRoot" header with value set to the apiRoot of the target HTTP
  // server when forwarding the HTTP response to the NF as HTTP client.
  // Did the request contain a TaR header (saved in original_tar_)? If not, it was not
  // a preferred-host routing, or topology-hiding is enabled -> in either case we don't
  // have to do anything here (Applies to SCP and SEPP because Ericsson SEPP has reselection
  // capabilities that enables it to add SCP reselection specific headers without violating
  // TS 29500):
  // ULID(S30)
  addTaRInResponse(encoder_callbacks_,run_ctx_.getReqOrRespHeaders());

  // ULID(S32)
  Http::FilterHeadersStatus return_value = Http::FilterHeadersStatus::Continue;

  ENVOY_STREAM_LOG(debug, "Finding start filter case(s) from FilterPhaseConfig(s)",
                    *decoder_callbacks_);
  return_value = processResponseFilterPhases();

  // Only print headers and metadata if we're not paused (e.g. due to SLF lookup):
  if (deferred_filter_case_ptr_ == nullptr) {
    if(return_value == Http::FilterHeadersStatus::StopIteration || run_ctx_.getReqOrRespHeaders() == nullptr) {
        ENVOY_STREAM_LOG(trace, "Not logging headers for direct replies in the response path",
            *decoder_callbacks_);
    }
    else {
      ENVOY_STREAM_LOG(debug, "Response headers:{}", *decoder_callbacks_,
                       logHeaders(*run_ctx_.getReqOrRespHeaders()));
    }
    ENVOY_STREAM_LOG(trace, "Dyn. Metadata:{}", *decoder_callbacks_,
          encoder_callbacks_->streamInfo().dynamicMetadata().DebugString());
  }

  // Step the ingress per-RP counters, response xx
  uint64_t response_code = Http::Utility::getResponseStatus(decoder_callbacks_->responseHeaders().value());
  if(originating_rp_name_.has_value()){
   stats_->incIngressRpRqXx(originating_rp_name_.value(), response_code);
  }

  if (body_->isModified()) {
    // A response body is already present in encoding buffer
    // Encoding modified body into response
    if (encoder_callbacks_->encodingBuffer()) {
      encoder_callbacks_->modifyEncodingBuffer([&](auto& buffer) {
        ENVOY_STREAM_LOG(trace, "modifyEncodingBuffer", *decoder_callbacks_);
        buffer.drain(buffer.length());
        // add() copies the string (include/envoy/buffer/buffer.h)
        const auto& body_string = body_->getBodyAsString();
        ENVOY_STREAM_LOG(trace, "new body: {}", *decoder_callbacks_, body_string);
        buffer.add(absl::string_view(body_string));
        // Minor guard for sanity check 
        if(!body_string.empty() ) {
          run_ctx_.getReqOrRespHeaders()->setContentLength(body_string.length());
          ENVOY_STREAM_LOG(trace, "new response body is set:{}", *decoder_callbacks_, body_string);
        }
      });
    }
    // No response body is present in encoding buffer
    // Adding encoded data to create a new response body
    else {
      ENVOY_STREAM_LOG(trace, "addEncodedData", *decoder_callbacks_);
      const auto& body_string = body_->getBodyAsString();
      ENVOY_STREAM_LOG(trace, "new body: {}", *decoder_callbacks_, body_string);
      Buffer::OwnedImpl body(body_string);
      encoder_callbacks_->addEncodedData(body, true);
      // Minor guard for sanity check 
      if(!body_string.empty()){
        run_ctx_.getReqOrRespHeaders()->setContentLength(body_string.length());
        ENVOY_STREAM_LOG(trace, "new response body is created:{}", *decoder_callbacks_, body_string);
      }
    }
  }
  // DND 60533 Remove Contenet Length header when 
  // Response Status code is 204
  if( run_ctx_.getReqOrRespHeaders() != nullptr && !local_reply_ &&
      Http::CodeUtility::is2xxNoContent(Http::Utility::getResponseStatus(
                *dynamic_cast<Http::ResponseHeaderMap*>(run_ctx_.getReqOrRespHeaders()))) && 
                run_ctx_.getReqOrRespHeaders()->ContentLength()) {
    run_ctx_.getReqOrRespHeaders()->removeContentLength();
  }
  return return_value;
}

//-------------------------------------------------------------------------------------------------

// Process the given filter-case. This function can jump (via action go-to) to
// another filter-case. This is handled inside the function, not by recursively
// calling this function (which would be possible but might lead to a stack overflow
// since enabling tail recursion in clang/llvm has other effects and is not
// possible)
// ProcessFcMode indicates if the given screening happens for
// user-defined message screening or SEPP Edge Screening
Http::FilterHeadersStatus EricProxyFilter::processFilterCase(ProcessFcMode fc_mode) {
  // Most actions result in continuing the filter chain:
  pfcstate_headers_changed_ = false;

  while (true) {
    switch (pfcstate_next_state_) {

    case FCState::StartFilterCase:
      // Navigate to that Filter-Case
      if (fc_mode == ProcessFcMode::Screening) {
        pfcstate_filter_case_ = config_->filterCaseByName(pfcstate_fc_name_);
      } else if (fc_mode == ProcessFcMode::TopologyHiding || fc_mode == ProcessFcMode::TopologyUnhiding) {
        pfcstate_filter_case_ = config_->getFilterCaseByNameForServiceCaseForRP(
            run_ctx_.getRoamingPartnerName(), service_case_name_, pfcstate_fc_name_,
            run_ctx_.isRequest(), (run_ctx_.isRequest()) ^ (config_->isOriginExt()));
      }

      if (pfcstate_filter_case_ == nullptr) {
        ENVOY_STREAM_LOG(warn, "Could not find-filter case in config: {}",
                         *decoder_callbacks_, pfcstate_fc_name_);
        return Http::FilterHeadersStatus::Continue;
      }
      //ENVOY_STREAM_LOG(trace, pfcstate_filter_case_->rulesAndFilterdataAsString(), *decoder_callbacks_);
      // Load first filter rule
      pfcstate_filter_rule_it_ = std::begin(pfcstate_filter_case_->filterRules());
      if (pfcstate_filter_rule_it_ == std::end(pfcstate_filter_case_->filterRules())) {
        ENVOY_STREAM_LOG(debug, "This filter case ({}) has no rules", *decoder_callbacks_, pfcstate_fc_name_);
        return Http::FilterHeadersStatus::Continue;
      } else {
        pfcstate_next_state_ = FCState::LoadFilterData;
      }
      break;

    case FCState::NextFilterRule: {
      auto pfcstate_filter_rule_it_current = pfcstate_filter_rule_it_;
      pfcstate_filter_rule_it_++;
      if (pfcstate_filter_rule_it_ == std::end(pfcstate_filter_case_->filterRules())) {
        ENVOY_STREAM_LOG(trace, "No more rules in filter-case: {}", *decoder_callbacks_, pfcstate_fc_name_);

        // We need to update the variables here just before exiting/returning from our filter.
        // This is for the case the last action updated a header, and a variable that depends
        // on that header is later used in a response filter rule
        // Only do it if Screening mode
        if (fc_mode == ProcessFcMode::Screening) {
          updateVariablesForFilterRule(pfcstate_filter_rule_it_current);
        }
        return Http::FilterHeadersStatus::Continue;
      } else {
        pfcstate_next_state_ = FCState::LoadFilterData;
      }
      break;
      }

    case FCState::LoadFilterData: {
      ENVOY_STREAM_LOG(debug, "Processing filter rule: {}", *decoder_callbacks_,
          (*pfcstate_filter_rule_it_)->name());
      // 8.1   Look up all the var_value_index in var_updated_by table in the run-context:
      // if all of the updated_by_rc values are equal to the current Filter-Case it
      // means that the variables are already up-to-date and we can proceed with step 8.2
      // 8.2.  Foreach id in filterdata_required: Execute the filter-data rule:
      updateVariablesForFilterRule(pfcstate_filter_rule_it_);

      // 8.3  Foreach header-value-index in header_value_indices_required:
      for (const auto& hdr_val_idx : (*pfcstate_filter_rule_it_)->headerValueIndicesRequired()) {
        // 8.3.1  Copy (= make absl::string_view of) the contents of the header whose name
        //  is found by looking up header_configmap_reverse with the header-value-index
        auto hdr_name = std::string(run_ctx_.rootContext()->headerName(hdr_val_idx));
        auto hdr = run_ctx_.getReqOrRespHeaders()->get(Envoy::Http::LowerCaseString(hdr_name));
        if (!hdr.empty()) {
          auto hdr_values = std::vector<absl::string_view>(hdr.size());
          for(size_t i = 0; i < hdr.size(); i++){
            hdr_values.at(i) = hdr[i]->value().getStringView();
          }
          run_ctx_.updateHeaderValue(hdr_val_idx, hdr_values, run_ctx_.getReqOrResp());
        }
      }

      ENVOY_STREAM_LOG(debug, "Variables:{}", *decoder_callbacks_, run_ctx_.debugStringVarValue());

      // Extract query parameters from url in path header
      // Get query parameter value indices for current filter rule, then find query
      // parameter names for each indices from root context and finally store the
      // extracted query parameter values for each indices in run context
      if (!(*pfcstate_filter_rule_it_)->queryParamValueIndicesRequired().empty()) {
        const auto& path_hdr = run_ctx_.getReqHeaders()->get(Http::LowerCaseString(":path"));
        if (!path_hdr.empty()) {
          const auto& path_str = path_hdr[0]->value().getStringView();
          const auto req_query_params = Http::Utility::QueryParamsMulti::parseAndDecodeQueryString(path_str);
          for (const auto& query_param_val_idx : (*pfcstate_filter_rule_it_)->queryParamValueIndicesRequired()) {
            auto query_param = run_ctx_.rootContext()->queryParamName(query_param_val_idx);
            const auto matched_param = req_query_params.getFirstValue(query_param.data());
            if (matched_param.has_value()) {
              run_ctx_.updateQueryParamValue(query_param_val_idx, matched_param.value());
            } else {
              ENVOY_STREAM_LOG(trace, "Did not find param {} in query", *decoder_callbacks_,
                               query_param);
            }
          }
        }
      }

      // 8.4  Execute the condition operator-tree
      if ((*pfcstate_filter_rule_it_)->compiledCondition() == nullptr) {
        ENVOY_STREAM_LOG(debug, "No condition in filter-rule {}", *decoder_callbacks_,
                  (*pfcstate_filter_rule_it_)->name());
        return Http::FilterHeadersStatus::Continue;
      }
      bool matches = (*pfcstate_filter_rule_it_)->compiledCondition()->eval(run_ctx_);
      // 8.5  If the result is “true”, execute the corresponding action
      ENVOY_STREAM_LOG(debug, "Condition match: {}", *decoder_callbacks_, matches);
      if (matches) {

        // Step the appropriate invocations counter
        if(fc_mode == ProcessFcMode::Screening) {
          incTotalInvocationsCounter();
        }
        // Load first action
        pfcstate_action_it_ = std::begin((*pfcstate_filter_rule_it_)->actions());
        pfcstate_next_state_ = FCState::ExecuteAction;
      } else {
        // NextFilterRule (the iterator is stepped in there)
        pfcstate_next_state_ = FCState::NextFilterRule;
      }
    } break;

    case FCState::LoadNextAction:
      pfcstate_action_it_++;
      if (pfcstate_action_it_ == std::end((*pfcstate_filter_rule_it_)->actions())) {
        pfcstate_next_state_ = FCState::NextFilterRule;
      } else {
        pfcstate_next_state_ = FCState::ExecuteAction;
      }
      break;

    case FCState::ExecuteAction: {
      auto [action_result, action_changed_headers, next_filter_case_name] =
          executeAction(**pfcstate_action_it_);
      switch (action_result) {
      case ActionResult::Next:
        pfcstate_next_state_ = FCState::LoadNextAction;
        pfcstate_headers_changed_ = action_changed_headers;
        break;
      case ActionResult::GotoFC:
        if (fc_mode == ProcessFcMode::TopologyHiding) {
          updateFailureTopologyHidingCounters();
        } else if (fc_mode == ProcessFcMode::TopologyUnhiding) {
          updateFailureTopologyUnhidingCounters();
        }
        updateVariablesForFilterRule(pfcstate_filter_rule_it_);
        pfcstate_fc_name_ = *next_filter_case_name;
        pfcstate_next_state_ = FCState::StartFilterCase;
        break;
      case ActionResult::Exit: // this lets the filter chain continue
        // We need to update the variables here just before exiting/returning from our filter.
        // This is for the case the last action updated a header, and a variable that depends
        // on that header is later used in a response filter rule
        updateVariablesForFilterRule(pfcstate_filter_rule_it_);
        return Http::FilterHeadersStatus::Continue;
        break;
      case ActionResult::StopIteration: // stops the filter chain
        return Http::FilterHeadersStatus::StopIteration;
        break;
      case ActionResult::PauseIteration: // pauses the filter chain
        // store the pointer to current processed filter case, needed in SLF lookup callbacks
        deferred_filter_case_ptr_ = pfcstate_filter_case_.get();
        // When execution is resumed, continue with the next filter rule:
        pfcstate_next_state_ = FCState::LoadNextAction;
        return Http::FilterHeadersStatus::StopIteration;
        break;
      }
    } break;

    default:
      ENVOY_STREAM_LOG(error, "Unknown next state {}", *decoder_callbacks_,
          static_cast<int>(pfcstate_next_state_));
      return Http::FilterHeadersStatus::Continue;
    }
  }
}

// Service Context Populated from request
// ULID(S41)
void EricProxyFilter::populateServiceContext(RunContext& run_ctx, Http::StreamDecoderFilterCallbacks* decoder_callbacks) {
  auto itr = run_ctx.getReqHeaders()->get(Http::LowerCaseString("3gpp-Sbi-Callback"));
  if (!itr.empty()) {
    // Its a notification request do standard extraction from getReqApi*
    const auto& api_name = getReqApiNameForSbaCb(itr[0]->value().getStringView());
    const auto& api_version = getReqApiVersionForSbaCb(itr[0]->value().getStringView());
    run_ctx.getServiceClassifierCtx().setApiName(api_name);
    run_ctx.getServiceClassifierCtx().setApiVersion(api_version);
    run_ctx.getServiceClassifierCtx().setIsNotify(true);
  } else {
    // Regular service request
    // Respect apiRoot/Deployment specific strings when determining api contexts
    // Lands on heap but optimized allocation with array than vectors 
    // as there is no need for fancy resize() calls in this situation 
    // which is completely of deterministic size
    std::array<re2::RE2::Arg,3> argv;
    std::array<re2::RE2::Arg*,3> args;
    std::array<re2::StringPiece,3> ws;
    for (int i = 0; i < 3; ++i) {
        args[i] = &argv[i];
        argv[i] = &ws[i];
    }
    // Strip Query part from the path
    auto path_hdr = Http::Utility::stripQueryString(run_ctx.getReqHeaders()->
                              get(Http::LowerCaseString(":path"))[0]->value());
    // RE2::PartialMatchN(path_hdr,config_->getApiContextsRE(),&(args[0]),3);
    //If api contexts belongs to regular service not nrf-bootstrapping ot nrf-ouath services
    if (RE2::PartialMatchN(path_hdr, run_ctx.rootContext()->getApiContextsRE(),&(args[0]),3)) {
      run_ctx.getServiceClassifierCtx().setApiName(std::string(ws[0]));
      run_ctx.getServiceClassifierCtx().setApiVersion(std::string(ws[1]));
      run_ctx.getServiceClassifierCtx().setResource(absl::StrCat("/",std::string(ws[2])));
    } else if (RE2::PartialMatchN(path_hdr, run_ctx.rootContext()->getBootstrapContextRE(),&(args[0]),1)) {
      run_ctx.getServiceClassifierCtx().setApiName("bootstrapping");
      run_ctx.getServiceClassifierCtx().setApiVersion("-"); // doesnt mean anything for bootstrapping
      run_ctx.getServiceClassifierCtx().setResource(absl::StrCat("/",std::string(ws[0])));
    } else if (RE2::PartialMatchN(path_hdr, run_ctx.rootContext()->getServiceTokenContextRE(),&(args[0]),1)) {
      //Api Context belongs to oauth/service tokens
      run_ctx.getServiceClassifierCtx().setApiName("oauth2");
      run_ctx.getServiceClassifierCtx().setApiVersion("-");
      run_ctx.getServiceClassifierCtx().setResource(absl::StrCat("/",std::string(ws[0])));
    }    
  }
  const auto& method_hdr = run_ctx.getReqHeaders()->get(Http::LowerCaseString(":method"));
  if (!method_hdr.empty()) {
    run_ctx.getServiceClassifierCtx().setMethod(std::string(method_hdr[0]->value().getStringView()));
  }
  if (decoder_callbacks) {
    ENVOY_STREAM_LOG(debug, "ApiName: '{}', ApiVersion: '{}', Resource: '{}'", *decoder_callbacks, 
      run_ctx.getServiceClassifierCtx().getApiName(), 
      run_ctx.getServiceClassifierCtx().getApiVersion(), 
      run_ctx.getServiceClassifierCtx().getResource()
    );
  } else {
    ENVOY_LOG(trace, "ApiName: '{}', ApiVersion: '{}', Resource: '{}'", 
      run_ctx.getServiceClassifierCtx().getApiName(), 
      run_ctx.getServiceClassifierCtx().getApiVersion(), 
      run_ctx.getServiceClassifierCtx().getResource()
    );
  }
}

// Common code to update variables for the current or next filter rule
void EricProxyFilter::updateVariablesForFilterRule(std::vector<std::shared_ptr<FilterRuleWrapper>>::const_iterator pfcstate_filter_rule_iterator){
  if (pfcstate_headers_changed_ || !areVariablesUpdatedByFc(pfcstate_filter_case_)) {
    for (const auto& filter_data_weak : (*pfcstate_filter_rule_iterator)->filterdataRequired()) {
      if (std::shared_ptr<FilterDataWrapper> filter_data{filter_data_weak.lock()}) {
        ENVOY_STREAM_LOG(debug, "Processing filter data: {} for filter rule: {}",
            *decoder_callbacks_, filter_data->name(), (*pfcstate_filter_rule_iterator)->name());
        updateVariables(pfcstate_filter_case_, filter_data);
        pfcstate_headers_changed_ = false;
      }
    }
  }
}

// Update Topology Hiding/Unhiding Counters
void EricProxyFilter::updateSuccessTopologyHidingCounters() {
  if (!run_ctx_.stringModifierContext()) {
    return;
  }
  if (run_ctx_.stringModifierContext()->getMappingUnsuccessfulFilterCase().empty()) {
    if (run_ctx_.stringModifierContext()->isMappingSuccess()) {
      updateFqdnMappingCounters(true, EricProxyStats::FqdnCase::Success);
    }
    if (run_ctx_.stringModifierContext()->isMappingForwardedUnmodified()) {
      updateFqdnMappingCounters(true, EricProxyStats::FqdnCase::DoNothing);
    }
  }
  if (run_ctx_.stringModifierContext()->getScramblingUnsuccessfulFilterCase().empty()) {
    if (!run_ctx_.stringModifierContext()->getScramblingSuccess().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingSuccess()) {
        updateFqdnScramblingCounters(true, EricProxyStats::FqdnCase::Success, encryption_id);
      }
    }
    if (!run_ctx_.stringModifierContext()->getScramblingForwardedUnmodifiedFqdn().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingForwardedUnmodifiedFqdn()) {
        updateFqdnScramblingCounters(true, EricProxyStats::FqdnCase::ForwardedUnmodifiedFqdn, encryption_id);
      }
    }
    if (!run_ctx_.stringModifierContext()->getScramblingForwardedUnmodifiedIp().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingForwardedUnmodifiedIp()) {
        updateFqdnScramblingCounters(true, EricProxyStats::FqdnCase::ForwardedUnmodifiedIp, encryption_id);
      }
    }
    if (!run_ctx_.stringModifierContext()->getScramblingInvalidFqdn().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingInvalidFqdn()) {
        updateFqdnScramblingCounters(true, EricProxyStats::FqdnCase::InvalidFqdn, encryption_id);
      }
    }
    if (!run_ctx_.stringModifierContext()->getScramblingEncryptionIdNotFound().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingEncryptionIdNotFound()) {
        updateFqdnScramblingCounters(true, EricProxyStats::FqdnCase::EncryptionIdNotFound, encryption_id);
      }
    }
    if (!run_ctx_.stringModifierContext()->getScramblingIncorrectEncryptionId().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingIncorrectEncryptionId()) {
        updateFqdnScramblingCounters(true, EricProxyStats::FqdnCase::IncorrectEncryptionId, encryption_id);
      }
    }
  }
}

void EricProxyFilter::updateSuccessTopologyUnhidingCounters() {
  if (!run_ctx_.stringModifierContext()) {
    return;
  }
  if (run_ctx_.stringModifierContext()->getMappingUnsuccessfulFilterCase().empty()) {
    if (run_ctx_.stringModifierContext()->isMappingSuccess()) {
      updateFqdnMappingCounters(false, EricProxyStats::FqdnCase::Success);
    }
    if (run_ctx_.stringModifierContext()->isMappingForwardedUnmodified()) {
      updateFqdnMappingCounters(false, EricProxyStats::FqdnCase::DoNothing);
    }
  }
  if (run_ctx_.stringModifierContext()->getScramblingUnsuccessfulFilterCase().empty()) {
    if (!run_ctx_.stringModifierContext()->getScramblingSuccess().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingSuccess()) {
        updateFqdnScramblingCounters(false, EricProxyStats::FqdnCase::Success, encryption_id);
      }
    }
    if (!run_ctx_.stringModifierContext()->getScramblingForwardedUnmodifiedFqdn().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingForwardedUnmodifiedFqdn()) {
        updateFqdnScramblingCounters(false, EricProxyStats::FqdnCase::ForwardedUnmodifiedFqdn, encryption_id);
      }
    }
    if (!run_ctx_.stringModifierContext()->getScramblingForwardedUnmodifiedIp().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingForwardedUnmodifiedIp()) {
        updateFqdnScramblingCounters(false, EricProxyStats::FqdnCase::ForwardedUnmodifiedIp, encryption_id);
      }
    }
    if (!run_ctx_.stringModifierContext()->getScramblingInvalidFqdn().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingInvalidFqdn()) {
        updateFqdnScramblingCounters(false, EricProxyStats::FqdnCase::InvalidFqdn, encryption_id);
      }
    }
    if (!run_ctx_.stringModifierContext()->getScramblingEncryptionIdNotFound().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingEncryptionIdNotFound()) {
        updateFqdnScramblingCounters(false, EricProxyStats::FqdnCase::EncryptionIdNotFound, encryption_id);
      }
    }
    if (!run_ctx_.stringModifierContext()->getScramblingIncorrectEncryptionId().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingIncorrectEncryptionId()) {
        updateFqdnScramblingCounters(false, EricProxyStats::FqdnCase::IncorrectEncryptionId, encryption_id);
      }
    }
  }
}

void EricProxyFilter::updateFailureTopologyHidingCounters() {
  if (!run_ctx_.stringModifierContext()) {
    return;
  }
  if (!run_ctx_.stringModifierContext()->getMappingUnsuccessfulFilterCase().empty()) {
    updateFqdnMappingCounters(true, EricProxyStats::FqdnCase::Failure);
  }
  if (!run_ctx_.stringModifierContext()->getScramblingUnsuccessfulFilterCase().empty()) {
    if (!run_ctx_.stringModifierContext()->getScramblingInvalidFqdn().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingInvalidFqdn()) {
        updateFqdnScramblingCounters(true, EricProxyStats::FqdnCase::InvalidFqdn, encryption_id);
      }
    }
    if (!run_ctx_.stringModifierContext()->getScramblingEncryptionIdNotFound().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingEncryptionIdNotFound()) {
        updateFqdnScramblingCounters(true, EricProxyStats::FqdnCase::EncryptionIdNotFound, encryption_id);
      }
    }
    if (!run_ctx_.stringModifierContext()->getScramblingIncorrectEncryptionId().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingIncorrectEncryptionId()) {
        updateFqdnScramblingCounters(true, EricProxyStats::FqdnCase::IncorrectEncryptionId, encryption_id);
      }
    }
  }
}

void EricProxyFilter::updateFailureTopologyUnhidingCounters() {
  if (!run_ctx_.stringModifierContext()) {
    return;
  }
  if (!run_ctx_.stringModifierContext()->getMappingUnsuccessfulFilterCase().empty()) {
    updateFqdnMappingCounters(false, EricProxyStats::FqdnCase::Failure);
  }
  if (!run_ctx_.stringModifierContext()->getScramblingUnsuccessfulFilterCase().empty()) {
    if (!run_ctx_.stringModifierContext()->getScramblingInvalidFqdn().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingInvalidFqdn()) {
        updateFqdnScramblingCounters(false, EricProxyStats::FqdnCase::InvalidFqdn, encryption_id);
      }
    }
    if (!run_ctx_.stringModifierContext()->getScramblingEncryptionIdNotFound().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingEncryptionIdNotFound()) {
        updateFqdnScramblingCounters(false, EricProxyStats::FqdnCase::EncryptionIdNotFound, encryption_id);
      }
    }
    if (!run_ctx_.stringModifierContext()->getScramblingIncorrectEncryptionId().empty()) {
      for (const auto& encryption_id : run_ctx_.stringModifierContext()->getScramblingIncorrectEncryptionId()) {
        updateFqdnScramblingCounters(false, EricProxyStats::FqdnCase::IncorrectEncryptionId, encryption_id);
      }
    }
  }
}

void EricProxyFilter::updateFqdnMappingCounters(
  const bool& is_mapping, const EricProxyStats::FqdnCase& fqdn_case
) {
  stats_->buildFqdnMappingCounters(
    rp_name_topology_hiding_.value_or("unknown_rp"),
    run_ctx_.getServiceClassifierCtx().getApiName(),
    stats_->getOrigin(config_->isOriginInt()), run_ctx_.getReqOrResp(),
    is_mapping, fqdn_case
  ).inc();
}

void EricProxyFilter::updateFqdnScramblingCounters(
  const bool& is_scrambling, const EricProxyStats::FqdnCase& fqdn_case,
  const std::string& encryption_id
) {
  stats_->buildFqdnScramblingCounters(
    rp_name_topology_hiding_.value_or("unknown_rp"),
    run_ctx_.getServiceClassifierCtx().getApiName(),
    stats_->getOrigin(config_->isOriginInt()), run_ctx_.getReqOrResp(),
    is_scrambling, fqdn_case, encryption_id
  ).inc();
}

/**
 * Continue processing the request after the SLF lookup result arrived.
 * Sets pcfstate variables according to a deferred lookup result and
 * triggers continuation of paused filter case processing *
 */
void EricProxyFilter::continueProcessingAfterSlfResponse() {
  ENVOY_STREAM_LOG(debug, "Continue processing after lookup result arrived", *decoder_callbacks_);

  if (deferred_filter_case_ptr_ != nullptr) {
    pfcstate_fc_name_ = deferred_filter_case_ptr_->name();
    auto [action_result, action_changed_headers, next_filter_case_name] = deferred_lookup_result_;
    switch (action_result) {
    case ActionResult::Next:
      pfcstate_next_state_ = FCState::LoadNextAction;
      pfcstate_headers_changed_ = action_changed_headers;
      break;
    case ActionResult::GotoFC:
      pfcstate_fc_name_ = *next_filter_case_name;
      pfcstate_next_state_ = FCState::StartFilterCase;
      break;
    case ActionResult::StopIteration:
      deferred_filter_case_ptr_ = nullptr;
      // Nothing of the code until the end of this function is needed if we are here
      return;
    default:
      ENVOY_STREAM_LOG(error, "Unknown next state: {}", *decoder_callbacks_, static_cast<int>(pfcstate_next_state_));
    }
  }
  auto result = processFilterCase(ProcessFcMode::Screening);
  deferred_filter_case_ptr_ = nullptr;

  if (result != Http::FilterHeadersStatus::StopIteration) {
    // Perform egress-screening (= out-request-screening) if configured:
    result = processOutRequestScreening();
  }

  // Only print headers and metadata if we're not paused (e.g. due to SLF lookup):
  if (run_ctx_.getReqOrRespHeaders() != nullptr) {
    ENVOY_STREAM_LOG(debug, "Headers:{}", *decoder_callbacks_, logHeaders(*run_ctx_.getReqOrRespHeaders()));

    ENVOY_STREAM_LOG(trace, "Dyn. Metadata: {}", *decoder_callbacks_,
              decoder_callbacks_->streamInfo().dynamicMetadata().DebugString());
  }

  if (result == Http::FilterHeadersStatus::Continue) {
    // Clear the route-cache to make Envoy re-evaluate the routing rules.
    // We are not reaching this line if action-reject-message or action-drop-message
    // is invoked, so it's safe to clear the cached route.
    decoder_callbacks_->downstreamCallbacks()->clearRouteCache();
    decoder_callbacks_->continueDecoding();
  }
  // else nothing because iteration is already stopped
};


// Execute a single action and return how the exection will continue:
// - If this action is terminal, execution does not process and the filter ends
// - If this action is a go-to, then continue with the configured filter-case
// - All other actions (non-terminal, non-control-flow) will continue with the next one
ActionResultTuple EricProxyFilter::executeAction(const FilterActionWrapper& action) {
  ENVOY_STREAM_LOG(trace, "Execute next action", *decoder_callbacks_);
  //----- Header Actions ------------------------------------------------------------
  // Add Header (actions_header.cc)
  if (action.protoConfig().has_action_add_header()) {
    return actionAddHeader(dynamic_cast<const ActionAddHeaderWrapper&>(action));
  }

  // Remove Header (actions_header.cc)
  if (action.protoConfig().has_action_remove_header()) {
    return actionRemoveHeader(action);
  }

  // Modify Header (actions_header.cc)
  if (action.protoConfig().has_action_modify_header()) {
    return actionModifyHeader(dynamic_cast<const ActionModifyHeaderWrapper&>(action));
  }

  //----- Body Actions ---------------------------------------------------------------
  // Modify Body (actions_json_body.cc)
  if (action.protoConfig().has_action_modify_json_body()) {
    return actionModifyJsonBody(dynamic_cast<const ActionModifyJsonBodyWrapper&>(action));
  }

  // Create Body (actions_body.cc)
  if (action.protoConfig().has_action_create_body()) {
    return actionCreateBody(action);
  }

  //------ Query Param Actions -------------------------------------------------------
  // Modify Query Param
  if (action.protoConfig().has_action_modify_query_param()) {
    return actionModifyQueryParam(dynamic_cast<const ActionModifyQueryParamWrapper&>(action));
  }

  // Remove Query Param
  if (action.protoConfig().has_action_remove_query_param()) {
    return actionRemoveQueryParam(action);
  }

  //----- Lookup Actions -------------------------------------------------------------
  // Perform an SLF lookup to get the region for a SUPI (actions_lookup.cc)
  // DND-30048 Updated requirements on Nnrf interface demands Nslf lookup to
  // have requester and target nf-types in query string
  if (action.protoConfig().has_action_slf_lookup()) {
    //auto nslf_api_root = (*pfcstate_filter_rule_it_)->getNSlfApiRoot();
    return actionSlfLookup(dynamic_cast<const ActionSlfLookupWrapper&>(action));
  }

  //----- Discovery Actions -----------------------------------------------------------
  // Perform a delegated discovery (Option D) at the NRF (through the NLF).
  if (action.protoConfig().has_action_nf_discovery()) {
    return actionNfDiscovery(dynamic_cast<const ActionNfDiscoveryWrapper&>(action));
  }

  //----- Misc Actions ----------------------------------------------------------------
  // Write a log message to Envoy's log (actions_log.cc)
  if (action.protoConfig().has_action_log()) {
    return actionLog(dynamic_cast<const ActionLogWrapper&>(action));
  }

  // Report an event message to Envoy's log (actions_log.cc)
  if (action.protoConfig().has_action_report_event()) {
    return actionReportEvent(dynamic_cast<const ActionReportEventWrapper&>(action));
  }

  // Change a variable value (actions_misc.cc)
  if (action.protoConfig().has_action_modify_variable()) {
    return actionModifyVariable(dynamic_cast<const ActionModifyVariableWrapper&>(action));
  }

  //----- Control-Flow Actions --------------------------------------------------------
  // Go-To another Filter-Case (actions_misc.cc)
  if (!action.protoConfig().action_goto_filter_case().empty()) {
    return actionGotoFilterCase(action);
  }

  // Exit the filter case and go to the next filter (actions_misc.cc)
  if (action.protoConfig().action_exit_filter_case()) {
    return actionExitFilterCase();
  }

  //----- Terminal Actions ------------------------------------------------------------
  // Reject the request (send a direct response) (actions_misc.cc)
  if (action.protoConfig().has_action_reject_message()) {
    incRejectCounter();
    return actionRejectMessage(action);
  }

  // Modify the status code and body of a response (basically reject in the
  // response path) (actions_misc.cc)
  if (action.protoConfig().has_action_modify_status_code()) {
    return actionModifyStatusCode(action);
  }

  // Drop message by sending a HTTP2 RESET_STREAM frame (actions_misc.cc)
  if (action.protoConfig().action_drop_message()) {
    incDropCounter();
    return actionDropMessage();
  }

  // Route To Pool (actions_routing.cc)
  if (action.protoConfig().has_action_route_to_pool()) {
    return actionRouteToPool(dynamic_cast<const ActionRouteToPoolWrapper&>(action));
  }

  // Route To Roaming Partner (actions_routing.cc)
  if (action.protoConfig().has_action_route_to_roaming_partner()) {
    return actionRouteToRoamingPartner(dynamic_cast<const ActionRouteToRoamingPartnerWrapper&>(action));
  }

  // Error: we should not reach this point
  // Exit the filter-case and go to the next filter in the chain
  ENVOY_STREAM_LOG(error, "Unknown action", *decoder_callbacks_);
  return std::make_tuple(ActionResult::Exit, false, std::nullopt);
}

//------ Start-Filter-Case Processing ------------------------------------
// Return the start-filter-case(s) for in-request screening (phase 1)
std::vector<std::string> EricProxyFilter::getAllStartFcForInRequestScreening() {
  if (config_->isOriginExt()) { // origin is from external network
    if (originating_rp_name_) { // origin is from external network + roaming partner
      // Do we have a dedicated screening case for this roaming-partner?
      auto fc_list_it = config_->fp_in_req_screening_->ext_nw_per_rp_fc_.find(originating_rp_name_.value());
      if (fc_list_it != config_->fp_in_req_screening_->ext_nw_per_rp_fc_.end()) {
        return fc_list_it->second;
      }
      // No dedicated screening-case for this RP found -> use default screening case
      return config_->fp_in_req_screening_->ext_nw_fc_default_;
    } else { // origin is from ext. nw, but no RP present
      // This is usually when the request comes in through the non-TLS port
      // Return the default screening case for ext. nw.
      return config_->fp_in_req_screening_->ext_nw_fc_default_;
    }
  } else if (config_->isOriginControlPlane()) {
    // origin is control plane and this is an n32c handshake
    // request where no p1 screening is performed.
    return {};
  } else {
    // origin is from own/internal network
    return config_->fp_in_req_screening_->own_nw_fc_;
  }
}

// Return the start-filter-case(s) for out-response screening (phase 6)
std::vector<std::string> EricProxyFilter::getAllStartFcForOutResponseScreening() {
  if (config_->isOriginExt()) { // origin is from external network
    if (originating_rp_name_) { // origin is from external network + roaming partner
      // Do we have a dedicated screening case for this roaming-partner?
      auto fc_list_it = config_->fp_out_resp_screening_->ext_nw_per_rp_fc_.find(originating_rp_name_.value());
      if (fc_list_it != config_->fp_out_resp_screening_->ext_nw_per_rp_fc_.end()) {
        return fc_list_it->second;
      }
      // No dedicated screening-case for this RP found -> use default screening case
      return config_->fp_out_resp_screening_->ext_nw_fc_default_;
    } else { // origin is from ext. nw, but no RP present
      // This is usually when the request comes in through the non-TLS port
      // Return the default screening case for ext. nw.
      return config_->fp_out_resp_screening_->ext_nw_fc_default_;
    }
  } else if (config_->isOriginControlPlane()) {
    // origin is control plane and this is an n32c handshake response where no p6 screening is
    // performed.
    return {};
  } else {
    // origin is from own/internal network
    return config_->fp_out_resp_screening_->own_nw_fc_;
  }
}

// Return the (one and only) start-filter-case for routing (phase 2)
absl::optional<std::string> EricProxyFilter::getStartFcForRouting() {
  if (config_->isOriginExt()) { // origin is from external network
    if (originating_rp_name_) { // origin is from external network + roaming partner
      auto fc_list_it = config_->fp_routing_->ext_nw_per_rp_fc_.find(originating_rp_name_.value());
      if (fc_list_it != config_->fp_routing_->ext_nw_per_rp_fc_.end()) {
        if (fc_list_it->second.empty()) {
          ENVOY_STREAM_LOG(warn, "No routing case found for request originating in external network from roaming-partner '{}'", *decoder_callbacks_, originating_rp_name_.value());
          return {};
        }
        return fc_list_it->second.at(0);
      }
      // No dedicated routing-case for this RP found -> use default routing case
      if (config_->fp_routing_->ext_nw_fc_default_.empty()) {
        ENVOY_STREAM_LOG(warn, "No routing case found for request originating in external network from roaming-partner '{}'", *decoder_callbacks_, originating_rp_name_.value());
        return {};
      }
      return config_->fp_routing_->ext_nw_fc_default_.at(0);
    } else { // origin is from ext. nw, but no RP present
      // This is usually when the request comes in through the non-TLS port
      // Return the default routing case
      if (config_->fp_routing_->ext_nw_fc_default_.empty()) {
        ENVOY_STREAM_LOG(warn, "No routing case found for request originating in external network", *decoder_callbacks_);
        return {};
      }
      return config_->fp_routing_->ext_nw_fc_default_.at(0);
    }
  } else if (config_->isOriginControlPlane()) {
    // origin is control plane and this is an n32c hancshake originating from the manager. No
    // routing is performed by eric_proxy
    return {};
  } else { // origin is from own/internal network
    if (config_->fp_routing_->own_nw_fc_.empty()) {
      ENVOY_STREAM_LOG(warn, "No routing case found for request originating in own network",
                       *decoder_callbacks_);
      return {};
    }
    return config_->fp_routing_->own_nw_fc_.at(0);
  }
}

// Return the start-filter-case for out-request-screening phase 3
// Given the name of the pool that we'll be routing to (pool_name_ is a copy of
// what is stored in the "x-cluster" header minus a possible suffix that starts
// with "#!_#"), find the egress screening cases
// per pool names which don't have the suffixes.
std::vector<std::string> EricProxyFilter::getAllStartFcForOutRequestScreening() {
  if (!config_->fp_out_req_screening_->cluster_fc_.empty()) {
    // This caters to the n32c initiating sepp scenario. Said requests originating from the manager
    // come with an x-cluster header However the filter configuration for the n32c listener does not
    // containg routing and pool_name_ is not set. Check if the x-cluster is present and if it is,
    // populate pool_name_ to be used by inResponseScreening and continue with outRequestScreening
    // as usual
    if (!pool_name_.has_value() && !run_ctx_.getReqHeaders()->get(Http::LowerCaseString("x-cluster")).empty()) {
      setClusterName(std::string(
          run_ctx_.getReqHeaders()->get(Http::LowerCaseString("x-cluster"))[0]->value().getStringView()));
    }

    if (pool_name_) {
      ENVOY_STREAM_LOG(trace, "Applying egress screening for pool '{}'", *decoder_callbacks_,
                       pool_name_.value());
      auto fc_list_it = config_->fp_out_req_screening_->cluster_fc_.find(pool_name_.value());
      if (fc_list_it != config_->fp_out_req_screening_->cluster_fc_.end()) {
        return fc_list_it->second;
      } else {
        ENVOY_STREAM_LOG(trace, "No out-request screening-case found for pool '{}'",
                         *decoder_callbacks_, pool_name_.value());
        return {};
      }
    }
    ENVOY_STREAM_LOG(
        debug, "Routing didn't set pool/cluster name -> cannot find an out-request screening-case",
        *decoder_callbacks_);
    return {};
  }
  ENVOY_STREAM_LOG(debug, "No out-request screening-cases have been configured",
                   *decoder_callbacks_);
  return {};
}

// Return the start-filter-case for in-response-screening phase 4
// We use the pool name to which the request was routed to find the in-response
// screening case(s).
std::vector<std::string> EricProxyFilter::getAllStartFcForInResponseScreening() {
  if (pool_name_ && !config_->fp_in_resp_screening_->cluster_fc_.empty()) {
    ENVOY_STREAM_LOG(trace, "Applying in-response screening for pool '{}'", *decoder_callbacks_,
        pool_name_.value());
    auto fc_list_it = config_->fp_in_resp_screening_->cluster_fc_.find(pool_name_.value());
    if (fc_list_it != config_->fp_in_resp_screening_->cluster_fc_.end()) {
      return fc_list_it->second;
    } else {
      ENVOY_STREAM_LOG(trace, "No in-response screening-case found for pool '{}'", *decoder_callbacks_, pool_name_.value());
      return {};
    }
  } else {
    ENVOY_STREAM_LOG(debug,
                     "Routing didn't set pool/cluster name or no in-response screening-cases have "
                     "been configured -> cannot find an in-response screening-case",
                     *decoder_callbacks_);
    return {};
  }
}

//------------------------------------------------------------------------
void EricProxyFilter::copyRouteMdToDynamicMd(){
  if (!isRouteMetadataPresent()){
    // No route metadata found, nothing to copy
    return;
  }

  ENVOY_STREAM_LOG(trace, "Copying route metadata to dynamic metadata", *decoder_callbacks_);
  const auto route = decoder_callbacks_->route().get();
  //const auto& routeEntry = route->routeEntry();
  //const auto& metadata = routeEntry->metadata();
  const auto& metadata = route->metadata();
  const auto& md = metadata.filter_metadata();

  const auto& eric_proxy_route_md = md.find(filter_name_)->second;

  decoder_callbacks_->streamInfo().setDynamicMetadata(dyn_md_filtercases_namespace_, eric_proxy_route_md);
  ENVOY_STREAM_LOG(trace, "Dyn. Metadata: {}", *decoder_callbacks_,
    decoder_callbacks_->streamInfo().dynamicMetadata().DebugString());
}

// FIXME(eedala): remove this function and use getRouteMetadata() instead. First check if the last if() in this function is needed in the other one as well (it's missing there):
bool EricProxyFilter::isRouteMetadataPresent(){
  const auto route = decoder_callbacks_->route().get();
  if (route == nullptr) {
    ENVOY_STREAM_LOG(debug, "No route found, cannot read metadata", *decoder_callbacks_);
    return false;
  }
  // const auto& routeEntry = route->routeEntry();
  // if (routeEntry == nullptr) {
  //   ENVOY_STREAM_LOG(debug, "No routeEntry found (could be a direct response)", *decoder_callbacks_);
  //   return false;
  // }
  //const auto& metadata = routeEntry->metadata();
  const auto& metadata = route->metadata();
  if (!metadata.IsInitialized()) {
    ENVOY_STREAM_LOG(debug, "Route metadata is not initialized", *decoder_callbacks_);
    return false;
  }
  const auto& md = metadata.filter_metadata();

  if (!md.contains(filter_name_)){
    ENVOY_STREAM_LOG(debug, "No route metadata found in namespace: {}", *decoder_callbacks_,
        filter_name_);
    return false;
  }
  return true;
}

//  Returns true if the given authority includes a T-FQDN.
//  This should be the case if the host part ends with our own FQDN.
bool  EricProxyFilter::isTFqdnInAuthority(std::string authority){
  std::string own_fqdn_suffix = "." + config_->ownFqdnLc();
  // use Utility::parseAuthority to cater for optional port
  const auto host_attributes = Http::Utility::parseAuthority(authority);
  const auto host = host_attributes.host_;
  return (absl::EndsWith(host, own_fqdn_suffix));
}

bool EricProxyFilter::isPTFqdnInAuthority(std::string authority, std::string pseudo_fqdn){
  // use Utility::parseAuthority to cater for optional port
  const auto& host_attributes = Http::Utility::parseAuthority(authority);
  const auto& host = host_attributes.host_;
  return absl::StrContains(absl::AsciiStrToLower(host), absl::AsciiStrToLower(pseudo_fqdn));
}

// Find and replace the FQDN with the T-FQDN in an NRF Discovery Response
void EricProxyFilter::modifyTfqdnInNfDiscoveryResponse() {
  const auto json_body = body_->getBodyAsJson();
  if (!json_body || !body_->isBodyPresent()) {
    ENVOY_STREAM_LOG(debug, "Cannot parse JSON body. No TFQDN created.", *decoder_callbacks_);
    return;
  }

  ENVOY_STREAM_LOG(trace, "json_body: {}", *decoder_callbacks_, json_body->dump());

  const auto numOfNfInstances =
      json_body->contains("nfInstances") ? json_body->at("nfInstances").size() : 0;
  // Shortcut if there is nothing to do (the loop would skip, but this way we get A) a better
  // log message and B) don't overwrite the body_ with a copy of itself
  if (numOfNfInstances == 0) {
    ENVOY_STREAM_LOG(debug, "No nfInstances found in body, not creating any T-FQDN.",
        *decoder_callbacks_);
    return;
  }
  ENVOY_STREAM_LOG(debug, "Number of nfInstances found: {}", *decoder_callbacks_, numOfNfInstances);

  for (unsigned long nf_inst_idx = 0; nf_inst_idx < numOfNfInstances; nf_inst_idx++) {
    //DND-44546: T-FQDN encoding is not done for nfServiceList
    if (json_body->at("nfInstances").at(nf_inst_idx).contains("nfServiceList")) {
      ENVOY_STREAM_LOG(debug, "nfInstances[{}] contains nfServiceList", *decoder_callbacks_,
                       nf_inst_idx);

      for (auto& nf_svc :
           json_body->at("nfInstances").at(nf_inst_idx).at("nfServiceList").items()) {
        ENVOY_STREAM_LOG(trace, "nfInstances[{}].nfServiceList.nfServiceId='{}' ",
                         *decoder_callbacks_, nf_inst_idx, nf_svc.key());
        modifyTfqdnInNfDiscoveryResponseNfInstNfService(
            json_body->at("nfInstances").at(nf_inst_idx), nf_svc.value());
      }
    }
    // we should receive either nfServiceList or nfServices (deprecated)
    // but we will apply T-FQDN handling in both structures, if present
    if (json_body->at("nfInstances").at(nf_inst_idx).contains("nfServices")) {
      const auto numOfNfServices =
          json_body->at("nfInstances").at(nf_inst_idx)["nfServices"].size();
      ENVOY_STREAM_LOG(debug, "nfInstances[{}] contains {} nfServices", *decoder_callbacks_,
                       nf_inst_idx, numOfNfServices);
      auto svc_idx = 0;
      for (auto& nf_svc : json_body->at("nfInstances").at(nf_inst_idx).at("nfServices")) {
        ENVOY_STREAM_LOG(trace, "nfInstances[{}].nfServices[{}] ", *decoder_callbacks_, nf_inst_idx,
                         svc_idx);
        modifyTfqdnInNfDiscoveryResponseNfInstNfService(
            json_body->at("nfInstances").at(nf_inst_idx), nf_svc);
        svc_idx++;
      }
    }
  }
  body_->setBodyFromJson(json_body);
  ENVOY_STREAM_LOG(debug, "T-FQDN(s) created. Body is now: '{}'", *decoder_callbacks_,
      body_->getBodyAsString());
}

void EricProxyFilter::modifyTfqdnInNfDiscoveryResponseNfInstNfService(const Json& nf_inst, Json& nf_service) {
  ENVOY_STREAM_LOG(trace, "modifyTfqdnInNfDiscoveryResponseNfService()", *decoder_callbacks_);

      const std::string svc_scheme = nf_service["scheme"];
      ENVOY_STREAM_LOG(trace, "scheme='{}'", *decoder_callbacks_,svc_scheme);

      int svc_port = 0;
      if (nf_service.contains("ipEndPoints") && !nf_service["ipEndPoints"].empty()) {
        if (nf_service["ipEndPoints"].at(0).contains("port")) {
          svc_port = nf_service["ipEndPoints"].at(0)["port"];
        }
      }
      if (svc_port == 0) {
        svc_port = (svc_scheme == "https" ? 443 : 80);
      }

      ENVOY_STREAM_LOG(trace, "port={}", *decoder_callbacks_, svc_port);

      // Modify the "fqdn" field for the nfService
      std::string orig_svc_fqdn;
      if (nf_service.contains("fqdn")) {
        ENVOY_STREAM_LOG(trace, "FQDN is '{}'", *decoder_callbacks_, nf_service["fqdn"]);
        orig_svc_fqdn = nf_service["fqdn"];
      } else if (nf_inst.contains("fqdn")) {
        // Take the fqdn from the nfInstance
        orig_svc_fqdn = nf_inst["fqdn"];
      } else {
        ENVOY_STREAM_LOG(
            trace,
            "No FQDN found for nfInstance[{}] and nfService[{}], T-FQDN can not be generated", *decoder_callbacks_);
        return;
      }

      // Json json_body_mod = Json::parse(body_str);
      std::string tfqdn_label_decoded =
          absl::StrCat(svc_scheme, "://", orig_svc_fqdn, ":", svc_port);

      std::string tfqdn_encoded = TfqdnCodec::encode(tfqdn_label_decoded, decoder_callbacks_);
      absl::StrAppend(&tfqdn_encoded, ".", config_->ownFqdnLc());
      ENVOY_STREAM_LOG(trace, "FQDN = '{}'", *decoder_callbacks_, tfqdn_label_decoded);
      ENVOY_STREAM_LOG(trace, "encoded T-FQDN label = '{}'", *decoder_callbacks_, tfqdn_encoded);

      nf_service["fqdn"] = tfqdn_encoded;
      ENVOY_STREAM_LOG(trace, "FQDN modified in body to TFQDN", *decoder_callbacks_);
}
// Read route metadata (as opposed to dynamic-metadata) for our filter, given a key
// @param key
// @return an optional value associated with the key
absl::optional<std::string> EricProxyFilter::getRouteMetadata(std::string key) {
  ENVOY_STREAM_LOG(trace, "Getting route metadata for key: {} in namespace: {}",
      *decoder_callbacks_, key, filter_name_);
  const auto route = decoder_callbacks_->route().get();
  if (route == nullptr) {
    ENVOY_STREAM_LOG(debug, "No route found, cannot read metadata", *decoder_callbacks_);
    return {};
  }
  // const auto& routeEntry = route->routeEntry();
  // if (routeEntry == nullptr) {
  //   ENVOY_STREAM_LOG(debug, "No routeEntry found (could be a direct response)", *decoder_callbacks_);
  //   return {};
  // }
  // const auto& metadata = routeEntry->metadata();
  const auto& metadata = route->metadata();
  if (!metadata.IsInitialized()) {
    ENVOY_STREAM_LOG(debug, "Route metadata is not initialized", *decoder_callbacks_);
    return {};
  }
  const auto& md = metadata.filter_metadata();
  return getMetadataString(md, key);
}


// Add TaR in response if reselections happen on PR
void EricProxyFilter::addTaRInResponse(Http::StreamEncoderFilterCallbacks* callbacks,
    Http::RequestOrResponseHeaderMap* resp_hdrs)
{
  // If its SEPP node external i/f listener and Topo Hiding is enabled
  // Skip TaR addition procedure
  if(config_->isSeppNode() && config_->isOriginExt() && rp_config_->has_topology_hiding()) {
    return;
  }

  // no TaR came with the original request
  if (!original_tar_.has_value()) {
    return;
  }
  
  const auto filter_md = callbacks->streamInfo().dynamicMetadata().filter_metadata();
  const auto dyn_md_eric_proxy = filter_md.find("eric_proxy");
  if (dyn_md_eric_proxy == filter_md.end()) {
    return;
  }
  // It was preferred routing.
  // Check if it was direct routing. Nothing needs to be done for indirect routing because
  // then our next hop is not the producer/handler of the resource in the response
  // If there is a location header, do nothing.
  //TODO move to filter states
  if (! findInDynMetadata(&filter_md, "eric_proxy", "direct-or-indirect", "direct")) {
    return;
  }
  // If Location header was present skip
  const auto location_hdr = resp_hdrs->get(Http::LowerCaseString("location"));
  if(! location_hdr.empty()) {
    return;
  }

  // If there is already a tar header, do nothing because the previous SCP was closer to
  // the producer and knows better
  const auto tar_hdr = resp_hdrs->get(Http::LowerCaseString("3gpp-sbi-target-apiroot"));

  // If the status code is not 2xx, do nothing because no new resouce was created
  const auto status_hdr = resp_hdrs->get(Http::LowerCaseString(":status"));
  if (! tar_hdr.empty() || status_hdr.empty()) {
    return;
  }

  const auto status_hdr_val = status_hdr[0]->value().getStringView();
  if ((status_hdr_val.empty()) || (status_hdr_val.front() != '2')) {
    return;
  }


  // ULID(S31)
  // Find the producer which handled the request. If it's the same as the originally targetted host, no need to append TaR
  // const auto& last_host_it = dyn_md_eric_proxy->second.fields().find("last-host");
  if (
    run_ctx_.getSelectedHostAuthority().empty() ||
    (original_hostname_.has_value() && absl::EqualsIgnoreCase(run_ctx_.getSelectedHostAuthority(), *original_hostname_))
  ){
    return;
  }

  // Extract replace the host:port in the original tar header with the producer data that
  // handled the request
  const auto scheme = run_ctx_.getSelectedHostScheme() == RunContext::UpstreamHostScheme::Http ? "http" : "https";

  // const auto& new_tar_header = replaceHostPortInUrl(*original_tar_, last_host_it->second.string_value(), scheme);
  const auto new_tar_header = absl::StrCat(scheme,"://",
                                            run_ctx_.getSelectedHostAuthority(),
                                            run_ctx_.getSelectedHostApiPrefix());
  // Add the target-apiroot header to the response
  ENVOY_STREAM_LOG(debug, "Adding response header '3gpp-sbi-target-apiroot' with value '{}'",
        *callbacks, new_tar_header);
  resp_hdrs->addCopy(Http::LowerCaseString("3gpp-sbi-target-apiroot"), new_tar_header);
}


// Return true if the request was marked T-FQDN in dynamic metadata
// (this is needed to pass through unwanted filter instances in the response filter chain)
bool EricProxyFilter::isReqMarkedTFqdn() {
  // if (!encoder_callbacks_->streamInfo().dynamicMetadata().filter_metadata().contains("eric_proxy.sepp.routing")) {
  //   return false;
  // }
  const auto& filter_state = decoder_callbacks_->streamInfo().filterState();
  
  auto eric_sepp_state = filter_state->getDataMutable<StreamInfo::EricProxySeppState>(
                                                                StreamInfo::EricProxySeppState::key());
  if(!eric_sepp_state) {
    return false;
  }

  return eric_sepp_state->isTfqdnRequest();
}


// Returns the scheme from a request
// (this is needed to modify the scheme of the location header or callback URIs in the resopnse path)
absl::optional<std::string> EricProxyFilter::reqSchemeMD() {



   const auto& eric_sepp_state = decoder_callbacks_->streamInfo().filterState()
                                                ->getDataMutable<StreamInfo::EricProxySeppState>
                                                    (StreamInfo::EricProxySeppState::key());
  if(!eric_sepp_state)
  {
    return {};
  }

  absl::optional<std::string> req_scheme_opt_ = eric_sepp_state->isReqHttps()?
                                                                    std::string("https"):std::string("http");

  return req_scheme_opt_;
}

// Return true if the request was marked T-FQDN in dynamic metadata
// (this is needed to pass through unwanted filter instances in the response filter chain)
bool EricProxyFilter::isReqMarkedNfDiscovery() {

  const auto& eric_sepp_state = encoder_callbacks_->streamInfo().filterState()
                                                ->getDataMutable<StreamInfo::EricProxySeppState>
                                                    (StreamInfo::EricProxySeppState::key());
  if(!eric_sepp_state)
  {
    return false;
  }

  return (eric_sepp_state->doesNfTypeRequireTfqdn() && 
                  run_ctx_.getServiceClassifierCtx().getApiName() == "nnrf-disc");
}


// Read dynamic metadata (as opposed to route-metadata) for our filter, given a key and namespace
// @param key
// @param name_space
// @return an optional value associated with the key in the given namespace
absl::optional<std::string> EricProxyFilter::getDynamicMetadata(const std::string name_space, const std::string key) {
  ENVOY_STREAM_LOG(trace, "Getting dynamic metadata for key: {} in namespace: {}",
      *decoder_callbacks_, key, name_space);

  if (!decoder_callbacks_->streamInfo().dynamicMetadata().filter_metadata().contains(name_space)){
    ENVOY_STREAM_LOG(debug, "No metadata found in namespace: {}",
        *decoder_callbacks_, name_space);
    return {};
  }

  const auto dynamic_md_eric_proxy =
    decoder_callbacks_->streamInfo().dynamicMetadata().filter_metadata().find(name_space);
  if (dynamic_md_eric_proxy->second.fields().contains(key)){
    return dynamic_md_eric_proxy->second.fields().find(key)->second.string_value();
  }
  return {};
}

// Set Dynamic Metdata for a given namespace and a provided key-value pair
//
// @param name_space Namespace of the associated dynamic MD
// @param keys  List of Keys of DynMD HashTable
// @param values List of Values of DynMD HashTable
// @param is_decoder_md Set it to true if Dyn MD is for decoder_callbacks and false if DynMD is for encoder_callbacks
// @return true if operation was succesful
bool EricProxyFilter::setEncoderOrDecoderDynamicMetadata(const std::string name_space,
                                                          std::vector<std::string> keys,
                                                          std::vector<std::string> values,
                                                          bool is_decoder_md)
{
  try {
    ProtobufWkt::Struct dynMD;
    int idx = 0;
    for (const auto& key : keys) {
      *(*dynMD.mutable_fields())[key]
        .mutable_string_value() = values.at(idx);
      idx++;
    }

    if (is_decoder_md) {
      decoder_callbacks_->streamInfo().setDynamicMetadata(name_space, dynMD);
    } else {
      encoder_callbacks_->streamInfo().setDynamicMetadata(name_space, dynMD);
    }
  }
  catch(std::exception e)
  {
    ENVOY_STREAM_LOG(debug,"Error in setting Dyn MD, in namespace:'{}', key:'{}', value:'{}'",
          *decoder_callbacks_,name_space,keys,values);
    ENVOY_STREAM_LOG(debug, "Exception e:'{}'",*decoder_callbacks_,e.what());
    return false;
  }
  return true;
}

// Common code to read metadata. Different wrappers based on type of metadata to be returned

absl::optional<std::string> EricProxyFilter::getMetadataString(
    google::protobuf::Map<std::basic_string<char>, google::protobuf::Struct> metadata,
    std::string key) {
  auto metadata_value = absl::optional<std::string>();
  const auto metadata_it = metadata.find(filter_name_);
  if (metadata_it == metadata.end()) {
    // Namespace not found
    ENVOY_STREAM_LOG(debug, "Metadata namespace '{}' not found", *decoder_callbacks_,
        filter_name_);
    return metadata_value;
  }

  auto value_it = metadata_it->second.fields().find(key);
  if (value_it == metadata_it->second.fields().end()) {
    // Key not found
    ENVOY_STREAM_LOG(debug, "Metadata key '{}' not found", *decoder_callbacks_, key);
    return metadata_value;
  } else if (!value_it->second.has_string_value()) {
    ENVOY_STREAM_LOG(debug, "Metadata value is not a string", *decoder_callbacks_);

  } else {
    ENVOY_STREAM_LOG(debug, "Metadata is: {}", *decoder_callbacks_,
                     value_it->second.string_value());
    metadata_value.emplace(value_it->second.string_value());
  }
  return metadata_value;
}

ProtobufWkt::RepeatedPtrField<ProtobufWkt::Value> EricProxyFilter::getMetadataList(
    google::protobuf::Map<std::basic_string<char>, google::protobuf::Struct> metadata,
    std::string key) {
  auto empty = ProtobufWkt::RepeatedPtrField<ProtobufWkt::Value>();
  const auto metadata_it = metadata.find(filter_name_);
  if (metadata_it == metadata.end()) {
    // Namespace not found
    ENVOY_STREAM_LOG(debug, "Metadata namespace '{}' not found", *decoder_callbacks_, filter_name_);
    return empty;
  }

  auto value_it = metadata_it->second.fields().find(key);
  if (value_it == metadata_it->second.fields().end()) {
    // Key not found
    ENVOY_STREAM_LOG(debug, "Metadata key '{}' not found", *decoder_callbacks_, key);
    return empty;
  }
  if (!value_it->second.has_list_value()) {
    ENVOY_STREAM_LOG(debug, "Metadata value is not a list", *decoder_callbacks_);
    return empty;
  }

  return value_it->second.list_value().values();
}

absl::optional<double> EricProxyFilter::getMetadataDouble(
    google::protobuf::Map<std::basic_string<char>, google::protobuf::Struct> metadata,
    std::string key) {
  auto metadata_value = absl::optional<double>();
  const auto metadata_it = metadata.find(filter_name_);
  if (metadata_it == metadata.end()) {
    // Namespace not found
    ENVOY_STREAM_LOG(debug, "Metadata namespace '{}' not found", *decoder_callbacks_, filter_name_);
    return metadata_value;
  }

  auto value_it = metadata_it->second.fields().find(key);
  if (value_it == metadata_it->second.fields().end()) {
    // Key not found
    ENVOY_STREAM_LOG(debug, "Metadata key '{}' not found", *decoder_callbacks_, key);
    return metadata_value;
  } else if (!value_it->second.has_number_value()) {
    ENVOY_STREAM_LOG(debug, "Metadata value is not a double", *decoder_callbacks_);
  } else {
    metadata_value.emplace(value_it->second.number_value());
  }
  return metadata_value;
}

/*
 * Common code to get a source value for filter-data from a header.
 */
std::string EricProxyFilter::getSourceFromHeader(const Http::RequestOrResponseHeaderMap& headers,
    const std::string& source_header) {
    std::string source_value;
    auto hdr = headers.get(Http::LowerCaseString(std::string(source_header)));
    if (!hdr.empty()) {
      // If needed, combine multiple header values into one, join with comma "," as per RFC7230
      std::vector<absl::string_view> header_values(hdr.size());
      for (size_t i = 0; i < hdr.size(); i++) {
       header_values.at(i) = hdr[i]->value().getStringView();
      }
      source_value = absl::StrJoin(header_values, ",");
    } else {
      ENVOY_STREAM_LOG(debug, "Header '{}' not found", *decoder_callbacks_, source_header);
    }
    return source_value;
}
/**
 * Update variables for a given filter case
 */
// FIXME (eedala): add parameter headers_changed and don't go into json-body-pointer part if headers have changed
void EricProxyFilter::updateVariables(std::shared_ptr<FilterCaseWrapper> filter_case,
                                 std::shared_ptr<FilterDataWrapper> filter_data) {
  ENVOY_STREAM_LOG(debug, "Update variables for filter case: {}, filter data:{}",
      *decoder_callbacks_, filter_case->name(), filter_data->name());
  // 8.2.1 Read the data from the source (header, path, json-body)
  // 8.2.2 If there is a modifier-regex, execute it (will come later)
  // 8.2.3 Dependent on the destination:
  //    8.2.3.1   If the destination-variable is name (= a simple variable)
  //    8.2.3.1.1 Store the variable in the var_value table and set updated_by_rc
  Json source_value;
  if (filter_data->sourceIsPath()) {
    // Source == path
    ENVOY_STREAM_LOG(debug, "Reading from URI path", *decoder_callbacks_);
    auto path = run_ctx_.getReqHeaders()->get(Envoy::Http::LowerCaseString(":path"));
    if(!path.empty()) {
      source_value = std::string(path[0]->value().getStringView());
    } else {
      ENVOY_STREAM_LOG(debug, "Path is not found. This is unexpected.", *decoder_callbacks_);
    }
  } else if (filter_data->sourceIsHeader()) {
    // Source == header (request or response, depends on if we are in request or response
    // processing)
    ENVOY_STREAM_LOG(debug, "Reading from header: {}", *decoder_callbacks_,
        filter_data->sourceHeader());
    source_value = getSourceFromHeader(*run_ctx_.getReqOrRespHeaders(), filter_data->sourceHeader());
  } else if (filter_data->sourceIsReqHeader()) {
    // Source == request header
    ENVOY_STREAM_LOG(debug, "Reading from request header: {}", *decoder_callbacks_,
        filter_data->sourceReqHeader());
    source_value = getSourceFromHeader(*run_ctx_.getReqHeaders(), filter_data->sourceReqHeader());
  } else if (filter_data->sourceIsRespHeader()) {
    // Source == response header
    ENVOY_STREAM_LOG(debug, "Reading from response header: {}", *decoder_callbacks_,
        filter_data->sourceRespHeader());
    source_value = getSourceFromHeader(*run_ctx_.getReqOrRespHeaders(), filter_data->sourceRespHeader());
  } else if (filter_data->sourceIsBodyJsonPointer()) {
    // Source = body-JSON-pointer
    auto json_pointer_arg = filter_data->sourceBodyJsonPointer();
    ENVOY_STREAM_LOG(debug, "Reading via body-json-pointer: {}", *decoder_callbacks_, json_pointer_arg);
    if (body_->isBodyPresent()) {
      // Internally, the body can be spread over several slices (when the body arrived
      // in multiple HTTP/2 frames). We need it as one block of contiguous memory:
      ENVOY_STREAM_LOG(debug, "Body is defined", *decoder_callbacks_);
      StatusOr<Json> json_value = body_->readWithPointer(json_pointer_arg);
      if (json_value.ok()) {
        source_value = *json_value;
      } else {
    //    return;
      }
    } else {
      ENVOY_STREAM_LOG(debug, "Body is empty", *decoder_callbacks_);
     //   return;
    }
  }
  // At this point, we should have a source value

  // 8.2.3.1 If the destination-variable is name (= a simple variable)
  if (!filter_data->variableName().empty() ) {
    // varCaptureGroups for a simple variable should have only one entry
    auto var_value_idx = filter_data->varCaptureGroups().begin()->second;
    // If the source value does not exist, then we need to store an empty string
    // in the variable as per decision from 2022-03-07
    if (source_value.is_null()) {
      source_value = "";
    }
    // Update Only if extracted value is not empty. DND-29092 check if dest. var is empty.
    if ((source_value.is_string() && !source_value.get<std::string>().empty())
        || source_value.is_boolean()
        || run_ctx_.varValueIsEmpty(var_value_idx)) {
      run_ctx_.updateVarValue(var_value_idx, source_value, filter_case.get());
      ENVOY_STREAM_LOG(trace, "Stored simple variable: '{}', value: '{}', at index: '{}'",
        *decoder_callbacks_, filter_data->variableName(), source_value.dump(), var_value_idx);
    }

  // 8.2.3.2 If the destination-variable is extractor-regex
  } else if (!filter_data->extractorRegex().empty()) {
    ENVOY_STREAM_LOG(trace, "Updating variables from extractor-regex: '{}', source: '{}'",
        *decoder_callbacks_, filter_data->extractorRegex(), source_value.dump());
    // 8.2.3.2.1 Match the regex to the source
    // Check if source_value is of type string. If not, then we cannot apply a regex to it.
    if (source_value.is_string()) {
      auto num_groups = filter_data->re2ExtractorRegex().NumberOfCapturingGroups();
      std::vector<re2::RE2::Arg> argv(num_groups);
      std::vector<re2::RE2::Arg*> args(num_groups);
      std::vector<re2::StringPiece> ws(num_groups);
      for (int i = 0; i < num_groups; ++i) {
        args[i] = &argv[i];
        argv[i] = &ws[i];
      }

      // for the RE2 call we should use "dump" (eedrak) 
      //std::string source_value_str = source_value.dump();
      std::string source_value_str = source_value.template get<std::string>();
      RE2::PartialMatchN(source_value_str, filter_data->re2ExtractorRegex(), &(args[0]), num_groups);
      // 8.2.3.2.2 Foreach var_capturegroup entry
      // 8.2.3.2.2.1 Store the data from the capture_group at var_value_index in the
      //             var_value table and set updated_by_rc to the ID of this Filter-Case
      //             in the var_updated_by table to the ID of this Filter-Case

    // DND-29092 check if var is empty
    // Update Only if extracted value is not empty
      for (const auto& capture : filter_data->re2ExtractorRegex().NamedCapturingGroups()) {
        auto value = ws[capture.second - 1];
        CaptureGroup cg = capture.second;
        auto var_capture_groups = filter_data->varCaptureGroups();
        auto var_value_idx = var_capture_groups[cg];
        if(! value.empty())
        {
          run_ctx_.updateVarValue(var_value_idx, value, filter_case.get());
          ENVOY_STREAM_LOG(trace, "Extracted value not empty. Updating variable: '{}', "
              "value: '{}', at index: '{}'",
            *decoder_callbacks_, capture.first, value, var_value_idx);
        } else {
          // DND-30806: Fix NBC so that a non-matching variable is equal to '' (empty string)
          if (run_ctx_.varValue(var_value_idx).is_null()) {
            ENVOY_STREAM_LOG(trace, "Extracted value is empty, and variable is null. "
                "Updating variable: '{}' at index: '{}' to empty string",
              *decoder_callbacks_, capture.first, var_value_idx);
            run_ctx_.updateVarValue(var_value_idx, "", filter_case.get());
          } else {
            ENVOY_STREAM_LOG(trace, "Extracted value is empty. Not updating non-empty variable: "
                "'{}' at index: '{}'",
              *decoder_callbacks_, capture.first, var_value_idx);
          }
        }
      }
    // If the source value does not exist or is not a string, then we need to store empty strings in all
    // capture variables as per decision from 2022-03-07
    } else {
      for (const auto& capture : filter_data->re2ExtractorRegex().NamedCapturingGroups()) {
        CaptureGroup cg = capture.second;
        auto var_capture_groups = filter_data->varCaptureGroups();
        auto var_value_idx = var_capture_groups[cg];
        // DND-29092 check if var is empty. Update Only if extracted value is not empty
        if (run_ctx_.varValueIsEmpty(var_value_idx)) {
          ENVOY_STREAM_LOG(trace, "Extracted value is not a string, and variable is empty. "
              "Updating variable: '{}' at index: '{}' to empty string",
            *decoder_callbacks_, capture.first, var_value_idx);
          run_ctx_.updateVarValue(var_value_idx, "", filter_case.get());
        } else {
            ENVOY_STREAM_LOG(trace, "Extracted value is empty. Not updating non-empty variable: "
                "'{}' at index: '{}'",
              *decoder_callbacks_, capture.first, var_value_idx);
          }
      }
    }
  } else {
    ENVOY_STREAM_LOG(info, "No destination variable defined in filter data: {}, for header: {}",
        *decoder_callbacks_, filter_data->name(), source_value.dump());
  }
}

// Only needed for testing. Can be removed once body and json are separated.
// Read from an element from a JSON-encoded string via a Json-Pointer.
// Returns Json() (= Json null) if the element is not found.
const Envoy::StatusOr<Json>
EricProxyFilter::readFromJsonWithPointer(const std::string& body_str,
                                         const std::string& json_pointer_str,
                                         Http::StreamDecoderFilterCallbacks* decoder_callbacks) {
  if (decoder_callbacks != nullptr) {
    ENVOY_STREAM_LOG(trace, "JSON body is: {}", *decoder_callbacks, body_str);
  } else {
    ENVOY_LOG(trace, "JSON body is: {}", body_str);
  }
  Json json_body;
  try {
    json_body = Json::parse(body_str);
  } catch (Json::parse_error& e) {
    if (decoder_callbacks != nullptr) {
      ENVOY_STREAM_LOG(debug, "Malformed JSON body ({})", *decoder_callbacks, e.what());
    } else {
      ENVOY_LOG(debug, "Malformed JSON body ({})", e.what());
    }
    // TODO(eedala): increment statistics counter for malformed body
    return absl::InvalidArgumentError("Malformed JSON body");
  } catch (...) {
    if (decoder_callbacks != nullptr) {
      ENVOY_STREAM_LOG(debug, "Unknown error", *decoder_callbacks);
    } else {
      ENVOY_LOG(debug, "Unknown error");
    }
    return absl::InvalidArgumentError("Unknown error");
  }
  Json::json_pointer json_pointer;
  try {
    json_pointer = Json::json_pointer(json_pointer_str);
  } catch (Json::parse_error& e) {
    // Shoud not happen (should have been caught in a validator)
    if (decoder_callbacks != nullptr) {
      ENVOY_STREAM_LOG(debug, "Malformed JSON pointer ({}: {})", *decoder_callbacks, e.what(),
                       json_pointer_str);
    } else {
      ENVOY_LOG(debug, "Malformed JSON pointer ({}: {})", e.what(), json_pointer_str);
    }
    return absl::InvalidArgumentError("Malformed JSON pointer");
  } catch (...) {
    if (decoder_callbacks != nullptr) {
      ENVOY_STREAM_LOG(debug, "Unknown error", *decoder_callbacks);
    } else {
      ENVOY_LOG(debug, "Unknown error");
    }
    return absl::InvalidArgumentError("Unknown error");
  }

  try {
    return json_body.at(json_pointer);
  } catch (Json::out_of_range& e) {
    if (decoder_callbacks != nullptr) {
      ENVOY_STREAM_LOG(debug, "Can not find json_pointer in body", *decoder_callbacks);
    } else {
      ENVOY_LOG(info, "Can not find json_pointer in body");
    }
    return Json();
  } catch (Json::parse_error& e) {
    if (decoder_callbacks != nullptr) {
      ENVOY_STREAM_LOG(debug, "Malformed JSON pointer ({}: {})", *decoder_callbacks, e.what(),
                       json_pointer_str);
    } else {
      ENVOY_LOG(debug, "Malformed JSON pointer ({}: {})", e.what(), json_pointer_str);
    }
    return absl::InvalidArgumentError("Malformed JSON pointer");
  } catch (...) {
    if (decoder_callbacks != nullptr) {
      ENVOY_STREAM_LOG(debug, "Unknown error", *decoder_callbacks);
    } else {
      ENVOY_LOG(debug, "Unknown error");
    }
    return absl::InvalidArgumentError("Unknown error");
  }
}

// Modify a JSON object via one or more extended JSON-pointers and one(!) given
// function that modifies the element(s).
// Return an optional with the modified json.
// Sometimes we need to modify existing json, sometimes to return copy as result
absl::Status EricProxyFilter::modifyJson(
  Http::StreamDecoderFilterCallbacks* decoder_callbacks,
  std::shared_ptr<Json> json_src, std::vector<std::string>& targets,
  std::function<std::string(const std::string&)> modifier_function,
  int error_handling_flags
) {
  return modifyJson(decoder_callbacks, json_src, targets, &modifier_function, 1, error_handling_flags);
}

// Modify a JSON object via one or more extended JSON-pointers and a  vector of one or more 
// given function that modifies the element(s).
// Return an optional with the modified json.
// Sometimes we need to modify existing json, sometimes to return copy as result
absl::Status EricProxyFilter::modifyJson(
  Http::StreamDecoderFilterCallbacks* decoder_callbacks,
  std::shared_ptr<Json> json_src, std::vector<std::string>& targets,
  const std::vector<std::function<std::string(const std::string&)>>& modifier_functions,
  int error_handling_flags
) {
  return modifyJson(decoder_callbacks, json_src, targets, &modifier_functions[0], modifier_functions.size(), error_handling_flags);  
}

// private modifyJson() interface, allows code sharing between use cases for single or multiple
// modifier functions, without the need to initialize a vector
absl::Status EricProxyFilter::modifyJson(
  Http::StreamDecoderFilterCallbacks* decoder_callbacks,
  std::shared_ptr<Json> json_src, std::vector<std::string>& targets,
  const std::function<std::string(const std::string&)>* modifier_functions,
  const std::size_t& modifier_functions_len,                         
  int error_handling_flags
) {
  if (!json_src) {
    return absl::NotFoundError("Malformed JSON");
  }
  ENVOY_STREAM_LOG(trace, "JSON source is: '{}'", *decoder_callbacks, json_src->dump());

  bool found{false};
  for (const auto& target : targets) {
    ENVOY_STREAM_LOG(trace, "Trying JSON pointer '{}'", *decoder_callbacks, target);
    Json::json_pointer json_pointer;
    try {
      json_pointer = Json::json_pointer(target);
    } catch (Json::parse_error& e) {
      // Should not happen (should have been caught in a validator)
      ENVOY_STREAM_LOG(debug, "Malformed JSON pointer ('{}': '{}')", *decoder_callbacks, e.what(), target);
      return absl::InvalidArgumentError("Malformed JSON pointer");
    }
    try {
      JsonUtils::map_at(json_src.get(), json_pointer, modifier_functions, modifier_functions_len, error_handling_flags);
      ENVOY_STREAM_LOG(trace, "Found JSON pointer '{}'", *decoder_callbacks, target);
      found = true;
    } catch (Json::exception& e) {
      ENVOY_STREAM_LOG(trace, "Element '{}' not found in JSON body via JSON pointer ('{}')",
          *decoder_callbacks, target, e.what());
    }
  }
  if (found) {
    return absl::OkStatus();
  } else {
    return absl::NotFoundError("Element not found in JSON body via JSON pointer(s)");
  }
}

void EricProxyFilter::createTargetApiRootfromAuthorityHeader(Http::RequestOrResponseHeaderMap* headers){
  ENVOY_STREAM_LOG(trace, "createTargetApiRootfromAuthorityHeader()",*decoder_callbacks_);
  auto auth_hdr = headers->get(Http::LowerCaseString(":authority"));
  if (!auth_hdr.empty()) {
    auto authority = std::string(auth_hdr[0]->value().getStringView());
    createTargetApiRootfromString(authority, headers);
  }
}

// Create and store the 3gpp-Sbi-Target-apiRoot header from a given string (usually coming
// from :authority). Adds a scheme to the host+port to make it a valid target-apiRoot header
void EricProxyFilter::createTargetApiRootfromString(std::string& new_value, Http::RequestOrResponseHeaderMap* headers) {
  std::string tar_value;
  auto scheme_hdr = headers->get(Http::LowerCaseString(":scheme"));
  if (!scheme_hdr.empty()) {
    auto scheme = std::string(scheme_hdr[0]->value().getStringView());
    tar_value = absl::StrCat(scheme, "://", new_value);
  }
  ENVOY_STREAM_LOG(trace, "created 3gpp-Sbi-target-apiRoot:{}, from value:{}",*decoder_callbacks_, tar_value, new_value);
  headers->setCopy(Http::LowerCaseString("3gpp-Sbi-target-apiRoot"), tar_value);
}

// Create and store the 3gpp-Sbi-Target-apiRoot header from a decoded T-FQDN Label (incl. a scheme)
void EricProxyFilter::createTargetApiRootfromDecodedTFqdnLabel(std::string& new_value, Http::RequestOrResponseHeaderMap* headers) {
  ENVOY_STREAM_LOG(trace, "created 3gpp-Sbi-target-apiRoot:{},",*decoder_callbacks_, new_value);
  headers->setCopy(Http::LowerCaseString("3gpp-Sbi-target-apiRoot"), new_value);
}

// Check if the authority header contains only the own fqdn. An eventual port is ignored.
// If the :authority header contains an IPv6 address starting with "[" then remove the "[]"
// before comparing.
bool EricProxyFilter::authorityIsOnlyOwnFqdn(absl::string_view authority, const std::string& own_fqdn) {
  auto authority_lc = absl::AsciiStrToLower(authority);
  auto own_fqdn_lc = absl::AsciiStrToLower(own_fqdn);
  if (absl::StartsWith(authority_lc, own_fqdn_lc)) {
    return (authority_lc.size() == own_fqdn_lc.size()  // same length = same strings
         || authority_lc.substr(own_fqdn_lc.size(), 1) == ":");  // next char after own FQDN is : -> port starts
  } else {
    // Check if first character of authority is "[" and there is a "]" after own_fqdn.size() characters:
    if (((authority_lc.size() >= own_fqdn_lc.size() + 2) &&
          absl::StartsWith(authority_lc, "[") &&
          (authority_lc.substr(own_fqdn_lc.size() + 1, 1) == "]"))) {
      return (authority_lc.substr(1, own_fqdn_lc.size()) == own_fqdn_lc);
    } else {
      return false;
    }
  }
}

std::string EricProxyFilter::encodeTfqdnUri(std::string orig_uri){
  ENVOY_STREAM_LOG(debug, "encodeTfqdnUri()", *decoder_callbacks_);
  Http::Utility::Url orig_url = Http::Utility::Url();
  orig_url.initialize(absl::string_view(orig_uri),false);
  auto orig_uri_scheme = std::string(orig_url.scheme());
  auto orig_uri_host_and_port = std::string(orig_url.hostAndPort());
  auto orig_uri_path_and_query_params = std::string(orig_url.pathAndQueryParams());
  //Http::Utility::extractHostPathFromUri(orig_uri, orig_uri_host, orig_uri_path);

  //We only modify the URI if we get an absolute URItfqdn_label_decoded
  if (!orig_uri_host_and_port.empty()){
    auto tfqdn_label_decoded = absl::StrCat(orig_uri_scheme, "://", orig_uri_host_and_port);
    auto tfqdn_label_encoded = TfqdnCodec::encode(tfqdn_label_decoded, decoder_callbacks_);
    std::string tfqdn_encoded_uri;
    // avoid trailing "/" if path is empty
    if (orig_uri_path_and_query_params == "/"){
      tfqdn_encoded_uri = absl::StrCat(orig_uri_scheme, "://", tfqdn_label_encoded, ".",
          config_->ownFqdnLc());
    } else {
      tfqdn_encoded_uri = absl::StrCat(orig_uri_scheme, "://", tfqdn_label_encoded, ".",
          config_->ownFqdnLc(), orig_uri_path_and_query_params);
    }
    ENVOY_STREAM_LOG(debug, "T-FQDN encoded URI = {}", *decoder_callbacks_, tfqdn_encoded_uri);
    return tfqdn_encoded_uri;
  } else {
    ENVOY_STREAM_LOG(debug, "no Host found in URI, T-FQDN can not be generated", *decoder_callbacks_);
    return orig_uri;
  }
}


std::string EricProxyFilter::encodeTfqdnUri(std::string orig_uri, std::string scheme){
  ENVOY_STREAM_LOG(debug, "encodeTfqdnUri()", *decoder_callbacks_);
  absl::string_view orig_uri_host;
  absl::string_view orig_uri_path;
  Http::Utility::extractHostPathFromUri(orig_uri, orig_uri_host, orig_uri_path);
  //We only modify the URI if we get an absolute URI

  if (!orig_uri_host.empty()){
    std::string tfqdn_encoded_uri, tfqdn;
    auto host_pos_in_orig_uri = orig_uri.find(std::string(orig_uri_host));
    //if (scheme == "https"){
      // TODO change once int_tls_port is implemented manager + eric_proxy
    //  tfqdn = TfqdnCodec::encode(orig_uri_host_str.c_str()  + "." +  config_->ownFqdnWithIntPortLc();
    //} else {
    //  tfqdn = TfqdnCodec::encode(orig_uri_host_str.c_str()  + "." +  config_->ownFqdnWithIntPortLc();
    //}
    absl::StrAppend(&tfqdn, TfqdnCodec::encode(orig_uri_host, decoder_callbacks_), ".",
                    config_->ownFqdnWithIntPortLc());
    tfqdn_encoded_uri = orig_uri.replace(0, host_pos_in_orig_uri + orig_uri_host.length(), tfqdn);
    ENVOY_STREAM_LOG(debug, "T-FQDN encoded URI w/o scheme = {}", *decoder_callbacks_, tfqdn_encoded_uri);
    tfqdn_encoded_uri = scheme + "://" +  tfqdn_encoded_uri;
    ENVOY_STREAM_LOG(debug, "T-FQDN encoded URI = {}", *decoder_callbacks_, tfqdn_encoded_uri);
    return tfqdn_encoded_uri;
  } else {
    ENVOY_STREAM_LOG(debug, "no Host found in URI, T-FQDN can not be generated", *decoder_callbacks_);
    return orig_uri;
  }
}

// Return true if all variables have been updated by this filter case (if not, then they
// will be updated soon by the caller of this function)
bool EricProxyFilter::areVariablesUpdatedByFc(std::shared_ptr<FilterCaseWrapper> filter_case) {
  // Look up all the var_value_index in var_updated_by table in the run-context:
  // if all of the updated_by_rc values are equal to the current Filter-Case it
  // means that the variables are already up-to-date
  for (const auto& var_filter_data_entry : filter_case->varFilterData()) {
    if (run_ctx_.varUpdatedBy(var_filter_data_entry.first) != filter_case.get()) {
      ENVOY_STREAM_LOG(debug, "Not all variables are up to date for filter case: {}. "
          "At least '{}' needs to be updated", *decoder_callbacks_,
          filter_case->name(), run_ctx_.rootContext()->variableName(var_filter_data_entry.first));
      return false;
    }
  }
  return true;
}

// For a string that is a uri split the scheme,fqdn,port+resource
// into a tuple and return it. If it cannot find scheme in the beginning
// do nothing and return the fqdn in 2nd arg of tuple
std::tuple<std::string, std::string, std::string>
EricProxyFilter::splitUriForMapping(absl::string_view uri) {
  ENVOY_LOG(trace, "splitUriForMapping: '{}'", uri);
  std::string prefix = "";
  std::string suffix = "";

  if (uri.compare(0, 7, "http://") == 0) {
    uri.remove_prefix(7);
    prefix = "http://";
  } else if (uri.compare(0, 8, "https://") == 0) {
    uri.remove_prefix(8);
    prefix = "https://";
  }

  std::string fqdn = std::string(uri);
  const auto& brk_pos = uri.find(':');
  if (brk_pos != std::string::npos) {
    fqdn = std::string(uri.substr(0, brk_pos));
    suffix =  std::string(uri.substr(brk_pos, uri.length()));
    ENVOY_LOG(trace, "prefix: '{}', fqdn: '{}', suffix: '{}'", prefix, fqdn, suffix);
    return std::make_tuple(prefix, fqdn, suffix);
  }

  const auto& pos_start = uri.find('/');
  if ((brk_pos == std::string::npos) && (pos_start != std::string::npos)) {
    fqdn = std::string(uri.substr(0, pos_start));
    suffix = std::string(uri.substr(pos_start, uri.length()));
    ENVOY_LOG(trace, "prefix: '{}', fqdn: '{}', suffix: '{}'", prefix, fqdn, suffix);
    return std::make_tuple(prefix, fqdn, suffix);
  }

  ENVOY_LOG(trace, "prefix: '{}', fqdn: '{}', suffix: '{}'", prefix, fqdn, suffix);
  return std::make_tuple(prefix, fqdn, suffix);
}

// For a string that contain multiple labels separated by dots, split the labels
absl::StatusOr<std::vector<std::string>> EricProxyFilter::splitLabels(absl::string_view labels) {
  ENVOY_LOG(trace, "splitLabels: '{}'", labels);
  if (labels.empty()) {
    ENVOY_LOG(trace, "FQDN is in invalid 3gpp format");
    return absl::Status(absl::StatusCode::kInvalidArgument, "FQDN is in invalid 3gpp format");
  }

  std::vector<std::string> label_list;
  int start, end = -1;
  do {
    start = end + 1;
    end = labels.find('.', start);
    if (labels.substr(start, end - start).empty()) {
      ENVOY_LOG(trace, "FQDN is in invalid 3gpp format");
      return absl::Status(absl::StatusCode::kInvalidArgument, "FQDN is in invalid 3gpp format");
    }
    label_list.push_back(std::string(labels.substr(start, end - start)));
  } while (end != -1);

  ENVOY_LOG(trace, "label_list: '{}'", label_list);
  return label_list;
}

// For a string that is a uri, split the scheme, fqdn & port+resource
// into a tuple and return it. If it cannot find scheme in the beginning
// do nothing and return the fqdn in 2nd arg of tuple
absl::StatusOr<std::tuple<std::string, std::vector<std::string>, std::string, std::string>>
EricProxyFilter::splitUriForScrambling(absl::string_view uri, const std::regex& regex_valid_plmn) {
  ENVOY_LOG(trace, "splitUriForScrambling: '{}'", uri);
  std::string scheme = "";
  std::vector<std::string> labels;
  std::string plmn = "";
  std::string port = "";
  std::string resource = "";

  // Check if it is authority (host + port) and it is valid
  if (Http::HeaderUtility::authorityIsValid(uri)) {
    Http::Utility::Url absolute_url;

    // Make it a uri and check if it is invalid
    if (!absolute_url.initialize(absl::StrCat("http://", uri), false)) {
      ENVOY_LOG(trace, "authority (host + port) is invalid");
      return absl::Status(absl::StatusCode::kInvalidArgument, "authority (host + port) is invalid");
    }

    const auto authority = Http::Utility::parseAuthority(uri);
    // Check if it is an IP address
    if (authority.is_ip_address_) {
      ENVOY_LOG(trace, "IP address is present");
      return absl::Status(absl::StatusCode::kFailedPrecondition, "IP address is present");
    }

    const auto& fqdn = std::string(authority.host_);
    // Check if the FQDN is not in 3gpp format
    std::smatch match;
    if (!std::regex_match(fqdn, match, regex_valid_plmn)) {
      ENVOY_LOG(trace, "FQDN is in invalid 3gpp format");
      return absl::Status(absl::StatusCode::kInvalidArgument, "FQDN is in invalid 3gpp format");
    }
    // Extract labels and plmn from FQDN
    const auto& labels_result = splitLabels(match.str(1));
    if (!labels_result.ok()) {
      return labels_result.status();
    }
    labels = labels_result.value();
    plmn = match.str(2);
  
    if (authority.port_.has_value()) {
      port = absl::StrCat(":", authority.port_.value());
    }

    ENVOY_LOG(trace, "scheme: '{}', labels: '{}', plmn: '{}', portAndResource: '{}'", scheme, labels, plmn, absl::StrCat(port, resource));
    return std::make_tuple(scheme, labels, plmn, absl::StrCat(port, resource));
  }

  Http::Utility::Url absolute_url;

  // Check if it is uri and if it is invalid
  if (!absolute_url.initialize(uri, false)) {
    ENVOY_LOG(trace, "URI is invalid");
    return absl::Status(absl::StatusCode::kInvalidArgument, "URI is invalid");
  }

  // Check if the scheme is invalid
  if (!absolute_url.scheme().empty() && !Http::Utility::schemeIsValid(absolute_url.scheme())) {
    ENVOY_LOG(trace, "scheme is invalid");
    return absl::Status(absl::StatusCode::kInvalidArgument, "scheme is invalid");
  }

  const auto authority = Http::Utility::parseAuthority(absolute_url.hostAndPort());
  // Check if it is an IP address
  if (authority.is_ip_address_) {
    ENVOY_LOG(trace, "IP address is present");
    return absl::Status(absl::StatusCode::kFailedPrecondition, "IP address is present");
  }

  if (!absolute_url.scheme().empty()) {
    scheme = absl::StrCat(absolute_url.scheme(), "://");
  }

  const auto& fqdn = std::string(authority.host_);
  // Check if the FQDN is not in 3gpp format
  std::smatch match;
  if (!std::regex_match(fqdn, match, regex_valid_plmn)) {
    ENVOY_LOG(trace, "FQDN is in invalid 3gpp format");
    return absl::Status(absl::StatusCode::kInvalidArgument, "FQDN is in invalid 3gpp format");
  }
  // Extract labels and plmn from FQDN
  const auto& labels_result = splitLabels(match.str(1));
  if (!labels_result.ok()) {
    return labels_result.status();
  }
  labels = labels_result.value();
  plmn = match.str(2);

  if (authority.port_.has_value()) {
    port = absl::StrCat(":", authority.port_.value());
  }
  if (absolute_url.pathAndQueryParams() != "/" || uri.back() == '/') {
    resource = std::string(absolute_url.pathAndQueryParams());
  }

  ENVOY_LOG(trace, "scheme: '{}', labels: '{}', plmn: '{}', portAndResource: '{}'", scheme, labels, plmn, absl::StrCat(port, resource));
  return std::make_tuple(scheme, labels, plmn, absl::StrCat(port, resource));
}

/*
* Returns a vector of string modification function based 
* on the provided "string_modifiers" configuration
*/
std::vector<std::function<std::string(const std::string&)>>
EricProxyFilter::prepareStringModifiers(
  const StringModifiers& string_modifiers, RunContext& run_ctx,
  Http::StreamDecoderFilterCallbacks* decoder_callbacks
) {
  std::vector<std::function<std::string(const std::string&)>> string_mod_functions;
  for (const auto& string_modifier : string_modifiers){
    string_mod_functions.push_back(prepareStringModifier(string_modifier, run_ctx, decoder_callbacks));
  }

  return string_mod_functions;
}

/*
* Returns a single string modification function based 
* on the provided "string_modifier" configuration
*/
std::function<std::string(const std::string&)>
EricProxyFilter::prepareStringModifier(
  const StringModifier& string_modifier, RunContext& run_ctx,
  Http::StreamDecoderFilterCallbacks* decoder_callbacks
) {
  switch (string_modifier.string_modifier_case()) {
    case StringModifier::kToUpper: {
      return ([](auto& str) { 
          std::string str_uc = str;
          std::transform(str_uc.begin(), str_uc.end(), str_uc.begin(), ::toupper);
          return str_uc;
        });
      break;
    }
    case StringModifier::kToLower: {
      return ([](auto& str) { 
          std::string str_lc = str;
          std::transform(str_lc.begin(), str_lc.end(), str_lc.begin(), ::tolower);
          return str_lc;
        });
      break;
    }
    case StringModifier::kPrepend: {
      auto prependValue = varHeaderConstValueAsString(
        string_modifier.prepend(), false, run_ctx, decoder_callbacks
      );
      return ([prependValue](auto& str) { return (prependValue + str); });
      break;
    }
    case StringModifier::kAppend: {
      auto appendValue = varHeaderConstValueAsString(
        string_modifier.append(), false, run_ctx, decoder_callbacks
      );
      return ([appendValue](auto& str) { return (str + appendValue); });
      break;
    }
    case StringModifier::kTableLookup: {
      ENVOY_LOG(trace, "string modifier: table lookup");
      return ([&](const auto& str) {
        const auto& table_name = string_modifier.table_lookup().lookup_table_name();

        Transformation transform;
        if (string_modifier.table_lookup().transform() == Transformation::DEFAULT) {
          transform = Transformation::ONLY_FQDN;
        } else {
          transform = string_modifier.table_lookup().transform();
        }

        auto kvt_val = transformAndLookup(str, table_name, transform, run_ctx);
        if (kvt_val.has_value()) {
          if (run_ctx.stringModifierContext()) {
            run_ctx.stringModifierContext()->setIsMappingSuccess(true);
          }
          return kvt_val.value();
        }

        if (string_modifier.table_lookup().has_default_value()) {
          if (run_ctx.stringModifierContext()) {
            run_ctx.stringModifierContext()->setIsMappingSuccess(true);
          }
          return string_modifier.table_lookup().default_value();
        }

        if (string_modifier.table_lookup().has_do_nothing()) {
          if (run_ctx.stringModifierContext()) {
            run_ctx.stringModifierContext()->setIsMappingForwardedUnmodified(true);
          }
          return str;
        }

        if (string_modifier.table_lookup().has_fc_unsuccessful_operation()) {
          if (run_ctx.stringModifierContext()) {
            run_ctx.stringModifierContext()->setMappingUnsuccessfulFilterCase(
              string_modifier.table_lookup().fc_unsuccessful_operation()
            );
          }
        }

        throw std::string("Key not found in table lookup");
      });
      break;
    }
    case StringModifier::kScramblingProfile: {
      ENVOY_LOG(trace, "string modifier: scrambling profile");
      return ([&](const auto& str) {
        Transformation transform;
        if (string_modifier.scrambling_profile().transform() == Transformation::DEFAULT) {
          transform = Transformation::ONLY_LABEL;
        } else {
          transform = string_modifier.scrambling_profile().transform();
        }

        std::string encryption_id = "unknown_id";
        absl::StatusOr<std::string> val;
        if ((run_ctx.isRequest()) ^ (run_ctx.rootContext()->isOriginExt())) {
          val = transformAndScramble(str, transform, run_ctx, encryption_id);
        } else {
          val = transformAndDescramble(str, transform, run_ctx, encryption_id);
        }

        if (val.ok()) {
          if (run_ctx.stringModifierContext()) {
            run_ctx.stringModifierContext()->populateScramblingSuccess(encryption_id);
          }
          return val.value();
        }

        if (val.status().code() == absl::StatusCode::kFailedPrecondition) {
          if (run_ctx.stringModifierContext()) {
            run_ctx.stringModifierContext()->populateScramblingForwardedUnmodifiedIp(encryption_id);
          }
          return str;
        }

        if (val.status().code() == absl::StatusCode::kNotFound) {
          if (run_ctx.stringModifierContext()) {
            run_ctx.stringModifierContext()->populateScramblingEncryptionIdNotFound(encryption_id);
          }
        }

        if (val.status().code() == absl::StatusCode::kInvalidArgument) {
          if (run_ctx.stringModifierContext()) {
            run_ctx.stringModifierContext()->populateScramblingInvalidFqdn(encryption_id);
          }
        }

        if (val.status().code() == absl::StatusCode::kAborted) {
          if (run_ctx.stringModifierContext()) {
            run_ctx.stringModifierContext()->populateScramblingIncorrectEncryptionId(encryption_id);
          }
        }

        if (string_modifier.scrambling_profile().has_default_value()) {
          if (run_ctx.stringModifierContext()) {
            run_ctx.stringModifierContext()->populateScramblingSuccess(encryption_id);
          }
          return string_modifier.scrambling_profile().default_value();
        }

        if (string_modifier.scrambling_profile().has_do_nothing()) {
          if (run_ctx.stringModifierContext()) {
            run_ctx.stringModifierContext()->populateScramblingForwardedUnmodifiedFqdn(encryption_id);
          }
          return str;
        }

        if (string_modifier.scrambling_profile().has_fc_unsuccessful_operation()) {
          if (run_ctx.stringModifierContext()) {
            run_ctx.stringModifierContext()->setScramblingUnsuccessfulFilterCase(
              string_modifier.scrambling_profile().fc_unsuccessful_operation()
            );
          }
        }

        throw std::string(val.status().message());
      });
      break;
    }
    case StringModifier::kSearchAndReplace: {
      return (EricProxySearchAndReplace::searchAndReplaceFunction(string_modifier.search_and_replace(), decoder_callbacks , run_ctx));
      break;
    }    
    default: {
      ENVOY_LOG(trace, "unsupported string_modifier: '{}'", string_modifier.string_modifier_case());
      //  return a dummy modifier, should we throw here or use statusOr ?
      return ([string_modifier](auto& str) { return str;});
      break;
    }
  }
}

// Do a table lookup based on variable after transformation rule in table_lookup
std::optional<std::string> EricProxyFilter::transformAndLookup(
  absl::string_view uri, const std::string& table_name,
  const Transformation& transform, RunContext& run_ctx
) {
  switch(transform) {
    case Transformation::ONLY_LABEL:
      break;
    case Transformation::ONLY_FQDN: {
      const auto& [prefix, fqdn, suffix] = splitUriForMapping(uri);
      auto kvt_val = run_ctx.rootContext()->kvtValue(table_name, fqdn);
      if (kvt_val.has_value()) {
        return absl::StrCat(prefix, kvt_val.value(), suffix);
      } else {
        // No such data exists in map
        return std::nullopt;
      }
      break;
    }
    case Transformation::NO_TRANSFORMATION:
      break;
    default:
      ENVOY_LOG(trace, "Invalid Transform mode");
      break;
  }

  return std::nullopt;
}

// Scramble after transformation rule in scrambling profile
absl::StatusOr<std::string> EricProxyFilter::transformAndScramble(
  absl::string_view uri, const Transformation& transform,
  RunContext& run_ctx, std::string& encryption_id
) {
  switch(transform) {
    case Transformation::ONLY_LABEL: {
      // Get encryption profile for scrambling
      const auto& rp_name = run_ctx.getRoamingPartnerName();
      const auto& scrambling_encryption_profile = run_ctx.rootContext()->scramblingEncryptionProfile();
      const auto& scrambling_encryption_profile_itr = scrambling_encryption_profile.find(rp_name);
      if (scrambling_encryption_profile_itr == scrambling_encryption_profile.end()) {
        ENVOY_LOG(trace, "Scrambling encryption profile not found for roaming partner");
        return absl::Status(absl::StatusCode::kNotFound, "Scrambling encryption profile not found for roaming partner");
      }
      const auto& [generation_prefix, key, iv] = scrambling_encryption_profile_itr->second;
      encryption_id = generation_prefix.substr(1);

      // Apply split uri for scrambling
      const auto& result = splitUriForScrambling(uri, run_ctx.rootContext()->getRegexValidPlmn());
      if (!result.ok()) {
        return result.status();
      }
      const auto& [scheme, labels, plmn, portAndResource] = result.value();

      // Apply FQDN scrambling on all labels
      std::string scrambled_labels = "";
      for (const auto& label : labels) {    
        if (scrambled_labels.empty()) {
          const auto& scrambled_label = scramble(label, key, iv, generation_prefix);
          if (scrambled_label.empty()) {
            ENVOY_LOG(trace, "Incorrect scrambling encryption profile");
            return absl::Status(absl::StatusCode::kAborted, "Incorrect scrambling encryption profile");
          }
          absl::StrAppend(&scrambled_labels, scrambled_label);
        } else {
          const auto& scrambled_label = scramble(label, key, iv);
          if (scrambled_label.empty()) {
            ENVOY_LOG(trace, "Incorrect scrambling encryption profile");
            return absl::Status(absl::StatusCode::kAborted, "Incorrect scrambling encryption profile");
          }
          absl::StrAppend(&scrambled_labels, ".", scrambled_label);
        }
      }
      return absl::StrCat(scheme, scrambled_labels, plmn, portAndResource);
      break;
    }
    case Transformation::ONLY_FQDN:
      break;
    case Transformation::NO_TRANSFORMATION:
      break;
    default:
      ENVOY_LOG(trace, "Invalid Transform mode");
      break;
  }

  ENVOY_LOG(trace, "Transform mode not applicable");
  return absl::Status(absl::StatusCode::kUnknown, "Transform mode not applicable");
}

// Scramble after transformation rule in scrambling profile
absl::StatusOr<std::string> EricProxyFilter::transformAndDescramble(
  absl::string_view uri, const Transformation& transform,
  RunContext& run_ctx, std::string& encryption_id
) {
  switch(transform) {
    case Transformation::ONLY_LABEL: {
      // Get encryption profile for descrambling
      const auto& rp_name = run_ctx.getRoamingPartnerName();
      const auto& descrambling_encryption_profiles = run_ctx.rootContext()->descramblingEncryptionProfiles();
      const auto& descrambling_encryption_profiles_itr = descrambling_encryption_profiles.find(rp_name);
      if (descrambling_encryption_profiles_itr == descrambling_encryption_profiles.end()) {
        ENVOY_LOG(trace, "Descrambling encryption profiles not found for roaming partner");
        return absl::Status(absl::StatusCode::kNotFound, "Descrambling encryption profiles not found for roaming partner");
      }

      // Apply split uri for descrambling
      const auto& result = splitUriForScrambling(uri, run_ctx.rootContext()->getRegexValidPlmn());
      if (!result.ok()) {
        return result.status();
      }
      const auto& [scheme, scrambled_labels, plmn, portAndResource] = result.value();

      // Extract generation prefix from first scrambled label
      const uint32_t& generation_prefix_length = 5;
      if (scrambled_labels.at(0).size() <= generation_prefix_length) {
        ENVOY_LOG(trace, "Generation prefix can not be extracted");
        return absl::Status(absl::StatusCode::kNotFound, "Generation prefix can not be extracted");
      }
      const auto& generation_prefix = StringUtil::toUpper(scrambled_labels.at(0).substr(0, generation_prefix_length));
      const auto& descrambling_encryption_profile = descrambling_encryption_profiles_itr->second;
      const auto& descrambling_encryption_profile_itr = descrambling_encryption_profile.find(generation_prefix);
      if (descrambling_encryption_profile_itr == descrambling_encryption_profile.end()) {
        ENVOY_LOG(trace, "Generation prefix not found in descrambling encryption profiles");
        return absl::Status(absl::StatusCode::kNotFound, "Generation prefix not found in descrambling encryption profiles");
      }
      encryption_id = generation_prefix.substr(1);
      const auto& key = descrambling_encryption_profile_itr->second.first;
      const auto& iv = descrambling_encryption_profile_itr->second.second;
      ENVOY_LOG(trace, "generation_prefix: '{}'", generation_prefix);

      // Apply FQDN descrambling on all scrambled labels
      std::string descrambled_labels = "";
      for (const auto& scrambled_label : scrambled_labels) {
        if (descrambled_labels.empty()) {
          const auto& encoded_label = StringUtil::toUpper(scrambled_label.substr(generation_prefix_length));
          const auto& descrambled_label = descramble(encoded_label, key, iv);
          if (descrambled_label.empty()) {
            ENVOY_LOG(trace, "Incorrect descrambling encryption profile");
            return absl::Status(absl::StatusCode::kAborted, "Incorrect descrambling encryption profile");
          }
          absl::StrAppend(&descrambled_labels, descrambled_label);
        } else {
          const auto& encoded_label = StringUtil::toUpper(scrambled_label);
          const auto& descrambled_label = descramble(encoded_label, key, iv);
          if (descrambled_label.empty()) {
            ENVOY_LOG(trace, "Incorrect descrambling encryption profile");
            return absl::Status(absl::StatusCode::kAborted, "Incorrect descrambling encryption profile");
          }
          absl::StrAppend(&descrambled_labels, ".", descrambled_label);
        }
      }
      return absl::StrCat(scheme, descrambled_labels, plmn, portAndResource);
      break;
    }
    case Transformation::ONLY_FQDN:
      break;
    case Transformation::NO_TRANSFORMATION:
      break;
    default:
      ENVOY_LOG(trace, "Invalid Transform mode");
      break;
  }

  ENVOY_LOG(trace, "Transform mode not applicable");
  return absl::Status(absl::StatusCode::kUnknown, "Transform mode not applicable");
}

std::string EricProxyFilter::scramble(
  const std::string& original_string, const unsigned char* key,
  const unsigned char* iv, const std::string& generation_prefix
) {
  ENVOY_LOG(trace, "scramble()");
  ENVOY_LOG(trace, "original_string: '{}'", original_string);

  const EVP_CIPHER* cipher_type = EVP_aes_256_gcm();
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

  // Initialize the encryption operation
  if (!EVP_EncryptInit_ex(ctx, cipher_type, nullptr, key, iv)) {
    ENVOY_LOG(trace, "Init encrypt function failed");
    EVP_CIPHER_CTX_free(ctx);
    return "";
  }

  int len = 0;
  int tag_len = 4;
  int plaintext_len = original_string.size();
  const unsigned char* plaintext = reinterpret_cast<const unsigned char*>(original_string.c_str());
  int ciphertext_len = plaintext_len + EVP_CIPHER_block_size(cipher_type) + tag_len;
  unsigned char* ciphertext = static_cast<unsigned char*>(malloc(ciphertext_len));

  // ENVOY_LOG(trace, "After encrypt init: len: {}, plaintext_len: {}, tag_len: {}, ciphertext_len: {}", len, plaintext_len, tag_len, ciphertext_len);

  // Provide the message to be encrypted, and obtain the encrypted output
  // EVP_EncryptUpdate can be called multiple times if necessary
  if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
    ENVOY_LOG(trace, "Update encrypt function failed");
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    return "";
  }
  ciphertext_len = len;

  // ENVOY_LOG(trace, "After encrypt update: len: {}, plaintext_len: {}, tag_len: {}, ciphertext_len: {}", len, plaintext_len, tag_len, ciphertext_len);

  // Finalise the encryption
  if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    ENVOY_LOG(trace, "Final encrypt function failed");
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    return "";    
  }
  ciphertext_len += len;

  // ENVOY_LOG(trace, "After encrypt final: len: {}, plaintext_len: {}, tag_len: {}, ciphertext_len: {}", len, plaintext_len, tag_len, ciphertext_len);

  // std::cout << std::endl << "Hex representation after AES-256 encryption:" << std::endl << std::endl;
  // for (auto i = ciphertext; i < ciphertext + ciphertext_len; i++) {
  //   std::cout << std::hex << static_cast<int>(*i) << "  ";
  // }
  // std::cout << std::endl << std::endl;

  // Get the tag
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, ciphertext + ciphertext_len)) {
    ENVOY_LOG(trace, "Ctrl cipher context function failed");
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    return "";     
  }

  ciphertext_len += tag_len;

  // ENVOY_LOG(trace, "After encrypt final with tag: len: {}, plaintext_len: {}, tag_len: {}, ciphertext_len: {}", len, plaintext_len, tag_len, ciphertext_len);

  // std::cout << std::endl << "Hex representation after AES-256 encryption with tag:" << std::endl << std::endl;
  // for (auto i = ciphertext; i < ciphertext + ciphertext_len; i++) {
  //   std::cout << std::hex << static_cast<int>(*i) << "  ";
  // }
  // std::cout << std::endl << std::endl;

  std::string encoded_string = Envoy::Base32::encode(reinterpret_cast<char*>(ciphertext), ciphertext_len, false);
  std::string scrambled_string;
  if (!generation_prefix.empty()) {
    scrambled_string = absl::StrCat(generation_prefix, encoded_string);
  } else {
    scrambled_string = encoded_string;
  }

  ENVOY_LOG(trace, "base32_encoded_string: '{}'", encoded_string);
  ENVOY_LOG(trace, "generation_prefix: '{}'", generation_prefix);
  ENVOY_LOG(trace, "scrambled_string: '{}'", scrambled_string);

  // Clean up
  EVP_CIPHER_CTX_free(ctx);
  free(ciphertext);

  return scrambled_string;
}

std::string EricProxyFilter::descramble(
  const std::string& scrambled_string, const unsigned char* key,
  const unsigned char* iv
) {
  ENVOY_LOG(trace, "descramble()");
  ENVOY_LOG(trace, "scrambled_string (base32_encoded_string): '{}'", scrambled_string);

  const EVP_CIPHER* cipher_type = EVP_aes_256_gcm();
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

  // Initialise the decryption operation
  if (!EVP_DecryptInit_ex(ctx, cipher_type, nullptr, key, iv)) {
    ENVOY_LOG(trace, "Init decrypt function failed");
    EVP_CIPHER_CTX_free(ctx);
    return "";
  }

  auto decoded_string = Envoy::Base32::decodeWithoutPadding(scrambled_string);

  // ENVOY_LOG(trace, "Decoded string size: {}", decoded_string.size());

  if (decoded_string.empty()) {
    ENVOY_LOG(trace, "Base32 decoding failed");
    return "";
  }

  // std::cout << std::endl << "Hex representation before AES-256 decryption with tag:" << std::endl << std::endl;
  // for (auto i = reinterpret_cast<const unsigned char*>(decoded_string.c_str()); i < reinterpret_cast<const unsigned char*>(decoded_string.c_str()) + decoded_string.size(); i++) {
  //   std::cout << std::hex << static_cast<int>(*i) << "  ";
  // }
  // std::cout << std::endl << std::endl;

  int len = 0;
  int tag_len = 4;
  int plaintext_len = decoded_string.size() - tag_len;
  if (plaintext_len <= 0) {
    ENVOY_LOG(trace, "Empty decoded bytes after removing tag");
    return "";
  }  
  unsigned char* plaintext = static_cast<unsigned char*>(malloc(plaintext_len + 1));
  int ciphertext_len = plaintext_len;
  const unsigned char* ciphertext = reinterpret_cast<const unsigned char*>(decoded_string.c_str());

  // ENVOY_LOG(trace, "After decrypt init: len: {}, plaintext_len: {}, tag_len: {}, ciphertext_len: {}", len, plaintext_len, tag_len, ciphertext_len);

  // std::cout << std::endl << "Hex representation before AES-256 decryption:" << std::endl << std::endl;
  // for (auto i = ciphertext; i < ciphertext + ciphertext_len; i++) {
  //   std::cout << std::hex << static_cast<int>(*i) << "  ";
  // }
  // std::cout << std::endl << std::endl;

  // Provide the message to be decrypted, and obtain the plaintext output
  // EVP_DecryptUpdate can be called multiple times if necessary
  if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    ENVOY_LOG(trace, "Update decrypt function failed");
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return ""; 
  }
  plaintext_len = len;

  // ENVOY_LOG(trace, "After decrypt update: len: {}, plaintext_len: {}, tag_len: {}, ciphertext_len: {}", len, plaintext_len, tag_len, ciphertext_len);

  // Set expected tag value.
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, reinterpret_cast<uint8_t*>(const_cast<char*>(decoded_string.c_str())) + ciphertext_len)) {
    ENVOY_LOG(trace, "Ctrl cipher context function failed");
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return "";     
  }

  // Finalise the decryption. A positive return value indicates success,
  // anything else is a failure - the plaintext is not trustworthy.
  if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    ENVOY_LOG(trace, "Final decrypt function failed");
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return ""; 
  }
  plaintext_len += len;
  *(plaintext + plaintext_len) = '\0';

  // ENVOY_LOG(trace, "After decrypt final: len: {}, plaintext_len: {}, tag_len: {}, ciphertext_len: {}", len, plaintext_len, tag_len, ciphertext_len);

  std::string descrambled_string(reinterpret_cast<char*>(plaintext));
  ENVOY_LOG(trace, "descrambled_string: '{}'", descrambled_string);

  // Clean up
  EVP_CIPHER_CTX_free(ctx);
  free(plaintext);

  return descrambled_string;
}

/**
 * Returns a string containg a printout of supplied headers.
 * Can be invoked by a logger for debugging and troubleshooting purposes
 */
std::string EricProxyFilter::logHeaders(const Http::RequestOrResponseHeaderMap& headers) const {
  std::string log_message = "\n  ";
  headers.iterate([&](const Http::HeaderEntry& entry) -> Http::HeaderMap::Iterate {
    absl::StrAppend(&log_message, entry.key().getStringView(), ": ", entry.value().getStringView(),
                    "\n  ");
    return Http::HeaderMap::Iterate::Continue;
  });
  return log_message;
}

// Sets the cached RP name (originating_rp_name_) from rpNameTable.
// In real scenarios this is retrieved from the ssl connection but in testing, usually from md
// It also caches the corresponding RoamingPartner configuration from the config
void EricProxyFilter::setOriginatingRpName(){
  // Do we have a test (orig.) rp_name ?
  // For test purposes dynamic metadata "test_rp" in "eric.proxy.test" takes precedence
  if (encoder_callbacks_->streamInfo().dynamicMetadata().filter_metadata().contains("eric.proxy.test")) {
    const auto dynamic_md_eric_proxy_test = encoder_callbacks_->streamInfo().dynamicMetadata().filter_metadata().find("eric.proxy.test");
    if (dynamic_md_eric_proxy_test->second.fields().contains("test_rp_name")) {
      const auto md_test_rp_name = dynamic_md_eric_proxy_test->second.fields().find("test_rp_name");
      originating_rp_name_ = md_test_rp_name->second.string_value();
      ENVOY_STREAM_LOG(debug, "Found test_rp_name in dyn. MD test_rp_name='{}'", *decoder_callbacks_, originating_rp_name_.value_or(""));
      return;
    }
  }
  if(decoder_callbacks_->connection() && decoder_callbacks_->connection()->ssl()){
    if (config_ != nullptr && !config_->protoConfig().rp_name_table().empty()) {
      auto dn_to_rp_table = run_ctx_.rootContext()->kvTable(config_->protoConfig().rp_name_table());
      if (!dn_to_rp_table.empty()) {
        originating_rp_name_ = decoder_callbacks_->connection()->ssl()->getRoamingPartnerName(
            dn_to_rp_table, config_->getDnToRegexTable(), config_updated_at_);
        return;
      }
    }
  }
}

// Set the cluster name and the pool name, which is the cluster name minus the suffix
// that starts with "#!_#"
void EricProxyFilter::setClusterName(const std::string& cluster_name) {
  cluster_name_ = cluster_name;
    auto startpos_suffix = cluster_name.find("#!_#");
    if (startpos_suffix == std::string::npos) {  // no suffix found -> pool name = cluster name
      pool_name_ = cluster_name;
    } else { // suffix found
      pool_name_ = std::string(cluster_name, 0, startpos_suffix);
    }
}

//------------------------------------------------------------------------
// Attempts to find the given metadata key 'metadata_child' on the given metadata structure
// 'filter_metadata' under 'metadata parent' (for example 'eric_proxy'). If metadata key is found,
// its value is compared with the expected 'value' and the result of the comparison is returned
bool EricProxyFilter::findInDynMetadata(
    const ::google::protobuf::Map<std::string, ::google::protobuf::Struct>* filter_metadata,
    const std::string& metadata_parent, const std::string& metadata_child,
    const std::string& value) {
  // Check if Metadata Parent value contains Child value, e.g. eric_proxy.sepp.routing: { support:
  // }
  if (EricProxyFilter::findInDynMetadata(filter_metadata, metadata_parent,
                                         metadata_child)) {
    // Check if specific string value at Parent: { Child: value } exists
    const auto& current_val = EricProxyFilter::extractFromDynMetadata(filter_metadata, metadata_parent, metadata_child);
    return (current_val == value);
  }
  return false;
};

// An overloaded static helper function which checks in the Dynamic Metadata whether a specific
// Child exists under Parent: { Child: ... } and returns true if so, otherwise false. The input
// parameters are metadata_names = Parent.string, value = Child.string
bool EricProxyFilter::findInDynMetadata(
    const ::google::protobuf::Map<std::string, ::google::protobuf::Struct>* filter_metadata,
    const std::string& metadata_parent, const std::string& metadata_child) {
  // Check if specific Child metadata inside Parent metadata exists, e.g. Parent: { Child: ... }
  return (EricProxyFilter::findInDynMetadata(filter_metadata, metadata_parent)
     && (filter_metadata->find(metadata_parent)->second.fields().contains(metadata_child)));
};

// A static helper function which checks in the Dynamic Metadata whether a specific parent
// metadata exists in the given Filter Metadata map and returns true if so, otherwise false. The
// input parameters are the Filter Metadata map from the respective callbacks pointer and the
// Parent.string to be checked for.
bool EricProxyFilter::findInDynMetadata(
    const ::google::protobuf::Map<std::string, ::google::protobuf::Struct>* filter_metadata,
    const std::string& metadata_parent) {
  // Check if specific Parent metadata inside given Filter Metadata exists, e.g. {Parent: {...}}
  return filter_metadata->contains(metadata_parent);
};

// A static helper function which extracts and returns a specific string value from the Dynamic
// Metadata under Parent: { Child: value } The input parameters are the Filter Metadata map from
// the respective callbacks pointer, Parent.string, Child.string and the string value to be
// checked for.
std::string EricProxyFilter::extractFromDynMetadata(
    const ::google::protobuf::Map<std::string, ::google::protobuf::Struct>* filter_metadata,
    const std::string& metadata_parent, const std::string& metadata_child) {
  return filter_metadata->find(metadata_parent)
      ->second.fields()
      .find(metadata_child)
      ->second.string_value();
};

//-------------------------------------------------------------------------------------------------
// Counters processing
//
/** Increments message screening invocations counters.
 */
// TODO(eankokt): Find a way to optimize so that we use a generic function that does any stepping
void EricProxyFilter::incTotalInvocationsCounter() {
  switch (phase_) {
    case FCPhase::Screening1:
      stats_->buildScreeningCounter(pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name(), stats_->invInReq(), decoder_callbacks_).inc();
      ENVOY_STREAM_LOG(trace, "Stepped InReq counter for case: {} and rule: {}",
          *decoder_callbacks_, pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name());
      break;
    case FCPhase::Screening3:
      stats_->buildEgressScreeningCounter(pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name(), stats_->invOutReq(),pool_name_.value(), decoder_callbacks_).inc();
      ENVOY_STREAM_LOG(trace, "Stepped OutReq counter for case: {} and rule: {}"
          , *decoder_callbacks_, pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name());
      break;
    case FCPhase::Screening4:
      stats_->buildEgressScreeningCounter(pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name(), stats_->invInResp(),pool_name_.value(), decoder_callbacks_).inc();
      ENVOY_STREAM_LOG(trace, "Stepped InResp counter for case: {} and rule: {}"
      , *decoder_callbacks_, pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name());
      break;
    case FCPhase::Screening6:
      stats_->buildScreeningCounter(pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name(), stats_->invOutResp(), decoder_callbacks_).inc();
      ENVOY_STREAM_LOG(trace, "Stepped OutResp counter for case: {} and rule: {}",
          *decoder_callbacks_, pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name());
      break;
    default:
      ENVOY_STREAM_LOG(trace, "Routing invocation counters are not stepped", *decoder_callbacks_);
  }
}

/** Increments message screening / routing stage reject counters.
 */
void EricProxyFilter::incRejectCounter() {
  switch (phase_) {
  case FCPhase::Screening1:
    stats_->buildScreeningCounter(pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name(), stats_->rejectIn(), decoder_callbacks_).inc();
    ENVOY_STREAM_LOG(trace, "Stepped InReq reject counter for case: {} and rule: {}",
        *decoder_callbacks_, pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name());
    break;
  case FCPhase::Routing2:
    ENVOY_STREAM_LOG(trace, "Stepping reject counter not applicable for routing stage case: {} and rule: {}",
        *decoder_callbacks_, pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name());
    break;
  case FCPhase::Screening3:
    // stats_->buildScreeningCounter(pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name(), stats_->rejectOut(), decoder_callbacks_).inc();
    stats_->buildEgressScreeningCounter(pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name(), stats_->rejectOut(),pool_name_.value(), decoder_callbacks_).inc();
    ENVOY_STREAM_LOG(trace, "Stepped OutReq reject counter for case: {} and rule: {}",
        *decoder_callbacks_, pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name());
    break;
  default:
    ENVOY_STREAM_LOG(trace, "Wrong filter phase ({}) to increment a reject counter", *decoder_callbacks_, fcPhaseName(phase_));
  }
}

/** Increments message screening drop counters.
 */
void EricProxyFilter::incDropCounter() {
  switch (phase_) {
  case FCPhase::Screening1:
    stats_->buildScreeningCounter(pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name(), stats_->dropIn(), decoder_callbacks_).inc();
    ENVOY_STREAM_LOG(trace, "Stepped InReq drop counter for case: {} and rule: {}",
        *decoder_callbacks_, pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name());
    break;
  case FCPhase::Screening3:
    //stats_->buildScreeningCounter(pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name(), stats_->dropOut(), decoder_callbacks_).inc();
    stats_->buildEgressScreeningCounter(pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name(), stats_->dropOut(),pool_name_.value(), decoder_callbacks_).inc();
    ENVOY_STREAM_LOG(trace, "Stepped OutReq drop counter for case: {} and rule: {}",
        *decoder_callbacks_, pfcstate_fc_name_, (*pfcstate_filter_rule_it_)->name());
    break;
  default:
    ENVOY_STREAM_LOG(trace, "Wrong filter phase ({}) to increment a drop counter", *decoder_callbacks_, fcPhaseName(phase_));
  }
}

//-------------------------------------------------------------------------------------------------
// TODO: these two helper functions will be removed when the sans list is moved under the
// 'RoamingPartner' configuration

// Populates the RoamingPartner object from the configuration, that matches the
// provided RP name (usually retrieved by the ssl connection).
// If no match is found, it does not populate the RP object
void EricProxyFilter::setRpConfigFromRpName() {
  if (config_ && originating_rp_name_.has_value()) {
    for (const auto& rp : config_->protoConfig().roaming_partners()) {
      if (rp.name() == originating_rp_name_.value()) {
        rp_config_ = rp;
      }
    }
  }
}

// Populates the RoamingPartner object from the configuration, based on the provided
// cluster name (the cluster that belongs to the RP).
// If no match is found, it does not populate the RP object
void EricProxyFilter::setRpConfigFromClusterName() {
  if (config_ && cluster_name_.has_value()) {
    for (const auto& rp : config_->protoConfig().roaming_partners()) {
      if (rp.pool_name() == cluster_name_.value()) {
        rp_config_ = rp;
      }
    }
  }
}

// Helper to replace host&port in the source_url with the host&port from the target_url
// If the source_url or target_url cannot be parsed (missing schema for example), then
// the un-modified source_url is returned.
std::string EricProxyFilter::replaceHostPortInUrl(absl::string_view source_url,
                                                  absl::string_view new_host_port,
                                                  absl::string_view scheme,
                                                  Http::StreamDecoderFilterCallbacks* cb) {
  Http::Utility::Url source_url_parts = Http::Utility::Url();
  if (!source_url_parts.initialize(absl::string_view(source_url), false)) {
    if (cb) {
      ENVOY_STREAM_LOG(trace, "Failed to parse source url '{}', returning unmodified source-url",
                       *cb, source_url);
    }
    // Failed to parse URL
    return std::string(source_url);
  }
  if (scheme.empty()) {
    auto source_scheme = source_url_parts.scheme();
    auto source_path_and_query_params = source_url_parts.pathAndQueryParams();

    return absl::StrCat(source_scheme, "://", new_host_port, source_path_and_query_params);
  } else {
    auto source_path_and_query_params = source_url_parts.pathAndQueryParams();

    return absl::StrCat(scheme, "://", new_host_port, source_path_and_query_params);
  }
}

//------------------------------------------------------------------------
// Create and return a Retry Policy for SLF lookup and NF discovery
envoy::config::route::v3::RetryPolicy EricProxyFilter::retryPolicyForLookup(
    Upstream::ThreadLocalCluster* thread_local_cluster,
    std::chrono::milliseconds& timeout){
  envoy::config::route::v3::RetryPolicy retry_policy;
  retry_policy.set_retry_on("5xx,reset,connect-failure,refused-stream");
  retry_policy.add_retry_host_predicate()->set_name("envoy.retry_host_predicates.previous_hosts");
  envoy::extensions::retry::host::previous_hosts::v3::PreviousHostsPredicate previous_hosts_config;
  retry_policy.mutable_retry_host_predicate(0)->mutable_typed_config()->PackFrom(previous_hosts_config);
  // max-retries = MAX(3, num-SLF-hosts-in-cluster) --> try each SLF once
  auto& host_sets = thread_local_cluster->prioritySet().hostSetsPerPriority();
  auto total_host_count = 0;
  for(const auto &hosts : host_sets) {
      total_host_count += hosts->hosts().size();
  }
  auto max_retries = 3;
  if(total_host_count < 3) {
    max_retries = total_host_count;
  }
  retry_policy.mutable_num_retries()->set_value(max_retries);

  // Timeout for one try/retry/reselect is the configured SLF-timeout value divided
  // by the number of max_retries + 1 (the +1 is for the first try AND to protect
  // against division by zero)
  auto per_try_timeout = timeout / (max_retries + 1);
  // The cast drops fractions of a second = we get only whole seconds
  auto seconds = std::chrono::duration_cast<std::chrono::seconds>(per_try_timeout);
  auto nanos = (per_try_timeout - seconds) * 1000;
  retry_policy.mutable_per_try_timeout()->set_nanos(nanos.count());
  retry_policy.mutable_per_try_timeout()->set_seconds(seconds.count());
  return retry_policy;
  }

//------------------------------------------------------------------------

// Report an event from Eric-Proxy.  This function adds:
// - "ID" which is Envoy's stream/request-id and a suffix with an incrementing
//   number. This way, the order of events originating from the same request
//   can be determined (in case they have the same timestamp). The Envoy
//   stream-ID is different from the HTTP/2 stream-ID.
// - the own FQDN into "source"
// - the own node-type into "source-type"
// - the roaming-partner if there is one, otherwise empty string
  void EricProxyFilter::reportEvent(EricEvent::EventType type, EricEvent::EventCategory category,
                                    EricEvent::EventSeverity severity, const std::string& message,
                                    ActionOnFailure action, const std::string& ulid,
                                    absl::optional<std::string> sub_spec) {
    if (action.has_respond_with_error()) {
      EventReporter::reportEventViaFilterState(
          decoder_callbacks_->streamInfo(),
          {type, category, severity, message,
           vec_proto_fw_action_.at(action.action_specifier_case()),
           (rp_config_.has_value()) ? rp_config_->name() : "", config_->ownFqdnLc(),
           config_->nodeTypeUc(), ulid, sub_spec,
           std::to_string(action.respond_with_error().status()),
           action.respond_with_error().detail()});
    } else {
      EventReporter::reportEventViaFilterState(
          decoder_callbacks_->streamInfo(),
          {type, category, severity, message,
           vec_proto_fw_action_.at(action.action_specifier_case()),
           (rp_config_.has_value()) ? rp_config_->name() : "", config_->ownFqdnLc(),
           config_->nodeTypeUc(), ulid, sub_spec});
    }
  }

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
