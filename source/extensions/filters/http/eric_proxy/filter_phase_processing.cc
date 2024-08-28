#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_request_meta.h"
#include "source/common/stream_info/eric_proxy_state.h"
#include <algorithm>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// A request has come in. Go through the three phases ingress
// screening, routing, egress screening:
Http::FilterHeadersStatus EricProxyFilter::processRequestFilterPhases() {
  ENVOY_STREAM_LOG(debug, "ENTER processRequestFilterPhases()", *decoder_callbacks_);
  Http::FilterHeadersStatus return_value;
  // Starting point for the response processing. Default is to execute
  // all phases 4, 5, 6:
  response_start_phase_ = FCPhase::Screening4;

  // Phase 1a: SEPP pre-in_request_screening processing
  if (config_->isSeppNode()){
    // Create SEPP routing Filter-State Object (FSO)
    // Created at the beginning so that on specific points within sepp routing code
    // FSO can be retrieved and manipulated and stored in callbacks_ again
    // And no need to check if result of getMutableData() != nullptr on the request path
    // on the response path since it could be escaped because of configurable body checks it needs
    // to be checked because we definitely create it even before the edge request processing begins
    auto eric_proxy_sepp_state = std::make_unique<StreamInfo::EricProxySeppState>();
    decoder_callbacks_->streamInfo().filterState()
                            ->setData(StreamInfo::EricProxySeppState::key(), std::move(eric_proxy_sepp_state),
                              StreamInfo::FilterState::StateType::Mutable,
                              StreamInfo::FilterState::LifeSpan::Request);
    ENVOY_STREAM_UL_LOG(debug, "Processing Pre-In-Request-Screening phase", *decoder_callbacks_, ULID(S40));
    return_value = seppInRequestEdgeProcessing();
    if (return_value == Http::FilterHeadersStatus::StopIteration) {
      // Remember for the response processing to only start in phase 6
      // and skip phase 4 and 5:   (DO WE EVEN WANT 6 ???)
      response_start_phase_ = FCPhase::Screening6;
      ENVOY_STREAM_LOG(debug, "End Pre-In-Request-Screening phase", *decoder_callbacks_);
      return return_value;
    }
    ENVOY_STREAM_LOG(debug, "End Pre-In-Request-Screening phase", *decoder_callbacks_);
  }

  // Phase 1b: in_request_screening
  // ULID(S36)
  ENVOY_STREAM_UL_LOG(debug, "Processing In-Request-Screening", *decoder_callbacks_, ULID(S36));
  phase_ = FCPhase::Screening1;
  const auto& all_start_fc_in_req_scr = getAllStartFcForInRequestScreening();
  if (all_start_fc_in_req_scr.empty()) {
    ENVOY_STREAM_UL_LOG(trace, "No in-request-screening-case (ph. 1)", *decoder_callbacks_, ULID(S36));
  }
  for (auto& fc_name: all_start_fc_in_req_scr) {
    pfcstate_fc_name_ = fc_name;
    ENVOY_STREAM_UL_LOG(debug, "In-Request-Screening start-screening-case: '{}'", *decoder_callbacks_,
        ULID(S36), fc_name);
    pfcstate_next_state_ = FCState::StartFilterCase;
    return_value = processFilterCase(ProcessFcMode::Screening);
    if (return_value == Http::FilterHeadersStatus::StopIteration) {
      // Remember for the response processing to only start in phase 6
      // and skip phase 4 and 5:
      response_start_phase_ = FCPhase::Screening6;
      ENVOY_STREAM_UL_LOG(debug, "End In-Request-Screening", *decoder_callbacks_, ULID(S36));
      return return_value;
    }
  }
  ENVOY_STREAM_UL_LOG(debug, "End In-Request-Screening", *decoder_callbacks_, ULID(S36));

  if (config_->isNfPeerinfoActivated()) {
    // ULID(S53) Store 3gpp-sbi-nf-peer-info header in dyn-MD
    SbiNfPeerInfoHeaderRequestMetadata::updateSbiPeerInfoHeaderInMd(
        decoder_callbacks_, *run_ctx_.getReqOrRespHeaders());
    // ULID(S54) Delete 3gpp-sbi-nf-peer-info header from request
    SbiNfPeerInfoHeaderRequestMetadata::deleteSbiInfoHeader(*run_ctx_.getReqOrRespHeaders());
  }

  // Phase 2a: SEPP pre-routing request-processing
  // ULID(S18)
  if (config_->isSeppNode()){
    ENVOY_STREAM_UL_LOG(debug, "Processing Pre-routing phase", *decoder_callbacks_, ULID(S18));
    switch(seppRequestPreProcessing()) {
      case SeppReqPreProcResult::Continue:
        // nothing, most common case
        break;
      case SeppReqPreProcResult::DirectResponse:
        {
          // Remember for the response processing to only start in phase 6
          // and skip phase 4 and 5:
          response_start_phase_ = FCPhase::Screening6;
          ENVOY_STREAM_LOG(debug, "End Pre-routing phase", *decoder_callbacks_);
          return Http::FilterHeadersStatus::StopIteration;
        }
      // If the N32c request comes from our manager, there is no start-routing-case
      // configured because this filter is in a separate listener's filter-chain.
      //
      // Responding scenario (= we receive an N32c request from a RP)
      // Additionally, since the user doesn't configure the cluster towards
      // the manager (internal_n32c_server), they cannot configure out-request-screening
      // or in-response-screening because their start-screening-cases are configured
      // in the respective pools  ===> Skip routing, out-request and in-response screening
      // ULID(P05)
      case SeppReqPreProcResult::N32cReqFromRP:
      {
          response_start_phase_ = FCPhase::Response5;
          ENVOY_STREAM_UL_LOG(debug, "End Pre-routing phase. Will skip Routing, Out-Request- and In-Response-Screening phases for N32c request from RP",
              *decoder_callbacks_, ULID(P05));
          return Http::FilterHeadersStatus::Continue;
      }
      case SeppReqPreProcResult::N32cReqFromManager:
      {
          return Http::FilterHeadersStatus::Continue;
      }
      default:
        ENVOY_STREAM_UL_LOG(error, "Unknown return code", *decoder_callbacks_, ULID(S18));
    }
    ENVOY_STREAM_LOG(debug, "End Pre-routing phase", *decoder_callbacks_);
  }

  // DND-38571 DfP in SCP with TaR fails because of missing impl. for setting 
  // :authority to scp-own fqdn and preferred-host MD to host+port in TaR
  // ULID [C14]
  // else { // If SCP
  //   auto tar_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString("3gpp-Sbi-Target-apiRoot"));
  //   auto auth_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(":authority"));
  //   if( tar_hdr.empty())
  //   {
  //     // ULID [C15]
  //     // Check if :authority = own FQDN 
  //     // If no, then client doesnt support TaR and has sent the 
  //     // identity of producer in authority header, to match to our 
  //     // routing rules write :authority with own fqdn and port
  //     if((! auth_hdr.empty())&& ( auth_hdr[0]->value().getStringView() != config_->ownFqdnLc()))
  //     {
  //       // ULID [C16]
  //       run_ctx_.getReqOrRespHeaders()->setCopy(Http::LowerCaseString("3gpp-Sbi-target-apiroot"), 
  //                                       auth_hdr[0]->value().getStringView());
  //       // ULID [C17]
  //       run_ctx_.getReqOrRespHeaders()->remove(Http::LowerCaseString(":authority"));
  //       run_ctx_.getReqOrRespHeaders()->setCopy(Http::LowerCaseString(":authority"), 
  //                                       config_->ownFqdnWithExtPortLc());  
  //     }

  //   }
  // }

  // Phase 2b: routing. Skipped if processing an incoming N32c request from a RP.
  // ULID(S12)
  phase_ = FCPhase::Routing2;
  ENVOY_STREAM_UL_LOG(debug, "Processing Routing phase", *decoder_callbacks_, ULID(S12));
  auto fc_name_opt = getStartFcForRouting();
  // If there is no routing case, we'll run into a 404 (400) later in the
  // Envoy routing table.
  if (fc_name_opt) {
    pfcstate_fc_name_ = fc_name_opt.value();
    ENVOY_STREAM_UL_LOG(debug, "Routing-case name: {}", *decoder_callbacks_, ULID(S12), pfcstate_fc_name_);

    pfcstate_next_state_ = FCState::StartFilterCase;
    return_value = processFilterCase(ProcessFcMode::Screening);
    if (return_value == Http::FilterHeadersStatus::StopIteration) {
      // Remember to skip phase 4 when the response is being processed.
      // This is correct when StopIteration is set because of a direct response
      // or when the request is dropped.
      // However, if the StopIteration is set because of an SLF lookup,
      // then the response_start_phase_ will later (in out-request-screening)
      // be corrected.
      response_start_phase_ = FCPhase::Response5;
      ENVOY_STREAM_UL_LOG(debug, "End Routing phase", *decoder_callbacks_, ULID(S12));
      return return_value;
    }
  }
  ENVOY_STREAM_UL_LOG(debug, "End Routing phase", *decoder_callbacks_, ULID(S12));

  // DND 60738 Add Via Header on request path as per Rel 17 specs
  // Note : To be updated once we move to Upstream Filters and fix model limitation of SCP
  // ULID(S61)
  if(config_->isSeppNode()) {
    // Find the configuration for the roaming partner from the cluster name
    // rp_config_ is also used in an earlier stage but only if the request comes from the
    // external nw -> from a RP
    setRpConfigFromClusterName();
    if(rp_config_) {
      // If rp_config_ is correctly populated we will always get
      // own Fqdns to be used for via header correctly from the manager:
      // Listeners on the internal network have our *external* NW FQDN in the rp_config,
      // while listeners on the ext. nw. have our *internal* NW FQDN in the rp_config.
      // ULID(P12)
      run_ctx_.getReqOrRespHeaders()->appendCopy(Http::Headers::get().Via, "2.0 SEPP-"+ config_->getFqdnForViaHeader(rp_config_->name()));
    }
  } else {
    // ULID(C19)
    run_ctx_.getReqOrRespHeaders()->appendCopy(Http::Headers::get().Via, "2.0 SCP-"+ config_->ownFqdnLc());
  }
  // 3a: out_request_screening
  // ULID(S37)
  return_value = processOutRequestScreening();

  // Do this after egress request screening as it could modify the scheme, path 
  // aspects of TaR (moved from actions_routing to here)
  // If topology-hiding is off:
  // Remember the original target-apiroot header in case we have to
  // re-select the producer and the response doesn't contain a location header
  // TS29.500 R16 ch. 6.10.4
  // ULID(S60)
  if (findInDynMetadata(&decoder_callbacks_->streamInfo().dynamicMetadata().filter_metadata(),
                        "eric_proxy", "target-api-root-processing", "true")) {
    auto tar_hdr =
        run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString("3gpp-sbi-target-apiroot"));
    if (!tar_hdr.empty()) {
      ENVOY_STREAM_UL_LOG(debug, "Setting target-api-root-value dyn MD after egress screening:'{}'",
                          *decoder_callbacks_, ULID(S60), tar_hdr[0]->value().getStringView());
      const auto& eric_proxy_mutable_field = decoder_callbacks_->streamInfo()
                                                 .dynamicMetadata()
                                                 .mutable_filter_metadata()
                                                 ->find("eric_proxy")
                                                 ->second.mutable_fields();
      *(*eric_proxy_mutable_field)["target-api-root-value"].mutable_string_value() =
          std::string(tar_hdr[0]->value().getStringView());
    }
  }

  if (return_value == Http::FilterHeadersStatus::StopIteration) {
    return return_value;
  }

  // 3b: SEPP post-out_request_screening processing
  // ULID(S42)
  if (config_->isSeppNode()){
    ENVOY_STREAM_UL_LOG(debug, "Processing Post-Out-Request-Screening phase", *decoder_callbacks_, ULID(S42a));
    return_value = seppOutRequestEdgeProcessing();
    if (return_value == Http::FilterHeadersStatus::StopIteration) {
      // Remember for the response processing to only start in phase 6
      // and skip phase 4 and 5:
      response_start_phase_ = FCPhase::Screening6;
      ENVOY_STREAM_UL_LOG(debug, "End Post-Out-Request-Screening phase", *decoder_callbacks_, ULID(H33b));
      return return_value;
    }
    ENVOY_STREAM_UL_LOG(debug, "End Post-Out-Request-Screening phase", *decoder_callbacks_, ULID(S38));
  }

  return Http::FilterHeadersStatus::Continue;
}

// ULID(S37) Process out-request-screening a.k.a egress screening
// This is a separate function because it is called from both processFilterCase()
// and from continueProcessingAfterSlfResponse()
Http::FilterHeadersStatus EricProxyFilter::processOutRequestScreening() {
  ENVOY_STREAM_UL_LOG(debug, "Processing Out-Request-Screening", *decoder_callbacks_, ULID(S37a));
  phase_ = FCPhase::Screening3;
  response_start_phase_ = FCPhase::Screening4;
  for (auto& fc_name:  getAllStartFcForOutRequestScreening()) {
    pfcstate_fc_name_ = fc_name;
    ENVOY_STREAM_UL_LOG(debug, "Out-Request-Screening start-screening-case: '{}'", *decoder_callbacks_, ULID(S37b), fc_name);
    pfcstate_next_state_ = FCState::StartFilterCase;
    auto return_value = processFilterCase(ProcessFcMode::Screening);
    if (return_value == Http::FilterHeadersStatus::StopIteration) {
      ENVOY_STREAM_UL_LOG(debug, "End Out-Request-Screening", *decoder_callbacks_, ULID(S37c));
      return return_value;
    }
  }
  ENVOY_STREAM_UL_LOG(debug, "End Out-Request-Screening", *decoder_callbacks_, ULID(S37d));
  return Http::FilterHeadersStatus::Continue;
}


// A response has arrived. Apply egress and ingress message-screening
// and the necessary handling in the routing part.
// If we had a local response in phases 1 or 2 then we have to skip
// response processing for phase 4 and/or 5. This is because Envoy will
// always trigger the "whole" response path when a local reply is sent
// by our filter, so we have to make sure to not execute unwanted filter
// phases in the response path. 
// This is controlled by the variable response_start_phase_ that is set
// when the request is processed.
Http::FilterHeadersStatus EricProxyFilter::processResponseFilterPhases() {
  ENVOY_STREAM_LOG(debug, "ENTER processResponseFilterPhases()", *decoder_callbacks_);
  Http::FilterHeadersStatus return_value;

  // ULID(S48)
  if (config_->isSeppNode()) {
    // ULID(H50) Sepp TH Inresponse Processing
    auto return_val = seppInResponseEdgeProcessing();
    if (return_val == Http::FilterHeadersStatus::StopIteration) {
      ENVOY_STREAM_UL_LOG(debug, "Response processing ends after topo-unhiding/de-scrambling",
                          *decoder_callbacks_, ULID(H50));
      return return_val;
    }
    // DND-60738 TS 29500 Rel 17 Via header handling
    // If internal nw listener 
    // Add Via header with internal n/w FQDN if server header is absent
    // ULID(P13)
    if(!local_reply_ &&
            Http::CodeUtility::is5xx(Http::Utility::getResponseStatus(
                *dynamic_cast<Http::ResponseHeaderMap*>(run_ctx_.getReqOrRespHeaders()))) &&
                run_ctx_.getReqOrRespHeaders()->get(Http::Headers::get().Server).empty()) {
      run_ctx_.getReqOrRespHeaders()->appendCopy(Http::Headers::get().Via,
                                                 "2.0 SEPP-" + config_->ownFqdnLc());
    }
  } else {
    // If SCP Node then add all n/w FQDN on Via header if server header
    // is absent
    // ULID(C20)
    if(!local_reply_ &&
              Http::CodeUtility::is5xx(Http::Utility::getResponseStatus(
                *dynamic_cast<Http::ResponseHeaderMap*>(run_ctx_.getReqOrRespHeaders()))) &&
                run_ctx_.getReqOrRespHeaders()->get(Http::Headers::get().Server).empty()) {
        run_ctx_.getReqOrRespHeaders()->appendCopy(Http::Headers::get().Via,"2.0 SCP-"+ config_->ownFqdnLc());
    }
  }

  // ULID(S34)  Ph. 4: in_response_screening
  if (response_start_phase_ == FCPhase::Screening4) {
    ENVOY_STREAM_UL_LOG(debug, "Processing In-Response-Screening", *decoder_callbacks_, ULID(S34a));
    phase_ = FCPhase::Screening4;
    for (auto& fc_name: getAllStartFcForInResponseScreening()) {
      pfcstate_fc_name_ = fc_name;
      ENVOY_STREAM_UL_LOG(debug, "In-Response-Screening start-screening-case: '{}'", *decoder_callbacks_, ULID(S34b), fc_name);
      pfcstate_next_state_ = FCState::StartFilterCase;
      return_value = processFilterCase(ProcessFcMode::Screening);
      if (return_value == Http::FilterHeadersStatus::StopIteration) {
        ENVOY_STREAM_UL_LOG(debug, "End In-Response-Screening", *decoder_callbacks_, ULID(S34c));
        return return_value;
      }
    }
    ENVOY_STREAM_LOG(debug, "End In-Response-Screening", *decoder_callbacks_);
  }

  // 5: routing response-processing
  if (response_start_phase_ == FCPhase::Screening4 || response_start_phase_ == FCPhase::Response5) {
    // ULID(S24)
    if(config_->isSeppNode()) {
      seppResponsePreProcessing();
    } else if(config_->isScpNode()) {
      // ULID(S33)
      scpResponsePreProcessing();
    }
  }
  // End of SCP/SEPP processing

  // 6a: ULID(S35) out_response_screening
  ENVOY_STREAM_UL_LOG(debug, "Processing Out-Response-Screening", *decoder_callbacks_, ULID(S35a));
  phase_ = FCPhase::Screening6;
  for (auto& fc_name: getAllStartFcForOutResponseScreening()) {
    pfcstate_fc_name_ = fc_name;
    ENVOY_STREAM_UL_LOG(debug, "Out-Response-Screening start-screening-case: '{}'",
                        *decoder_callbacks_, ULID(S35b), fc_name);
    pfcstate_next_state_ = FCState::StartFilterCase;
    return_value = processFilterCase(ProcessFcMode::Screening);
    if (return_value == Http::FilterHeadersStatus::StopIteration) {
      ENVOY_STREAM_UL_LOG(debug, "End Out-Response-Screening", *decoder_callbacks_, ULID(S35c));
      return return_value;
    }
  }
  ENVOY_STREAM_UL_LOG(debug, "End Out-Response-Screening", *decoder_callbacks_, ULID(S35d));

  // 6b: SEPP post-out_response_screening processing
  // ULID(S39)
  if(config_->isSeppNode()) {
    return seppOutResponseEdgeProcessing();
  }

  return Http::FilterHeadersStatus::Continue;
}



} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy



