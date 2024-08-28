#include "envoy/http/header_map.h"
#include "proxy_filter_config.h"
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/header_utility.h"
#include "source/common/http/utility.h"
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <regex>
#include <string>
#include <vector>
#include "source/extensions/filters/http/eric_proxy/tfqdn_codec.h"
#include "source/common/common/empty_string.h"
#include "source/common/stream_info/eric_proxy_state.h"
#include "source/common/network/utility.h"

// Methods in this file are all in the EricProxyFilter class.
// They are stored in a separate file to keep action processing
// separate.

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// ----- Start Service Case Processing -------------

// Check if the service context of given request matches any 
// of the service context vectors for a given roaming partner
// and return all matched service case and filter case names
// TODO : Maybe pull it to contexts.cc 
std::vector<std::pair<std::string, std::string>>
EricProxyFilter::evalServiceContextMatch(std::vector<std::shared_ptr<ServiceCaseWrapper>>&  service_vector) {
  // For all service cases associated with this roaming partner
  // Check which service contexts match with 3gpp Sbi context of this request
  // and return all the names of the service cases along with filter cases that matched
  // During processing of each returned matched service case, the current
  // service case would be stored to service_case_name_
  // The processFilterCase under TopologyHiding flag will then pick up the filter cases
  // from this service_case_name_ and not from config_->filterCaseByName(fc_name)
  std::vector<std::pair<std::string, std::string>> allMatchedScFcNames;
  if (service_vector.empty()) {
    return allMatchedScFcNames;
  }
  for (const auto& svc_case : service_vector) {
    if (svc_case->eval(&run_ctx_)) {
      auto sc_name = svc_case->getServiceCaseName();
      ENVOY_STREAM_LOG(debug, "Matched with service case:'{}'", *decoder_callbacks_, sc_name);
      auto fc_name = svc_case->getMainFilterCaseName();      
      allMatchedScFcNames.push_back(std::make_pair(sc_name, fc_name));
    }
  }
  return allMatchedScFcNames;
}


std::vector<std::pair<std::string, std::string>> EricProxyFilter::getAllMatchedStartScForTopoHiding() {
  auto service_vector =
      config_->getServiceCaseVectorForRP(rp_config_->name(), run_ctx_.isRequest(), true);
  return evalServiceContextMatch(service_vector);
}

std::vector<std::pair<std::string, std::string>> EricProxyFilter::getAllMatchedStartScForTopoUnhiding() {
  auto service_vector =
      config_->getServiceCaseVectorForRP(rp_config_->name(), run_ctx_.isRequest(), false);
  return evalServiceContextMatch(service_vector);
}

// ----------- End Start Service Case Processing -----------

Http::FilterHeadersStatus EricProxyFilter::seppInRequestEdgeProcessing() {
  ENVOY_STREAM_LOG(trace, "seppInRequestEdgeProcessing()", *decoder_callbacks_);

  ENVOY_STREAM_UL_LOG(trace, "Request comes from {} network", *decoder_callbacks_, ULID(P06),
    config_->isOriginExt() ? "ext." : "int.");
  if (config_->isOriginExt()) {
    // Request comes from ext. network

    // ULID(P07)
    switch (n32cSeppPreprocessing()) {
    case SeppReqPreProcResult::N32cReqFromRP:
      // It's an N32c request -> continue with next phase
      return Http::FilterHeadersStatus::Continue;
      break;
    case SeppReqPreProcResult::DirectResponse:
      // No N32c request and no N32c handshake has taken place -> direct response
      // -> continue with out-response-screening (phase 6)
      response_start_phase_ = FCPhase::Screening6;
      ENVOY_STREAM_UL_LOG(debug, "End Pre-routing phase", *decoder_callbacks_, ULID(P07));
      return Http::FilterHeadersStatus::StopIteration;
    default:
      break;
    }

    // ULID(H21) Is topo-hiding (TH) on for this roaming-partner (RP)?
    // Find the name of the roaming partner and its RP configuration
    if (!rp_config_) {
      ENVOY_STREAM_UL_LOG(trace, "No configuration for the RP with name '{}' was found",
                       *decoder_callbacks_, ULID(P07), originating_rp_name_.value_or("unknown"));
      return Http::FilterHeadersStatus::Continue;
    }
    ENVOY_STREAM_UL_LOG(trace, "Found configuration for the RP with name: '{}' (name in config: '{}')",
                     *decoder_callbacks_, ULID(P07), originating_rp_name_.value(), rp_config_->name());

    // Set the Roaming Partner name in run context
    run_ctx_.setRoamingPartnerName(rp_config_->name());

    // ULID(H21) Check if topology-hiding is configured for the roaming partner
    if (!rp_config_->has_topology_hiding()) {
      ENVOY_STREAM_UL_LOG(debug, "TH is off for this RP", *decoder_callbacks_, ULID(H21));
      return Http::FilterHeadersStatus::Continue;
    }
    rp_name_topology_hiding_ = rp_config_->name();
    ENVOY_STREAM_UL_LOG(trace, "RP name {}", *decoder_callbacks_, ULID(H21), rp_name_topology_hiding_.value_or("unknown_rp"));

    // ULID(H21) Topology-hiding configuration found for the roaming partner
    ENVOY_STREAM_UL_LOG(debug, "TH is on for this RP", *decoder_callbacks_, ULID(H21));

    // ULID(H29) Flag "topo_hiding"
    ENVOY_STREAM_UL_LOG(debug, "Flag request Topo-Hiding", *decoder_callbacks_, ULID(H29));
    is_req_flagged_topo_hiding_ = true;

    // ULID(H46)
    // SEPP Topology Unhiding For requests and External listener (Ext-to-Int request flow).
    // FQDN um-mapping (for requetss to our NRF) or FQDN de-scrambling (for other SBI requests).
    // SEPP Topology Unhiding State Machine
    if (rp_config_->topology_hiding().has_service_profile()) {
      ENVOY_STREAM_UL_LOG(debug, "TH Service Profile (FQDN Scrambling/Mapping) is on for this RP", *decoder_callbacks_, ULID(H46));
      // External listener
      // Get Topology Unhiding Service Cases for In-Request
      const auto& all_start_sc_fc = getAllMatchedStartScForTopoUnhiding();
      if (all_start_sc_fc.empty()) {
        ENVOY_STREAM_UL_LOG(debug, "StartFc not found: No service cases matched", *decoder_callbacks_, ULID(H46));
      }
      run_ctx_.stringModifierContext() = std::make_unique<StringModifierContext>();
      for (const auto& start_sc_fc : all_start_sc_fc) {
        ENVOY_STREAM_UL_LOG(debug, "Processing matched service case: '{}', StartFc for Topology Unhiding in In-Request and Ext-to-Int request flow: '{}'",
                         *decoder_callbacks_, ULID(H46), start_sc_fc.first, start_sc_fc.second);
        service_case_name_ = start_sc_fc.first;
        pfcstate_fc_name_ = start_sc_fc.second;
        pfcstate_next_state_ = FCState::StartFilterCase;
        // TODO (enaidev) : Uncomment when all apsects covered for first tests
        auto return_val = processFilterCase(ProcessFcMode::TopologyUnhiding);
        // If direct response then do not enter any of the screening phases 
        // again as User-defined screening is unaware of SeppEdge screening
        if (return_val == Http::FilterHeadersStatus::StopIteration) {
          is_sepp_edge_screening_terminated_ = true;
          ENVOY_STREAM_UL_LOG(debug, "End Sepp Edge Screening for in request", *decoder_callbacks_, ULID(H46));
          return return_val;
        }
        if (
          !run_ctx_.stringModifierContext()->getMappingUnsuccessfulFilterCase().empty() ||
          !run_ctx_.stringModifierContext()->getScramblingUnsuccessfulFilterCase().empty()
        ) {
          break;
        }
      }
      updateSuccessTopologyUnhidingCounters();
    }

    // ULID(H29_1) Flag "topo_hiding"
    // if (roaming_partner->topology_hiding().fqdn_mapping() == true){
    //   ENVOY_STREAM_UL_LOG(debug, "TH FQDN Mapping", *decoder_callbacks_, ULID(H29_1));
    //   if(ingress_th_nrf_fqdn_mapping()!=Http::FilterHeadersStatus::Continue){
    //     return Http::FilterHeadersStatus::StopIteration;
    //   }
    // }


    // ULID(H22) Check if it is a NF discovery request
    if (run_ctx_.getServiceClassifierCtx().getApiName() == "nnrf-disc") { // marked as NF Discovery
      ENVOY_STREAM_UL_LOG(debug, "Request is NF Discovery", *decoder_callbacks_, ULID(H22));

      // Find target NF type
      const auto& path_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(":path"));
      const auto& path_str = !path_hdr.empty() ? path_hdr[0]->value().getStringView() : "";
      const auto query_parameters = Http::Utility::QueryParamsMulti::parseQueryString(path_str);
      const auto target_nf_type_parameter = query_parameters.getFirstValue("target-nf-type");

      // target-nf-type is mandatory if the discovery is for resource "nf-instances" (TS29.510)
      // ULID(H37)
      if (absl::StrContains(path_str, "nf-instances")) {
        ENVOY_STREAM_UL_LOG(trace, "does the path contain 'nf-instances'?", *decoder_callbacks_,"H37");      
        if (!target_nf_type_parameter.has_value()){
          ENVOY_STREAM_UL_LOG(trace, "No query-parameter 'target-nf-type', TH is not applied", *decoder_callbacks_,"H38");
          //TODO: should we reject here (Mandatory IE Missing)
          sendLocalReplyForMissingTargetNfTypeInNfDiscovery();
          return Http::FilterHeadersStatus::StopIteration;
        }
      } else {
        // "Nrf query with 'searches', TH tec. might be applied depending on response content" 
        ENVOY_STREAM_UL_LOG(debug, "Flag request Nnrf_NFDiscovery (search_discovery)", *decoder_callbacks_, ULID(H39));
        is_req_flagged_search_discovery_ = true;
        return Http::FilterHeadersStatus::Continue;
      }
      ENVOY_STREAM_LOG(trace, "target-nf-type = {}", *decoder_callbacks_, target_nf_type_parameter.value_or("empty"));

      // ULID(H13) Flag "nf_discovery"
      ENVOY_STREAM_UL_LOG(
          debug, "Flag request Nnrf_NFDiscovery (nf_instance_discovery) for target-nf-type {}",
          *decoder_callbacks_, ULID(H13), target_nf_type_parameter.value_or("empty"));
      is_req_flagged_nf_instance_discovery_ = true;

      // ULID(H17) Check if TH IP hiding is configured for the roaming partner
      if (rp_config_->topology_hiding().ip_hiding().ip_hiding_per_target_nf_type().empty()) {
        ENVOY_STREAM_UL_LOG(debug, "TH IP Hiding is off for this RP", *decoder_callbacks_, ULID(H17));
        return Http::FilterHeadersStatus::Continue;
      }

      // ULID(H17) TH IP hiding configuration found for the roaming partner
      ENVOY_STREAM_UL_LOG(debug, "TH IP Hiding is on for this RP", *decoder_callbacks_, ULID(H17));

      // ULID(H17) Check if TH IP hiding is configured for the target NF type
      auto ip_hiding_per_target_nf_type =
          rp_config_->topology_hiding().ip_hiding().ip_hiding_per_target_nf_type();
      auto action_on_fqdn_absence_iter =
          ip_hiding_per_target_nf_type.find(target_nf_type_parameter.value_or("empty_nf_type"));

      if (action_on_fqdn_absence_iter == ip_hiding_per_target_nf_type.end()) {
        ENVOY_STREAM_UL_LOG(trace, "TH IP Hiding is not configured for requested nf type {}",
                            *decoder_callbacks_, ULID(H17), target_nf_type_parameter.value_or("empty_nf_type"));
        return Http::FilterHeadersStatus::Continue;
      }

      // ULID(H17) TH IP hiding configured for the target NF type
      // Flag "th_ip_hiding"
      ENVOY_STREAM_UL_LOG(trace, "TH IP Hiding is configured for requested target-nf-type {} -> Flag request",
                          *decoder_callbacks_, ULID(H17), target_nf_type_parameter.value_or("empty_nf_type"));
      is_req_flagged_th_ip_hiding_ = true;

      ip_hiding_action_on_fqdn_absence_ = action_on_fqdn_absence_iter->second;
      ip_hiding_type_on_fqdn_absence_ = action_on_fqdn_absence_iter->first;

    } else {
      ENVOY_STREAM_UL_LOG(debug, "Request is not NF Discovery", *decoder_callbacks_, ULID(H22));
    }
  }

  // No special processing if the request comes from the internal NW or the manager
  return Http::FilterHeadersStatus::Continue;
}

SeppReqPreProcResult EricProxyFilter::seppRequestPreProcessing() {
  // ULID(P00) Is origin = internal network?
  if (config_->isOriginInt()) {
    ENVOY_STREAM_UL_LOG(trace, "Request comes from internal network", *decoder_callbacks_,
                        ULID(T00));

    // ULID(P10) REL17 3gpp-sbi-originating-network-id header handling.
    // If it's present and plmnIds have been provided for the own SEPP,compare the header's contents
    // with the supplied plmn ids. If no match is found, reject. If the header is not present,
    // append it in the following format: 3gpp-Sbi-Originating-Network-Id:
    // '<space>'<primary mcc>-<primary mnc>; src: SEPP-<own_fqdn> Own_fqdn
    // does not contain port as the definition for what comes after 'src: ' does not include ':'
    if (config_->protoConfig().has_plmn_ids()) {
      // ULID(P14)
      const auto& nw_id_hdr = run_ctx_.getReqOrRespHeaders()->get(
          Http::LowerCaseString("3gpp-sbi-originating-network-id"));
      if (!nw_id_hdr.empty() &&
          !performPlmnIdMatch(nw_id_hdr, config_->protoConfig().plmn_ids(), decoder_callbacks_)) {
        // ULID(P15)
        ENVOY_STREAM_UL_LOG(
            trace,
            "3gpp-sbi-originating-network-id header contents: {}, do not match those "
            "configured for the SEPP",
            *decoder_callbacks_, ULID(P15), nw_id_hdr[0]->value().getStringView());

        static const std::string reject_msg =
            R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "plmn_id_mismatch"})";
        sendLocalReplyWithSpecificContentType(
            400, "application/problem+json", reject_msg,
            StreamInfo::ResponseCodeDetails::get().DirectResponse);
        return SeppReqPreProcResult::DirectResponse;
      } else if (nw_id_hdr.empty() && !config_->networkIdHeaderValue().empty()) {
        run_ctx_.getReqOrRespHeaders()->setCopy(
            Http::LowerCaseString("3gpp-Sbi-Originating-Network-Id"),
            config_->networkIdHeaderValue());
      }
    }

    // ULID(T01) Is TFQDN in authority ? (here: is there an :authority header at all?)
    auto auth_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(":authority"));
    ENVOY_STREAM_UL_LOG(trace, ":authority header is empty? {}", *decoder_callbacks_, ULID(T01),
                        auth_hdr.empty());
    if (!auth_hdr.empty()) {
      std::string own_fqdn_suffix = "." + config_->ownFqdnLc();
      auto authority = absl::AsciiStrToLower(auth_hdr[0]->value().getStringView());

      // On request path FSO is never a nullptr
      const auto& filter_state = decoder_callbacks_->streamInfo().filterState();
      const auto& eric_sepp_state = filter_state->getDataMutable<StreamInfo::EricProxySeppState>(
                                              StreamInfo::EricProxySeppState::key());
      // ULID(T01) Is T-FQDN in :authority ?
      if (isTFqdnInAuthority(authority)) {
        ENVOY_STREAM_UL_LOG(trace, "TFqdn is in authority", *decoder_callbacks_, ULID(T01));

        // T-FQDN in :authority ? Y
        ENVOY_STREAM_UL_LOG(debug, "From internal network, T-FQDN present", *decoder_callbacks_,
                            ULID(T05));

        // ULID(T05) Mark Req. as T-FQDN in filter-state-object
        ENVOY_STREAM_UL_LOG(trace, "Mark Req. as T-FQDN in filter-state-object", *decoder_callbacks_,
                            ULID(T05));
        eric_sepp_state->setIsTfqdnRequest(true);
        // TODO(enaidev) : make the following line into a generic function

        // Store the T-FQDN Req. scheme in filter-state-obj.
        auto scheme_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(":scheme"));
        if (!scheme_hdr.empty()) {
          auto scheme = absl::AsciiStrToLower(scheme_hdr[0]->value().getStringView());
          eric_sepp_state->setIsReqHttps(scheme == "https");
        }
        // std::unique_ptr<StreamInfo::EricProxySeppState> eric_sepp_state_ptr(eric_sepp_state);
        // filter_state->setData(StreamInfo::EricProxySeppState::key(),
        //  std::move(eric_sepp_state_ptr),
        //  StreamInfo::FilterState::StateType::Mutable,
        //  StreamInfo::FilterState::LifeSpan::Request);

        // ULID(T07)  T-FQDN -> FQDN in :authority
        auto producer_label = authority.erase(authority.find(own_fqdn_suffix), std::string::npos);
        ENVOY_STREAM_UL_LOG(debug, "Producer label = '{}'", *decoder_callbacks_, ULID(T07),
                            producer_label);

        std::string fqdn = TfqdnCodec::decode(producer_label, decoder_callbacks_);
        if (fqdn == EMPTY_STRING) { // decoding error, no valid TFQDN
          sendLocalReplyWithSpecificContentType(
              400, "application/problem+json",
              R"({"status": 400, "title": "Bad Request", "cause": "MANDATORY_IE_INCORRECT", "detail": "decoding_error_tfqdn_invalid"})",
              StreamInfo::ResponseCodeDetails::get().DirectResponse);
          return SeppReqPreProcResult::DirectResponse;
        }
        ENVOY_STREAM_UL_LOG(debug, "Decoded FQDN = {}", *decoder_callbacks_, ULID(T07), fqdn);

        // ULID(T07) Write decoded producer-label = target host directly to TaR header
        ENVOY_STREAM_UL_LOG(trace,
                            "Write decoded producer-label = target host directly to TaR header",
                            *decoder_callbacks_, ULID(T07));
        createTargetApiRootfromDecodedTFqdnLabel(fqdn, run_ctx_.getReqOrRespHeaders());

        // ULID(T10) Write own FQDN into :authority (so that the vhost matches when going into
        // Envoy routing after our filter is finished)
        ENVOY_STREAM_UL_LOG(trace, "Writing own FQDN into :authority", *decoder_callbacks_, ULID(T10));
        run_ctx_.getReqOrRespHeaders()->setCopy(Http::LowerCaseString(":authority"),
                                      config_->ownFqdnWithIntPortLc());
      } else {
        // ULID(T01)  T-FQDN in :authority ? N
        ENVOY_STREAM_UL_LOG(debug, "from internal network, T-FQDN not present", *decoder_callbacks_,
                            ULID(T01));
        auto tar_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot"));
        // ULID(T02)  3gpp-Sbi-target-apiRoot header present ?
        ENVOY_STREAM_UL_LOG(trace, "Is 3gpp-Sbi-target-apiRoot header empty: {}",
                            *decoder_callbacks_, ULID(T02), tar_hdr.empty());
        if (tar_hdr.empty()) {
          // 3gpp-Sbi-target-apiRoot header present = N
          // ULID(T04)  Is :authority = own FQDN? (ignore port)
          ENVOY_STREAM_UL_LOG(trace, "Is :authority = own FQDN?", *decoder_callbacks_, ULID(T04));
          if (!authorityIsOnlyOwnFqdn(auth_hdr[0]->value().getStringView(), config_->ownFqdnLc())) {
            // ULID(T09)  N:  :authority -> TaR
            ENVOY_STREAM_UL_LOG(trace, ":authority != own FQDN, :authority -> TaR",
                                *decoder_callbacks_, ULID(T09));
            createTargetApiRootfromAuthorityHeader(run_ctx_.getReqOrRespHeaders());
            // ULID(T11)  Write own FQDN and **internal** port into :authority (so that the vhost
            // matches when going into Envoy routing after our filter is finished)
            ENVOY_STREAM_UL_LOG(trace, "Writing own FQDN and **internal** port into :authority",
                                *decoder_callbacks_, ULID(T11));
            run_ctx_.getReqOrRespHeaders()->setCopy(Http::LowerCaseString(":authority"),
                                          config_->ownFqdnWithIntPortLc());
          } // Y: just bypassed the previous line
        } else {
          // ULID(T02)  3gpp-Sbi-target-apiRoot header present = Y
          auto tar = absl::AsciiStrToLower(tar_hdr[0]->value().getStringView());
          // ULID(T03)  T-FQDN in  3gpp-Sbi-target-apiRoot?
          if (isTFqdnInAuthority(tar)) {
            ENVOY_STREAM_UL_LOG(trace, "T-FQDN is in 3gpp-Sbi-target-apiRoot", *decoder_callbacks_,
                                ULID(T03));
            // T-FQDN in  3gpp-Sbi-target-apiRoot = Y
            // ULID(T06)  mark request as T-FQDN in filter-state-obj
            ENVOY_STREAM_UL_LOG(trace, "Marking request as T-FQDN in filter-state-object",
                                *decoder_callbacks_, ULID(T06));
            eric_sepp_state->setIsTfqdnRequest(true);

            auto producer_label = tar.erase(tar.find(own_fqdn_suffix), std::string::npos);
            // ULID(T35) Take out scheme info
            std::string delimiter = "://";
            if (producer_label.find("http://") != std::string::npos ||
                producer_label.find("https://") != std::string::npos) {
              producer_label.erase(0, producer_label.find(delimiter) + delimiter.length());
            }
            ENVOY_STREAM_UL_LOG(debug, "Producer label = {}", *decoder_callbacks_, ULID(T08), producer_label);

            // ULID(T08)  T-FQDN -> FQDN in 3gpp-Sbi-target-apiRoot
            ENVOY_STREAM_UL_LOG(trace, "T-FQDN -> FQDN in 3gpp-Sbi-target-apiRoot",
                                *decoder_callbacks_, ULID(T08));
            std::string fqdn = TfqdnCodec::decode(producer_label, decoder_callbacks_);
            if (fqdn == EMPTY_STRING) { // decoding error, no valid TFQDN
              sendLocalReplyWithSpecificContentType(
                  400, "application/problem+json",
                  R"({"status": 400, "title": "Bad Request", "cause": "MANDATORY_IE_INCORRECT", "detail": "decoding_error_tfqdn_invalid"})",
                  EricProxyResponseCodeDetails::get().TfqdnDecodingFailure);
              return SeppReqPreProcResult::DirectResponse;
            }
            ENVOY_STREAM_UL_LOG(debug, "Decoded FQDN = {}", *decoder_callbacks_, ULID(T08), fqdn);
            createTargetApiRootfromDecodedTFqdnLabel(fqdn, run_ctx_.getReqOrRespHeaders());
          } else {
            ENVOY_STREAM_UL_LOG(trace, "T-FQDN is NOT in 3gpp-Sbi-target-apiRoot",
                                *decoder_callbacks_, ULID(T03));
          }
          // T-FQDN in 3gpp-Sbi-target-apiRoot = N
        }
      }
    }
  } else if (config_->isOriginExt()) {
    // Request comes from ext. network
    ENVOY_STREAM_UL_LOG(trace, "Request comes from ext. network", *decoder_callbacks_, ULID(P05));
    // ULID(P05) Is this an N32c request from a roaming partner?
    if (is_n32c_request_from_rp_) {
      ENVOY_STREAM_UL_LOG(trace, "Bypass routing, out-request screening 3, and in-response screening 4",
          *decoder_callbacks_, ULID(P06));
      return SeppReqPreProcResult::N32cReqFromRP;
    }

    // ULID(P11) REL17 3gpp-sbi-originating-network-id header handling. If it's present and
    // plmnIds have been provided for the originating RP compare the header's contents with the
    // supplied plmn ids. If no match is found, drop the request
    const auto& nw_id_hdr = run_ctx_.getReqOrRespHeaders()->get(
        Http::LowerCaseString("3gpp-sbi-originating-network-id"));
    if (!nw_id_hdr.empty() && rp_config_ && rp_config_->has_plmn_ids() &&
        !performPlmnIdMatch(nw_id_hdr, rp_config_->plmn_ids(), decoder_callbacks_)) {
      ENVOY_STREAM_UL_LOG(trace,
                          "3gpp-sbi-originating-network-id header contents: {}, do not match those "
                          "configured for ingress RP {}",
                          *decoder_callbacks_, ULID(P11), nw_id_hdr[0]->value().getStringView(),
                          rp_config_->name());
      actionDropMessage();
      return SeppReqPreProcResult::DirectResponse;
    }

    // ULID(H01) Check if TH is on for this RP (pseude-profile only, the other topo-hiding
    // is handled elsewhere)
    if (rp_config_ && rp_config_->topology_hiding().pseudo_profiles_size() > 0) { // has TH pseudo profile
      ENVOY_STREAM_UL_LOG(debug, "TH pseudo profile is on", *decoder_callbacks_, ULID(H02));
      ENVOY_STREAM_UL_LOG(debug, "Pseudo profiles size: {}", *decoder_callbacks_, ULID(H02),
                          rp_config_->topology_hiding().pseudo_profiles_size());

      // ULID(H02) Check if it is an NF discovery request

      // TODO: update due to DND-39045
      // do we rely on flags from earlier phases here, or allow "fixes" via ingress-screening?
      // -> service-classification is done once in ULID(S41) and thus the results cannot be
      //    changed by in-request screening (ph.1)
      if (run_ctx_.getServiceClassifierCtx().getApiName() == "nnrf-disc") { // marked as NF Discovery
        ENVOY_STREAM_UL_LOG(debug, "Request is NF Discovery", *decoder_callbacks_, ULID(H11));

        const auto& path_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(":path"));
        const auto& path_str = !path_hdr.empty() ? path_hdr[0]->value().getStringView() : "";
        const auto query_parameters = Http::Utility::QueryParamsMulti::parseQueryString(path_str);
        const auto target_nf_type_parameter = query_parameters.getFirstValue("target-nf-type");

        if (target_nf_type_parameter.has_value()) {
          ENVOY_STREAM_UL_LOG(debug, "target-nf-type = {}", *decoder_callbacks_, ULID(H11),
                              target_nf_type_parameter.value_or("empty_nf_type"));
          // TODO(eedala): convert this loop into a map-lookup where the map is set up at config
          // time
          for (const auto& profile_per_type : rp_config_->topology_hiding().pseudo_profiles()) {
            if (profile_per_type.nf_type() ==
                target_nf_type_parameter.value_or("empty_nf_type")) { // it's configured for nf type
              ENVOY_STREAM_UL_LOG(debug, "Replying with configured pseudo-profile for {}",
                                  *decoder_callbacks_, ULID(H11), profile_per_type.nf_type());
              sendLocalReplyWithSpecificContentType(
                  200, "application/json", profile_per_type.pseudo_profile(), EMPTY_STRING);
              stats_
                  ->buildTHcounters(
                      rp_name_topology_hiding_.value_or("unknown_rp"), // maybe_rp->name()
                      target_nf_type_parameter.value_or("empty_nf_type"), stats_->svcPrefix(),
                      stats_->response(), stats_->thPseudoSearchResult())
                  .inc();
              return SeppReqPreProcResult::DirectResponse;
            }
          }
          ENVOY_STREAM_UL_LOG(debug, "TH pseudo profile not configured for {}, no TH pseudo profile is returned",
                              *decoder_callbacks_, ULID(H11), target_nf_type_parameter.value_or("empty_nf_type"));

        } else {
          ENVOY_STREAM_UL_LOG(debug, "No query-parameter 'target-nf-type', TH pseudo profile is not applied",
                              *decoder_callbacks_, ULID(H11));
        }
      } else {
        ENVOY_STREAM_UL_LOG(debug, "Request is not NF Discovery, TH pseudo profile is not applied",
                            *decoder_callbacks_, ULID(H02));
      }
    } else {
      ENVOY_STREAM_UL_LOG(debug, "TH pseudo profile is off", *decoder_callbacks_, ULID(H01));
    }

    // ULID(P01) If the 3gpp-Sbi-Target-apiRoot header is present -> replace Topo-Hi. pseudo-FQDN
    //           if configured.
    //           If the TaR header is not present and :authority is not our own -> move current
    //           value of :authority into TaR and set own FQDN + **external** port into :authority.
    //           External port because we are here in the path of request from roaming-partner.
    const auto& tar_hdr =
        run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString("3gpp-Sbi-target-apiRoot"));
    ENVOY_STREAM_UL_LOG(trace, "Is 3gpp-Sbi-Target-apiRoot header empty: {}", *decoder_callbacks_,
                        ULID(P01), tar_hdr.empty());
    if (tar_hdr.empty()) { // No, not present
      // ULID(P02) Is :authority = own FQDN? (ignore port)
      const auto& auth_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(":authority"));
      if ((!auth_hdr.empty()) &&
          (!authorityIsOnlyOwnFqdn(auth_hdr[0]->value().getStringView(), config_->ownFqdnLc()))) {
        ENVOY_STREAM_UL_LOG(trace, ":authority != own FQDN", *decoder_callbacks_, ULID(P02));
        // ULID(P03)  N:  :authority -> TaR
        ENVOY_STREAM_UL_LOG(trace, "Writing :authority in TaR", *decoder_callbacks_, ULID(P03));
        createTargetApiRootfromAuthorityHeader(run_ctx_.getReqOrRespHeaders());
        // ULID(P04)  Write own FQDN and **external** port into :authority (so that the vhost
        // matches when going into Envoy routing after our filter is finished)
        ENVOY_STREAM_UL_LOG(trace, "Writing own FQDN and **external** port into :authority",
                            *decoder_callbacks_, ULID(P04));
        run_ctx_.getReqOrRespHeaders()->setCopy(Http::LowerCaseString(":authority"),
                                      config_->ownFqdnWithExtPortLc());
      }
    } else { // 3gpp-Sbi-target-apiRoot is present
      ENVOY_STREAM_UL_LOG(debug, "3gpp-Sbi-target-apiRoot is present", *decoder_callbacks_, "H04");
      // ULID(H04) Is topo-hiding (TH) on for this roaming-partner?
      if (rp_config_ && rp_config_->topology_hiding().pseudo_profiles_size() > 0) { // has TH pseudo profile
        ENVOY_STREAM_UL_LOG(debug, "TH pseudo profile is on", *decoder_callbacks_, ULID(H05));

        const auto& tar = absl::AsciiStrToLower(tar_hdr[0]->value().getStringView());
        ENVOY_STREAM_LOG(trace, "tar: {}", *decoder_callbacks_, tar);
        for (const auto& pseudo_fqdn : rp_config_->topology_hiding().pseudo_fqdn()) {
          if (isPTFqdnInAuthority(tar, pseudo_fqdn)) {
            ENVOY_STREAM_UL_LOG(debug, "Marking request as TH pseudo fqdn", *decoder_callbacks_, ULID(H06));
            // ULID(H06) Remember pseudo-FQDN from request so we can:
            // A) remove TaR header in H07
            // B) stamp it into the location header in the response in H08
            topo_hide_pseudo_fqdn_ = pseudo_fqdn;
            break;
          }
        }
      } else {
        ENVOY_STREAM_UL_LOG(debug, "TH pseudo profile is off", *decoder_callbacks_, ULID(H04));
      }
    }
  }
  // In case no internal or external network port is defined the request is coming
  // from the manager on the n32c dedicated listener, where no preprocessing
  // is needed and seppRequestPreProcessing() can be skipped
  else {
    ENVOY_STREAM_UL_LOG(trace, "Request comes from manager, forwarding to RP", *decoder_callbacks_, ULID(H01));
    return SeppReqPreProcResult::N32cReqFromManager;
  }

  return SeppReqPreProcResult::Continue;
}

// ULID(S42) This (phase 3b) happens after phase 3a (out-request-screening): SEPP-specific actions for
// requests coming from the internal network only.
Http::FilterHeadersStatus EricProxyFilter::seppOutRequestEdgeProcessing() {
  ENVOY_STREAM_UL_LOG(trace, "seppOutRequestEdgeProcessing()", *decoder_callbacks_, ULID(S42));

  if (config_->isOriginInt()) {
    // ULID(H49) Request comes from own network
    ENVOY_STREAM_UL_LOG(trace, "Request comes from own network", *decoder_callbacks_, ULID(H49a));

    // Find the cluster name
    if (!cluster_name_.has_value()) {
      ENVOY_STREAM_UL_LOG(trace, "Routing didn't set cluster name, can not find configuration for the RP",
                          *decoder_callbacks_, ULID(H49b));
      return Http::FilterHeadersStatus::Continue;
    }
    ENVOY_STREAM_UL_LOG(trace, "Found cluster with name: {}", *decoder_callbacks_, ULID(H49c),
                        cluster_name_.value_or("empty"));

    if (!rp_config_) {
      ENVOY_STREAM_UL_LOG(trace, "No configuration for the RP with pool name '{}' was found",
                       *decoder_callbacks_, ULID(H49d), cluster_name_.value_or("empty"));
      return Http::FilterHeadersStatus::Continue;
    }

    ENVOY_STREAM_UL_LOG(trace,
                     "Found configuration for the RP with pool name: '{}' (name in config: '{}')",
                     *decoder_callbacks_, ULID(H49e), cluster_name_.value_or("unknown"), rp_config_->name());

    // Set the Roaming Partner name in run context
    run_ctx_.setRoamingPartnerName(rp_config_->name());

    // ULID(H23) Check if topology-hiding is configured for the roaming partner
    if (!rp_config_->has_topology_hiding()) {
      ENVOY_STREAM_UL_LOG(debug, "TH is off for this RP", *decoder_callbacks_, ULID(H23a));
      return Http::FilterHeadersStatus::Continue;
    }

    // Topology-hiding configuration found for the roaming partner
    ENVOY_STREAM_UL_LOG(debug, "TH is on for this RP", *decoder_callbacks_, ULID(H23b));

    // ULID(H24) SEPP Topology Hiding For requests and internal listener (Int-to-Ext request flow)
    // SEPP Topology Hiding State Machine
    if (rp_config_->topology_hiding().has_service_profile()) {
      ENVOY_STREAM_UL_LOG(debug, "TH Service Profile (FQDN Scrambling/Mapping) is on for this RP",
                          *decoder_callbacks_, ULID(H24a));
      // Internal listener
      // Get Topology Hiding Service Cases for Out-Request
      const auto& all_start_sc_fc = getAllMatchedStartScForTopoHiding();
      if (all_start_sc_fc.empty()) {
        ENVOY_STREAM_UL_LOG(debug, "StartFc not found: No service cases matched", *decoder_callbacks_, ULID(H24b));
      }
      run_ctx_.stringModifierContext() = std::make_unique<StringModifierContext>();
      for (const auto& start_sc_fc : all_start_sc_fc) {
        ENVOY_STREAM_UL_LOG(debug, "Processing matched service case: '{}', StartFc for Topology Hiding in Out-Request and Int-to-Ext request flow: '{}'",
                         *decoder_callbacks_, ULID(H24c), start_sc_fc.first, start_sc_fc.second);
        service_case_name_ = start_sc_fc.first;
        pfcstate_fc_name_ = start_sc_fc.second;
        pfcstate_next_state_ = FCState::StartFilterCase;
        rp_name_topology_hiding_ = rp_config_->name();
        auto return_val = processFilterCase(ProcessFcMode::TopologyHiding);
        // If direct response then do not enter any of the screening phases 
        // again as User-defined screening is unaware of SeppEdge screening
        if(return_val == Http::FilterHeadersStatus::StopIteration) {
          is_sepp_edge_screening_terminated_ = true;
          ENVOY_STREAM_UL_LOG(debug, "End Sepp Edge Screening for out request", *decoder_callbacks_, ULID(H24d));
          return return_val;
        }
        if (!run_ctx_.stringModifierContext()->getMappingUnsuccessfulFilterCase().empty() ||
            !run_ctx_.stringModifierContext()->getScramblingUnsuccessfulFilterCase().empty()) {
          break;
        }
      }
      updateSuccessTopologyHidingCounters();
    }

    // ULID(H30a) Topology-hiding IP-hiding processing
    // Check if TH IP hiding configured for this RP
    if (rp_config_->topology_hiding().ip_hiding().ip_hiding_per_target_nf_type().empty()) {
      ENVOY_STREAM_UL_LOG(debug, "TH IP Hiding is off for this RP", *decoder_callbacks_, ULID(H30a));
      return Http::FilterHeadersStatus::Continue;
    }

    // ULID(H30b) TH IP hiding configuration found for the roaming partner
    ENVOY_STREAM_UL_LOG(debug, "TH IP Hiding is on for this RP", *decoder_callbacks_, ULID(H30b));
    rp_name_topology_hiding_ = rp_config_->name();

    // ULID(H31) Check if request is NF Status Notify and TH IP hiding configured for NF Type
    auto callback_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString("3gpp-Sbi-Callback"));
    if (callback_hdr.empty()) {
      ENVOY_STREAM_UL_LOG(trace, "3gpp-Sbi-Callback header is not present, not hiding any IP addresses", *decoder_callbacks_, ULID(H31a));
      return Http::FilterHeadersStatus::Continue;
    }
    auto cb_hdr_val = callback_hdr[0]->value().getStringView();
    auto brk_pos = cb_hdr_val.find(';');
    if (brk_pos != std::string::npos) {
      cb_hdr_val.remove_suffix(cb_hdr_val.length() - brk_pos);
    }
    if (!(cb_hdr_val == "Nnrf_NFManagement_NFStatusNotify")) {
      ENVOY_STREAM_UL_LOG(trace, "Request is not NF Status Notify, not hiding any IP addresses",
                       *decoder_callbacks_, ULID(H31b));
      return Http::FilterHeadersStatus::Continue;
    }
    ENVOY_STREAM_UL_LOG(trace, "Request is NF Status Notify", *decoder_callbacks_, ULID(H31c));

    const auto json_body = body_->getBodyAsJson();
    // json_body is a nullptr only if body is malformed, if body is empty 
    // json_body is not nullptr but body_->isBodyPresent() returns false
    if (!json_body || !body_->isBodyPresent()) {
      ENVOY_STREAM_UL_LOG(trace, "Cannot parse JSON body, not hiding any IP addresses", *decoder_callbacks_, ULID(H32a));
      sendLocalReplyForInvalidJsonBodyInNfStatusNotify();
      return Http::FilterHeadersStatus::StopIteration;
    }

    if (json_body->contains("nfProfile")) {
      // NF Profile found in the body
      ENVOY_STREAM_UL_LOG(trace, "nfProfile found in body", *decoder_callbacks_, ULID(H31d));

      // Find the NF Type
      if (!json_body->at("nfProfile").contains("nfType")) {
        ENVOY_STREAM_UL_LOG(trace, "No nfType found in body, not hiding any IP addresses", *decoder_callbacks_, ULID(H32b));
        sendLocalReplyForInvalidJsonElementInNfStatusNotify();
        return Http::FilterHeadersStatus::StopIteration;
      }
      if (!json_body->at("nfProfile").at("nfType").is_string()) {
        ENVOY_STREAM_UL_LOG(trace, "nfType in body is not a string, not hiding any IP addresses", *decoder_callbacks_, ULID(H32c));
        sendLocalReplyForInvalidJsonElementInNfStatusNotify();
        return Http::FilterHeadersStatus::StopIteration;
      }

      // NF Type found in the body
      ENVOY_STREAM_UL_LOG(trace, "nfType found in body: {}", *decoder_callbacks_, ULID(H31e),
                          json_body->at("nfProfile").at("nfType"));

      // Check if TH IP hiding configured for the NF Type
      const std::string& target_nf_type = json_body->at("nfProfile").at("nfType");

      if (setThIpHidingIfConfiguredForNfType(rp_config_, target_nf_type)) {
        // TH IP hiding configured for the NF Type
        ENVOY_STREAM_UL_LOG(debug, "TH IP Hiding configured for requested nf type '{}'",
                            *decoder_callbacks_, ULID(H31f), json_body->at("nfProfile").at("nfType"));
        return hideIpAddressesInNfStatusNotifyRequestWithNfProfile();
      } else {
        ENVOY_STREAM_UL_LOG(debug, "TH IP Hiding is not configured for requested nf type '{}'",
                            *decoder_callbacks_, ULID(H31g), json_body->at("nfProfile").at("nfType"));
        return Http::FilterHeadersStatus::Continue;
      }
      
    } else {
      // No NF Profile found in the body, checking for profileChanges
      ENVOY_STREAM_UL_LOG(trace, "No nfProfile found in body, checking for profileChanges", *decoder_callbacks_, ULID(H31h));

      if (!json_body->contains("profileChanges")) {
        ENVOY_STREAM_UL_LOG(trace, "Neither nfProfile nor profileChanges found in body, not hiding any IP addresses",
                            *decoder_callbacks_, ULID(H31i));
        return Http::FilterHeadersStatus::Continue;
      }
      if (!json_body->at("profileChanges").is_array()) {
        ENVOY_STREAM_UL_LOG(trace, "profileChanges is not a list, not hiding any IP addresses", *decoder_callbacks_, ULID(H31j));
        sendLocalReplyForInvalidJsonElementInNfStatusNotify();
        return Http::FilterHeadersStatus::StopIteration;
      }
      // Profile Changes found in the body
      ENVOY_STREAM_UL_LOG(trace, "profileChanges found in body", *decoder_callbacks_, ULID(H31k));

      const auto num_profile_changes = json_body->at("profileChanges").size();
      if (num_profile_changes == 0) {
        ENVOY_STREAM_UL_LOG(trace, "profileChanges is empty, not hiding any IP addresses", *decoder_callbacks_, ULID(H31l));
        return Http::FilterHeadersStatus::Continue;
      }      

      // Check configurations for TH IP Hiding in NF Status Notify with Profile Changes
      if (
        rp_config_->topology_hiding().ip_hiding().ipv4_subnet_per_target_nf_type().empty() &&
        rp_config_->topology_hiding().ip_hiding().ipv6_subnet_per_target_nf_type().empty()
      ) {
        ENVOY_STREAM_UL_LOG(trace, "Neither IPv4 nor IPv6 subnet per target NF type found, not hiding any IP addresses", *decoder_callbacks_, ULID(H31m));
        return Http::FilterHeadersStatus::Continue;
      }

      // TH IP Hiding in NF Status Notify with Profile Changes is configured
      ENVOY_STREAM_UL_LOG(trace, "TH IP Hiding in NF Status Notify with Profile Changes is configured", *decoder_callbacks_, ULID(H31n));
      if (!rp_config_->topology_hiding().ip_hiding().ipv4_subnet_per_target_nf_type().empty()) {
        // ipv4_subnet_per_target_nf_type_ = roaming_partner->topology_hiding().ip_hiding().ipv4_subnet_per_target_nf_type();
        ipv4_subnet_per_target_nf_type_ = config_->
                                          getSubnetCidrNfTypePerRp(true)[rp_config_->name()];
      } else {
        ipv4_subnet_per_target_nf_type_ = absl::nullopt;
      }

      if (!rp_config_->topology_hiding().ip_hiding().ipv6_subnet_per_target_nf_type().empty()) {
        // ipv6_subnet_per_target_nf_type_ = roaming_partner->topology_hiding().ip_hiding().ipv6_subnet_per_target_nf_type();
        ipv6_subnet_per_target_nf_type_ = config_->
                                          getSubnetCidrNfTypePerRp(false)[rp_config_->name()];
      } else {
        ipv6_subnet_per_target_nf_type_ = absl::nullopt;
      }

      return hideIpAddressesInNfStatusNotifyRequestWithProfileChanges();
    }
  }

  return Http::FilterHeadersStatus::Continue;
}

void EricProxyFilter::seppResponsePreProcessing() {
  // ULID(T29)
  ENVOY_STREAM_UL_LOG(debug, "Sepp T-FQDN response processing", *decoder_callbacks_, ULID(T29));
  // T-FQDN response processing
  // IF REQ was marked T-FQDN in dyn. Metadata
  if (isReqMarkedTFqdn()) {
    // ULID(T30) FQDN -> T-FQDN in location header
    ENVOY_STREAM_UL_LOG(debug, "Process response for T-FQDN request", *decoder_callbacks_, ULID(T30));
    auto location_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString("location"));
    if (!location_hdr.empty()) {
      auto location_hdr_value = std::string(location_hdr[0]->value().getStringView());
      auto modified_location_hdr = encodeTfqdnUri(location_hdr_value);
      run_ctx_.getReqOrRespHeaders()->setCopy(Envoy::Http::LowerCaseString("location"),
                                    absl::string_view(modified_location_hdr));
    }
  } else {
    // ELSE REQ was not marked T-FQDN in dyn. Metadata
    //   IF REQ was marked NF-Discovery in dyn. Metadata
    if (isReqMarkedNfDiscovery()) {
      // ULID(T31)
      ENVOY_STREAM_UL_LOG(debug, "Processing NF-Discovery response", *decoder_callbacks_, ULID(T31));
      if (encoder_callbacks_->encodingBuffer() &&
          (encoder_callbacks_->encodingBuffer()->length() > 0)) {
        // ULID(T32) modyfyJson (response body) FQDN -> T-FQDN for
        ENVOY_STREAM_UL_LOG(trace, "modyfy JSON", *decoder_callbacks_, ULID(T32));
        modifyTfqdnInNfDiscoveryResponse();
      } else {
        ENVOY_STREAM_UL_LOG(debug, "Missing NF-Discovery response body", *decoder_callbacks_, ULID(T31b));
      }
    }
  }
  // ULID(T33)
}

// For Sepp Edge Processing on In-Response
Http::FilterHeadersStatus EricProxyFilter::seppInResponseEdgeProcessing() {
  ENVOY_STREAM_LOG(trace, "seppInResponseEdgeProcessing()", *decoder_callbacks_);

  // ULID(H50) SEPP Topology Unhiding For responses and Internal
  // listener (Int-to-Ext request flow)
  // SEPP Topology Unhiding State Machine
  if (config_->isOriginInt() && rp_config_.has_value() &&
      rp_config_.value().has_topology_hiding() &&
      rp_config_.value().topology_hiding().has_service_profile()) {
    ENVOY_STREAM_UL_LOG(debug, "TH Service Profile (FQDN Scrambling/Mapping) is on for this RP", *decoder_callbacks_, ULID(H50));
    // Internal listener
    // Get Topology Unhiding Service Cases for In-Response
    // Only execute SEPP edge screening if request counterpart
    // did not terminate with local reply or StopIteration
    if (!local_reply_ && !is_sepp_edge_screening_terminated_) {
      const auto& all_start_sc_fc = getAllMatchedStartScForTopoUnhiding();
      if (all_start_sc_fc.empty()) {
        ENVOY_STREAM_LOG(debug, "StartFc not found: No service cases matched", *decoder_callbacks_);
      }
      run_ctx_.stringModifierContext() = std::make_unique<StringModifierContext>();
      for (const auto& start_sc_fc : all_start_sc_fc) {
        ENVOY_STREAM_UL_LOG(debug, "Processing matched service case: '{}', StartFc for Topology Unhiding in In-Response and Int-to-Ext request flow: '{}'",
                         *decoder_callbacks_, ULID(H50), start_sc_fc.first, start_sc_fc.second);
        service_case_name_ = start_sc_fc.first;
        pfcstate_fc_name_ = start_sc_fc.second;
        pfcstate_next_state_ = FCState::StartFilterCase;
        // TODO (enaidev) : Uncomment when all apsects covered for first tests
        rp_name_topology_hiding_ = rp_config_->name();
        auto return_val = processFilterCase(ProcessFcMode::TopologyUnhiding);
        // If direct response then do not enter any of the screening phases 
        // again as User-defined screening is unaware of SeppEdge screening
        ENVOY_STREAM_UL_LOG(trace, "return_val: {}, service_case: {}", *decoder_callbacks_, ULID(H50),
                         static_cast<uint64_t>(return_val), service_case_name_);
        if (return_val == Http::FilterHeadersStatus::StopIteration) {
          ENVOY_STREAM_UL_LOG(debug, "End Sepp Edge Screening for in response", *decoder_callbacks_, ULID(H50));
          return return_val;
        }
        if (!run_ctx_.stringModifierContext()->getMappingUnsuccessfulFilterCase().empty() ||
            !run_ctx_.stringModifierContext()->getScramblingUnsuccessfulFilterCase().empty()) {
          break;
        }
      }
      updateSuccessTopologyUnhidingCounters();
    } else {
      ENVOY_STREAM_UL_LOG(debug, "local_reply: {}, SEPP edge screening terminated: {}",
                          *decoder_callbacks_, ULID(H50), local_reply_,
                          is_sepp_edge_screening_terminated_);
    }
  }

  return Http::FilterHeadersStatus::Continue;
}

Http::FilterHeadersStatus EricProxyFilter::seppOutResponseEdgeProcessing() {
  // ULID(H19) Topology-hiding response processing
  ENVOY_STREAM_UL_LOG(debug, "Sepp Topology-hiding response processing", *decoder_callbacks_, ULID(H19));
  auto result = Http::FilterHeadersStatus::Continue;
  const auto status_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(":status"));
  const auto& status_hdr_val = status_hdr[0]->value().getStringView();
  if (is_req_flagged_topo_hiding_) { // Set in H29
    ENVOY_STREAM_UL_LOG(debug, "Process response for Topology-hiding request", *encoder_callbacks_,
                        ULID(H19));
    // ULID(H40) Start DND-39045 (Support "searches" Paths in Envoy) EEDRAK
    ENVOY_STREAM_UL_LOG(debug, "is req. flagged 'search_discovery'?", *encoder_callbacks_, ULID(H40));
    if (is_req_flagged_search_discovery_ && (!status_hdr_val.empty()) && ((status_hdr_val == "200"))) {
      // ULID(H41)
      const auto nf_disc_response_body = body_->getBodyAsJson();
      if (nf_disc_response_body) {
        if (!nf_disc_response_body->at("nfInstances").empty()) {
          auto& extracted_nf_type = nf_disc_response_body->at("nfInstances").at(0).at("nfType");
          ENVOY_STREAM_UL_LOG(debug, "Extracted NF-Type from the first NF-Profile={}",
                              *encoder_callbacks_, ULID(H41a), extracted_nf_type);
          ENVOY_STREAM_UL_LOG(debug, "Set TH flags based on RP configuration and extracted NF-type",
                              *encoder_callbacks_, ULID(H41b), extracted_nf_type);
          is_req_flagged_th_ip_hiding_ =
              setThIpHidingIfConfiguredForNfType(rp_config_, extracted_nf_type);
        }
      }
    }
    // End  DND-39045 (Support "searches" Paths in Envoy) EEDRAK

    // ULID(H47) SEPP Topology Hiding For responses and External
    // listener (Ext-to-Int request flow)
    // SEPP Topology Hiding State Machine
    if (config_->isOriginExt() && rp_config_ &&
        rp_config_->has_topology_hiding() && rp_config_->topology_hiding().has_service_profile()) {
      ENVOY_STREAM_UL_LOG(debug, "TH Service Profile (FQDN Scrambling/Mapping) is on for this RP",
                          *decoder_callbacks_, ULID(H47));
      // External listener
      // Get Topology Hiding Service Cases for Out-Response
      // Do response edge processing only if Request Side counterpart 
      // did not send a local reply or return StopIteration
      if (!local_reply_ && !is_sepp_edge_screening_terminated_) {
        // ULID(H48)
        const auto& all_start_sc_fc = getAllMatchedStartScForTopoHiding();
        if (all_start_sc_fc.empty()) {
          ENVOY_STREAM_UL_LOG(debug, "StartFc not found: No service cases matched",
                              *decoder_callbacks_, ULID(H48a));
        }
        run_ctx_.stringModifierContext() = std::make_unique<StringModifierContext>();
        for (const auto& start_sc_fc : all_start_sc_fc) {
          ENVOY_STREAM_UL_LOG(debug,
                              "Processing matched service case: '{}', StartFc for Topology "
                              "Hiding in Out-Response and Ext-to-Int request flow: '{}'",
                              *decoder_callbacks_, ULID(H48b), start_sc_fc.first,
                              start_sc_fc.second);
          service_case_name_ = start_sc_fc.first;
          pfcstate_fc_name_ = start_sc_fc.second;
          pfcstate_next_state_ = FCState::StartFilterCase;
          auto return_val = processFilterCase(ProcessFcMode::TopologyHiding);
          // If direct response then do not enter any of the screening phases 
          // again as User-defined screening is unaware of SeppEdge screening
          ENVOY_STREAM_UL_LOG(trace, "Return_val: {}, service_case: {}", *decoder_callbacks_,
                           ULID(H48c), static_cast<uint64_t>(return_val), service_case_name_);
          if (return_val == Http::FilterHeadersStatus::StopIteration) {
            ENVOY_STREAM_UL_LOG(debug, "End Sepp Edge Screening for out response",
                                *decoder_callbacks_, ULID(H48d));
            return return_val;
          }
          if (!run_ctx_.stringModifierContext()->getMappingUnsuccessfulFilterCase().empty() ||
              !run_ctx_.stringModifierContext()->getScramblingUnsuccessfulFilterCase().empty()) {
            break;
          }
        }
        updateSuccessTopologyHidingCounters();
      } else {
        ENVOY_STREAM_UL_LOG(debug, "Local_reply: {}, SEPP edge screening terminated:{}", *decoder_callbacks_,
                         ULID(H48e), local_reply_, is_sepp_edge_screening_terminated_);
      }
    }

    // TopoHide Phase2 (IP Hiding)
    // ULID(H26) Topology-hiding IP-hiding response processing
    if (is_req_flagged_th_ip_hiding_ && (!status_hdr_val.empty()) && ((status_hdr_val == "200"))) {
      if (hideIpAddressesInNfDiscoveryResponse() == Http::FilterHeadersStatus::StopIteration) {
        return Http::FilterHeadersStatus::StopIteration;
      }
    }

    // ULID(H09) Topology-hiding pseudo-profile response processing
    if (topo_hide_pseudo_fqdn_.has_value()) {
      ENVOY_STREAM_UL_LOG(debug, "MD has TH pseudo fqdn, TopoHiding value: {}", *decoder_callbacks_,
                          ULID(H09), topo_hide_pseudo_fqdn_.value());
      auto location_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString("location"));
      // ULID(H08) Apply topo-hiding to location-header by replacing the address
      if (!location_hdr.empty()) {
        ENVOY_STREAM_UL_LOG(debug, "Original location header: {}", *decoder_callbacks_, ULID(H08),
                            location_hdr[0]->value().getStringView());
        Http::Utility::Url orig_url = Http::Utility::Url();
        orig_url.initialize(absl::string_view(location_hdr[0]->value().getStringView()), false);
        auto orig_uri_scheme = std::string(orig_url.scheme());
        auto orig_uri_path_and_query_params = std::string(orig_url.pathAndQueryParams());
        auto uri = orig_uri_scheme + "://" + topo_hide_pseudo_fqdn_.value() +
                   orig_uri_path_and_query_params;
        ENVOY_STREAM_UL_LOG(debug, "New location header: {}", *decoder_callbacks_, ULID(H08), uri);
        run_ctx_.getReqOrRespHeaders()->setCopy(Envoy::Http::LowerCaseString("location"),
                                      absl::string_view(uri));
      }
      // ULID(H10)
      // Apply topo-hiding to server-header by removing it. The http-connection-manager
      // will then insert the server_name (which the SEPP manager configured from the
      // service-address fqdn value)
      ENVOY_STREAM_UL_LOG(debug, "Removing 'server' headers from response", *encoder_callbacks_, ULID(H10));
      run_ctx_.getReqOrRespHeaders()->remove(Envoy::Http::LowerCaseString("server"));
    }
  }

  return result;
}

//-------------------------------------------------------------------------------------------------
// TH IP Hiding Processing for Nnrf_NFManagement -> NFStatusNotify
// in NotificationData -> nfProfile

/**
 * Find and delete IP addresses in NF Status Notify request with NF Profile
 */
Http::FilterHeadersStatus EricProxyFilter::hideIpAddressesInNfStatusNotifyRequestWithNfProfile() {
  ENVOY_STREAM_UL_LOG(debug, "Hiding IP Addresses in NF Status Notify Request with NF Profile", *decoder_callbacks_, "H31");

  if (!ip_hiding_action_on_fqdn_absence_.has_value()) {
    ENVOY_STREAM_LOG(trace, "No action on fqdn absence found, not hiding any IP addresses.",
                     *decoder_callbacks_);
    return Http::FilterHeadersStatus::Continue;
  }

  if (!ip_hiding_action_on_fqdn_absence_->has_request_action()) {
    ENVOY_STREAM_LOG(trace, "No request action on fqdn absence found, not hiding any IP addresses.",
                     *decoder_callbacks_);
    return Http::FilterHeadersStatus::Continue;
  }

  // Checking for an error case.
  // Apply Ip Hiding if there is no error case.
  auto result = isThIpHidingErrorCaseInNfProfile();
  if (!result.has_value()) {
    sendLocalReplyForInvalidJsonElementInNfStatusNotify();
    return Http::FilterHeadersStatus::StopIteration;
  }

  if (!result.value()) {
    if (hideIpAddressesInNfProfile() == Http::FilterHeadersStatus::StopIteration) {
      return Http::FilterHeadersStatus::StopIteration;
    }
    stats_
        ->buildTHcounters(rp_name_topology_hiding_.value_or("unknown_rp"),
                          ip_hiding_type_on_fqdn_absence_.value_or("unknown_type"),
                          stats_->typePrefix(), stats_->request(), stats_->appliedSuccess())
        .inc();
    return Http::FilterHeadersStatus::Continue;
  }

  // We have an error case because no fqdn was found, neither on NF Profile level nor on
  // NF Service level
  ENVOY_STREAM_LOG(trace, "Error case: no fqdn was found, neither on NF Profile level nor on NF Service level",
                  *decoder_callbacks_);  
  return handleThIpHidingErrorCaseInNfProfile();
}

/**
 * Check for TH IP Hiding error case in a NF Profile
 */
absl::optional<bool> EricProxyFilter::isThIpHidingErrorCaseInNfProfile() {
  // Checking TH IP Hiding error case in a NF Profile for NF Status Notify
  ENVOY_STREAM_LOG(trace, "Checking for an error case in a NF Profile", *decoder_callbacks_);

  // Checking error case on Profile Level
  // If there is either fqdn or interPlmnFqdn at
  // profile level then there is no error case
  const auto json_body = body_->getBodyAsJson();
  if (
    json_body->at("nfProfile").contains("fqdn") ||
    json_body->at("nfProfile").contains("interPlmnFqdn")
  ) {
    return false;
  }

  // Check for error case in nfServiceList and if nfServiceList is
  // not present then only check for error case in nfServices
  if (json_body->at("nfProfile").contains("nfServiceList")) {
    if (!json_body->at("nfProfile").at("nfServiceList").is_object()) {
      ENVOY_STREAM_LOG(trace, "nfServiceList in nfProfile is not an object, not hiding any IP addresses", *decoder_callbacks_);
      return absl::nullopt;
    }
    // Checking error case on Service Level
    // Since there is neither fqdn nor interPlmnFqdn at
    // profile level therefore if there is neither fqdn
    // nor interPlmnFqdn even at one service level then
    // there is an error case
    for (auto& nf_svc : json_body->at("nfProfile").at("nfServiceList").items()) {
      if (
        !(nf_svc.value().contains("fqdn") ||
        nf_svc.value().contains("interPlmnFqdn"))
      ) {
        return true;
      }
    }
    // Since either fqdn or interPlmnFqdn is present at all 
    // service levels therefore it is not an error case
    return false;
  }
  
  // Since nfServiceList is not present, therefore
  // check for error case in nfServices
  if (json_body->at("nfProfile").contains("nfServices")) {
    if (!json_body->at("nfProfile").at("nfServices").is_array()) {
      ENVOY_STREAM_LOG(trace, "nfServices in nfProfile is not a list, not hiding any IP addresses", *decoder_callbacks_);
      return absl::nullopt;
    }
    // Checking error case on Service Level
    // Since there is neither fqdn nor interPlmnFqdn at
    // profile level therefore if there is neither fqdn
    // nor interPlmnFqdn even at one service level then
    // there is an error case
    for (auto& nf_svc : json_body->at("nfProfile").at("nfServices")) {
      if (
        !(nf_svc.contains("fqdn") ||
        nf_svc.contains("interPlmnFqdn"))
      ) {
        return true;
      }
    }
    // Since either fqdn or interPlmnFqdn is present at all 
    // service levels therefore it is not an error case
    return false;
  }

  // Since there is neither fqdn nor interPlmnFqdn at profile
  // level and there is neither nfServiceList nor nfServices
  // present, therefore it is an error case
  return true;
}

/**
 * Find and delete IP addresses in a NF Profile
 */
Http::FilterHeadersStatus EricProxyFilter::hideIpAddressesInNfProfile() {
  // Applying IP Hiding in a NF Profile for NF Status Notify
  ENVOY_STREAM_LOG(trace, "Applying IP Hiding in a NF Profile", *decoder_callbacks_);

  // IP Hiding on Profile Level
  const auto json_body = body_->getBodyAsJson();
  json_body->at("nfProfile").erase("ipv4Addresses");
  json_body->at("nfProfile").erase("ipv6Addresses");

  // IP Hiding in nfServiceList
  if (json_body->at("nfProfile").contains("nfServiceList")) {
    if (!json_body->at("nfProfile").at("nfServiceList").is_object()) {
      ENVOY_STREAM_LOG(trace, "nfServiceList in nfProfile is not an object, not hiding any IP addresses", *decoder_callbacks_);
      sendLocalReplyForInvalidJsonElementInNfStatusNotify();
      return Http::FilterHeadersStatus::StopIteration;
    }
    // IP Hiding on Service Level
    for (auto& nf_svc : json_body->at("nfProfile").at("nfServiceList").items()) {
      if (nf_svc.value().contains("ipEndPoints")) {
        if (!nf_svc.value().at("ipEndPoints").is_array()) {
          ENVOY_STREAM_LOG(trace, "ipEndPoints for nfServiceList in nfProfile is not a list, not hiding any IP addresses", *decoder_callbacks_);
          sendLocalReplyForInvalidJsonElementInNfStatusNotify();
          return Http::FilterHeadersStatus::StopIteration;
        }
        for (auto& ip_ep : nf_svc.value().at("ipEndPoints")) {
          ip_ep.erase("ipv4Address");
          ip_ep.erase("ipv6Address");
        }
      }
    }
  }
  
  // IP Hiding in nfServices
  if (json_body->at("nfProfile").contains("nfServices")) {
    if (!json_body->at("nfProfile").at("nfServices").is_array()) {
      ENVOY_STREAM_LOG(trace, "nfServices in nfProfile is not a list, not hiding any IP addresses", *decoder_callbacks_);
      sendLocalReplyForInvalidJsonElementInNfStatusNotify();
      return Http::FilterHeadersStatus::StopIteration;
    }
    // IP Hiding on Service Level
    for (auto& nf_svc : json_body->at("nfProfile").at("nfServices")) {
      if (nf_svc.contains("ipEndPoints")) {
        if (!nf_svc.at("ipEndPoints").is_array()) {
          ENVOY_STREAM_LOG(trace, "ipEndPoints for nfServices in nfProfile is not a list, not hiding any IP addresses", *decoder_callbacks_);
          sendLocalReplyForInvalidJsonElementInNfStatusNotify();
          return Http::FilterHeadersStatus::StopIteration;
        }
        for (auto& ip_ep : nf_svc.at("ipEndPoints")) {
          ip_ep.erase("ipv4Address");
          ip_ep.erase("ipv6Address");
        }
      }
    }
  }

  body_->setBodyFromJson(json_body);

  return Http::FilterHeadersStatus::Continue;
}

/**
 * Handle TH IP Hiding error case in NF Profile with configured action
 */
Http::FilterHeadersStatus EricProxyFilter::handleThIpHidingErrorCaseInNfProfile() {
  auto request_action = ip_hiding_action_on_fqdn_absence_->request_action();
  stats_
      ->buildTHcounters(rp_name_topology_hiding_.value_or("unknown_rp"),
                        ip_hiding_type_on_fqdn_absence_.value_or("unknown_type"),
                        stats_->typePrefix(), stats_->request(), stats_->fqdnMissing())
      .inc();

  // Applying request action on fqdn absence
  switch (request_action.action_case()) {
  case ThActionOnFqdnAbsence::Action::kApplyIpHiding:
    ENVOY_STREAM_LOG(trace, "Applying apply_ip_hiding request action on fqdn absence", *decoder_callbacks_);
    if (hideIpAddressesInNfProfile() == Http::FilterHeadersStatus::StopIteration) {
      return Http::FilterHeadersStatus::StopIteration;
    }
    stats_
        ->buildTHcounters(rp_name_topology_hiding_.value_or("unknown_rp"),
                          ip_hiding_type_on_fqdn_absence_.value_or("unknown_type"),
                          stats_->typePrefix(), stats_->request(), stats_->appliedSuccess())
        .inc();
    return Http::FilterHeadersStatus::Continue;
    break;
  case ThActionOnFqdnAbsence::Action::kForward:
    ENVOY_STREAM_LOG(trace, "Applying forward request action on fqdn absence", *decoder_callbacks_);
    return Http::FilterHeadersStatus::Continue;
    break;
  case ThActionOnFqdnAbsence::Action::kDrop:
    ENVOY_STREAM_LOG(trace, "Applying drop request action on fqdn absence", *decoder_callbacks_);
    actionDropMessage();
    return Http::FilterHeadersStatus::StopIteration;
    break;
  case ThActionOnFqdnAbsence::Action::kRespondWithError:
    ENVOY_STREAM_LOG(trace, "Applying respond_with_error request action on fqdn absence", *decoder_callbacks_);
    respondWithError(request_action.respond_with_error());
    return Http::FilterHeadersStatus::StopIteration;
    break;
  default:
    ENVOY_STREAM_LOG(trace, "Invalid request action on fqdn absence.", *decoder_callbacks_);
    return Http::FilterHeadersStatus::Continue;
    break;
  }
}

//-------------------------------------------------------------------------------------------------
// TH IP Hiding Processing for Nnrf_NFManagement -> NFStatusNotify
// in NotificationData -> profileChanges

/**
 * Find and delete IP addresses in NF Status Notify request with Profile Changes
 */
Http::FilterHeadersStatus EricProxyFilter::hideIpAddressesInNfStatusNotifyRequestWithProfileChanges() {
  ENVOY_STREAM_UL_LOG(debug, "Hiding IP Addresses in NF Status Notify Request with Profile Changes", *decoder_callbacks_, "H31");

  // Find NF Type
  auto result = findNfTypeInNfStatusNotifyRequestWithProfileChanges();
  if (!result.has_value()) {
    ENVOY_STREAM_LOG(trace, "Configuration error for TH IP Hiding in NF Status Notify with Profile Changes", *decoder_callbacks_);
    stats_
    ->buildTHcounters(rp_name_topology_hiding_.value_or("unknown_rp"),
                      ip_hiding_profile_changes_nf_type_.value_or("unknown_type"),
                      stats_->typePrefix(), stats_->request(), stats_->configurationError())
    .inc();
    return Http::FilterHeadersStatus::Continue;
  }

  if (result.value() == Http::FilterHeadersStatus::StopIteration) {
    return Http::FilterHeadersStatus::StopIteration;
  }

  if (!ip_hiding_profile_changes_nf_type_.has_value() || ip_hiding_profile_change_indices_.empty()) {
    ENVOY_STREAM_LOG(trace, "No NF Type can be found because no IP Addresses are found in Profile Changes that belong to configured subnets, not hiding any IP addresses",
                     *decoder_callbacks_);
    return Http::FilterHeadersStatus::Continue;
  }
  // NF Type found
  ENVOY_STREAM_LOG(trace, "NF Type found: {}", *decoder_callbacks_, ip_hiding_profile_changes_nf_type_.value());
  stats_
  ->buildTHcounters(rp_name_topology_hiding_.value_or("unknown_rp"),
                    ip_hiding_profile_changes_nf_type_.value_or("unknown_type"),
                    stats_->typePrefix(), stats_->request(), stats_->appliedSuccess())
  .inc();

  return hideIpAddressesInProfileChanges();
}

absl::optional<Http::FilterHeadersStatus> EricProxyFilter::findNfTypeInNfStatusNotifyRequestWithProfileChanges() {
  const auto json_body = body_->getBodyAsJson();
  const auto num_profile_changes = json_body->at("profileChanges").size();

  for (uint32_t profile_change_idx = 0; profile_change_idx < num_profile_changes; profile_change_idx++) {
    if (!json_body->at("profileChanges").at(profile_change_idx).contains("path")) {
      ENVOY_STREAM_LOG(trace, "path in profileChanges is not found, not hiding any IP addresses", *decoder_callbacks_);
      sendLocalReplyForInvalidJsonElementInNfStatusNotify();
      return Http::FilterHeadersStatus::StopIteration;
    }
    if (!json_body->at("profileChanges").at(profile_change_idx).at("path").is_string()) {
      ENVOY_STREAM_LOG(trace, "path in profileChanges is not a string, not hiding any IP addresses", *decoder_callbacks_);
      sendLocalReplyForInvalidJsonElementInNfStatusNotify();
      return Http::FilterHeadersStatus::StopIteration;
    }

    std::string path = json_body->at("profileChanges").at(profile_change_idx).at("path");
    if (std::regex_match(path, config_->regexIpv4Addresses())) {
      auto result = findNfTypeForIpv4AddressesInProfileChange(profile_change_idx);
      if (!result.has_value()) {
        return absl::nullopt;
      }
      if (result.value() == Http::FilterHeadersStatus::StopIteration) {
        return Http::FilterHeadersStatus::StopIteration;
      }
    } else if (std::regex_match(path, config_->regexIpv6Addresses())) {
      auto result = findNfTypeForIpv6AddressesInProfileChange(profile_change_idx);
      if (!result.has_value()) {
        return absl::nullopt;
      }
      if (result.value() == Http::FilterHeadersStatus::StopIteration) {
        return Http::FilterHeadersStatus::StopIteration;
      }
    } else if (std::regex_match(path, config_->regexIpv4Address())) {
      auto result = findNfTypeForIpv4AddressInProfileChange(profile_change_idx);
      if (!result.has_value()) {
        return absl::nullopt;
      }
      if (result.value() == Http::FilterHeadersStatus::StopIteration) {
        return Http::FilterHeadersStatus::StopIteration;
      }
    } else if (std::regex_match(path, config_->regexIpv6Address())) {
      auto result = findNfTypeForIpv6AddressInProfileChange(profile_change_idx);
      if (!result.has_value()) {
        return absl::nullopt;
      }
      if (result.value() == Http::FilterHeadersStatus::StopIteration) {
        return Http::FilterHeadersStatus::StopIteration;
      }
    }
  }

  return Http::FilterHeadersStatus::Continue;
}

absl::optional<Http::FilterHeadersStatus> EricProxyFilter::findNfTypeForIpv4AddressesInProfileChange(const int& profile_change_idx) {
  return findNfTypeForIpAddressesInProfileChange(ipv4_subnet_per_target_nf_type_, profile_change_idx);
}

absl::optional<Http::FilterHeadersStatus> EricProxyFilter::findNfTypeForIpv6AddressesInProfileChange(const int& profile_change_idx) {
  return findNfTypeForIpAddressesInProfileChange(ipv6_subnet_per_target_nf_type_, profile_change_idx);
}

absl::optional<Http::FilterHeadersStatus> EricProxyFilter::findNfTypeForIpAddressesInProfileChange(
  const absl::optional<std::map<std::string,std::vector<Network::Address::CidrRange>>>& ip_subnet_per_target_nf_type,
  const int&  profile_change_idx
) {
  // Return if IP subnet per target NF type is not configured
  if (!ip_subnet_per_target_nf_type.has_value()) {
    return Http::FilterHeadersStatus::Continue;
  }

  const auto json_body = body_->getBodyAsJson();
  if (json_body->at("profileChanges").at(profile_change_idx).contains("newValue")) {
    if (!json_body->at("profileChanges").at(profile_change_idx).at("newValue").is_array()) {
      ENVOY_STREAM_LOG(trace, "newValue in profileChanges is not a list for IpAddresses, not hiding any IP addresses", *decoder_callbacks_);
      sendLocalReplyForInvalidJsonElementInNfStatusNotify();
      return Http::FilterHeadersStatus::StopIteration;
    }

    auto num_ip_addresses = json_body->at("profileChanges").at(profile_change_idx).at("newValue").size();
    for (uint32_t ip_addresses_idx = 0; ip_addresses_idx < num_ip_addresses; ip_addresses_idx++) {
      if (!json_body->at("profileChanges").at(profile_change_idx).at("newValue").at(ip_addresses_idx).is_string()) {
        ENVOY_STREAM_LOG(trace, "Element of newValue list in profileChanges is not a string, not hiding any IP addresses", *decoder_callbacks_);
        sendLocalReplyForInvalidJsonElementInNfStatusNotify();
        return Http::FilterHeadersStatus::StopIteration;
      }
      
      std::string ip_address = json_body->at("profileChanges").at(profile_change_idx).at("newValue").at(ip_addresses_idx);
      for (auto& itr : ip_subnet_per_target_nf_type.value()) {
        for (auto subnet_idx = 0; subnet_idx < static_cast<int>(itr.second.size()); subnet_idx++) {
          if (isIpAddressInSubnet(ip_address, itr.second.at(subnet_idx))) {
            // Checking if we already found NF Type and if we already have NF Type but
            // it is different from current NF Type then it is a configuration error
            if (ip_hiding_profile_changes_nf_type_.has_value()) {
              if (itr.first != ip_hiding_profile_changes_nf_type_.value()) {
                return absl::nullopt;
              }
            }
            // Found NF Type
            ip_hiding_profile_changes_nf_type_ = itr.first;
            // IP address in current profile change index belongs to the configured
            // subnet, we need to delete the current index from Profile Changes.
            // To do this, we have to store indices of Profile Changes which we want to
            // delete in a vector and use this vector later on to delete these indices.
            // But when we delete an element from vector then the size of vector is decreased
            // by one and hence, the indices should also be decreased by one in order to
            // delete the correct element further.
            // Therefore, we are storing the indices here subtracted by the current
            // size of the vector which stores the indices.
            ip_hiding_profile_change_indices_.push_back(profile_change_idx - ip_hiding_profile_change_indices_.size());
            return Http::FilterHeadersStatus::Continue;
          }
        }
      }
    }
  }

  return Http::FilterHeadersStatus::Continue;
}

absl::optional<Http::FilterHeadersStatus> EricProxyFilter::findNfTypeForIpv4AddressInProfileChange(const int& profile_change_idx) {
  return findNfTypeForIpAddressInProfileChange(ipv4_subnet_per_target_nf_type_, profile_change_idx);
}

absl::optional<Http::FilterHeadersStatus> EricProxyFilter::findNfTypeForIpv6AddressInProfileChange(const int& profile_change_idx) {
  return findNfTypeForIpAddressInProfileChange(ipv6_subnet_per_target_nf_type_, profile_change_idx);
}

absl::optional<Http::FilterHeadersStatus> EricProxyFilter::findNfTypeForIpAddressInProfileChange(
  const absl::optional<std::map<std::string,std::vector<Network::Address::CidrRange>>>& ip_subnet_per_target_nf_type,
  const int&  profile_change_idx
) {
  // Return if IP subnet per target NF type is not configured
  if (!ip_subnet_per_target_nf_type.has_value()) {
    return Http::FilterHeadersStatus::Continue;
  }

  const auto json_body = body_->getBodyAsJson();
  if (json_body->at("profileChanges").at(profile_change_idx).contains("newValue")) {
    if (!json_body->at("profileChanges").at(profile_change_idx).at("newValue").is_string()) {
      ENVOY_STREAM_LOG(trace, "newValue in profileChanges is not a string for IpAddress, not hiding any IP addresses", *decoder_callbacks_);
      sendLocalReplyForInvalidJsonElementInNfStatusNotify();
      return Http::FilterHeadersStatus::StopIteration;
    }

    std::string ip_address = json_body->at("profileChanges").at(profile_change_idx).at("newValue");
    for (auto& itr : ip_subnet_per_target_nf_type.value()) {
      for (int subnet_idx = 0; subnet_idx < static_cast<int>(itr.second.size()); subnet_idx++) {
        if (isIpAddressInSubnet(ip_address, itr.second.at(subnet_idx))) {
          // Checking if we already found NF Type and if we already have NF Type but
          // it is different from current NF Type then it is a configuration error
          if (ip_hiding_profile_changes_nf_type_.has_value()) {
            if (itr.first != ip_hiding_profile_changes_nf_type_.value()) {
              return absl::nullopt;
            }
          }
          // Found NF Type
          ip_hiding_profile_changes_nf_type_ = itr.first;
          // IP address in current profile change index belongs to the configured
          // subnet, we need to delete the current index from Profile Changes.
          // To do this, we have to store indices of Profile Changes which we want to
          // delete in a vector and use this vector later on to delete these indices.
          // But when we delete an element from vector then the size of vector is decreased
          // by one and hence, the indices should also be decreased by one in order to
          // delete the correct element further.
          // Therefore, we are storing the indices here subtracted by the current
          // size of the vector which stores the indices.
          ip_hiding_profile_change_indices_.push_back(profile_change_idx - ip_hiding_profile_change_indices_.size());
          return Http::FilterHeadersStatus::Continue;
        }
      }
    }
  }

  return Http::FilterHeadersStatus::Continue;
}

bool EricProxyFilter::isIpAddressInSubnet(const std::string& ip_address,
                                          const Network::Address::CidrRange& subnet_range) {
  // If the subnet range is not valid, always return false:
  if (!subnet_range.isValid()) {
    return false;
  }
  Network::Address::InstanceConstSharedPtr addr = Network::Utility::parseInternetAddressNoThrow(ip_address);
  // Address cannot be parsed -> cannot be in subnet
  if (addr == nullptr) {
    return false;
  }
  // IsInRange() takes care of IPv4 vs IPv6 and returns false if address and subnet use
  // different versions:
  if (subnet_range.isInRange(*addr)) {
    return true;
  }
  return false;
}

Http::FilterHeadersStatus EricProxyFilter::hideIpAddressesInProfileChanges() {
  // Applying IP Hiding in Profile Changes for NF Status Notify
  const auto json_body = body_->getBodyAsJson();

  for (auto& itr : ip_hiding_profile_change_indices_) {
    json_body->at("profileChanges").erase(itr);
  }

  body_->setBodyFromJson(json_body);

  return Http::FilterHeadersStatus::Continue;
}

//-------------------------------------------------------------------------------------------------
// TH IP Hiding Processing for Nnrf_NFDiscovery -> NFDiscover
// in SearchResult -> nfInstances


// Find and delete IP addresses in an NRF Discovery Response
Http::FilterHeadersStatus EricProxyFilter::hideIpAddressesInNfDiscoveryResponse() {
  // ULID(H26)
  ENVOY_STREAM_UL_LOG(debug, "Hiding IP Addresses in NF Discovery Response", *encoder_callbacks_, ULID(H26));

  const auto json_body = body_->getBodyAsJson();
  // json_body is a nullptr only if body is malformed , if body is empty 
  // json_body is not nullptr but body_->isBodyPresent() returns false
  if (!json_body || !body_->isBodyPresent()) {
    ENVOY_STREAM_UL_LOG(trace, "Cannot parse JSON body, not hiding any IP addresses",
                        *encoder_callbacks_, ULID(H26b));
    sendLocalReplyForInvalidJsonBodyInNfDiscovery();
    return Http::FilterHeadersStatus::StopIteration;
  }

  if (!json_body->contains("nfInstances")) {
    ENVOY_STREAM_UL_LOG(trace, "No nfInstances found in body, not hiding any IP addresses",
                        *encoder_callbacks_, ULID(H26c));
    sendLocalReplyForInvalidJsonElementInNfDiscovery();
    return Http::FilterHeadersStatus::StopIteration;
  }
  if (!json_body->at("nfInstances").is_array()) {
    ENVOY_STREAM_UL_LOG(trace, "nfInstances is not a list, not hiding any IP addresses",
                        *encoder_callbacks_, ULID(H26d));
    sendLocalReplyForInvalidJsonElementInNfDiscovery();
    return Http::FilterHeadersStatus::StopIteration;
  }
  // NF Instances found in body
  ENVOY_STREAM_UL_LOG(trace, "nfInstances found in body", *encoder_callbacks_, ULID(H26e));

  if (json_body->at("nfInstances").empty()) {
    ENVOY_STREAM_UL_LOG(trace, "nfInstances is empty, not hiding any IP addresses",
                        *encoder_callbacks_, ULID(H26f));
    return Http::FilterHeadersStatus::Continue;
  }

  if (!ip_hiding_action_on_fqdn_absence_.has_value()) {
    ENVOY_STREAM_UL_LOG(trace, "No action on fqdn absence found, not hiding any IP addresses.",
                        *encoder_callbacks_, ULID(H26g));
    return Http::FilterHeadersStatus::Continue;
  }

  if (!ip_hiding_action_on_fqdn_absence_->has_response_action()) {
    ENVOY_STREAM_UL_LOG(trace,
                        "No response action on fqdn absence found, not hiding any IP addresses.",
                        *encoder_callbacks_, ULID(H26h));
    return Http::FilterHeadersStatus::Continue;
  }

  // Checking for an error case.
  // Apply Ip Hiding if there is no error case.
  auto result = isThIpHidingErrorCaseInNfInstances();
  if (!result.has_value()) {
    // ULID(H36)
    sendLocalReplyForInvalidJsonElementInNfDiscovery();
    return Http::FilterHeadersStatus::StopIteration;
  }

  if (!result.value()) {
    if (hideIpAddressesInNfInstances() == Http::FilterHeadersStatus::StopIteration) {
      return Http::FilterHeadersStatus::StopIteration;
    }
    stats_
        ->buildTHcounters(rp_name_topology_hiding_.value_or("unknown_rp"),
                          ip_hiding_type_on_fqdn_absence_.value_or("unknown_type"),
                          stats_->typePrefix(), stats_->response(), stats_->appliedSuccess())
        .inc();
    return Http::FilterHeadersStatus::Continue;
  }

  // We have an error case because no fqdn was found, neither on NF Profile level nor on
  // NF Service level
  ENVOY_STREAM_UL_LOG(trace, "Error: No FQDN was found, neither on NF Profile level nor on NF Service level",
                   *encoder_callbacks_, ULID(H26n));
  return handleThIpHidingErrorCaseInNfInstances();
}

/**
 * Check for TH IP Hiding error case in NF Instances (multiple NF Profiles)
 */
absl::optional<bool> EricProxyFilter::isThIpHidingErrorCaseInNfInstances() {
  // Checking TH IP Hiding error case in NF Instances for NF Discovery
  ENVOY_STREAM_LOG(trace, "Checking for an error case in NF Instances", *encoder_callbacks_);

  const auto json_body = body_->getBodyAsJson();

  for (auto& nf_inst : json_body->at("nfInstances")) {
    // Checking error case on Profile Level
    // If there is fqdn at profile level then
    // we will move to next NF Instance
    if (nf_inst.contains("fqdn")) {
      continue;
    }

    // Check for error case in nfServiceList and if nfServiceList is
    // not present then only check for error case in nfServices
    if (nf_inst.contains("nfServiceList")) {
      if (!nf_inst.at("nfServiceList").is_object()) {
        ENVOY_STREAM_LOG(trace, "nfServiceList in nfInstances is not an object, not hiding any IP addresses", *encoder_callbacks_);
        return absl::nullopt;
      }
      // Checking error case on Service Level
      // Since there is no fqdn at profile level therefore
      // if there is no fqdn even at one service level
      // then there is an error case
      for (auto& nf_svc : nf_inst.at("nfServiceList").items()) {
        if (!nf_svc.value().contains("fqdn")) {
          return true;
        }
      }
      // Since fqdn is present at all service levels
      // therefore we will move to next NF Instance
      continue;
    }

    // Since nfServiceList is not present, therefore
    // check for error case in nfServices
    if (nf_inst.contains("nfServices")) {
      if (!nf_inst.at("nfServices").is_array()) {
        ENVOY_STREAM_LOG(trace, "nfServices in nfInstances is not a list, not hiding any IP addresses", *encoder_callbacks_);
        return absl::nullopt;
      }
      // Checking error case on Service Level
      // Since there is no fqdn at profile level therefore
      // if there is no fqdn even at one service level
      // then there is an error case
      for (auto& nf_svc : nf_inst.at("nfServices")) {
        if (!nf_svc.contains("fqdn")) {
          return true;
        }
      }
      // Since fqdn is present at all service levels
      // therefore we will move to next NF Instance
      continue;
    }

    // Since there is no fqdn at profile level and there
    // is neither nfServiceList nor nfServices present,
    // therefore it is an error case
    return true;
  }

  // No error case found
  return false;
}

// Find and delete IP addresses in NF Instances (multiple NF Profiles)
Http::FilterHeadersStatus EricProxyFilter::hideIpAddressesInNfInstances() {
  // ULID(H26)  Applying IP Hiding in NF Instances for NF Discovery
  ENVOY_STREAM_UL_LOG(trace, "Applying IP Hiding in NF Instances", *encoder_callbacks_, ULID(H26i));

  const auto json_body = body_->getBodyAsJson();
  for (auto& nf_inst : json_body->at("nfInstances")) {
    // IP Hiding on Profile Level
    nf_inst.erase("ipv4Addresses");
    nf_inst.erase("ipv6Addresses");

    // IP Hiding in nfServiceList
    if (nf_inst.contains("nfServiceList")) {
      if (!nf_inst.at("nfServiceList").is_object()) {
        ENVOY_STREAM_UL_LOG(
            trace, "nfServiceList in nfInstances is not an object, not hiding any IP addresses",
            *encoder_callbacks_, ULID(H26j));
        sendLocalReplyForInvalidJsonElementInNfDiscovery();
        return Http::FilterHeadersStatus::StopIteration;
      }
      // IP Hiding on Service Level
      for (auto& nf_svc : nf_inst.at("nfServiceList").items()) {
        if (nf_svc.value().contains("ipEndPoints")) {
          if (!nf_svc.value().at("ipEndPoints").is_array()) {
            ENVOY_STREAM_UL_LOG(trace,
                                "ipEndPoints for nfServiceList in nfInstances is not a list, not "
                                "hiding any IP addresses",
                                *encoder_callbacks_, ULID(H26k));
            sendLocalReplyForInvalidJsonElementInNfDiscovery();
            return Http::FilterHeadersStatus::StopIteration;
          }
          for (auto& ip_ep : nf_svc.value().at("ipEndPoints")) {
            ip_ep.erase("ipv4Address");
            ip_ep.erase("ipv6Address");
          }
        }
      }
    }

    // IP Hiding in nfServices
    if (nf_inst.contains("nfServices")) {
      if (!nf_inst.at("nfServices").is_array()) {
        ENVOY_STREAM_UL_LOG(trace,
                            "nfServices in nfInstances is not a list, not hiding any IP addresses",
                            *encoder_callbacks_, ULID(H26l));
        sendLocalReplyForInvalidJsonElementInNfDiscovery();
        return Http::FilterHeadersStatus::StopIteration;
      }
      // IP Hiding on Service Level
      for (auto& nf_svc : nf_inst.at("nfServices")) {
        if (nf_svc.contains("ipEndPoints")) {
          if (!nf_svc.at("ipEndPoints").is_array()) {
            ENVOY_STREAM_UL_LOG(trace,
                                "ipEndPoints for nfServices in nfInstances is not a list, not "
                                "hiding any IP addresses",
                                *encoder_callbacks_, ULID(H26m));
            sendLocalReplyForInvalidJsonElementInNfDiscovery();
            return Http::FilterHeadersStatus::StopIteration;
          }
          for (auto& ip_ep : nf_svc.at("ipEndPoints")) {
            ip_ep.erase("ipv4Address");
            ip_ep.erase("ipv6Address");
          }
        }
      }
    }
  }

  body_->setBodyFromJson(json_body);

  return Http::FilterHeadersStatus::Continue;
}

/**
 * Handle TH IP Hiding error case in NF Instances (multiple NF Profiles) with configured action
 */
Http::FilterHeadersStatus EricProxyFilter::handleThIpHidingErrorCaseInNfInstances() {
  auto response_action = ip_hiding_action_on_fqdn_absence_->response_action();
  stats_
      ->buildTHcounters(rp_name_topology_hiding_.value_or("unknown_rp"),
                        ip_hiding_type_on_fqdn_absence_.value_or("unknown_type"),
                        stats_->typePrefix(), stats_->response(), stats_->fqdnMissing())
      .inc();

  // Applying response action on fqdn absence
  switch (response_action.action_case()) {
  case ThActionOnFqdnAbsence::Action::kApplyIpHiding:
    ENVOY_STREAM_LOG(trace, "Applying apply_ip_hiding response action on fqdn absence", *encoder_callbacks_);
    if (hideIpAddressesInNfInstances() == Http::FilterHeadersStatus::StopIteration) {
      return Http::FilterHeadersStatus::StopIteration;
    }
    stats_
        ->buildTHcounters(rp_name_topology_hiding_.value_or("unknown_rp"),
                          ip_hiding_type_on_fqdn_absence_.value_or("unknown_type"),
                          stats_->typePrefix(), stats_->response(), stats_->appliedSuccess())
        .inc();
    return Http::FilterHeadersStatus::Continue;
    break;
  case ThActionOnFqdnAbsence::Action::kForward:
    ENVOY_STREAM_LOG(trace, "Applying forward response action on fqdn absence", *encoder_callbacks_);
    return Http::FilterHeadersStatus::Continue;
    break;
  case ThActionOnFqdnAbsence::Action::kDrop: {
    ENVOY_STREAM_LOG(trace, "Applying drop response action on fqdn absence", *encoder_callbacks_);
    actionDropMessage();
    return Http::FilterHeadersStatus::StopIteration;
    break;
  }
  case ThActionOnFqdnAbsence::Action::kRespondWithError: {
    ENVOY_STREAM_LOG(trace, "Applying respond_with_error response action on fqdn absence", *encoder_callbacks_);
    respondWithError(response_action.respond_with_error());
    return Http::FilterHeadersStatus::StopIteration;
    break;
  }
  default:
    ENVOY_STREAM_LOG(trace, "Invalid response action on fqdn absence.", *encoder_callbacks_);
    return Http::FilterHeadersStatus::Continue;
    break;
  }
}

//-------------------------------------------------------------------------------------------------
// TH IP Hiding Common Processing

// ULID(H41) Set all filter.cc properties needed to apply TH IP Hiding and returns
// true if configured for the given RoamingPartner and NF-Type
bool EricProxyFilter::setThIpHidingIfConfiguredForNfType(std::optional<RoamingPartner> rp,
                                                         const std::string& nf_type) {
  if (!rp) {
    return false;
  }
  auto ip_hiding_per_target_nf_type = rp->topology_hiding().ip_hiding().ip_hiding_per_target_nf_type();
  auto action_on_fqdn_absence_iter = ip_hiding_per_target_nf_type.find(nf_type);

  if (action_on_fqdn_absence_iter != ip_hiding_per_target_nf_type.end()){
    ip_hiding_action_on_fqdn_absence_ = action_on_fqdn_absence_iter->second;
    ip_hiding_type_on_fqdn_absence_ = action_on_fqdn_absence_iter->first;
    return true; 
  }
  ENVOY_STREAM_UL_LOG(debug, "TH IP Hiding is not configured for RP={}, NF-Type={}",
                   *encoder_callbacks_, ULID(H41c), rp->name(), nf_type);
  return false;
}

/**
 * Respond with error as configured
 */
void EricProxyFilter::respondWithError(const RejectMessageAction& reject_config) {
  ENVOY_STREAM_LOG(trace, "respondWithError()", *decoder_callbacks_);

  auto status_code = reject_config.status();
  std::string title;
  std::string format_name;
  std::string content_type;

  switch (reject_config.message_format()) {
  case JSON: {
    format_name = "JSON";
    content_type = "application/problem+json";

    // status code and title are mandatory via YANG
    // detail and cause are optional and if not present should be omitted from the body
    const auto& detail = reject_config.detail();
    const auto& cause = reject_config.cause();
    title = absl::StrCat("{\"status\": ", status_code, ", \"title\": \"", reject_config.title(),
                         "\"");
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
    title = reject_config.title();
    format_name = "text";
    content_type = "text/plain";
    break;
  default:
    ENVOY_STREAM_LOG(warn, "Unknown message_format for action_reject_message", *decoder_callbacks_);
    format_name = "unknown format";
    content_type = "text/plain";
  }

  sendLocalReplyWithSpecificContentType(status_code, content_type, title,
                                        StreamInfo::ResponseCodeDetails::get().DirectResponse);
}
/**
 * Handles n32c related checks. Specifically:
 * > Finds if a request is a n32c coming from a roaming partner
 * > If request is not a handshake it performs the necessary checks
 *   to find if the originating sepp has performed a successful n32c handshake with us
 *   if not the request is rejected
 *
 *  Called from seppInRequestEdgeProcessing in order to reject as early as possible
 */
SeppReqPreProcResult EricProxyFilter::n32cSeppPreprocessing() {

  // the following are sepp specific requiring a tls connection
  if (config_->isOriginExt() && decoder_callbacks_->connection() &&
      decoder_callbacks_->connection()->ssl()) {
    const auto& route = decoder_callbacks_->route().get();
    if (route && route->routeEntry()) {
      // ULID(P07) Is this an N32c request from RP?
      // Mark this request as N32c request that comes in from a RP's sepp.
      // Our own N32c requests (sent by our manager) do not need to be marked
      // because we have a different listener for those and just don't configure
      // any routing-cases in there.
      if (route->metadata().filter_metadata().contains("envoy.filters.http.eric_proxy")) {
        // request matched the catch all route on the first pass, not an n32c req
        const auto route_sans_md =
            getMetadataList(route->metadata().filter_metadata(), "ineligible_sans");
        // ineligible SANs have been supplied by RDS, check if data cached on the connection are
        // still valid or not
        const auto route_sans_version_md =
            getMetadataDouble(route->metadata().filter_metadata(), "ineligible_sans_version");
        if (!route_sans_version_md) {
          ENVOY_STREAM_LOG(debug, "No route metadata version on the catch all route",
                           *decoder_callbacks_);
          return SeppReqPreProcResult::Continue;
        }

        auto& conn_timestamp = decoder_callbacks_->connection()->ssl()->n32cInfoTimestamp();

        // cached data is stale, check if the new metadata on the route contain a SAN that matched
        // to those of the presented certs
        if (fabs(route_sans_version_md.value() - conn_timestamp) > EPSILON) {
          ENVOY_STREAM_LOG(debug,
                           "Cached metadata version is stale, starting comparisons between "
                           "ineligible and presented SANs",
                           *decoder_callbacks_);
          conn_timestamp = route_sans_version_md.value();
          if (!route_sans_md.empty()) {

            const auto cert_san_span =
                decoder_callbacks_->connection()->ssl()->dnsSansPeerCertificate();
            // perform a match between sans of presented certificate and not eligible DNs due to
            // n32c if no match found let the request go through, otherwise send local reply
            // ULID(P08)
            for (const auto& san : cert_san_span) {
              for (const auto& sepp : route_sans_md) {
                if (absl::AsciiStrToLower(san) == absl::AsciiStrToLower(sepp.string_value())) {
                  ENVOY_STREAM_UL_LOG(debug,
                                   "Presented SAN {} matches SEPP fqdn with no successful "
                                   "handshake, rejecting request",
                                   *decoder_callbacks_, ULID(P09), san);
                  sendLocalReplyWithSpecificContentType(
                      403, "application/problem+json",
                      R"({"status": 403, "title": "Forbidden", "cause": "-", "detail": "n32c_handshake_unsuccessful"})",
                      StreamInfo::ResponseCodeDetails::get().DirectResponse);
                  decoder_callbacks_->connection()->ssl()->n32cHandshakeState() = false;

                  return SeppReqPreProcResult::DirectResponse;
                }
                ENVOY_STREAM_LOG(debug,
                                 "Comparing certificate SAN: {} with ineligible SAN: {}, no match",
                                 *decoder_callbacks_, san, sepp.string_value());
              }
            }
          }
          // either the list was poulated and all sans have been compared, or it was empty -> set
          // handshake state to true
          decoder_callbacks_->connection()->ssl()->n32cHandshakeState() = true;
          // we've seen this metadata already, if there was not a successful cached handshake before
          // reject
        } else if (!decoder_callbacks_->connection()->ssl()->n32cHandshakeState()) {  // ULID(P09)
          sendLocalReplyWithSpecificContentType(
              403, "application/problem+json",
              R"({"status": 403, "title": "Forbidden", "cause": "-", "detail": "n32c_handshake_unsuccessful"})",
              StreamInfo::ResponseCodeDetails::get().DirectResponse);
          return SeppReqPreProcResult::DirectResponse;
        }
      // Request is an n32c handshake request
      } else if (route->routeEntry()->clusterName() == "internal_n32c_server") {
        ENVOY_STREAM_UL_LOG(debug, "Detected N32c request from RP", *decoder_callbacks_, ULID(P07));
        is_n32c_request_from_rp_ = true;
        return SeppReqPreProcResult::N32cReqFromRP;
      }
    }
  }
  return SeppReqPreProcResult::Continue;
}

namespace {
// returns if two string views representing two MNCs (configured and received in
// originating-network-id-header) are equal. Simple equality is not enough because there might be a
// starting '0' in either that should be ignored. Both received mncs can be either 2 or 3 digits
static bool compareMncs(absl::string_view a, absl::string_view b) {
  const int sub = a.size() - b.size();
  if (sub == 0) {
    return (a == b);
  } else if (sub > 0 && a[0] == '0') {
    return ((a[1] == b[0]) && (a[2] == b[1]));
  } else if (sub < 0 && b[0] == '0') {
    return ((b[1] == a[0]) && (b[2] == a[1]));
  }
  return false;
}
} // namespace

bool EricProxyFilter::performPlmnIdMatch(
    const Envoy::Http::HeaderMap::GetResult& header_val,
    const ::envoy::extensions::filters::http::eric_proxy::v3::PlmnIdInfo& plmn_ids,
    Http::StreamDecoderFilterCallbacks* decoder_callbacks) {
  // tokenize the header and get mnc/mcc
  static re2::RE2 plmnIdRegex{"^[[:blank:]]?(?P<mcc>\\d{3})\\-(?P<mnc>\\d{2,3})([\\-\\;]{1}|$)"};
  std::string mcc, mnc;
  if (!re2::RE2::PartialMatch(header_val[0]->value().getStringView(), plmnIdRegex, &mcc, &mnc)) {
    ENVOY_STREAM_LOG(trace,
                     "3gpp-Sbi-Originating-Network-Id header malformed. Proceeding as if no match "
                     "with configured plmn ids was found",
                     *decoder_callbacks);
    return false;
  }
  // check the primary supplied plmnIds. These are mandatory to exist if plmn_ids are provided
  if (plmn_ids.primary_plmn_id().mcc() == mcc &&
      compareMncs(plmn_ids.primary_plmn_id().mnc(), mnc)) {
    return true;
  }
  if (!plmn_ids.additional_plmn_ids().empty()) {
    for (const auto& plmn_id_pair : plmn_ids.additional_plmn_ids()) {
      if (plmn_id_pair.mcc() == mcc && compareMncs(plmn_id_pair.mnc(), mnc)) {
        return true;
      }
    }
  }
  return false;
}

void EricProxyFilter::sendLocalReplyForInvalidJsonBodyInNfStatusNotify() {
  const std::string message = R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_body"})";
  sendLocalReplyWithSpecificContentType(
    400, "application/problem+json", message,
    StreamInfo::ResponseCodeDetails::get().DirectResponse
  );
}

void EricProxyFilter::sendLocalReplyForInvalidJsonElementInNfStatusNotify() {
  const std::string message = R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "request_invalid_json_element"})";
  sendLocalReplyWithSpecificContentType(
    400, "application/problem+json", message,
    StreamInfo::ResponseCodeDetails::get().DirectResponse
  );
}

void EricProxyFilter::sendLocalReplyForInvalidJsonBodyInNfDiscovery() {
  const std::string message = R"({"status": 500, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_invalid_json_body"})";
  sendLocalReplyWithSpecificContentType(
    500, "application/problem+json", message,
    StreamInfo::ResponseCodeDetails::get().DirectResponse
  );
}

void EricProxyFilter::sendLocalReplyForInvalidJsonElementInNfDiscovery() {
  // ULID(H36)
  const std::string message = R"({"status": 500, "title": "Internal Server Error", "cause": "SYSTEM_FAILURE", "detail": "response_invalid_json_element"})";
  sendLocalReplyWithSpecificContentType(
    500, "application/problem+json", message,
    StreamInfo::ResponseCodeDetails::get().DirectResponse
  );
}

void EricProxyFilter::sendLocalReplyForMissingTargetNfTypeInNfDiscovery() {
  const std::string message = R"({"status": 400, "title": "Bad Request", "cause": "MANDATORY_QUERY_PARAM_MISSING", "detail": "missing_target-nf-type"})";
  sendLocalReplyWithSpecificContentType(
    400, "application/problem+json", message,
    StreamInfo::ResponseCodeDetails::get().DirectResponse
  );
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
