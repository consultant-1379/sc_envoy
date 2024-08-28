#include "envoy/http/header_map.h"
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/header_utility.h"
#include "source/common/http/utility.h"
#include <cstddef>
#include <vector>
#include "source/extensions/filters/http/eric_proxy/tfqdn_codec.h"
#include "source/common/common/empty_string.h"

// Methods in this file are all in the EricProxyFilter class.

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

void EricProxyFilter::scpResponsePreProcessing(){
  const auto enc_filter_md = encoder_callbacks_->streamInfo().dynamicMetadata().filter_metadata();
  const auto dec_filter_md = decoder_callbacks_->streamInfo().dynamicMetadata().filter_metadata();

  const auto dyn_md_eric_proxy = enc_filter_md.find("eric_proxy");

  // If response comes from a next-hop SCP
  // Do not add Sbi-Producer-Id
  // ULID(C10) If MD direct-or-indirect = direct
  // then response comes from a non-proxy peer
  if (dyn_md_eric_proxy != enc_filter_md.end() &&
      findInDynMetadata(&enc_filter_md, "eric_proxy", "direct-or-indirect", "direct")) {
    // If response :status is temporary/permanent redirect 307/308 both supported in SBA
    // do not add Producer-Id as Producer context was not the selected or reselected
    // peer and we do not set indirect_redirect handling ASK Amarisa
    const auto status_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(":status"));
    // ULID(C01)
    if (!status_hdr.empty()) {
      const auto& status_hdr_val = status_hdr[0]->value().getStringView();
      // ULID(C02)
      if ((!status_hdr_val.empty()) && ((status_hdr_val != "307") || (status_hdr_val != "308"))) {
        // Sanity check if encoder_callback filter contains nf-inst-id MD
        // which contains NfInstanceId provided by scp-manager via Nnrf Discovery
        // If MD not present skip rest of execution as peer may be a Proxy/SEPP(?)
        // ULID(C03)
        if (EricProxyFilter::findInDynMetadata(&dec_filter_md, "eric_proxy", "routing-behaviour") &&
            findInDynMetadata(&enc_filter_md, "eric_proxy", "nf-inst-id") &&
            extractFromDynMetadata(&dec_filter_md, "eric_proxy", "routing-behaviour") != "STRICT") {
          const auto& routing_behavior = EricProxyFilter::
            extractFromDynMetadata(&dec_filter_md, "eric_proxy", "routing-behaviour");
          const auto& nfInstId = extractFromDynMetadata(&enc_filter_md, "eric_proxy", "nf-inst-id");
          std::string nfServInstId = "";
          std::string nfSetId = "";
          std::string nfServiceSetId = "";
          if (findInDynMetadata(&enc_filter_md, "eric_proxy", "nf-serv-inst-id")) {
            nfServInstId = extractFromDynMetadata(&enc_filter_md, "eric_proxy", "nf-serv-inst-id");
          }
          if (findInDynMetadata(&enc_filter_md, "eric_proxy", "nf-set-id")) {
            nfSetId = extractFromDynMetadata(&enc_filter_md, "eric_proxy", "nf-set-id");
          }
          if (findInDynMetadata(&enc_filter_md, "eric_proxy", "nf-serv-set-id")) {
            nfServiceSetId = extractFromDynMetadata(&enc_filter_md, "eric_proxy", "nf-serv-set-id");
          }

          // - nfinst (NF instance): indicates a NF Instance ID, as defined in 3GPP TS 29.510 [8].
          // Example: 3gpp-Sbi-Producer-Id: nfinst=54804518-4191-46b3-955c-ac631f953ed8
          auto prodId = std::string(" nfinst=").append(nfInstId);
          if (!nfServInstId.empty()) {
            prodId.append("; nfservinst=" + nfServInstId);
          }
          if (!nfSetId.empty()) {
            prodId.append("; nfset=" + nfSetId);
          }
          if (!nfServiceSetId.empty()) {
            prodId.append("; nfserviceset=" + nfServiceSetId);
          }

          // Only add Sbi-Producer-Id if request had a TaR header in PR
          // which is indicated by original-target-apiroot MD
          // if not-exists then it was not Prefered host routing
          // ULID(C11)
          if (routing_behavior ==
                  routing_behaviour_str_.at(static_cast<int>(RoutingBehaviour::PREFERRED)) &&
              original_tar_.has_value()) {
            // If Preferred add Sbi-Producer-Id Only on a reselection which is
            // indicated by presence of last-host Dyn MD being different than
            // the hostname of the host originally decided by the filter to route to (or if an
            // original host was not picked at all because it wasn't present in the hostmap)
            const auto& last_host = run_ctx_.getSelectedHostAuthority();
            if (!last_host.empty() &&
                ( !original_hostname_.has_value() ||
                 !absl::EqualsIgnoreCase(last_host, *original_hostname_))) {
              // ULID [C04] Add the Sbi-Producer-Id header to the response
              ENVOY_STREAM_UL_LOG(
                  debug, "Adding Producer-ID header for PR '3gpp-sbi-producer-id' with value '{}'",
                  *decoder_callbacks_, ULID(C04), prodId);
              run_ctx_.getReqOrRespHeaders()->addCopy(Http::LowerCaseString("3gpp-sbi-producer-id"),
                                                      prodId);
            }
          } else if (routing_behavior == routing_behaviour_str_.at(static_cast<int>(
                                             RoutingBehaviour::ROUND_ROBIN))) { // ULID(C12)
            // ULID(C05) If Round Robin, always add Sbi-Producer-Id header
            ENVOY_STREAM_UL_LOG(
                debug, "Adding Producer-ID header for RR '3gpp-sbi-producer-id' with value '{}'",
                *decoder_callbacks_, ULID(C05), prodId);
            run_ctx_.getReqOrRespHeaders()->addCopy(Http::LowerCaseString("3gpp-sbi-producer-id"), prodId);
          }
        } else { // ULID(C06)
          ENVOY_STREAM_UL_LOG(debug, "NF Instance ID missing or routing behaviour couldn't be obtained.",
              *decoder_callbacks_, "C06");
        }
      } else { // ULID(C07)
        ENVOY_STREAM_UL_LOG(
            debug, "Producer sent a :status redirect/unknown: '{}', so not attaching Producer ID",
            *decoder_callbacks_, ULID(C07), status_hdr_val);
      }
    } else { // ULID(C08)
      ENVOY_STREAM_UL_LOG(debug, "Response without :status not allowed in SBA", *decoder_callbacks_,
                          ULID(C08));
    }
  } else { // ULID(C09)
    ENVOY_STREAM_UL_LOG(debug, "No Producer-ID required for Indirect routing", *decoder_callbacks_,
                        ULID(C09));
  }
  // ULID(C13) End of SCP response pre-processing
}



} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
