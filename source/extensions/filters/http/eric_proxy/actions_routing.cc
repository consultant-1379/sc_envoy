#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "contexts.h"
#include "envoy/http/header_map.h"
#include "proxy_filter_config.h"
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/header_utility.h"
#include "source/common/http/utility.h"
#include "source/common/stream_info/eric_proxy_state.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

// Methods in this file are all in the EricProxyFilter class.
// They are stored in a separate file to keep action processing
// separate.

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// Route To Pool
ActionResultTuple EricProxyFilter::actionRouteToPool(const ActionRouteToPoolWrapper& action) {
  const auto proto_config = action.protoConfig().action_route_to_pool();
  ENVOY_STREAM_LOG(debug, "Routing to Pool: {} with behaviour {}", *decoder_callbacks_,
                   varOrStringAsString(proto_config.pool_name()),
                   proto_config.routing_behaviour());
  // Check and set keep-authority-header in dyn. metadata
  if (proto_config.keep_authority_header()) {
    ENVOY_STREAM_LOG(trace, "Setting MD keep-authority-header: true", *decoder_callbacks_);
    ProtobufWkt::Struct metadata;
    // Flag to indicate that keep-authority-header processing is needed:
    *(*metadata.mutable_fields())["keep-authority-header"].mutable_string_value() = "true";
    decoder_callbacks_->streamInfo().setDynamicMetadata("eric_proxy", metadata);
  }

  // ULID(S19)
  if (config_->isSeppNode()) {
    prepareSeppRoutingExtToInt(*run_ctx_.getReqOrRespHeaders());
  }

  // ULID(C18)
  prepareScpStrictRoutingForDfP(*run_ctx_.getReqOrRespHeaders(), proto_config.routing_behaviour());
  
  executeRoutingAction(varOrStringAsString(proto_config.pool_name()),
                       proto_config.routing_behaviour(),
                       proto_config.preserve_if_indirect(),
                       proto_config.preferred_target());

  // Remote routing
  if (proto_config.routing_behaviour() == RoutingBehaviour::REMOTE_ROUND_ROBIN ||
      proto_config.routing_behaviour() == RoutingBehaviour::REMOTE_PREFERRED) {
    executeRemoteRoutingAction(action);
  }

  return std::make_tuple(ActionResult::Exit, true, std::nullopt);
}

// Route To Roaming Partner
ActionResultTuple
EricProxyFilter::actionRouteToRoamingPartner(const ActionRouteToRoamingPartnerWrapper& action) {
  const auto proto_config = action.protoConfig().action_route_to_roaming_partner();
  ENVOY_STREAM_LOG(debug, "Routing to Roaming Partner: {} with behaviour {}", *decoder_callbacks_,
                   proto_config.roaming_partner_name(),
                   proto_config.routing_behaviour());

  // Check and set keep-authority-header in dyn. metadata
  if (proto_config.keep_authority_header()) {
    ENVOY_STREAM_LOG(trace, "Setting MD keep-authority-header: true", *decoder_callbacks_);
    ProtobufWkt::Struct metadata;
    // Flag to indicate that keep-authority-header processing is needed:
    *(*metadata.mutable_fields())["keep-authority-header"].mutable_string_value() = "true";
    decoder_callbacks_->streamInfo().setDynamicMetadata("eric_proxy", metadata);
  }

  if (config_->isSeppNode()) {
    prepareSeppRoutingIntToExt(*run_ctx_.getReqOrRespHeaders());
  }
  auto cluster_name =
      config_->rpPoolName(proto_config.roaming_partner_name());
  executeRoutingAction(cluster_name, proto_config.routing_behaviour(),
                       proto_config.preserve_if_indirect(),
                       proto_config.preferred_target());
  return std::make_tuple(ActionResult::Exit, true, std::nullopt);
}

//-------------------------------------------------------------------------------------
// Helper functions for the actions above

// ULID(C18) SCP only: If strict routing + dyn-fwd:
// 1. Write host+port from TaR into :authority
// 2. Write scheme from TaR into :scheme
// 3. Set dyn-MD to remove TaR header in DFP code (so that strict routing and strict_dfp
//    routing can use the same routing-tables
void EricProxyFilter::prepareScpStrictRoutingForDfP(Http::RequestOrResponseHeaderMap& headers,
                                        const RoutingBehaviour& behaviour)
{
  if( absl::string_view(routing_behaviour_str_.at(behaviour)) == "STRICT_DFP" )
  {
    ENVOY_STREAM_UL_LOG(debug, "SCP: Prepare routing for Dyn Forwarding Proxy", *decoder_callbacks_, ULID(C18));
    auto tar_hdr = headers.get(Http::LowerCaseString("3gpp-Sbi-Target-apiroot"));
    if(! tar_hdr.empty())
    {
      std::string scheme = "http";
      if(tar_hdr[0]->value().getStringView().compare(0,8,"https://") == 0) {
        scheme = "https";
      }
      // Remove existing authority header
      headers.remove(Http::LowerCaseString(":authority"));
      // Set host-port from TaR as :authority header
      headers.setCopy(Http::LowerCaseString(":authority"),
                      extractHostAndPort(tar_hdr[0]->value().getStringView(), headers, false));
      // Set scheme according to TaR
      headers.remove(Http::LowerCaseString(":scheme"));
      headers.setCopy(Http::LowerCaseString(":scheme"), scheme);
      // Set dyn MD to remove TaR header in DfP so that existing rule for
      // strict route matching can be preserved
      std::vector<std::string> key({"dfp_remove_tar"});
      std::vector<std::string> value({"true"});
      EricProxyFilter::setEncoderOrDecoderDynamicMetadata("eric_proxy",
                          key, value, true);
    }

  }
  
}


// Maybe not required for Sbi-Producer-Id handling ??
// But useful idea to have for Option D handling in SCP
// Specifically with choice of NRF specified by NF Consumer
// Handling for SCP Indirect Routing via Sbi-Discovery-* or Sbi-target-api-root headers
// void EricProxyFilter::prepareScpRouting(const Action& action)


// Sepp/T-FQDN handling Ext -> Int
void EricProxyFilter::prepareSeppRoutingExtToInt(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_STREAM_UL_LOG(debug, "Sepp prepare route to pool action", *decoder_callbacks_, ULID(T34));
  if (config_->isOriginExt()) { // ULID(T34)
    if (config_->isTFqdnConfigured()) {
      ENVOY_STREAM_UL_LOG(debug, "Applying T-FQDN Handling", *decoder_callbacks_, ULID(T34));
      const auto& eric_proxy_sepp_state = decoder_callbacks_->streamInfo().filterState()->getDataMutable<StreamInfo::EricProxySeppState>
                                                            (StreamInfo::EricProxySeppState::key());
      // ProtobufWkt::Struct metadata;
      // ULID(T20) Mark request as ext_to_int in filter-state-objto indicate the sepp routing direction:
      eric_proxy_sepp_state->setRoutingDirection(StreamInfo::EricProxySeppState::RoutingDirection::ExtToInt);
      // ULID(T21) Convert Callback-URI in body to T-FQDN
      if (body_->isBodyPresent()) {
        auto reqApiNameAndVersion = absl::StrCat(run_ctx_.getServiceClassifierCtx().getApiName(),"/",
                                                  run_ctx_.getServiceClassifierCtx().getApiVersion());
        ENVOY_STREAM_UL_LOG(debug, "reqApiNameAndVersion: '{}'", *decoder_callbacks_, ULID(T21),
                            reqApiNameAndVersion);

        // TODO(eedala): Should we log a (debug?) message if there is no callback_uri_klv_table
        // configured?
        std::vector<std::string> cb_uri_json_pointers =
            run_ctx_.rootContext()->klvtValues(config_->protoConfig().callback_uri_klv_table(),
                                               reqApiNameAndVersion, decoder_callbacks_);
        ENVOY_STREAM_UL_LOG(trace, "cb_uri_json_pointers: '{}'", *decoder_callbacks_, ULID(T21),
                            cb_uri_json_pointers);

        std::string own_fqdn = config_->ownFqdnLc();
        // Create TFQDN
        ENVOY_STREAM_LOG(trace, "action routing modifying Json", *decoder_callbacks_);
        auto orig_body = body_->getBodyAsJson();
        if (orig_body != nullptr) {
          // ULID(T21) We do not want to modify the body (buffer) at this point, hence we create 
          // a pointer to a copy and modify that:
          auto modified_body = std::make_shared<Json>(*orig_body);
          const auto status =
              EricProxyFilter::modifyJson(decoder_callbacks_, modified_body, cb_uri_json_pointers,
                                          [this](auto& str) { return encodeTfqdnUri(str); });

          if (status.ok()) {
            ENVOY_STREAM_UL_LOG(debug, "T-FQDN label created in modified_body: '{}'",
                                *decoder_callbacks_, ULID(T22), modified_body->dump());
            // ULID(T22) Store modified Body and Content-Length in filter-state-object
            const auto modified_body_str = modified_body->dump();
            eric_proxy_sepp_state->setModifiedBody(std::move(modified_body_str));
          } else {
            ENVOY_STREAM_UL_LOG(debug, "T-FQDN label creation failed for target '{}'",
                                *decoder_callbacks_, ULID(T21), status.message());
          }
        }
      }
    }
    // ULID(H07) If topo-hiding is on, remove 3gpp-Sbi-Target-apiRoot
    if (topo_hide_pseudo_fqdn_.has_value()) {
      ENVOY_STREAM_UL_LOG(debug, "Removing 3gpp-Sbi-target-apiRoot header", *decoder_callbacks_,
                          "H07");
      headers.remove(Http::LowerCaseString("3gpp-Sbi-target-apiRoot"));
    }
  }
}

/**
 * Sepp/T-FQDN handling Int -> Ext
 */
void EricProxyFilter::prepareSeppRoutingIntToExt(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_STREAM_LOG(debug, "Sepp prepare route to roaming partner action", *decoder_callbacks_);
  if (config_->isOriginInt()) {
    // Upper part of the "big picture", int -> ext
    ENVOY_STREAM_LOG(debug, "Applying T-FQDN Handling, Int -> Ext", *decoder_callbacks_);
    const auto& eric_proxy_sepp_state = decoder_callbacks_->streamInfo().filterState()->getDataMutable<StreamInfo::EricProxySeppState>
                                                            (StreamInfo::EricProxySeppState::key());
    eric_proxy_sepp_state->setRoutingDirection(StreamInfo::EricProxySeppState::RoutingDirection::IntToExt);
    // IF Req.apiName = "nrf-disc"
    if (run_ctx_.getServiceClassifierCtx().getApiName() == "nnrf-disc") {
      ENVOY_STREAM_LOG(debug, "nnrf-disc detected", *decoder_callbacks_);
      // AND Req.queryString = ["requester-nf-type"] in ["smf","pcf"] (from config)
      auto path_hdr = headers.get(Http::LowerCaseString(":path"));
      auto path_str = path_hdr[0]->value().getStringView();
      auto query_parameters = Http::Utility::QueryParamsMulti::parseQueryString(path_str);
      auto requester_nf_type = query_parameters.getFirstValue("requester-nf-type");
      ENVOY_STREAM_LOG(debug, "requester-nf-type={}", *decoder_callbacks_, requester_nf_type.value_or("empty"));

      // Compare case-insensitively by converting both sides to lower-case:
      Http::LowerCaseString requester_nf_type_lc{requester_nf_type.value_or("empty_nf_type")};
      for (const auto& nf_type_requiring_t_fqdn : config_->nfTypesRequiringTFqdnLc()) {
        if (nf_type_requiring_t_fqdn == requester_nf_type_lc) {
          eric_proxy_sepp_state->setNfTypeRequiresTfqdn(true);
          return;
        }
      }
    }
  }
}

/**
 * Return the apiName retrieved from the path header
 * The apiName is present in 3gpp-Sbi-Callback header for notification
 * requests and apiVersion is denoted after a semicolon if apiVersion is not
 * equal to 1
 */
std::string EricProxyFilter::getReqApiNameForSbaCb(absl::string_view sba_cb_hdr) {
  // If we enter here we know the request is a notification and 
  // service contexts have to be extracted from 3gpp-sbi-callback hdr
  std::string apiName = "";
  // Get ApiName from Nnrf_NFManagement_NFStatusNotify = NFManagement
  auto brk_pos = sba_cb_hdr.find(';');
  if (brk_pos != std::string::npos) {
    sba_cb_hdr.remove_suffix(sba_cb_hdr.length() - brk_pos);
  }
  apiName = std::string(sba_cb_hdr);
  return apiName;
}

std::string EricProxyFilter::getResource(Http::RequestOrResponseHeaderMap& headers) {
  auto path_hdr = headers.get(Http::LowerCaseString(":path"));
  auto sbi_cb_hdr = headers.get(Http::LowerCaseString("3gpp-sbi-callback"));
  // Only get resource from :path header if transaction is not a notification request
  if(!path_hdr.empty() && (sbi_cb_hdr.empty())) {
    auto strip_path = Http::Utility::stripQueryString(path_hdr[0]->value());
    std::vector<std::string> path_info =
        absl::StrSplit(strip_path, '/');
    if (path_info.size() > 2) {
      std::string res{ "/" + absl::StrJoin(path_info.begin() + 3, path_info.end(), "/")};
      return res;
    } else {
      ENVOY_STREAM_LOG(debug, "Cannot determine resource: Path is not a 5G service URI",
          *decoder_callbacks_);
    }
  }
  return "";
}

/**
 * Return the apiVersion retrieved from 3gpp-Sbi-Callback header
 */
std::string EricProxyFilter::getReqApiVersionForSbaCb(absl::string_view sba_cb_hdr) {
  std::string apiVersion = "";
  auto brk_pos = sba_cb_hdr.find(';');
  if (brk_pos != std::string::npos) {
    sba_cb_hdr.remove_prefix(brk_pos);
  } else {
    // default is 'v1' in case apiVersion is not mentioned
    // in Sbi-Callback header
    apiVersion = "v1";
    return apiVersion;
  }
  auto eq_pos = sba_cb_hdr.find('=');
  if (eq_pos != std::string::npos) {
    sba_cb_hdr.remove_prefix(eq_pos + 1);
  }
  // If apiVersion is included in callback its just a number
  // For e.g. apiVersion=2
  apiVersion = absl::StrCat("v",std::string(sba_cb_hdr));
  return apiVersion;
}

/**
 * Return a list of callback-URIs in JSON-pointer format for a given API
 */
std::vector<std::string>
EricProxyFilter::getCbUriJsonPointersForApi(const std::string& req_api_name) {
  std::vector<std::string> cbUriJsonPointers;
  auto klv_tables = config_->protoConfig().key_list_value_tables();
  for (const auto& klv_table : klv_tables) {
    if (klv_table.name() == config_->protoConfig().callback_uri_klv_table()) {
      for (const auto& klvEntry : klv_table.entries()) {
        if (klvEntry.key() == req_api_name) {
          for (const auto& cbUri : klvEntry.value()) {
            cbUriJsonPointers.push_back(cbUri);
          }
        }
      }
    }
  }
  return cbUriJsonPointers;
}


 // Common part for action_route_* where target-api-root processing is done (if needed).
 // Returns true/false if the headers were modified
void EricProxyFilter::executeRoutingAction(const std::string& cluster_name,
                                           const RoutingBehaviour& routing_behaviour,
                                           const PreserveIfIndirect& preserve_if_indirect,
                                           const VarHeaderConstValue& preferred_target) {
  // Check the uri in header to be valid based on
  // RFC 3986 <https://datatracker.ietf.org/doc/html/rfc3986> URI Generic Syntax
  // if the header is empty return true
  // should be valid scheme + valid authority (host + port)
  // TODO: change this lambda into a "normal" function
  const auto isValidHeader = [](const Envoy::Http::HeaderMap::GetResult& header) -> bool {
    if (!header.empty()) {
      Http::Utility::Url absolute_url;
      if (absolute_url.initialize(header[0]->value().getStringView(), false)) {
        if (!Http::Utility::schemeIsValid(absolute_url.scheme())) {
          ENVOY_LOG(trace, "Scheme is not valid in {}", header[0]->value().getStringView());
          return false;
        }
        if (!Http::HeaderUtility::authorityIsValid(absolute_url.hostAndPort())) {
          ENVOY_LOG(trace, "Authority is not valid in {}", header[0]->value().getStringView());
          return false;
        }
        return true;
      } else {
        // can not initialize
        ENVOY_LOG(trace, "Header: {} is not rfc3986 conform", header[0]->value().getStringView());
        return false;
      }
    } else {
      // Header is empty do not check
      return true;
    }
  };

  // ULID(S55) Set cluster name, also in x-cluster header
  setClusterName(cluster_name);
  run_ctx_.getReqOrRespHeaders()->setCopy(Http::LowerCaseString("x-cluster"), cluster_name_.value());
  ProtobufWkt::Struct metadata;

  // ULID(S56) Set routing-behaviour in dyn. metadata
  ENVOY_STREAM_UL_LOG(debug, "Setting MD routing-behaviour: {}", *decoder_callbacks_, ULID(S56),
                   routing_behaviour_str_.at(routing_behaviour));
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() =
      routing_behaviour_str_.at(routing_behaviour);

  // ULID(S57) Set up dyn-MD to preserve request data for indirect routing
  if (preserve_if_indirect != NOTHING &&
      routing_behaviour != RoutingBehaviour::REMOTE_ROUND_ROBIN &&
      routing_behaviour != RoutingBehaviour::REMOTE_PREFERRED) {
    ENVOY_STREAM_UL_LOG(debug, "Applying preserve_if_indirect", *decoder_callbacks_, ULID(S57));
    applyPreserveIfIndirect(preserve_if_indirect);
  }

  // Check headers 3gpp-sbi-target-apiroot and x-notify-uri for validity
  // TODO: should this be done earlier?
  auto tar_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString("3gpp-Sbi-Target-apiRoot"));
  if (routing_behaviour == RoutingBehaviour::STRICT || routing_behaviour == RoutingBehaviour::PREFERRED ||
      routing_behaviour == RoutingBehaviour::STRICT_DFP || routing_behaviour == RoutingBehaviour::REMOTE_PREFERRED) {
    if (!isValidHeader(run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString("3gpp-Sbi-Target-apiRoot")))) {
      sendLocalReplyWithSpecificContentType(
          400, "application/problem+json",
          R"({"status": 400, "title": "Bad Request", "cause": "MANDATORY_IE_INCORRECT", "detail": "3gpp-sbi-target-apiroot_header_malformed"})",
          StreamInfo::ResponseCodeDetails::get().DirectResponse);
      return;
    }
    if (!isValidHeader(run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString("x-Notify-URI")))) {
      sendLocalReplyWithSpecificContentType(
          400, "application/problem+json",
          R"({"status": 400, "title": "Bad Request", "cause": "MANDATORY_IE_INCORRECT", "detail": "x-notify-uri_header_malformed"})",
          StreamInfo::ResponseCodeDetails::get().DirectResponse);
      return;
    }
  }

  // Store the preferred host so that the router part can insert it into :authority
  // during a re-select (only if the enpoint.supports is "Null", in all other cases
  // the :authority is set to the selected host):
  // ULID(S28)
  ENVOY_STREAM_UL_LOG(debug, "Setting MD preferred-host", *decoder_callbacks_, ULID(S28));
  std::string preferred_host("");
  if (config_->isSeppNode()) {
    // FIXME TODO: See boxes P02 P03 pP04, H05 H06 T09 T10 T11: If pref host is in auth,
    // it gets copied to TaR and we replace :auth with our fqdn, from the prerouting stage but only
    // for the SEPP (boxes on the scp path are not implemented). The 'preferred-host' md configured
    // here, is used when the selected host does not support TaR which get removed and :auth is
    // replaced from the preferred-host. IT's independent from the 'preferred_target' config
    // parameter as opposed to the 'host md'. All this combined with the different handling with SCP
    // is very confusing and should be revisitted. But for SEPP TaR contents take prescedence over
    // whatever is configured in preferred_target both for 'preferred-host' and 'host' md
    if (!tar_hdr.empty()) {
      // Remove scheme and path when going from target-apiroot to authority
      preferred_host = extractHostAndPort(tar_hdr[0]->value().getStringView(), *run_ctx_.getReqOrRespHeaders(), false);
    }
  }
  // DND-38571 Dynamic Forwarding in SCP fails because authority header is not
  // changed to TaR if TaR exists (much older problem , but missed probably
  // because we do not have SCP CI tests with NoTaR producer NF's)
  // No need to put preferred-host MD with :authority hdr value
  // as behavior is normalized for SCP authority header handling in ULID(C14) & beyond
  // The following code looks suspicious but to be fixed after adaptations from
  // DND-38747 It handles only cases where authority doesnt have own-fqdn and has
  // preferred host

  else { // SCP
    auto auth_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(":authority"));
    if (!auth_hdr.empty()) { // should not happen, this header is mandatory
      preferred_host = absl::AsciiStrToLower(auth_hdr[0]->value().getStringView());
    }
  }
  if (!preferred_host.empty()) {
    ENVOY_STREAM_UL_LOG(debug, "preferred-host metadata: {}", *decoder_callbacks_, ULID(S28), preferred_host);
    *(*metadata.mutable_fields())["preferred-host"].mutable_string_value() = preferred_host;
  }

  // If topology-hiding is off:
  // Remember the original target-apiroot header in case we have to
  // re-select the producer and the response doesn't contain a location header
  // TS29.500 R16 ch. 6.10.4
  // ULID(S29)
  if (!topo_hide_pseudo_fqdn_.has_value()) {
    auto orig_tar_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString("3gpp-Sbi-Target-apiRoot"));
    if (!orig_tar_hdr.empty()) {
      original_tar_.emplace(orig_tar_hdr[0]->value().getStringView());
    }
  }

  decoder_callbacks_->streamInfo().setDynamicMetadata("eric_proxy", metadata);

  // Following code only applies for Strict+Preferred+Remote Preferred Routing
  if (preferred_target.val_case() != VarHeaderConstValue::VAL_NOT_SET) {
    // FIXME TODO: See boxes P02 P03 P04, H05 H06 T09 T10 T11: If pref host is in auth,
    // it gets copied to TaR and we replace :auth with our fqdn, from the prerouting stage but only
    // for the SEPP (boxes on the scp path are not implemented). All this combined with the
    // different handling with SCP is very confusing and should be revisited. But for SEPP, TaR
    // contents take precedence over whatever is configured in preferred_target both for
    // 'preferred-host' and 'host' md
    if (config_->isSeppNode() && !tar_hdr.empty()) {
      //DND 59215 Strip the api Prefix in setTargetHost() 
      std::string tar_val = std::string(tar_hdr[0]->value().getStringView());
      setTargetHost(
          tar_val,
          // extractHostAndPort(tar_hdr[0]->value().getStringView(), *run_ctx_.getReqOrRespHeaders()),
          *run_ctx_.getReqOrRespHeaders(), routing_behaviour);
    } else {
      auto hdr = varHeaderConstValueAsString(preferred_target, false);
      //DND 59215 Strip the api Prefix in setTargetHost() 
      setTargetHost(
        hdr,
        // extractHostAndPort(hdr, *run_ctx_.getReqOrRespHeaders()),
                    *run_ctx_.getReqOrRespHeaders(), routing_behaviour);
    }
  }
}


// ULID(S57) Set up metadata so that direct/indirect routing can happen at a later stage.
void EricProxyFilter::applyPreserveIfIndirect(const PreserveIfIndirect& preserve_if_indirect) {
  switch (preserve_if_indirect) {
  case TARGET_API_ROOT: {
    ProtobufWkt::Struct metadata;
    // Flag to indicate that target-api-root processing is needed:
    *(*metadata.mutable_fields())["target-api-root-processing"].mutable_string_value() = "true";
    decoder_callbacks_->streamInfo().setDynamicMetadata("eric_proxy", metadata);
  } break;
  case ABSOLUTE_PATH: {
    // Shortcut: if there was no absolute path in the request, there is nothing
    // we can do for indirect routing. In that case, don't even enable absolute
    // path processing:
    auto absolute_path_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString("x-eric-original-absolute-path"));
    if (!absolute_path_hdr.empty()) {
      ProtobufWkt::Struct metadata;
      // Flag to indicate that absolute-path-processing is needed:
      *(*metadata.mutable_fields())["absolute-path-processing"].mutable_string_value() = "true";
      // Set the value that needs to be used for direct routing:
      auto relative_path_hdr = run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(":path"));
      std::string relative_path(
          (relative_path_hdr.empty()) ? ("") : relative_path_hdr[0]->value().getStringView());
      *(*metadata.mutable_fields())["relative-path-value"].mutable_string_value() = relative_path;
      // Set the value for indirect routing: (cannot be empty, see the guard above)
      std::string absolute_path(absolute_path_hdr[0]->value().getStringView());
      *(*metadata.mutable_fields())["absolute-path-value"].mutable_string_value() = absolute_path;
      decoder_callbacks_->streamInfo().setDynamicMetadata("eric_proxy", metadata);
      run_ctx_.getReqOrRespHeaders()->remove(Http::LowerCaseString("x-eric-original-absolute-path"));
    }
  } break;
  default:
    ENVOY_STREAM_UL_LOG(error, "Unsupported option for preserve_if_indirect", *decoder_callbacks_, ULID(S57));
  }
}


// ULID(S59) Set the preferred/strict target host (inluding port).
// It is also set in the header x-host, which is used by Envoy-routes
// to set Omit-Host-Metadata for this host so that it's excluded by
// re-selections.
//
// It's assumed the provided value is already in lowercase and no extra
// check is performed on its integrity
void EricProxyFilter::setTargetHost(std::string host_with_port_lc_and_path,
                                    Http::RequestOrResponseHeaderMap& headers,
                                    const RoutingBehaviour& rb) {
  absl::string_view host_lc;
  absl::string_view path_hdr;
  Envoy::Http::Utility::extractHostPathFromUri(host_with_port_lc_and_path,host_lc,path_hdr);
  // Http::HeaderUtility::hostHasPort(host_lc);
  std::string host_with_port_lc =  extractHostAndPort(host_with_port_lc_and_path, *run_ctx_.getReqOrRespHeaders());
  ENVOY_STREAM_UL_LOG(debug, "Applying preferred_target -> {}", *decoder_callbacks_,
                   ULID(S59a), host_with_port_lc);

  headers.setCopy(Http::LowerCaseString("x-host"), host_with_port_lc);

  if (!cluster_name_.has_value()) {
    ENVOY_STREAM_UL_LOG(debug,
                     "Target cluster not found/determined, cannot do preferred/strict routing",
                     *decoder_callbacks_, ULID(S59b));
    return;
  }
  ENVOY_STREAM_UL_LOG(debug, "Trying to find preferred host: {}, cluster name: {}",
                   *decoder_callbacks_, ULID(S59c), host_with_port_lc, cluster_name_.value());

  //  check if target cluster is an aggregate cluster. Aggregate clusters don't have a host
  //  priority map however for preferred routing only hosts from the primary pool can be preferred
  //  and not the last resort According to the cluster naming format supplied by the manager, aggr
  //  clusters contain #!_#LRP in their name
  Envoy::Upstream::ThreadLocalCluster* cluster_with_pref_host;

  const auto startpos_suffix = cluster_name_.value().find("#!_#LRP");
  if (startpos_suffix == std::string::npos) { // not aggregate cluster
    cluster_with_pref_host = config_->clusterManager().getThreadLocalCluster(cluster_name_.value());
  } else {
    cluster_with_pref_host = config_->clusterManager().getThreadLocalCluster(
        absl::string_view(cluster_name_.value()).substr(0, startpos_suffix));
  }

  if (cluster_with_pref_host == nullptr) {
    ENVOY_STREAM_UL_LOG(debug, "No cluster named {} in configuration ", *decoder_callbacks_,
                     ULID(S59d), cluster_name_.value());
    return;
  }
  // Support for multihomed Upstream Producers
  // if sbi-target-apiroot/ authority hdr (in case of route_based on authority header) indicates an -
  // - IP address : It takes precedence over FQDN and IP family preference wouldnt impact it
  // - FQDN with multiple IP endpoints of different IP family, IP Family preference would dictate the
  //        host endpoint that is chosen first in PR and SR 
  // The following code has to be executed here without any config time wrapping
  // as CDS updates could alter the state of hostmap without trigerring an LDS update
  // So all the vector index construction has to happen at request time as there is 
  // a requirement to randomize the first preferred host if producer is multihomed on
  // the preferred ip family
  IPver pref_ip_fam_version = IPver::Default;
  bool retry_multiple_address = false;
  EricProxyClusterTypedMetadataFactory cluster_md_factory;
  const EricProxyClusterTypedMetadataObject* cluster_md_object = nullptr;

  if (cluster_with_pref_host->info()->typedMetadata().get<EricProxyClusterTypedMetadataObject>(cluster_md_factory.name()) 
                        != nullptr) {
    ENVOY_STREAM_UL_LOG(debug, "Cluster md named {} found in configuration ", *decoder_callbacks_,
                      ULID(S59e), cluster_md_factory.name());
    cluster_md_object = cluster_with_pref_host->info()
                              ->typedMetadata()
                              .get<EricProxyClusterTypedMetadataObject>(cluster_md_factory.name());
      
      
    pref_ip_fam_version = cluster_md_object->preferred_ip_family_;
    retry_multiple_address = cluster_md_object->preferred_host_retry_multiple_address_;
  } else {
    ENVOY_STREAM_UL_LOG(debug, "Cluster md named {} not found in cluster configuration",*decoder_callbacks_,
                    ULID(S59f), cluster_md_factory.name());
  } 

  const auto host_map = cluster_with_pref_host->prioritySet().crossPriorityHostMap();
  
  const auto& it = host_map->find(host_with_port_lc);
  if (it != host_map->end()) {
  // DND-59215 Api Prefix support
  // Check if apiPrefix for the preferred host matches with the api Prefix received in TaR
  // if it matches proceed with setting setUpstreamOverrideHost() else
  // if not matching then return and dont set an overriden host by setUpstreamOverrideHost()
  // By SBA specs Rel 17 all IP endpoints of a given nf-service instance have same 
  // api Prefix, so its good enough to just check at  vector entry 0
  // api Prefix is available in endpoint MD parent envoy.eric_proxy at key apiPrefix
  // ULID(S62)
  if(!run_ctx_.getServiceClassifierCtx().isNotify()) {
    const Protobuf::Value& val = Envoy::Config::Metadata::metadataValue(it->second.at(0).first->metadata().get(),
                                            "envoy.eric_proxy","prefix");
    // Get the api prefix configured for the preferred host
    if(val.has_string_value()) {
      const auto& api_prefix = val.string_value();
      if(!absl::StartsWith(path_hdr,api_prefix)) {
        // If api prefix in TaR doesnt match api Prefix of host
        // dont set preferred host in setOverrideHost();
        // TODO(ULID)
        ENVOY_STREAM_LOG(debug,"Api Prefix for the preferred host:{} doesnt match \
                                  the apiRoot mentioned in preferred target variable:{}, \
                                  not overriding the host",
                          *decoder_callbacks_,api_prefix,path_hdr);
        return ;
      }
    }
  }
    ENVOY_STREAM_UL_LOG(debug, "Found preferred host in hostmap (lookup): {}", *decoder_callbacks_,
                     ULID(S59g), host_with_port_lc);

    setIPFamilyPolicy(pref_ip_fam_version, retry_multiple_address, rb, host_with_port_lc,
                      it->second);
    original_hostname_ = it->first;
    // with intruducing Stateful session, need a strict parameter:
    // https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/stateful_session/v3/stateful_session.proto#envoy-v3-api-msg-extensions-filters-http-stateful-session-v3-statefulsession
    // set it to false by default
    // TODO: configure
    decoder_callbacks_->setUpstreamOverrideHost({it->first, false});

  } else { // Check if target host may be reachable via an intermediary proxy by indirect routing
    ENVOY_STREAM_UL_LOG(debug, "Unable to find preferred host: {} in hostmap (lookup) for cluster {}",
                     *decoder_callbacks_, ULID(S59h), host_with_port_lc,
                     cluster_with_pref_host->info()->name());
    
    // EricProxyClusterTypedMetadataFactory cluster_md_factory;
    if (cluster_md_object == nullptr) {
      ENVOY_STREAM_UL_LOG(debug, "No cluster md named {} found in configuration ", *decoder_callbacks_,
                       ULID(S59i), cluster_md_factory.name());
      return;
    }

    // START: support for indirect routing and loop prevention as well as interplmn fqdn
    // If the cluster has indirect routing metadata, loop prevention is checked by default
    const auto& found_indirect_it = cluster_md_object->producer_proxy_map.find(host_with_port_lc);
    if (found_indirect_it != cluster_md_object->producer_proxy_map.end()) {
      // pick one of the SCPs servicing the preferred producer at random
      // and make sure it's not on the via header.
      // This part also caters to interplmnfqdn
      ENVOY_STREAM_UL_LOG(debug,"Begin Via header filtering",*decoder_callbacks_, ULID(S59j));
      std::vector<std::tuple<absl::string_view, absl::string_view, IPver>> filtered_hosts;
      std::copy_if(found_indirect_it->second.begin(), found_indirect_it->second.end(),
                   std::back_inserter(filtered_hosts), [&](const auto& found_indirect_entry) {
                     for (const auto& via_entry : decoder_callbacks_->viaHeaderContents()) {
                       if (absl::EqualsIgnoreCase(via_entry, std::get<0>(found_indirect_entry)) ||
                           absl::EqualsIgnoreCase(via_entry, std::get<1>(found_indirect_entry))) {
                         return false;
                       }
                     }
                     return true;
                   });
      if (filtered_hosts.empty()) {
        ENVOY_STREAM_UL_LOG(debug,
                            "All hosts are in via header, cannot find indirect preferred host",
                            *decoder_callbacks_, ULID(S59k));
        return;
      }
      ENVOY_STREAM_UL_LOG(debug, "Hosts from via header filtered, continue processing",
                          *decoder_callbacks_, ULID(S59l));
  
      std::tuple<absl::string_view, absl::string_view, IPver> pref_host_pref_ip_fam;
      std::vector<std::tuple<absl::string_view,absl::string_view,IPver>> pref_hosts_pref_ip_fam {};
      std::vector<std::tuple<absl::string_view,absl::string_view,IPver>> pref_hosts_other_ip_fam {};
      if (filtered_hosts.size() == 1) {
        pref_host_pref_ip_fam = filtered_hosts.front();
      } else {
        // We should try to choose an endpoint of a preferred IP family
        for (const auto& entry : filtered_hosts) {
          if (std::get<2>(entry) == pref_ip_fam_version || pref_ip_fam_version == IPver::Default) {
            pref_hosts_pref_ip_fam.push_back(entry);
          } else {
            pref_hosts_other_ip_fam.push_back(entry);
          }
        }
        if (!pref_hosts_pref_ip_fam.empty()) {
          pref_host_pref_ip_fam =
              pref_hosts_pref_ip_fam.at(random_.random() % pref_hosts_pref_ip_fam.size());
        } else {
          return;
        }
      }
      const auto& fqdn_it = host_map->find(std::get<0>(pref_host_pref_ip_fam));
      if (fqdn_it != host_map->end()) {
        ENVOY_STREAM_UL_LOG(debug, "Found indirect preferred host in hostmap (lookup): {}",
                        *decoder_callbacks_, ULID(S59m), fqdn_it->first);
        setIPFamilyPolicy(pref_ip_fam_version, retry_multiple_address,
                          rb, std::string(std::get<0>(pref_host_pref_ip_fam)), fqdn_it->second);
        // with intruducing Stateful session, need a strict parameter:
        // https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/stateful_session/v3/stateful_session.proto#envoy-v3-api-msg-extensions-filters-http-stateful-session-v3-statefulsession
        // set it to false by default
        // TODO: configure
        decoder_callbacks_->setUpstreamOverrideHost({fqdn_it->first, false});
        original_hostname_ = fqdn_it->first;

        // if the host is addressable via an interplmn fqdn, present in the hosts metadata and that
        // fqdn
        // is how the host was queried, update the filter_state so that the router knows to modify the
        // :auth header properly and not with the hostname
        // Since with multihoming support many endpoints can have one addressable fqdn
        // Interplmn fqdn property is assumed to be equally present to different endpoints
        // of the preferred fqdn ( Maybe this handling will need to be changed in future )
        const auto& val = Config::Metadata::metadataValue(
            fqdn_it->second.at(0).first->metadata().get(), std::move("envoy.eric_proxy"),
            std::move("interplmn_fqdn"));
        if (val.has_list_value() && val.list_value().values(0).string_value() == host_with_port_lc) {
          // const Envoy::StreamInfo::FilterStateSharedPtr& filter_state =
          //     decoder_callbacks_->streamInfo().filterState();
          // auto eric_proxy_state = std::make_unique<StreamInfo::EricProxyState>();
          const auto& eric_proxy_state = decoder_callbacks_->streamInfo().filterState()->getDataMutable<StreamInfo::EricProxyState>
                                                            (StreamInfo::EricProxyState::key());
          // an example to check run_ctx population in
          // FSO TODO move the creation of FSO to an earlier point and just use getDataMutable and 
          // set the run_ctx in the FSO
          // eric_proxy_state->setEricRunContextPtr(&run_ctx_); 
          eric_proxy_state->setStrValueForKey(StreamInfo::EricProxyState::StringValues::InterplmnFqdn,
                                              host_with_port_lc);
          // filter_state->setData(StreamInfo::EricProxyState::key(), std::move(eric_proxy_state),
          //                       StreamInfo::FilterState::StateType::ReadOnly,
          //                       StreamInfo::FilterState::LifeSpan::Request);
        }
        return;
      } else {
        // FQDN is not found, so we are checking for IP-address now.
        // No IP Preference policy to be applied now.
        const auto& ip_it = host_map->find(std::get<0>(pref_host_pref_ip_fam));
        if (ip_it != host_map->end()) {
          ENVOY_STREAM_UL_LOG(debug, "Found indirect preferred host in hostmap (lookup): {}",
                          *decoder_callbacks_, ULID(S59n), ip_it->first);
          // with intruducing Stateful session, need a strict parameter:
          // https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/stateful_session/v3/stateful_session.proto#envoy-v3-api-msg-extensions-filters-http-stateful-session-v3-statefulsession
          // set it to false by default
          // TODO: configure
          decoder_callbacks_->setUpstreamOverrideHost({ip_it->first, false});
          return ;
        }
        // Preferred host (with at least one IP)
        // of preferred IP family have no entries for FQDN or IP in host map.
        // Attempt on other host with at least one IP of IP family != preferred_ip_family_version
        if(filtered_hosts.size() > 1 && !pref_hosts_other_ip_fam.empty()) {
          std::tuple<absl::string_view, absl::string_view, IPver>
              pref_host_other_ip_fam = pref_hosts_other_ip_fam.at(random_.random() % pref_hosts_other_ip_fam.size());
          const auto& ofqdn_it = host_map->find(std::get<0>(pref_host_other_ip_fam));
          if(ofqdn_it != host_map->end()) {
            // Found fqdn of a proxy with atleast one IP of different family in host map
            ENVOY_STREAM_UL_LOG(debug, "Found indirect preferred host in hostmap (lookup): {}",
                          *decoder_callbacks_, ULID(S59o), ofqdn_it->first);
            setIPFamilyPolicy(pref_ip_fam_version, retry_multiple_address,
                            rb, std::string(std::get<0>(pref_host_other_ip_fam)), ofqdn_it->second);
            // with intruducing Stateful session, need a strict parameter:
            // https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/stateful_session/v3/stateful_session.proto#envoy-v3-api-msg-extensions-filters-http-stateful-session-v3-statefulsession
            // set it to false by default
            // TODO: configure
            decoder_callbacks_->setUpstreamOverrideHost({ofqdn_it->first, false});
            return;
          } else {
            // Couldn't find FQDN of other host as well, try its IP address in hostmap
            const auto& oip_it = host_map->find(std::get<1>(pref_host_other_ip_fam));
            if (oip_it != host_map->end()) {
              ENVOY_STREAM_UL_LOG(debug, "Found indirect preferred host in hostmap (lookup): {}",
                                  *decoder_callbacks_, ULID(S59p), oip_it->first);
              decoder_callbacks_->setUpstreamOverrideHost({oip_it->first, false});

              return;
            } else {
              // If inirect routing host cannot be determined after two attempts then return
              // without setting override_host
              return;
            }
          }
        } else { return ; }
      }
   
  }
  // print hostmap contents
  // std::string map_str = "[";
  // for (const auto& entry : *host_map) {
  //   absl::StrAppend(&map_str, entry.first, ", ");
  }
  // absl::StrAppend(&map_str, "]");
  // ENVOY_STREAM_UL_LOG(debug, "hostmap contents:\n {}", *decoder_callbacks_, ULID(S59q), map_str);
}

void EricProxyFilter::setIPFamilyPolicy(const IPver pref_ip_version,
                                        bool retry_multiple_addr,
                                        const RoutingBehaviour& rb,
                                        const std::string& pref_host,
                                        const std::vector<std::pair<std::shared_ptr<Envoy::Upstream::Host>, unsigned short>>& host_vector) {
  // If target endpoint mentioned in TaR or authority is an Ipv4/v6 address
  // IP Family Preference should not be enforced
  const auto target_endpoint = Http::Utility::parseAuthority(pref_host);

    if((rb == RoutingBehaviour::PREFERRED || rb == RoutingBehaviour::STRICT) &&
        !target_endpoint.is_ip_address_)
    {
      // Create the retry index vector for the target host
      // const auto& it_host_vector = ;
      std::vector<uint32_t> v4_index {};
      std::vector<uint32_t> v6_index {};
    
      uint32_t idx = 0;
      std::for_each(host_vector.begin(),host_vector.end(),
                      [&idx,&v4_index,&v6_index](const auto& host) {
                        switch(host.first->address()->ip()->version()) {
                          case Envoy::Network::Address::IpVersion::v4:
                            v4_index.push_back(idx);
                            break;
                          case Envoy::Network::Address::IpVersion::v6:
                            v6_index.push_back(idx);
                            break;
                        }
                        idx = idx + 1;
                      });
      std::random_shuffle(v4_index.begin(),v4_index.end(),
                            [&](int){ return random_.random() % v4_index.size();});
      std::random_shuffle(v6_index.begin(),v6_index.end(),
                              [&](int){ return random_.random() % v6_index.size();});
      switch(pref_ip_version){
        case IPver::Default:
        case IPver::IPv4:
          v4_index.insert(v4_index.end(),v6_index.begin(),v6_index.end());
          if(retry_multiple_addr) {
            ENVOY_LOG(debug,"Setting prefHostRetryIndices():{}",fmt::format("{}",v4_index));
            decoder_callbacks_->setPreferredHostRetryIndices(v4_index);
          } else {
            ENVOY_LOG(debug,"Setting prefHostRetryIndices():{}",fmt::format("{}",v4_index.at(0)));
            decoder_callbacks_->setPreferredHostRetryIndices({v4_index.at(0)});
          }
          break;
        case IPver::IPv6:
          v6_index.insert(v6_index.end(),v4_index.begin(),v4_index.end());
          ENVOY_LOG(debug,"Setting prefHostRetryIndices():{}",fmt::format("{}",v6_index));
          if(retry_multiple_addr) {
            ENVOY_LOG(debug,"Setting prefHostRetryIndices():{}",fmt::format("{}",v6_index));
            decoder_callbacks_->setPreferredHostRetryIndices(v6_index); 
          } else {
            ENVOY_LOG(debug,"Setting prefHostRetryIndices():{}",fmt::format("{}",v6_index.at(0)));
            decoder_callbacks_->setPreferredHostRetryIndices({v6_index.at(0)});
          }
          break;
        default:
          break;
      }
    }
}

/**
 * Extract the host and port part from a given URL-like string.
 * and make everything lowercase
 * Example:  http://www.aBc.com:80/path  --> www.abc.com:80
 * Example:  https://[fe:20::3]:443/path --> [fe:20::3]:443
* Example:  https://[FE:20::3]:443/path --> [fe:20::3]:443

 *
 * If the port is missing, add ":443" if it's a https scheme, otherwise
 * (http or no scheme) add ":80".
 * Example:  http://www.abc.com/path  --> www.abc.com:80
 * Example:  www.abc.com/path  --> www.abc.com:80
 * Example:  https://[fe:20::3]/path --> [fe:20::3]:443
 *
 * If the supplied URL-like string is empty, the return value is also empty.
 *
 * As a side-effect, if the schema is https, then add a header "x-scheme-https".
 */

std::string EricProxyFilter::extractHostAndPort(absl::string_view url,
                                                Http::RequestOrResponseHeaderMap& headers,
                                                bool add_scheme_header) {
  // Envoy has a handy function that does most of what we need, but it doesn't
  // remove the scheme, so we do that ourselves.
  bool isHttps = false;
  if (url.compare(0, 7, "http://") == 0) {
    url.remove_prefix(7);
  } else if (url.compare(0, 8, "https://") == 0) {
    url.remove_prefix(8);
    if (add_scheme_header) {
      headers.setCopy(Http::LowerCaseString("x-scheme-https"), "");
    }
    isHttps = true;
  }
  // Also remove a path
  auto posPathStart = url.find('/');
  if (posPathStart != absl::string_view::npos) {
    url.remove_suffix(url.length() - posPathStart);
  }

  // Shortcut if the address is empty -> return an empty string
  if (url.empty()) {
    return "";
  }
  // convert what we have to lowercase
  std::string lowercase_res = absl::AsciiStrToLower(url);
  // Check if port is present. If not, add it.
  if (absl::StrContains(url, ":")) {
    // ":" found, make sure it's not an IPv6 without port
    // If it ends with "]", it must be IPv6
    if (absl::EndsWith(url, "]")) {
      // IPv6 without port
      absl::StrAppend(&lowercase_res, isHttps ? ":443" : ":80");
    }
  } else {
    // IPv4/FQDN without port, add it
    absl::StrAppend(&lowercase_res, isHttps ? ":443" : ":80");
  }
  // url contains ':' but does not end with ']' so it has a port already
  return lowercase_res;
}

/**
 * Helper function that returns the (json-type) value referenced by "VarOrString" from
 * the configuration.
 * If a term_string is found, its value is returned as a Json object of type string.
 * If you need to have the term_string parsed into JSON, then use the function
 * varOrJsonStringAsJson() instead.
 */
Json EricProxyFilter::varOrStringAsJson(const VarOrString& var_or_string_ref, RunContext& run_ctx,
                                        Http::StreamDecoderFilterCallbacks* decoder_callbacks) {
  // TERM_STRING
  if (var_or_string_ref.has_term_string()) {
    return var_or_string_ref.term_string();
    // TERM_VAR
  } else {
    return varOrStringCommon(var_or_string_ref, run_ctx, decoder_callbacks);
  }
}

/**
 * Helper function that returns the (json-type) value referenced by "var_or_json_string_ref" from
 * the configuration.
 * If the var_or_json_string_ref is a string, then the string value is parsed as JSON.
 * This function is typically used in body-modification actions where a string means
 * "json-string".
 * If you need a string as a json-string, then use varOrStringAsJson() instead.
 */
Json EricProxyFilter::varOrJsonStringAsJson(const VarOrString& var_or_json_string_ref,
                                            RunContext& run_ctx,
                                            Http::StreamDecoderFilterCallbacks* decoder_callbacks) {
  // TERM_STRING
  if (var_or_json_string_ref.has_term_string()) {
    try {
      return Json::parse(var_or_json_string_ref.term_string());
    } catch (Json::parse_error& e) {
      // If we come here, it's a string that has no quotes around
      return var_or_json_string_ref.term_string();
    }
    // TERM_VAR
  } else {
    return varOrStringCommon(var_or_json_string_ref, run_ctx, decoder_callbacks);
  }
}

// Common code for the two functions above
Json EricProxyFilter::varOrStringCommon(const VarOrString& var_or_string_ref, RunContext& run_ctx,
                                        Http::StreamDecoderFilterCallbacks* decoder_callbacks) {
  if (var_or_string_ref.has_term_var()) {
    const auto& var_name = var_or_string_ref.term_var();
    if (!run_ctx.rootContext()->hasVarName(var_name)) {
      ENVOY_STREAM_LOG(debug, "variable {} not found in rootContext", *decoder_callbacks, var_name);
      return Json(); // json "null"
    }
    auto var_value_idx = run_ctx.rootContext()->findOrInsertVarName(var_name, decoder_callbacks);
    if (run_ctx.varValueIsEmpty(var_value_idx)) {
      ENVOY_STREAM_LOG(debug, "variable {} is not set in runContext", *decoder_callbacks, var_name);
      return Json(); // json "null"
    } else {
      return run_ctx.varValue(var_value_idx);
    }
  } else {
    ENVOY_STREAM_LOG(debug,
                     "Neither term_var nor term_string set, this should have "
                     "been caught by protobuf validation",
                     *decoder_callbacks);
    return Json(); // json "null"
  }
}

/**
 * Helper function that returns the String value referenced by "VarOrString" from
 * the configuration.
 * If you need a Json object instead, then use varOrJsonStringAsJson() or
 * varOrStringAsJson() instead.
 */
std::string
EricProxyFilter::varOrStringAsString(const VarOrString& var_or_string_ref, RunContext& run_ctx,
                                     Http::StreamDecoderFilterCallbacks* decoder_callbacks) {
  // TERM_STRING
  if (var_or_string_ref.has_term_string()) {
    return var_or_string_ref.term_string();
    // TERM_VAR
  } else if (var_or_string_ref.has_term_var()) {
    const auto& var_name = var_or_string_ref.term_var();
    if (!run_ctx.rootContext()->hasVarName(var_name)) {
      ENVOY_STREAM_LOG(debug, "variable {} not found in rootContext", *decoder_callbacks, var_name);
      return "";
    }
    auto var_value_idx = run_ctx.rootContext()->findOrInsertVarName(var_name, decoder_callbacks);
    // TODO: check if the branch below is what we want or call to_string on the json object it is
    //      of another type ?
    if (!run_ctx.varValue(var_value_idx).is_string() || run_ctx.varValueIsEmpty(var_value_idx)) {
      ENVOY_STREAM_LOG(debug, "variable '{}' (index: {}) is not set in runContext", *decoder_callbacks, var_name, var_value_idx);
      return "";
    } else {
      return run_ctx.varValueAsString(var_value_idx);
    }
  } else {
    ENVOY_STREAM_LOG(debug,
                     "Neither term_var nor term_string set, this should have "
                     "been caught by protobuf validation",
                     *decoder_callbacks);
    return "";
  }
}

void EricProxyFilter::executeRemoteRoutingAction(const FilterActionWrapper& action) {
  const auto proto_config = action.protoConfig().action_route_to_pool();

  if (proto_config.routing_behaviour() == RoutingBehaviour::REMOTE_PREFERRED) {
    if (!proto_config.has_remote_retries()) {
      ENVOY_STREAM_LOG(trace, "Remote preferred routing: remote_retries is not configured", *decoder_callbacks_);
      return;
    }
    if (proto_config.remote_retries().value() < 0) {
      ENVOY_STREAM_LOG(trace, "Remote preferred routing: remote_retries is less than 0", *decoder_callbacks_);
      return;
    }
  }

  if (!proto_config.has_remote_reselections()) {
    ENVOY_STREAM_LOG(trace, "Remote routing: remote_reselections is not configured", *decoder_callbacks_);
    return;
  }
  if (proto_config.remote_reselections().value() < 0) {
    ENVOY_STREAM_LOG(trace, "Remote routing: remote_reselections is less than 0", *decoder_callbacks_);
    return;
  }

  // Checks on the NF discovery result
  // NF discovery result is empty or no NF instances are found
  // or NF instances are empty in NLF lookup result
  if (
    discovery_result_json_.empty() ||
    !discovery_result_json_.contains("nfInstances") ||
    (discovery_result_json_.at("nfInstances").is_array() && discovery_result_json_.at("nfInstances").empty())
  ) {
    ENVOY_STREAM_LOG(trace, "NF discovery result is empty", *decoder_callbacks_);
    sendLocalReplyWithSpecificContentType(
        400, "application/problem+json",
        R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_empty_result"})",
        StreamInfo::ResponseCodeDetails::get().DirectResponse);
    return;
  }
  // Invalid NF instances in NLF lookup result
  if (!discovery_result_json_.at("nfInstances").is_array()) {
    ENVOY_STREAM_LOG(trace, "Invalid NF instances in NLF lookup result", *decoder_callbacks_);
    sendLocalReplyWithSpecificContentType(
        400, "application/problem+json",
        R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_response_malformed"})",
        StreamInfo::ResponseCodeDetails::get().DirectResponse);
    return;
  }

  ProtobufWkt::Struct metadata;

  // Flag to indicate that target-api-root processing is needed:
  *(*metadata.mutable_fields())["target-api-root-processing"].mutable_string_value() = "true";

  if (proto_config.preserve_disc_params_if_indirect().has_preserve_params()) {
    ENVOY_STREAM_LOG(trace, "Applying preserve_disc_params_if_indirect", *decoder_callbacks_);
    auto& disc_params_to_preserved_md = *(*metadata.mutable_fields())["disc-parameters-to-be-preserved-if-indirect"].mutable_list_value();
    for (const auto& preserve_param : proto_config.preserve_disc_params_if_indirect().preserve_params().values()){
      ENVOY_STREAM_LOG(trace, "preserve_param: {}", *decoder_callbacks_, preserve_param);
      disc_params_to_preserved_md.add_values()->set_string_value(preserve_param);
    }
  } else if (proto_config.preserve_disc_params_if_indirect().has_preserve_all()) {
    ENVOY_STREAM_LOG(trace, "Applying preserve_disc_params_if_indirect: preserve_all", *decoder_callbacks_);
    *(*metadata.mutable_fields())["preserve-all-disc-parameters-if-indirect"].mutable_string_value() = "true";
  }

  std::vector<std::string> tar_values;

  if (proto_config.routing_behaviour() == RoutingBehaviour::REMOTE_ROUND_ROBIN) {
    const auto& tar_list  = selectTarsForRemoteRouting(
      discovery_result_json_, proto_config.remote_reselections().value(), nf_disc_ip_version_, nf_set_id_
    );
    if (!tar_list.ok()) {
      if (tar_list.status().code() == absl::StatusCode::kInvalidArgument) {
        sendLocalReplyWithSpecificContentType(
            400, "application/problem+json",
            R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_response_malformed"})",
            StreamInfo::ResponseCodeDetails::get().DirectResponse);
        return;
      }
      sendLocalReplyWithSpecificContentType(
          400, "application/problem+json",
          R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_empty_result"})",
          StreamInfo::ResponseCodeDetails::get().DirectResponse);
      return;
    }
    tar_values = tar_list.value();
  }

  if (proto_config.routing_behaviour() == RoutingBehaviour::REMOTE_PREFERRED) {
    if (proto_config.preferred_target().val_case() == VarHeaderConstValue::VAL_NOT_SET) {
      ENVOY_STREAM_LOG(error, "Remote preferred routing: preferred_target is not configured", *decoder_callbacks_);
      return;
    }
    auto pref_host = varHeaderConstValueAsString(proto_config.preferred_target(), false);
    if (pref_host.empty()) {
      ENVOY_STREAM_LOG(error, "Remote preferred routing: preferred host is not present", *decoder_callbacks_);
      return;
    }
    const auto& tar_list = selectTarsForRemoteRouting(
      discovery_result_json_, proto_config.remote_reselections().value(), nf_disc_ip_version_, nf_set_id_,
      proto_config.remote_retries().value(), pref_host
    );
    if (!tar_list.ok()) {
      if (tar_list.status().code() == absl::StatusCode::kInvalidArgument) {
        sendLocalReplyWithSpecificContentType(
            400, "application/problem+json",
            R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_response_malformed"})",
            StreamInfo::ResponseCodeDetails::get().DirectResponse);
        return;
      }
      sendLocalReplyWithSpecificContentType(
          400, "application/problem+json",
          R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_empty_result"})",
          StreamInfo::ResponseCodeDetails::get().DirectResponse);
      return;
    }
    tar_values = tar_list.value();
  }

  if (tar_values.empty()) {
    ENVOY_STREAM_LOG(error, "Remote routing: list of TaRs is empty.", *decoder_callbacks_);
    return;
  }

  // Modify num_retries according to the size of TaR list
  run_ctx_.getReqOrRespHeaders()->addCopy(Http::LowerCaseString("x-envoy-max-retries"), tar_values.size() - 1);

  // Remove "target-api-root-value" from dyn. MD
  if(findInDynMetadata(&decoder_callbacks_->streamInfo().dynamicMetadata().filter_metadata(),
                        "eric_proxy","target-api-root-value")) {
      (*decoder_callbacks_->streamInfo().dynamicMetadata().mutable_filter_metadata())["eric_proxy"]
  .mutable_fields()->erase("target-api-root-value");
  }

  auto& tar_values_md = *(*metadata.mutable_fields())["target-api-root-values"].mutable_list_value();
  for (const auto& tar_value : tar_values) {
    ENVOY_STREAM_LOG(trace, "tar_value: {}", *decoder_callbacks_, tar_value);
    tar_values_md.add_values()->set_string_value(tar_value);
  }
  decoder_callbacks_->streamInfo().setDynamicMetadata("eric_proxy", metadata);
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
