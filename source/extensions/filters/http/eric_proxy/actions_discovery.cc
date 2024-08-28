#include <random>
#include "envoy/http/async_client.h"
#include "source/common/http/message_impl.h"
#include "source/common/http/utility.h"
#include "source/common/common/utility.h"
#include "source/extensions/common/tap/utility.h"
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_request_meta.h"
#include "include/nlohmann/json.hpp"


// Methods in this file are all in the EricProxyFilter class.
// They are stored in a separate file to keep action processing
// separate.

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using Json = nlohmann::json;

// Action-NF-Discovery:
// - Select discovery headers
// - Send discovery request to NLF
// The response is handled asynchronously in another method
ActionResultTuple EricProxyFilter::actionNfDiscovery(const ActionNfDiscoveryWrapper& action) {
  ENVOY_STREAM_UL_LOG(debug, "action-nf-discovery", *decoder_callbacks_, "A01");
  const auto proto_config = action.protoConfig().action_nf_discovery();

  // Check that the configured cluster exists
  const std::string& cluster_name = proto_config.cluster_name();
  const auto thread_local_cluster = config_->clusterManager().getThreadLocalCluster(cluster_name);
  if (thread_local_cluster == nullptr) {
    ENVOY_STREAM_UL_LOG(error, "NLF cluster ({}) invalid.", *decoder_callbacks_, "A02", cluster_name);
    sendLocalReplyWithSpecificContentType(
        504, "application/problem+json",
          R"({"status": 504, "title": "Gateway Timeout", "cause": "NRF_NOT_REACHABLE", "detail": "nf_discovery_nrf_not_reachable"})",
          StreamInfo::ResponseCodeDetails::get().DirectResponse);
    return std::make_tuple(ActionResult::StopIteration, true, std::nullopt);
  }

  // Construct the discovery message to NLF/NRF. "header" also contains the path (in ":path").
  auto headers = prepareNlfRequest(action);
  Http::RequestMessagePtr message(new Http::RequestMessageImpl(std::move(headers)));

  // This is the overall NRF-discovery-timeout including all retries and reselects:
  // The per-try-timeout is set in the retry_policy.
  auto timeout = std::chrono::milliseconds(proto_config.timeout());
  auto options = Http::AsyncClient::RequestOptions().setTimeout(timeout);
  auto retry_policy = retryPolicyForLookup(thread_local_cluster, timeout);
  options.setRetryPolicy(retry_policy);

  auto discoveryRequest =
    thread_local_cluster->httpAsyncClient().send(std::move(message), discovery_callbacks_, options);

  if (discoveryRequest != nullptr) {
    ENVOY_STREAM_UL_LOG(debug, "Discovery request sent", *decoder_callbacks_, "A03");
    lookup_request_ = discoveryRequest;
  } else {
    ENVOY_STREAM_UL_LOG(debug, "Discovery request sending failed", *decoder_callbacks_, "A04");
    sendLocalReplyWithSpecificContentType(
        504, "application/problem+json",
      R"({"status": 504, "title": "Gateway Timeout", "cause": "NRF_NOT_REACHABLE", "detail": "nf_discovery_nrf_not_reachable"})",
          StreamInfo::ResponseCodeDetails::get().DirectResponse);
    return std::make_tuple(ActionResult::StopIteration, true, std::nullopt);
  }
  // Store the action, so that we have access from the callbacks
  deferred_lookup_action_ = &action;
  return std::make_tuple(ActionResult::PauseIteration, false, std::nullopt);
}


// Prepare & return the request headers for the NF-discovery, including path and query parameters.
// When copying the received discovery parameters from header to query-parameter, apply
// the use- and add- configuration.
// Also copy the correlation-info header if present in the request.
std::unique_ptr<Http::RequestHeaderMapImpl> EricProxyFilter::prepareNlfRequest(
    const ActionNfDiscoveryWrapper& action) {
  auto nlf_headers = Http::RequestHeaderMapImpl::create();
  // Transfer the received headers into the querystring:
  auto querystring = prepareNlfQueryString(action);
  auto path = absl::StrCat("/nnlf-disc/v0/nf-instances/", config_->nodeTypeLc(), "?", querystring);
  nlf_headers->addCopy(Http::LowerCaseString(":path"), path);
  nlf_headers->addCopy(Http::LowerCaseString(":method"), "GET");
  nlf_headers->addCopy(Http::LowerCaseString(":authority"), "eric-sc-nlf");
  nlf_headers->addCopy(Http::LowerCaseString(":scheme"), "https");
  nlf_headers->addCopy(Http::LowerCaseString("user-agent"), config_->nodeTypeUc());
  nlf_headers->addCopy(Http::LowerCaseString("nrf-group"),
      action.protoConfig().action_nf_discovery().nrf_group_name());
  // If the received request includes the header 3gpp-Sbi-Correlation-Info, then add it
  // unmodified to the discovery request (TS 29.500 (Rel-17), section 6.13.2.2):
  auto corr_header_name = Http::LowerCaseString("3gpp-sbi-correlation-info");
  auto corr_header = run_ctx_.getReqHeaders()->get(corr_header_name);
  if (! corr_header.empty()) {
    nlf_headers->addCopy(corr_header_name, corr_header[0]->value().getStringView());
  }

  return nlf_headers;
}


// Callback: Successful NLF-discovery request. "Success" means we got a response
// from the NLF, but it doesn't mean it's always a 2xx response.
// This function is used in filter.h where it's put into "discovery_callbacks_".
void EricProxyFilter::onNfDiscoverySuccess(Http::ResponseMessagePtr&& lookup_resp) {
  ENVOY_STREAM_UL_LOG(debug, "onNfDiscoverySuccess()", *decoder_callbacks_, "A05");
  lookup_request_ = nullptr;
  auto nlf_status = lookup_resp->headers().getStatusValue();
  auto nlf_body = lookup_resp->bodyAsString();

  ENVOY_STREAM_UL_LOG(debug, "NLF status: {}, NLF body: {}", *decoder_callbacks_, "A05",
      nlf_status, nlf_body);

  if (nlf_status == "200") {
    processNfDiscoveryOk(nlf_body);
  } else {
    processNfDiscoveryErrors(nlf_status, nlf_body);
  }

  if (deferred_filter_case_ptr_ == nullptr){
    ENVOY_STREAM_UL_LOG(debug, "Filter chain execution was not paused yet. Just continue.",
        *decoder_callbacks_, "A06");
    return;
  }

  continueProcessingAfterSlfResponse();
}


// Callback: Request to NLF failed. This is not a 4xx/5xx situation (which is handled
// in onNfDiscoverySuccess()) but when the communication with the NLF failed.
// This function is used in filter.h where it's put into "discovery_callbacks_".
void EricProxyFilter::onNfDiscoveryFailure(Http::AsyncClient::FailureReason failure_reason) {
  ENVOY_STREAM_UL_LOG(debug, "Failure reason:{}", *decoder_callbacks_, "A07",
      static_cast<int>(failure_reason));
  lookup_request_ = nullptr;
  sendLocalReplyWithSpecificContentType(
      504, "application/problem+json",
      R"({"status": 504, "title": "Gateway Timeout", "cause": "NRF_NOT_REACHABLE", "detail": "nf_discovery_nrf_not_reachable"})",
      StreamInfo::ResponseCodeDetails::get().DirectResponse);
  deferred_lookup_result_ = std::make_tuple(ActionResult::StopIteration, true, std::nullopt);
  continueProcessingAfterSlfResponse();
}


// Received a 200 OK from the NLF
void EricProxyFilter::processNfDiscoveryOk(const std::string& body) {
  ENVOY_STREAM_LOG(trace, "processNfDiscoveryOk()", *decoder_callbacks_);
  // Decode the NF discovery result into a JSON object
  try {
    discovery_result_json_ = Json::parse(body);
  } catch (Json::parse_error& e) {
    ENVOY_STREAM_UL_LOG(debug, "Malformed JSON body in NF-discovery response ({})",
        *decoder_callbacks_, "A13", e.what());
    sendLocalReplyWithSpecificContentType(
        400, "application/problem+json",
        R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_response_malformed"})",
        StreamInfo::ResponseCodeDetails::get().DirectResponse);
    deferred_lookup_result_ = std::make_tuple(ActionResult::StopIteration, true, std::nullopt);
    return;
  }

  // Checks on the NF discovery result
  // NF discovery result is empty or no NF instances are found
  // or NF instances are empty in NLF lookup result
  // ULID A14
  if (
    discovery_result_json_.empty() ||
    !discovery_result_json_.contains("nfInstances") ||
    (discovery_result_json_.at("nfInstances").is_array() && discovery_result_json_.at("nfInstances").empty())
  ) {
    ENVOY_STREAM_UL_LOG(trace, "NF discovery result is empty", *decoder_callbacks_, "A14");
    sendLocalReplyWithSpecificContentType(
        400, "application/problem+json",
        R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_empty_result"})",
        StreamInfo::ResponseCodeDetails::get().DirectResponse);
    deferred_lookup_result_ = std::make_tuple(ActionResult::StopIteration, true, std::nullopt);
    return;
  }
  // Invalid NF instances in NLF lookup result
  // ULID A15
  if (!discovery_result_json_.at("nfInstances").is_array()) {
    ENVOY_STREAM_UL_LOG(trace, "Invalid NF instances in NLF lookup result", *decoder_callbacks_, "A15");
    sendLocalReplyWithSpecificContentType(
        400, "application/problem+json",
        R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_response_malformed"})",
        StreamInfo::ResponseCodeDetails::get().DirectResponse);
    deferred_lookup_result_ = std::make_tuple(ActionResult::StopIteration, true, std::nullopt);
    return;
  }

  // Setting IP version for endpoint selection from configured
  // IP version inside action_nf_discovery
  switch(deferred_lookup_action_->protoConfig().action_nf_discovery().ip_version()) {
  case envoy::extensions::filters::http::eric_proxy::v3::IPFamily::Default:
    nf_disc_ip_version_ = IPver::Default;
    break;
  case envoy::extensions::filters::http::eric_proxy::v3::IPFamily::IPv4:
    nf_disc_ip_version_ = IPver::IPv4;
    break;
  case envoy::extensions::filters::http::eric_proxy::v3::IPFamily::IPv6:
    nf_disc_ip_version_ = IPver::IPv6;
    break;
  case envoy::extensions::filters::http::eric_proxy::v3::IPFamily::DualStack:
    nf_disc_ip_version_ = IPver::DualStack;
    break;
  default:
    break;  
  }

  // User configured NF-selection-on-priority -> set preferred-host + nf-set-id
  if (deferred_lookup_action_->protoConfig().action_nf_discovery().has_nf_selection_on_priority()) {
    ENVOY_STREAM_LOG(trace, "nf selection on priority", *decoder_callbacks_);
    const auto& selected_nf = selectNfOnPriority(discovery_result_json_, nf_disc_ip_version_);
    if (!selected_nf.ok()) {
      if (selected_nf.status().code() == absl::StatusCode::kInvalidArgument) {
        sendLocalReplyWithSpecificContentType(
            400, "application/problem+json",
            R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_response_malformed"})",
            StreamInfo::ResponseCodeDetails::get().DirectResponse);
        deferred_lookup_result_ = std::make_tuple(ActionResult::StopIteration, true, std::nullopt);
        return;
      }
      sendLocalReplyWithSpecificContentType(
          400, "application/problem+json",
          R"({"status": 400, "title": "Bad Request", "cause": "NF_DISCOVERY_FAILURE", "detail": "nf_discovery_empty_result"})",
          StreamInfo::ResponseCodeDetails::get().DirectResponse);
      deferred_lookup_result_ = std::make_tuple(ActionResult::StopIteration, true, std::nullopt);
      return;
    }
    const auto& nf_sel_prio = deferred_lookup_action_->protoConfig().action_nf_discovery().nf_selection_on_priority();
    if (selected_nf->hostname.has_value()) {
      auto& dest_var = nf_sel_prio.var_name_preferred_host();
      updateDestVar(dest_var, selected_nf->hostname.value(), "preferred host");
    }
    if (selected_nf->set_id.has_value()) {
      auto& dest_var = nf_sel_prio.var_name_nf_set();
      updateDestVar(dest_var, selected_nf->set_id.value(), "nf-set ID");
      nf_set_id_ = selected_nf->set_id.value();
    }
    if (config_->isNfPeerinfoActivated() && selected_nf->nfInstanceId.has_value()) {
      ENVOY_STREAM_LOG(debug, "Setting the producer id to metadata", *decoder_callbacks_);
      ENVOY_STREAM_LOG(trace, "Found selected_nf_id: {}", *decoder_callbacks_, selected_nf->nfInstanceId.value_or("empty"));
      SbiNfPeerInfoHeaderRequestMetadata::updateDstInstInMetadata(decoder_callbacks_, selected_nf->nfInstanceId.value());
    }
  }
  // If the user uses action-remote-round-robin, the extraction of TaR headers from
  // the discovery result will be done there.
}


// Helper-function to store the received data in the configured variable incl. error processing.
void EricProxyFilter::updateDestVar(const std::string& dest_var, const std::string& value,
    const std::string& var_description) {
  auto fc_ptr = deferred_filter_case_ptr_;
  if (fc_ptr != nullptr) {
    auto dest_value_idx = run_ctx_.rootContext()->findOrInsertVarName(dest_var, decoder_callbacks_);
    run_ctx_.updateVarValue(dest_value_idx, value, fc_ptr);
    ENVOY_STREAM_LOG(debug, "Stored {}: '{}' in variable: '{}'", *decoder_callbacks_,
        var_description, value, dest_var);
  } else {
    ENVOY_STREAM_LOG(error, "Invalid fc_ptr", *decoder_callbacks_);
  }
}


// If we received a non-200 response from NLF, we end up here: Error handling.
// If it's a 504 (timeout, can come from ourselves or NLF), we send a 504.
// If it's a 429 (too many requests) or 5xx error, we will return 502.
// For all other cases, the received error response (including the body)
// will be forwarded to the requester.
void EricProxyFilter::processNfDiscoveryErrors(absl::string_view status, const std::string& body) {
  // 504 timeout
  if (status == "504") {
    ENVOY_STREAM_UL_LOG(debug, "action-nf-discovery: 504 timeout from {}", *decoder_callbacks_,
        "A08", body == "upstream request timeout" ? config_->nodeTypeUc() : "NLF");
    sendLocalReplyWithSpecificContentType(
      504, "application/problem+json",
      R"({"status": 504, "title": "Gateway Timeout", "cause": "NRF_NOT_REACHABLE", "detail": "nf_discovery_nrf_not_reachable"})",
      StreamInfo::ResponseCodeDetails::get().DirectResponse);
  // 429 too many requests or 5xx:
  } else if (status.front() == '5' || status == "429") {
  // 5xx and 429 errors:
    ENVOY_STREAM_UL_LOG(debug, "action-nf-discovery: {} -> 502 NF_DISCOVERY_ERROR", *decoder_callbacks_,
        "A09", status);
    // Extra debug message for easier troubleshooting:
    // 503 connect error, typically Envoy cannot reach the NLF.
    if (status == "503") {
      ENVOY_STREAM_UL_LOG(debug, "action-nf-discovery: 503 connect error/service unavailable from {}", *decoder_callbacks_,
          "A11", absl::StartsWith(body, "upstream connect error") ? config_->nodeTypeUc() : "NLF");
    }
    sendLocalReplyWithSpecificContentType(
      502, "application/problem+json",
      R"({"status": 502, "title": "Bad Gateway", "cause": "NF_DISCOVERY_ERROR", "detail": "nf_discovery_error_response_received"})",
      StreamInfo::ResponseCodeDetails::get().DirectResponse);
  } else {
    // All non-429 and non-5xx cases:
    ENVOY_STREAM_UL_LOG(debug, "action-nf-discovery: {} -> pass on to requester", *decoder_callbacks_,
        "A10", status);
    sendLocalReplyWithSpecificContentType(status, "application/problem+json", body,
      StreamInfo::ResponseCodeDetails::get().DirectResponse);
  }
  deferred_lookup_result_ = std::make_tuple(ActionResult::StopIteration, true, std::nullopt);
}


// Copy the 3gpp-Sbi-Discovery-* header values to the query-string (without the
// "3gpp-Sbi-Discovery-" part). Unless use_all_parameters is true, use only the
// ones listed in "use_parameters". If any of the parameters in "add_parameters_if_missing"
// are not in the **outgoing** request to the NLF, add them with their configured values.
std::string EricProxyFilter::prepareNlfQueryString(const ActionNfDiscoveryWrapper& action) {
  std::string query_string;
  // Keep track so that add-params knows which parameter is already present
  std::unordered_set<std::string> params_in_nlf_req;
  auto proto_config = action.protoConfig().action_nf_discovery();
  // Use all query parameters
  if (proto_config.use_all_parameters()) {
    run_ctx_.getReqHeaders()->iterate([&](const Http::HeaderEntry& entry) -> Http::HeaderMap::Iterate {
        if (absl::StartsWithIgnoreCase(entry.key().getStringView(), "3gpp-sbi-discovery-")) {
          // The "19" in the next line is the number of characters in "3gpp-sbi-discovery-"
          const std::string& param_name(std::string(entry.key().getStringView().substr(19)));
          addToQueryString(query_string, param_name, entry.value().getStringView());
          params_in_nlf_req.insert(absl::AsciiStrToLower(param_name));
        }
      return Http::HeaderMap::Iterate::Continue;
    });
  } else { // Use (=copy) only configured parameters
    if (proto_config.has_use_parameters()) {
      for (auto& param_name: proto_config.use_parameters().values()) {
        // Check if the configured header exists in the request:
        auto header_name = absl::StrCat("3gpp-sbi-discovery-", param_name);
        auto req_disc_headers = run_ctx_.getReqHeaders()->get(Http::LowerCaseString(header_name));
        if (!req_disc_headers.empty()) {
          // Yes -> add the received header value to the query string
          addToQueryString(query_string, param_name, req_disc_headers[0]->value().getStringView());
          params_in_nlf_req.insert(absl::AsciiStrToLower(param_name));
        }
      }
    }
  }

  // add-parameter-if-missing
  // Add default values if a discovery-parameter is missing in the **outgoing request to
  // the NLF** and if a default value is configured
  if (!proto_config.add_parameters_if_missing().empty()) {
    for (auto& it: proto_config.add_parameters_if_missing()) {
      // Check if the configured header exists in the request to NLF:
      if (params_in_nlf_req.find(absl::AsciiStrToLower(it.key())) == params_in_nlf_req.end()) {
        // No -> add the configured header+value to the query-string
        std::string value;
        if (it.value().has_term_string()) {
          // Add string constant:
          value = it.value().term_string();
        } else {
          // Add a variable value:
          // Get the variable index from the wrapper created at config time:
          std::optional<int> index = action.paramToAddIdx(it.value().term_var());
          if (index) {  // Found
            value = run_ctx_.varValueAsString(index.value());
          } else {  // Not found, should never happen
            ENVOY_STREAM_UL_LOG(error, "Variable not found for '{}'", *decoder_callbacks_,
                "A12", it.key());
            value = "";
          }
        }
        addToQueryString(query_string, it.key(), value);
      }
    }
  }
  return query_string;
}


// Add a parameter+value to the query-string. Percent-encode the value if needed.
// If the parameter is "service-names" or "required-features", and if the value is
// a list, then only use the first value of each list. See TS29.510 v16.12 table 6.2.3.2.3.1-1
// "URI-query parameters supported by the GET method on this resource"
void EricProxyFilter::addToQueryString(std::string& query_string, absl::string_view name, absl::string_view value) {
  // Special treatment for "service-names" and "required-features": only keep first element
  // if the value is a list
  if (name == "service-names" || name == "required-features") {
    auto sep_pos = value.find_first_of(" ,");
    if (sep_pos != absl::string_view::npos) {
      // The value is a list -> truncate to use only the first element
      value = value.substr(0, sep_pos);
    }
  }

  // Percent-encode if necessary:
  auto it = disc_params_needing_percent_encoding_.find(std::string(name));
  if (it == disc_params_needing_percent_encoding_.end()) {
    // No percent-encoding needed, just copy the value:
    absl::StrAppend(&query_string, name, "=", value, "&");
  } else {
    // Percent-encode the parameter value:
    absl::StrAppend(&query_string, name, "=",
        Http::Utility::PercentEncoding::encode(value, chars_needing_percent_encoding_), "&");
  }
}


// Extract constraints parameters (preferred host + port and nf-set-id)
// from NLF lookup result on reception of initial request.
// The parameter nlf_lookup_result exists (instead of using discovery_result_json_)
// so that we can have unit tests for this function.
absl::StatusOr<NfInstance>
EricProxyFilter::selectNfOnPriority(const Json& nlf_lookup_result, const IPver& ip_version) {
  // Find high priority endpoints including hostnames and
  // corresponding nf-set-ids with capacities on highest
  // priority level from NLF lookup result.
  // Create hostname with host and port.
  // Find nf-set-id from NF instance level.
  // Need to check for scheme at all NF service levels, null
  // will be returned if not present.
  // If host or port can not be found for an endpoint, then that
  // endpoint will not be considered for selection.
  // If two endpoints have same hostname then only first occured
  // endpoint would be considered for selection.
  // If IP endpoint is not present then only create endpoint
  // from NF service level attributes.
  std::pair<std::vector<NfInstance>,
  std::vector<uint64_t /*Cumulative capacity*/>> high_priority_endpoints;
  std::set<std::string> unique_hostnames;
  uint64_t max_priority = 65535;

  for (const auto& nf_instance : nlf_lookup_result.at("nfInstances")) {
    if (nf_instance.contains("nfServiceList")) {
      // Invalid NF service list
      // ULID(A16)
      if (!nf_instance.at("nfServiceList").is_object()) {
        ENVOY_LOG(trace, "Invalid NF service list");
        return absl::InvalidArgumentError("Invalid NF service list");
      }
      if (nf_instance.at("nfServiceList").empty()) {
        continue;
      }
      for (const auto& nf_service : nf_instance.at("nfServiceList").items()) {
        const auto& status = getHighPriorityEndpointsFromNfService(
          nf_instance, nf_service.value(), ip_version, high_priority_endpoints,
          unique_hostnames, max_priority
        );
        if (!status.ok()) {
          // ULID(A17)
          return status;
        }
      }
    } else if (nf_instance.contains("nfServices")) {
      // Invalid NF services
      // ULID(A18)
      if (!nf_instance.at("nfServices").is_array()) {
        ENVOY_LOG(trace, "Invalid NF services");
        return absl::InvalidArgumentError("Invalid NF services");
      }
      if (nf_instance.at("nfServices").empty()) {
        continue;
      }
      for (const auto& nf_service : nf_instance.at("nfServices")) {
        const auto& status = getHighPriorityEndpointsFromNfService(
          nf_instance, nf_service, ip_version, high_priority_endpoints,
          unique_hostnames, max_priority
        );
        if (!status.ok()) {
          // ULIDA19)
          return status;
        }
      }
    }
  }

  // No endpoints are found in NLF lookup result
  if (high_priority_endpoints.first.empty()) {
    // ULID(A20)
    ENVOY_LOG(trace, "No endpoints are found in NLF lookup result");
    return absl::NotFoundError("No endpoints are found in NLF lookup result");
  }

  // Selecting one endpoint randomly from high priority
  // endpoints while respecting the capacity or weight.
  // If there is only one endpoint in high priority endpoints, then
  // that endpoint will be selected and further process based on
  // capacity or weight will not be continued.
  if (high_priority_endpoints.first.size() == 1) {
    ENVOY_LOG(trace, "pref_host: '{}', nf-set-id: '{}'",
      high_priority_endpoints.first.front().hostname.value_or("empty"),
      high_priority_endpoints.first.front().set_id.value_or("empty")
    );
    return high_priority_endpoints.first.front();
  }

  const auto& cumulative_capacity_list = high_priority_endpoints.second;
  const auto& selected_idx = randomSelectionByWeight(cumulative_capacity_list);
  if (!selected_idx.has_value()) {
    ENVOY_LOG(trace, "No endpoints were selected");
    return absl::NotFoundError("No endpoints were selected");
  }

  ENVOY_LOG(trace, "pref_host: '{}', nf-set-id: '{}'",
    high_priority_endpoints.first.at(selected_idx.value()).hostname.value_or("empty"),
    high_priority_endpoints.first.at(selected_idx.value()).set_id.value_or("empty")
  );

  return high_priority_endpoints.first.at(selected_idx.value());
}

// Extract list of TaRs from NLF lookup result for remote routing.
// For remote round robin, randomly select the number of unique TaRs equal
// to number of reselections plus 1 (for first try) while respecting the
// priority and capacity so that TaRs with higher priority and capacity
// will likely be on top of the list.
// If number of TaRs is less than the number of reselections then stop further random
// selection and return the list of obtained TaRs so far.
// For remote preferred, select preferred TaR first as many times as number of retries
// plus 1 (for first try) and then randomly select the number of unique TaRs excluding
// preferred TaR equal to number of reselections while respecting the priority and
// capacity so that TaRs with higher priority and capacity will likely be on top
// of the list after preferred TaR.
// If number of TaRs after preferred TaR is less than the number of reselections then
// stop further random selection and return the list of obtained TaRs so far.
// The parameter nlf_lookup_result and nf_set_id exist (instead of using discovery_result_json_
// & nf_set_id_) so that we can have unit tests for this function.
absl::StatusOr<std::vector<std::string>> EricProxyFilter::selectTarsForRemoteRouting(
  const Json& nlf_lookup_result,
  const uint32_t& num_reselections,
  const IPver& ip_version,
  const absl::optional<std::string>& nf_set_id,
  const absl::optional<uint32_t>& num_retries,
  const absl::optional<std::string>& preferred_tar
) {
  std::vector<std::string> selected_tar_list;

  // Find TaRs with capacity on each priority level from NLF lookup result.
  // Create TaR with scheme, host and port.
  // If nf-set-id is already found using nf-selection-on-priority, then use
  // only those NF instances which have nf-set-id equal to the found one.
  // Need to check for scheme at all NF service levels, empty TaR list
  // will be returned if not present.
  // If host or port can not be found for an endpoint, then that
  // endpoint will not be included in TaR list.
  // If two endpoints have same TaR then only first occured
  // endpoint would be included in the TaR list.
  // If IP endpoint is not present then only create endpoint
  // from NF service level attributes.
  std::map<uint64_t /*Priority*/, std::pair<std::vector<std::string /*TaR*/>,
  std::vector<uint64_t /*Cumulative capacity*/>>> priority_levels;
  std::set<std::string> unique_tars;

  for (const auto& nf_instance : nlf_lookup_result.at("nfInstances")) {
    if (nf_set_id.has_value()) {
      const auto& nf_set = getNfSetIdForEndpoint(nf_instance);
      if (!nf_set.ok()) {
        if (nf_set.status().code() == absl::StatusCode::kInvalidArgument) {
          return nf_set.status();
        }
      } else {
        if (nf_set_id.value() != nf_set.value()) {
          continue;
        }
      }
    }
    if (nf_instance.contains("nfServiceList")) {
      // Invalid NF service list
      if (!nf_instance.at("nfServiceList").is_object()) {
        ENVOY_LOG(trace, "Invalid NF service list");
        return absl::InvalidArgumentError("Invalid NF service list");
      }
      if (nf_instance.at("nfServiceList").empty()) {
        continue;
      }
      for (const auto& nf_service : nf_instance.at("nfServiceList").items()) {
        const auto& status = getPriorityLevelsFromNfService(
          nf_instance, nf_service.value(), ip_version, priority_levels,
          unique_tars, preferred_tar
        );
        if (!status.ok()) {
          return status;
        }
      }
    } else if (nf_instance.contains("nfServices")) {
      // Invalid NF services
      if (!nf_instance.at("nfServices").is_array()) {
        ENVOY_LOG(trace, "Invalid NF services");
        return absl::InvalidArgumentError("Invalid NF services");
      }
      if (nf_instance.at("nfServices").empty()) {
        continue;
      }
      for (const auto& nf_service : nf_instance.at("nfServices")) {
        const auto& status = getPriorityLevelsFromNfService(
          nf_instance, nf_service, ip_version, priority_levels,
          unique_tars, preferred_tar
        );
        if (!status.ok()) {
          return status;
        }
      }
    }
  }

  if (num_retries.has_value() && preferred_tar.has_value()) {
    for (uint32_t idx = 0; idx < num_retries.value() + 1; idx++) {
      selected_tar_list.push_back(preferred_tar.value());
    }
  }

  if (priority_levels.empty()) {
    if (!selected_tar_list.empty()) {
      return selected_tar_list;
    }
    ENVOY_LOG(trace, "No endpoints are found in NLF lookup result");
    return absl::NotFoundError("No endpoints are found in NLF lookup result");  
  }

  // Create list of TaRs
  for (auto& priority_level : priority_levels) {
    auto& tar_list = priority_level.second.first;
    auto& cumulative_capacity_list = priority_level.second.second;
    while (!tar_list.empty()) {
      if (
        selected_tar_list.size() >= (num_retries.has_value() ?
        num_retries.value() + num_reselections + 1 : num_reselections + 1)
      ) {
        ENVOY_LOG(trace, "selected_tar_list: {}", selected_tar_list);
        return selected_tar_list;
      }
      const auto& selected_idx = randomSelectionByWeight(cumulative_capacity_list);
      if (!selected_idx.has_value()) {
        ENVOY_LOG(trace, "No endpoints were selected");
        return absl::NotFoundError("No endpoints were selected");
      }
      const auto selected_capacity = (selected_idx.value() == 0) ? cumulative_capacity_list.at(selected_idx.value()) :
      cumulative_capacity_list.at(selected_idx.value()) - cumulative_capacity_list.at(selected_idx.value() - 1);
      selected_tar_list.push_back(tar_list.at(selected_idx.value()));
      for (uint32_t idx = selected_idx.value() + 1; idx < cumulative_capacity_list.size(); idx++) {
        cumulative_capacity_list.at(idx) = cumulative_capacity_list.at(idx) - selected_capacity;
      }
      tar_list.erase(tar_list.begin() + selected_idx.value());
      cumulative_capacity_list.erase(cumulative_capacity_list.begin() + selected_idx.value());
    }
  }

  if (selected_tar_list.empty()) {
    ENVOY_LOG(trace, "No endpoints were selected");
    return absl::NotFoundError("No endpoints were selected");
  }

  ENVOY_LOG(trace, "selected_tar_list: {}", selected_tar_list);
  return selected_tar_list;
}

absl::Status EricProxyFilter::getHighPriorityEndpointsFromNfService(
  const Json& nf_instance, const Json& nf_service, const IPver& ip_version,
  std::pair<std::vector<NfInstance>, std::vector<uint64_t>>& high_priority_endpoints,
  std::set<std::string>& unique_hostnames, uint64_t& max_priority
) {
  const auto& scheme = getSchemeForEndpoint(nf_service);
  if (!scheme.ok()) {
    return scheme.status();
  }
  if (nf_service.contains("ipEndPoints")) {
    // Invalid IP endpoints
    if (!nf_service.at("ipEndPoints").is_array()) {
      ENVOY_LOG(trace, "Invalid IP endpoints");
      return absl::InvalidArgumentError("Invalid IP endpoints");
    }
    if (nf_service.at("ipEndPoints").empty()) {
      return absl::OkStatus();
    }
    std::vector<std::string> hostnames;
    for (const auto& ip_endpoint : nf_service.at("ipEndPoints")) {
      const auto& hostname_list = getHostnameListForEndpoints(nf_instance,
        nf_service, ip_version, ip_endpoint);
      if (!hostname_list.ok()) {
        if (hostname_list.status().code() == absl::StatusCode::kInvalidArgument) {
          return hostname_list.status();
        }
        continue;
      }
      for (const auto& hostname : hostname_list.value()) {
        if (!unique_hostnames.insert(hostname).second) {
          continue;
        }
        hostnames.push_back(hostname);
      }
    }
    if (hostnames.empty()) {
      return absl::OkStatus();
    }
    absl::optional<std::string> nf_set_id = absl::nullopt;
    const auto& nf_set = getNfSetIdForEndpoint(nf_instance);
    if (!nf_set.ok()) {
      if (nf_set.status().code() == absl::StatusCode::kInvalidArgument) {
        return nf_set.status();
      }
    } else {
      nf_set_id = nf_set.value();
    }
    const auto& priority = getPriorityForEndpoint(nf_instance, nf_service);
    if (!priority.ok()) {
      return priority.status();
    }
    const auto& capacity = getCapacityForEndpoint(nf_instance, nf_service);
    if (!capacity.ok()) {
      return capacity.status();
    }
    const uint64_t individual_capacity = capacity.value() / hostnames.size();
    for (const auto& hostname : hostnames) {
      if (priority.value() == max_priority) {
        high_priority_endpoints.first.push_back({hostname, nf_set_id, getNfInstanceIdForEndpoint(nf_instance)});
        if (high_priority_endpoints.second.empty()) {
          high_priority_endpoints.second.push_back(individual_capacity);
        } else {
          const auto& prev_cumulative_capacity = high_priority_endpoints.second.back();
          high_priority_endpoints.second.push_back(prev_cumulative_capacity + individual_capacity);
        }
      }
      if (priority.value() < max_priority) {
        high_priority_endpoints.first.clear();
        high_priority_endpoints.second.clear();
        high_priority_endpoints.first.push_back({hostname, nf_set_id, getNfInstanceIdForEndpoint(nf_instance)});
        high_priority_endpoints.second.push_back(individual_capacity);
        max_priority = priority.value();
      }
    }
  } else {
    const auto& hostname_list = getHostnameListForEndpoints(nf_instance,
      nf_service, ip_version);
    if (!hostname_list.ok()) {
      if (hostname_list.status().code() == absl::StatusCode::kInvalidArgument) {
        return hostname_list.status();
      }
      return absl::OkStatus();
    }
    if (hostname_list.value().empty()) {
      return absl::OkStatus();
    }
    const auto& hostname = hostname_list.value().front();
    if (unique_hostnames.find(hostname) != unique_hostnames.end()) {
      return absl::OkStatus();
    }
    absl::optional<std::string> nf_set_id = absl::nullopt;
    const auto& nf_set = getNfSetIdForEndpoint(nf_instance);
    if (!nf_set.ok()) {
      if (nf_set.status().code() == absl::StatusCode::kInvalidArgument) {
        return nf_set.status();
      }
    } else {
      nf_set_id = nf_set.value();
    }
    const auto& priority = getPriorityForEndpoint(nf_instance, nf_service);
    if (!priority.ok()) {
      return priority.status();
    }
    const auto& capacity = getCapacityForEndpoint(nf_instance, nf_service);
    if (!capacity.ok()) {
      return capacity.status();
    }
    if (priority.value() == max_priority) {
      high_priority_endpoints.first.push_back({hostname, nf_set_id, getNfInstanceIdForEndpoint(nf_instance)});
      if (high_priority_endpoints.second.empty()) {
        high_priority_endpoints.second.push_back(capacity.value());
      } else {
        const auto& prev_cumulative_capacity = high_priority_endpoints.second.back();
        high_priority_endpoints.second.push_back(prev_cumulative_capacity + capacity.value());
      }
      unique_hostnames.insert(hostname);
    }
    if (priority.value() < max_priority) {
      high_priority_endpoints.first.clear();
      high_priority_endpoints.second.clear();
      high_priority_endpoints.first.push_back({hostname, nf_set_id, getNfInstanceIdForEndpoint(nf_instance)});
      high_priority_endpoints.second.push_back(capacity.value());
      unique_hostnames.insert(hostname);
      max_priority = priority.value();
    }
  }

  return absl::OkStatus();
}

absl::Status EricProxyFilter::getPriorityLevelsFromNfService(
  const Json& nf_instance, const Json& nf_service, const IPver& ip_version,
  std::map<uint64_t, std::pair<std::vector<std::string>,
  std::vector<uint64_t>>>& priority_levels, std::set<std::string>& unique_tars,
  const absl::optional<std::string>& preferred_tar
) {
  const auto& scheme = getSchemeForEndpoint(nf_service);
  const auto& api_prefix = getApiPrefixForEndpoint(nf_service);
  if (!scheme.ok()) {
    return scheme.status();
  }
  if (nf_service.contains("ipEndPoints")) {
    // Invalid IP endpoints
    if (!nf_service.at("ipEndPoints").is_array()) {
      ENVOY_LOG(trace, "Invalid IP endpoints");
      return absl::InvalidArgumentError("Invalid IP endpoints");
    }
    if (nf_service.at("ipEndPoints").empty()) {
      return absl::OkStatus();
    }
    std::vector<std::string> tars;
    for (const auto& ip_endpoint : nf_service.at("ipEndPoints")) {
      const auto& tar_list = getTarListForEndpoints(scheme.value(),api_prefix.value(), nf_instance,
      nf_service, ip_version, ip_endpoint);
      if (!tar_list.ok()) {
        if (tar_list.status().code() == absl::StatusCode::kInvalidArgument) {
          return tar_list.status();
        }
        continue;
      }
      for (const auto& tar : tar_list.value()) {
        if (preferred_tar.has_value() && tar == preferred_tar.value()) {
          continue;
        }
        if (!unique_tars.insert(tar).second) {
          continue;
        }
        tars.push_back(tar);
      }
    }
    if (tars.empty()) {
      return absl::OkStatus();
    }
    const auto& priority = getPriorityForEndpoint(nf_instance, nf_service);
    if (!priority.ok()) {
      return priority.status();
    }
    const auto& capacity = getCapacityForEndpoint(nf_instance, nf_service);
    if (!capacity.ok()) {
      return capacity.status();
    }
    const uint64_t individual_capacity = capacity.value() / tars.size();
    for (const auto& tar : tars) {
      if (priority_levels.find(priority.value()) != priority_levels.end()) {
        priority_levels.at(priority.value()).first.push_back(tar);
        const auto& prev_cumulative_capacity = priority_levels.at(priority.value()).second.back();
        priority_levels.at(priority.value()).second.push_back(prev_cumulative_capacity + individual_capacity);
      } else {
        priority_levels[priority.value()] = std::make_pair(
          std::vector<std::string> {tar}, std::vector<uint64_t> {individual_capacity}
        );
      }
    }
  } else {
    const auto& tar_list = getTarListForEndpoints(scheme.value(),api_prefix.value(), nf_instance,
    nf_service, ip_version);
    if (!tar_list.ok()) {
      if (tar_list.status().code() == absl::StatusCode::kInvalidArgument) {
        return tar_list.status();
      }
      return absl::OkStatus();
    }
    if (tar_list.value().empty()) {
      return absl::OkStatus();
    }
    const auto& tar = tar_list.value().front();
    if (unique_tars.find(tar) != unique_tars.end()) {
      return absl::OkStatus();
    }
    if (preferred_tar.has_value() && tar == preferred_tar.value()) {
      return absl::OkStatus();
    }
    const auto& priority = getPriorityForEndpoint(nf_instance, nf_service);
    if (!priority.ok()) {
      return priority.status();
    }
    const auto& capacity = getCapacityForEndpoint(nf_instance, nf_service);
    if (!capacity.ok()) {
      return capacity.status();
    }
    if (priority_levels.find(priority.value()) != priority_levels.end()) {
      priority_levels.at(priority.value()).first.push_back(tar);
      const auto& prev_cumulative_capacity = priority_levels.at(priority.value()).second.back();
      priority_levels.at(priority.value()).second.push_back(prev_cumulative_capacity + capacity.value());
      unique_tars.insert(tar);
    } else {
      priority_levels[priority.value()] = std::make_pair(
        std::vector<std::string> {tar}, std::vector<uint64_t> {capacity.value()}
      );
      unique_tars.insert(tar);
    }
  }

  return absl::OkStatus();
}

// Find scheme for the endpoint from NF service level
absl::StatusOr<std::string> EricProxyFilter::getSchemeForEndpoint(const Json& nf_service) {
  // NF service does not contain scheme
  if (!nf_service.contains("scheme")) {
    ENVOY_LOG(trace, "NF service does not contain scheme");
    return absl::InvalidArgumentError("NF service does not contain scheme");
  }

  // Invalid scheme
  if (
    !nf_service.at("scheme").is_string() ||
    !(nf_service.at("scheme") == "http" ||
    nf_service.at("scheme") == "https")
  ) {
    ENVOY_LOG(trace, "Invalid scheme");
    return absl::InvalidArgumentError("Invalid scheme");
  }

  return nf_service.at("scheme");
}

absl::StatusOr<std::string> EricProxyFilter::getApiPrefixForEndpoint(const Json& nf_service) {

  // NF service does not contain api-prefix
  if (!nf_service.contains("apiPrefix")) {
    ENVOY_LOG(trace, "NF service does not contain api Prefix");
    return absl::StatusOr<std::string>("");
  }

  return nf_service.at("apiPrefix");
}

// Find hostname for the endpoint
absl::StatusOr<std::vector<std::string>> EricProxyFilter::getHostnameListForEndpoints(
  const Json& nf_instance, const Json& nf_service,
  const IPver& ip_version, const absl::optional<Json>& ip_endpoint
) {
  std::vector<std::string> hostname_list;
  const auto& host_list = getHostListForEndpoints(nf_instance, nf_service, ip_version, ip_endpoint);
  if (!host_list.ok()) {
    return host_list.status();
  }

  if (host_list.value().empty()) {
    return hostname_list;
  }

  const auto& port = getPortForEndpoint(nf_service, ip_endpoint);
  if (!port.ok()) {
    return port.status();
  }

  for (const auto& host : host_list.value()) {
    hostname_list.push_back(absl::StrCat(host, ":", port.value()));
  }

  return hostname_list;
}

// Find TaR for the endpoint
absl::StatusOr<std::vector<std::string>> EricProxyFilter::getTarListForEndpoints(
  const std::string& scheme, const std::string& api_prefix, const Json& nf_instance, const Json& nf_service,
  const IPver& ip_version, const absl::optional<Json>& ip_endpoint
) {
  std::vector<std::string> tar_list;
  const auto& host_list = getHostListForEndpoints(nf_instance, nf_service, ip_version, ip_endpoint);
  if (!host_list.ok()) {
    return host_list.status();
  }

  if (host_list.value().empty()) {
    return tar_list;
  }

  const auto& port = getPortForEndpoint(nf_service, ip_endpoint);
  if (!port.ok()) {
    return port.status();
  }

  for (const auto& host : host_list.value()) {
    tar_list.push_back(absl::StrCat(scheme, "://", host, ":", port.value(),api_prefix));
  }  

  return tar_list;
}

// Find list of hosts for the endpoints where FQDN should
// be considered as host for an endpoint.
// FQDN for the endpoint can be defined on both NF instance
// and NF service levels where NF service level overwrites the
// value on NF instance level.
// So, first NF service level FQDN should be considered and
// if it is not present then corresponding NF instance level
// FQDN should be considered.
// If there is no FQDN defined for the endpoint on any level,
// then IPv4 or IPv6 address in IP endpoint should be considered
// as host depends on the IP version. If IP version is Dual stack
// then both IPv4 and IPv6 addresses in IP endpoint should be
// considered as a list of hosts.
// At first IP address in IP endpoints should be considered and
// if it is not present then all IP addresses of IP addresses list
// at NF instance level should be considered as as a list of hosts.
// If neither FQDN nor IP address is present then the endpoint
// should be ignored.
absl::StatusOr<std::vector<std::string>> EricProxyFilter::getHostListForEndpoints(
  const Json& nf_instance, const Json& nf_service,
  const IPver& ip_version, const absl::optional<Json>& ip_endpoint
) {
  std::vector<std::string> host_list;
  if (nf_service.contains("fqdn")) {
    // Invalid fqdn in NF service
    if (!nf_service.at("fqdn").is_string()) {
      ENVOY_LOG(trace, "Invalid fqdn in NF service");
      return absl::InvalidArgumentError("Invalid fqdn in NF service");
    }
    host_list.push_back(nf_service.at("fqdn"));
    return host_list;
  }

  if (nf_instance.contains("fqdn")) {
    // Invalid fqdn in NF instance
    if (!nf_instance.at("fqdn").is_string()) {
      ENVOY_LOG(trace, "Invalid fqdn in NF instance");
      return absl::InvalidArgumentError("Invalid fqdn in NF instance");
    }
    host_list.push_back(nf_instance.at("fqdn"));
    return host_list;
  }

  if (ip_version == IPver::IPv4) {
    if (
      ip_endpoint.has_value() &&
      ip_endpoint.value().contains("ipv4Address")      
    ) {
      // Invalid ipv4Address
      if (!ip_endpoint.value().at("ipv4Address").is_string()) {
        ENVOY_LOG(trace, "Invalid ipv4Address");
        return absl::InvalidArgumentError("Invalid ipv4Address");
      }
      host_list.push_back(ip_endpoint.value().at("ipv4Address"));
      return host_list;
    }

    if (nf_instance.contains("ipv4Addresses")) {
      // Invalid ipv4Addresses
      if (!nf_instance.at("ipv4Addresses").is_array()) {
        ENVOY_LOG(trace, "Invalid ipv4Addresses");
        return absl::InvalidArgumentError("Invalid ipv4Addresses");
      }
      for (const auto& ipv4_address : nf_instance.at("ipv4Addresses")) {
        // Invalid ipv4Addresses element
        if (!ipv4_address.is_string()) {
          ENVOY_LOG(trace, "Invalid ipv4Addresses element");
          return absl::InvalidArgumentError("Invalid ipv4Addresses element");
        }
        host_list.push_back(std::string(ipv4_address));
      }
      return host_list;
    }

    ENVOY_LOG(trace, "Neither FQDN nor IPv4 address can be found");
    return absl::NotFoundError("Neither FQDN nor IPv4 address can be found");
  }
  
  if (ip_version == IPver::IPv6) {
    if (
      ip_endpoint.has_value() &&
      ip_endpoint.value().contains("ipv6Address")
    ) {
      // Invalid ipv6Address
      if (!ip_endpoint.value().at("ipv6Address").is_string()) {
        ENVOY_LOG(trace, "Invalid ipv6Address");
        return absl::InvalidArgumentError("Invalid ipv6Address");
      }
      const std::string& ipv6_address = ip_endpoint.value().at("ipv6Address");
      host_list.push_back(absl::StrCat("[", ipv6_address, "]"));
      return host_list;
    }

    if (nf_instance.contains("ipv6Addresses")) {
      // Invalid ipv6Addresses
      if (!nf_instance.at("ipv6Addresses").is_array()) {
        ENVOY_LOG(trace, "Invalid ipv6Addresses");
        return absl::InvalidArgumentError("Invalid ipv6Addresses");
      }
      for (const auto& ipv6_address : nf_instance.at("ipv6Addresses")) {
        // Invalid ipv6Addresses element
        if (!ipv6_address.is_string()) {
          ENVOY_LOG(trace, "Invalid ipv6Addresses element");
          return absl::InvalidArgumentError("Invalid ipv6Addresses element");
        }
        host_list.push_back(absl::StrCat("[", std::string(ipv6_address), "]"));
      }
      return host_list;
    }

    ENVOY_LOG(trace, "Neither FQDN nor IPv6 address can be found");
    return absl::NotFoundError("Neither FQDN nor IPv6 address can be found");
  }

  if (ip_version == IPver::DualStack) {
    if (
      ip_endpoint.has_value() &&
      ip_endpoint.value().contains("ipv4Address")
    ) {
      // Invalid ipv4Address
      if (!ip_endpoint.value().at("ipv4Address").is_string()) {
        ENVOY_LOG(trace, "Invalid ipv4Address");
        return absl::InvalidArgumentError("Invalid ipv4Address");
      }
      host_list.push_back(ip_endpoint.value().at("ipv4Address"));
    }
    if (
      ip_endpoint.has_value() &&
      ip_endpoint.value().contains("ipv6Address")
    ) {
      // Invalid ipv6Address
      if (!ip_endpoint.value().at("ipv6Address").is_string()) {
        ENVOY_LOG(trace, "Invalid ipv6Address");
        return absl::InvalidArgumentError("Invalid ipv6Address");
      }
      const std::string& ipv6_address = ip_endpoint.value().at("ipv6Address");
      host_list.push_back(absl::StrCat("[", ipv6_address, "]"));
    }

    if (!host_list.empty()) {
      return host_list;
    }

    if (nf_instance.contains("ipv4Addresses")) {
      // Invalid ipv4Addresses
      if (!nf_instance.at("ipv4Addresses").is_array()) {
        ENVOY_LOG(trace, "Invalid ipv4Addresses");
        return absl::InvalidArgumentError("Invalid ipv4Addresses");
      }
      for (const auto& ipv4_address : nf_instance.at("ipv4Addresses")) {
        // Invalid ipv4Addresses element
        if (!ipv4_address.is_string()) {
          ENVOY_LOG(trace, "Invalid ipv4Addresses element");
          return absl::InvalidArgumentError("Invalid ipv4Addresses element");
        }
        host_list.push_back(std::string(ipv4_address));
      }
    }

    if (nf_instance.contains("ipv6Addresses")) {
      // Invalid ipv6Addresses
      if (!nf_instance.at("ipv6Addresses").is_array()) {
        ENVOY_LOG(trace, "Invalid ipv6Addresses");
        return absl::InvalidArgumentError("Invalid ipv6Addresses");
      }
      for (const auto& ipv6_address : nf_instance.at("ipv6Addresses")) {
        // Invalid ipv6Addresses element
        if (!ipv6_address.is_string()) {
          ENVOY_LOG(trace, "Invalid ipv6Addresses element");
          return absl::InvalidArgumentError("Invalid ipv6Addresses element");
        }
        host_list.push_back(absl::StrCat("[", std::string(ipv6_address), "]"));
      }
    }

    if (!host_list.empty()) {
      return host_list;
    }

    ENVOY_LOG(trace, "Neither FQDN nor IPv4 address nor IPv6 address can be found");
    return absl::NotFoundError("Neither FQDN nor IPv4 address nor IPv6 address can be found");
  }

  ENVOY_LOG(trace, "Unsupported IP version");
  return absl::NotFoundError("Unsupported IP version");
}

// Find port for the endpoint.
// If no port is defined in the IP endpoint, then port is considered
// as 80 if scheme at NF service level is http and 443 if https.
absl::StatusOr<std::string> EricProxyFilter::getPortForEndpoint(
  const Json& nf_service, const absl::optional<Json>& ip_endpoint
) {
  if (
    ip_endpoint.has_value() &&
    ip_endpoint.value().contains("port")
  ) {
    // Invalid port
    if (!ip_endpoint.value().at("port").is_number_integer()) {
      ENVOY_LOG(trace, "Invalid port");
      return absl::InvalidArgumentError("Invalid port");
    }
    const int& port = ip_endpoint.value().at("port");
    return std::to_string(port);
  }

  if (nf_service.at("scheme") == "http") {
    return "80";
  }
  
  if (nf_service.at("scheme") == "https") {
    return "443";
  }

  ENVOY_LOG(trace, "Port can not be found");
  return absl::NotFoundError("Port can not be found");
}

// Find nf-set-id for the endpoint from NF instance level
absl::StatusOr<std::string> EricProxyFilter::getNfSetIdForEndpoint(const Json& nf_instance) {
  if (nf_instance.contains("nfSetIdList")) {
    // Invalid nfSetIdList
    if (!nf_instance.at("nfSetIdList").is_array()) {
      ENVOY_LOG(trace, "Invalid nfSetIdList");
      return absl::InvalidArgumentError("Invalid nfSetIdList");
    }
    // Invalid nfSetIdList element
    if (!nf_instance.at("nfSetIdList").empty()) {
      if (!nf_instance.at("nfSetIdList").front().is_string()) {
        ENVOY_LOG(trace, "Invalid nfSetIdList element");
        return absl::InvalidArgumentError("Invalid nfSetIdList element");
      }
      return nf_instance.at("nfSetIdList").front();
    }
  }

  ENVOY_LOG(trace, "No nfSetIdList is found in NF instance");
  return absl::NotFoundError("No nfSetIdList is found in NF instance");
}

// Find nf-instance=idfor the endpoint from NF instance level
absl::optional<std::string> EricProxyFilter::getNfInstanceIdForEndpoint(const Json& nf_instance) {
  if (nf_instance.contains("nfInstanceId")) {
    if (nf_instance.at("nfInstanceId").is_string()) {
      return nf_instance.at("nfInstanceId");
    } else {
      return absl::nullopt;
    }
  } else {
    ENVOY_LOG(trace, "No nfInstanceId is found in NF instance");
    return absl::nullopt;
  }
}

// Find priority for the endpoint.
// High priority means smaller priority number.
// Priority for the endpoint can be defined on both NF instance
// and NF service levels where NF service level overwrites the
// value on NF instance level.
// So, first NF service level priority should be considered and
// if it is not present then corresponding NF instance level
// priority should be considered.
// If there is no priority defined for the endpoint on any level,
// then the priority for that endpoint will be considered as
// 65535 (lowest priority).
absl::StatusOr<uint64_t> EricProxyFilter::getPriorityForEndpoint(const Json& nf_instance, const Json& nf_service) {
  if (nf_service.contains("priority")) {
    // Invalid priority in NF service
    if (
      !nf_service.at("priority").is_number_integer() ||
      !(nf_service.at("priority") >= 0 && nf_service.at("priority") <= 65535)
    ) {
      ENVOY_LOG(trace, "Invalid priority in NF service");
      return absl::InvalidArgumentError("Invalid priority in NF service");
    }
    return nf_service.at("priority");
  }

  if (nf_instance.contains("priority")) {
    // Invalid priority in NF instance
    if (
      !nf_instance.at("priority").is_number_integer() ||
      !(nf_instance.at("priority") >= 0 && nf_instance.at("priority") <= 65535)
    ) {
      ENVOY_LOG(trace, "Invalid priority in NF instance");
      return absl::InvalidArgumentError("Invalid priority in NF instance");
    }
    return nf_instance.at("priority");
  }

  return 65535;
}

// Find capacity for the endpoint.
// Capacity for the endpoint can be defined on both NF instance
// and NF service levels where NF service level overwrites the
// value on NF instance level.
// So, first NF service level capacity should be considered and
// if it is not present then corresponding NF instance level
// capacity should be considered.
// If there is no capacity defined for the endpoint at any level, then the
// capacity for that endpoint will be considered as 0 (lowest capacity).
absl::StatusOr<uint64_t> EricProxyFilter::getCapacityForEndpoint(const Json& nf_instance, const Json& nf_service) {
  if (nf_service.contains("capacity")) {
    // Invalid capacity in NF service
    if (
      !nf_service.at("capacity").is_number_integer() ||
      !(nf_service.at("capacity") >= 0 && nf_service.at("capacity") <= 65535)
    ) {
      ENVOY_LOG(trace, "Invalid capacity in NF service");
      return absl::InvalidArgumentError("Invalid capacity in NF service");
    }
    return nf_service.at("capacity");
  }

  if (nf_instance.contains("capacity")) {
    // Invalid capacity in NF instance
    if (
      !nf_instance.at("capacity").is_number_integer() ||
      !(nf_instance.at("capacity") >= 0 && nf_instance.at("capacity") <= 65535)
    ) {
      ENVOY_LOG(trace, "Invalid capacity in NF instance");
      return absl::InvalidArgumentError("Invalid capacity in NF instance");
    }
    return nf_instance.at("capacity");
  }

  return 0;
}

// Randomly returns an index from the cumulative weight list
absl::optional<uint32_t> EricProxyFilter::randomSelectionByWeight(const std::vector<uint64_t>& cumulative_weight) {
  // Cumulative weight list is empty
  if (cumulative_weight.empty()) {
    return absl::nullopt;
  }

  // If there is only one element in cumulative weight list
  // then we can directly return 0 as the first index
  if (cumulative_weight.size() == 1) {
    return 0;
  }

  // Last element of cumulative weight is 0 which means all endpoints capacities are
  // either 0 or not defined, so we randomly select one of them with equal weights.
  if (cumulative_weight.back() == 0) {
    std::random_device random_device;  // Will be used to obtain a seed for the random number engine
    std::mt19937 generator(random_device()); // Standard mersenne_twister_engine seeded with random_device()
    std::uniform_int_distribution<uint32_t> distribution(0, cumulative_weight.size() - 1);
    uint32_t random_idx = distribution(generator);
    return random_idx;
  }

  // Randomly select a number between 1 and max cumulative or total weight
  // and returns the index if it's corresponding cumulative weight value
  // is greater than or equal to the randomly selected number.
  std::random_device random_device;  // Will be used to obtain a seed for the random number engine
  std::mt19937 generator(random_device()); // Standard mersenne_twister_engine seeded with random_device()
  std::uniform_int_distribution<uint64_t> distribution(1, cumulative_weight.back());
  uint64_t random_cumulative_weight = distribution(generator);
  for (uint32_t idx = 0; idx < cumulative_weight.size(); idx++) {
    if (cumulative_weight[idx] >= random_cumulative_weight) {
      return idx;
    }
  }

  return absl::nullopt;
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy

