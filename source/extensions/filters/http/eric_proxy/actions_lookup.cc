#include "envoy/http/header_map.h"
#include "envoy/stream_info/stream_info.h"
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/header_utility.h"
#include "envoy/http/async_client.h"
#include "source/common/http/message_impl.h"
#include "include/nlohmann/json.hpp"
#include <string>

// Methods in this file are all in the EricProxyFilter class.
// They are stored in a separate file to keep action processing
// separate.

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using Json = nlohmann::json;

//----- Lookup Actions --------------------------------------------------------------------

// SlfLookup
ActionResultTuple EricProxyFilter::actionSlfLookup(const ActionSlfLookupWrapper& action) {
  const auto proto_config = action.protoConfig().action_slf_lookup();
  ENVOY_STREAM_LOG(debug, "actionSlfLookup() for ID {}", *decoder_callbacks_,
                   proto_config.supi_var());

  // Check that the configured cluster exists:
  const std::string& cluster = proto_config.cluster_name();
  const auto thread_local_cluster = config_->clusterManager().getThreadLocalCluster(cluster);
  if (thread_local_cluster == nullptr) {
    ENVOY_STREAM_LOG(error, "HTTP call cluster ({}) invalid. Must be configured",
                     *decoder_callbacks_, cluster);
    // FIXME(eedala): We need to go to an error-handling FC, not just continue
    return std::make_tuple(ActionResult::Next, false, std::nullopt);
  }

  // Get the SUPI/SUCI/GPSI and error-check:
  auto query_id_type = action.queryIdType();
  auto var_value_idx = action.sourceVarIdx();
  if (query_id_type.empty() || var_value_idx == -1) {
    auto fc_lookup_failure = proto_config.fc_lookup_failure();
    return std::make_tuple(ActionResult::GotoFC, false, fc_lookup_failure);
  }

  std::string query_id_value = "";

  if (!run_ctx_.varValue(var_value_idx).is_string() || run_ctx_.varValueIsEmpty(var_value_idx)) {
    auto fc_id_missing = proto_config.fc_id_missing();
    stats_->buildSlfFailureCounters(fc_id_missing, stats_->slfLookupIdentityMissing(), decoder_callbacks_).inc();
    return std::make_tuple(ActionResult::GotoFC, false, fc_id_missing);
  }
  query_id_value = run_ctx_.varValueAsString(var_value_idx);

  // Build message to SLF:
  auto nslf_api_root = action.nSlfApiRoot();
  ENVOY_STREAM_LOG(debug, "query_id_type={}, query_id_value={}, nslf_api_root={}",
                   *decoder_callbacks_, query_id_type, query_id_value, nslf_api_root);
  auto headers = prepareSlfLookupHeaders(query_id_type, query_id_value, nslf_api_root,
                                         action.protoConfig().action_slf_lookup().nrf_group_name());
  Http::RequestMessagePtr message(new Http::RequestMessageImpl(std::move(headers)));

  // This is the overall SLF-query-timeout including all retries and reselects:
  // The per-try-timeout is set a few lines further down in the retry_policy.
  auto timeout = std::chrono::milliseconds(proto_config.timeout());
  auto options = Http::AsyncClient::RequestOptions().setTimeout(timeout);
  auto retry_policy = retryPolicyForLookup(thread_local_cluster, timeout);
  options.setRetryPolicy(retry_policy);

  // Store the action, so that we have access from the callbacks
  deferred_lookup_action_ = &action;

  auto lookupRequest =
      thread_local_cluster->httpAsyncClient().send(std::move(message), lookup_callbacks_, options);

  if (lookupRequest != nullptr) {
    ENVOY_STREAM_LOG(debug, "HTTP call sent", *decoder_callbacks_);
    lookup_request_ = lookupRequest;
  } else {
    // Could only happen if TCP connection could not be 
    // established to SLF pod, step the service-unreachable counter in that case
    ENVOY_STREAM_LOG(debug, "HTTP call sending failed", *decoder_callbacks_);
    auto fc_lookup_failure = proto_config.fc_lookup_failure();
    stats_->buildSlfFailureCounters(fc_lookup_failure, stats_->slfLookupServiceUnreachable(), decoder_callbacks_).inc();
    return std::make_tuple(ActionResult::GotoFC, false, fc_lookup_failure);
  }
  return std::make_tuple(ActionResult::PauseIteration, false, std::nullopt);
}

// HTTP request to SLF was successful
void EricProxyFilter::onSlfLookupSuccess(Http::ResponseMessagePtr&& lookup_resp) {
  ENVOY_STREAM_LOG(debug, "onSlfLookupSuccess()", *decoder_callbacks_);
  lookup_request_ = nullptr;
  auto status = lookup_resp->headers().getStatusValue();
  auto body = lookup_resp->bodyAsString();

  ENVOY_STREAM_LOG(debug, "status: {}, body: {}", *decoder_callbacks_, status, body);

  if (status == "200") {
    processSlfLookupBodyOK(body);
  } else {
    processSlfLookupErrors(status);
  }
  if (deferred_filter_case_ptr_ == nullptr){
     ENVOY_STREAM_LOG(debug, "filter chain execution was not paused yet. Just continue", *decoder_callbacks_);
     return;
  }
  continueProcessingAfterSlfResponse();
}

std::unique_ptr<Http::RequestHeaderMapImpl> EricProxyFilter::prepareSlfLookupHeaders(
    std::string const& query_id_type, const std::string& query_id_value,
    const std::string& nslf_api_root, const std::string& nrf_group_name) {
  auto headers = Http::RequestHeaderMapImpl::create();
  auto req = absl::StrCat(nslf_api_root, query_id_type, "=", query_id_value, "&limit=1");

  headers->addCopy(Http::LowerCaseString(":path"), req);
  headers->addCopy(Http::LowerCaseString(":method"), "GET");
  headers->addCopy(Http::LowerCaseString(":authority"), "eric-sc-slf");
  headers->addCopy(Http::LowerCaseString(":scheme"), "https");
  headers->addCopy(Http::LowerCaseString("user-agent"), config_->nodeTypeUc());
  if (!nrf_group_name.empty()) { // optional parammeter
    headers->addCopy(Http::LowerCaseString("nrf-group"), nrf_group_name);
  }

  // If the received request includes the header 3gpp-Sbi-Correlation-Info, then add it
  // unmodified to the discovery request (TS 29.500 (Rel-17), section 6.13.2.2):
  auto corr_header_name = Http::LowerCaseString("3gpp-sbi-correlation-info");
  auto corr_header = run_ctx_.getReqHeaders()->get(corr_header_name);
  if (!corr_header.empty()) {
    headers->addCopy(corr_header_name, corr_header[0]->value().getStringView());
  }

  return headers;
}

void EricProxyFilter::processSlfLookupBodyOK(const std::string& body) {
  ENVOY_STREAM_LOG(trace, "processSlfLookupBodyOK()", *decoder_callbacks_);
  std::string address_ptr = "/addresses";
  Json json_body;

  try {
    json_body = Json::parse(body);
  } catch (Json::parse_error& e) {
    ENVOY_STREAM_LOG(debug, "Malformed JSON body in SLfLookup Response ({})", *decoder_callbacks_, e.what());
    auto next_fc = deferred_lookup_action_->protoConfig().action_slf_lookup().fc_lookup_failure();
    stats_->buildSlfFailureCounters(next_fc, stats_->slfLookupFailure(), decoder_callbacks_).inc();
    deferred_lookup_result_ = std::make_tuple(ActionResult::GotoFC, false, next_fc);
    return;
  }

  Json::json_pointer json_ptr_addresses;
  try {
    json_ptr_addresses = Json::json_pointer(address_ptr);
  } catch (Json::parse_error& e) {
    // Should not happen (should have been caught in the validator)
    ENVOY_STREAM_LOG(debug, "JSON pointer parse error ({})", *decoder_callbacks_, e.what());
    auto next_fc = deferred_lookup_action_->protoConfig().action_slf_lookup().fc_lookup_failure();
    deferred_lookup_result_ = std::make_tuple(ActionResult::GotoFC, false, next_fc);
    return;
  }
  Json addresses;
  try {
    addresses = json_body.at(json_ptr_addresses);
  } catch (Json::exception& e) {
    ENVOY_STREAM_LOG(debug, "No address list in SLfLookup Response ({})", *decoder_callbacks_, e.what());
    auto next_fc = deferred_lookup_action_->protoConfig().action_slf_lookup().fc_lookup_failure();
    stats_->buildSlfFailureCounters(next_fc, stats_->slfLookupFailure(), decoder_callbacks_).inc();  
    deferred_lookup_result_ = std::make_tuple(ActionResult::GotoFC, false, next_fc);
    return;
  }
  if (addresses.empty()) {
    ENVOY_STREAM_LOG(debug, "Empty address list in SLfLookup Response ({})", *decoder_callbacks_);
    auto next_fc = deferred_lookup_action_->protoConfig().action_slf_lookup().fc_id_not_found();
    stats_->buildSlfFailureCounters(next_fc, stats_->slfLookupIdentityNotFound(), decoder_callbacks_).inc();
    deferred_lookup_result_ = std::make_tuple(ActionResult::GotoFC, false, next_fc);
    return;
  }

  // The interface can be found in 5g_proto/esc/slf/src/main/resources/3gpp/Nslf_NfDiscovery.yaml
  bool region_found = false;
  std::string region;
  int priority_min = -1;
  for (const auto& el : addresses.items()) {
    const std::string fqdn = el.value().value("fqdn", "");
    // Priority is required, so we should always receive it
    const int priority = el.value().value("priority", 0);
    const auto& ipv4Addresses = el.value().value("ipv4Addresses", Json::array());
    const auto& ipv6Addresses = el.value().value("ipv6Addresses", Json::array());
    ENVOY_STREAM_LOG(debug, "fqdn: {}, priority: {}, ipv4Addresses: {}, ipv6Addresses: {}",
                     *decoder_callbacks_, fqdn, priority, ipv4Addresses.dump(),
                     ipv6Addresses.dump());
    if (priority >= 0) {
      if ((priority_min < 0) || priority < priority_min) {
        priority_min = priority;
        if (!fqdn.empty()) {
          region_found = true;
          region = fqdn;
        } else if (!ipv6Addresses.empty()) {
          region_found = true;
          region = ipv6Addresses.at(0);
        } else if (!ipv4Addresses.empty()) {
          region_found = true;
          region = ipv4Addresses.at(0);
        } else {
          ENVOY_STREAM_LOG(debug, "No addresses to assign to region", *decoder_callbacks_);
        }
      }
    }
  }

  if (! region_found) {
    ENVOY_STREAM_LOG(debug, "No address in SLfLookup Response", *decoder_callbacks_);
    auto next_fc = deferred_lookup_action_->protoConfig().action_slf_lookup().fc_dest_unknown();
    stats_->buildSlfFailureCounters(next_fc, stats_->slfLookupDestinationUnknown(), decoder_callbacks_).inc();
    deferred_lookup_result_ = std::make_tuple(ActionResult::GotoFC, false, next_fc);
    return;
  }

  auto dest_var = deferred_lookup_action_->protoConfig().action_slf_lookup().destination_variable();
  auto dest_value_idx = dynamic_cast<const ActionSlfLookupWrapper*>(deferred_lookup_action_)->destinationVarIdx();
  auto fc_ptr = deferred_filter_case_ptr_;
  if (fc_ptr != nullptr) {
    run_ctx_.updateVarValue(dest_value_idx, region, fc_ptr);
    ENVOY_STREAM_LOG(debug, "Stored region: '{}' in variable: '{}' (index: {})", *decoder_callbacks_, region, dest_var, dest_value_idx);
  } else {
    ENVOY_STREAM_LOG(error, "Invalid fc_ptr", *decoder_callbacks_);
  }
  // Continue with next action
  deferred_lookup_result_ = std::make_tuple(ActionResult::Next, false, std::nullopt);
}

void EricProxyFilter::processSlfLookupErrors(const absl::string_view status ){
  ENVOY_STREAM_LOG(trace, "processSlfLookupErrors(status: '{}')", *decoder_callbacks_, status);

  auto next_fc = deferred_lookup_action_->protoConfig().action_slf_lookup().fc_lookup_failure();
  if (status == "404"){
    next_fc = deferred_lookup_action_->protoConfig().action_slf_lookup().fc_dest_unknown();
    stats_->buildSlfFailureCounters(next_fc, stats_->slfLookupDestinationUnknown(), decoder_callbacks_).inc();
  }
  else
  {
    stats_->buildSlfFailureCounters(next_fc, stats_->slfLookupFailure(), decoder_callbacks_).inc();
  }
  deferred_lookup_result_ = std::make_tuple(ActionResult::GotoFC, false, next_fc);
}

void EricProxyFilter::onSlfLookupFailure( Http::AsyncClient::FailureReason failure_reason) {
  ENVOY_STREAM_LOG(debug, "Failure reason:{}", *decoder_callbacks_, static_cast<int>(failure_reason));
  lookup_request_ = nullptr;
  auto next_fc = deferred_lookup_action_->protoConfig().action_slf_lookup().fc_lookup_failure();
  deferred_lookup_result_ = std::make_tuple(ActionResult::GotoFC, false, next_fc);
  continueProcessingAfterSlfResponse();
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
