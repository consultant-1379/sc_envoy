#pragma once

#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "source/extensions/filters/http/common/pass_through_filter.h"
#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "source/extensions/filters/http/eric_proxy/contexts.h"
#include "source/extensions/filters/http/eric_proxy/proxy_filter_config.h"
#include "source/extensions/filters/http/eric_proxy/stats.h"
#include "source/extensions/filters/http/eric_proxy/wrappers.h"
#include "source/common/common/statusor.h"
#include "source/common/config/metadata.h"
#include "source/common/eric_event/eric_event_reporter.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/header_utility.h"
#include "source/common/stream_info/eric_event_state.h"
#include "source/common/stream_info/eric_proxy_state.h"
#include "re2/re2.h"
#include "include/nlohmann/json.hpp"
#include "body.h"
#include "alarm_notifier.h"

// Macro to define an ULID (unique logging-ID) in the code. Quotes are added
// automatically
// Usage1: in a comment:     // ULID(A05)
// Usage2: in a log message:
//   ENVOY_STREAM_UL_LOG(debug, "debug log: {}", *decoder_callbacks, ULID(T21), var);
#define ULID(x) #x

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

enum class ActionResult {
  Next,           // Continue with the next action
  GotoFC,         // Goto another filter case
  Exit,           // The action was terminal, exit the filter case, but continue in the filter chain
  StopIteration,  // The action was terminal, and the filter iteration shall be stopped
  PauseIteration, // The action was not terminal, the filter iteration shall be paused
};

enum class FCState {
  StartFilterCase, // A new filter-case shall be executed next
  NextFilterRule,  // A new filter-rule shall be executed next
  LoadFilterData,  // Fetch data for the current/upcoming rule
  LoadNextAction,  // A new action shall be execute next
  ExecuteAction,   // Execute the next action (the condition has matched)
};

enum class FCPhase : unsigned char {
  Undefined  = 0,
  Screening1 = 1,
  Routing2   = 2,
  Screening3 = 3,
  Screening4 = 4,
  Response5  = 5, // phase 5 actions are not configurable
  Screening6 = 6,
};
// Printable names for the phases, the order has to match the enum FCPhase:
const std::string fcPhaseNames[]{"undefined 0", "screening 1", "routing 2", "screening 3",
  "screening 4", "response 5", "screening 6"};

enum class SeppReqPreProcResult {
  Continue,           // Continue execution, nothing special happened
  DirectResponse,     // A direct response is sent, stop filter chain and start response at ph. 6
  N32cReqFromRP,      // N32c request from RP detected, bypass routing + out-req.-screening 3,
                      // skip in-response screening 4, then start response at ph. 5
  N32cReqFromManager, // N32c request from Manager detected. Bypass TFQDN and Topo-hiding,
                      // continue with routing.
};

enum class ProcessFcMode {
  Screening,
  TopologyHiding,
  TopologyUnhiding
};

struct NfInstance {
  absl::optional<std::string> hostname;
  absl::optional<std::string> set_id;
  absl::optional<std::string> nfInstanceId;

  bool operator==(const NfInstance& rhs) const {
    return rhs.hostname == this->hostname && rhs.nfInstanceId == this->nfInstanceId &&
           rhs.set_id == this->set_id;
  }
};


// Response code details for actions: reject-message, drop-message, modify-status-code. Used when sending local replies
struct EricProxyResponseCodeDetailValues {
  const absl::string_view DropResponseFromEricProxyFilter = "stream_reset_by_message_screening_action";
  const absl::string_view RejectResponseFromEricProxyFilter = "request_rejected_by_message_screening_action";
  const absl::string_view ModifyResponseFromEricProxyFilter = "response_modified_by_message_screening_action";
  const absl::string_view TfqdnDecodingFailure = "tfqdn_decoding_failure";
  const absl::string_view N32cHandshakeFailure = "n32c_handshake_incomplete";
};
using EricProxyResponseCodeDetails = ConstSingleton<EricProxyResponseCodeDetailValues>;
using NfDiscoveryAction = ::envoy::extensions::filters::http::eric_proxy::v3::NfDiscoveryAction;
using PerRpFcConfig = ::envoy::extensions::filters::http::eric_proxy::v3::PerRpFcConfig;

// Smallest difference between two floating point numbers we care about. Lower than that
// and we treat them as equal:
static const double EPSILON = 0.1;
// the threshold after which we don't process further header violations
static const int USFW_HEADERS_THRESHOLD = 20;

class LookupCallbacks : public Http::AsyncClient::Callbacks {
public:
  LookupCallbacks(std::function<void(Http::ResponseMessagePtr&&)>&& on_success,
                  std::function<void(Http::AsyncClient::FailureReason)>&& on_fail)
      : on_success_(on_success), on_fail_(on_fail) {}
  // Http::AsyncClient::Callbacks
  void onSuccess(const Http::AsyncClient::Request&, Http::ResponseMessagePtr&& m) override {
    on_success_(std::forward<Http::ResponseMessagePtr>(m));
  }
  void onFailure(const Http::AsyncClient::Request&, Http::AsyncClient::FailureReason f) override {
    on_fail_(f);
  }
  void onBeforeFinalizeUpstreamSpan(Tracing::Span&, const Http::ResponseHeaderMap*) override {}

private:
  const std::function<void(Http::ResponseMessagePtr&&)> on_success_;
  const std::function<void(Http::AsyncClient::FailureReason)> on_fail_;
};


using EricProxyFilterConfigSharedPtr = std::shared_ptr<EricProxyFilterConfig>;
using VarData = std::map<std::string, std::string>;
using AlarmEvent = envoy::extensions::filters::http::eric_proxy::v3::EricProxyAlarmEvent;
using AlarmEventType = envoy::extensions::filters::http::eric_proxy::v3::EricProxyAlarmEventType;
using AlarmTimeStamp = ::google::protobuf::Timestamp;
using Action = ::envoy::extensions::filters::http::eric_proxy::v3::Action;
using ActionResultTuple = std::tuple<ActionResult, bool, std::optional<std::string>>;
using RoutingBehaviour = ::envoy::extensions::filters::http::eric_proxy::v3::RoutingBehaviour;
using PreserveIfIndirect = ::envoy::extensions::filters::http::eric_proxy::v3::PreserveIfIndirect;
// using ServiceCaseConfig = ::envoy::extensions::filters::http::eric_proxy::v3::ThFqdnMappingProfile::
//                                 ServiceCase;
// using EndpointPolicy = ::envoy::extensions::filters::http::eric_proxy::v3::EndpointSelectionPolicy;
// using ServiceContext = ::envoy::extensions::filters::http::eric_proxy::v3::ThFqdnMappingProfile::ServiceContext;
using ServiceCaseConfig = ::envoy::extensions::filters::http::eric_proxy::v3::TopologyHidingServiceProfile::ServiceCase;
using ServiceContext = ::envoy::extensions::filters::http::eric_proxy::v3::TopologyHidingServiceProfile::ServiceContext;
using std::placeholders::_1;
using ThActionOnFqdnAbsence = envoy::extensions::filters::http::eric_proxy::v3::TopologyHiding_IpHiding_ActionOnFqdnAbsence;
using SubnetList = envoy::extensions::filters::http::eric_proxy::v3::TopologyHiding_IpHiding_SubnetList;
using Transformation = ::envoy::extensions::filters::http::eric_proxy::v3::Transformation;
using StringModifiers = google::protobuf::RepeatedPtrField<StringModifier>;
using LogValuesT = ::google::protobuf::RepeatedPtrField< ::envoy::extensions::filters::http::eric_proxy::v3::LogValue>;
using CheckHeaders = ::envoy::extensions::filters::http::eric_proxy::v3::CheckHeaders;
using CheckJsonSyntax = ::envoy::extensions::filters::http::eric_proxy::v3::CheckJsonSyntax;
using CheckMessageBytes = ::envoy::extensions::filters::http::eric_proxy::v3::CheckMessageBytes;
using CheckJsonLeaves = ::envoy::extensions::filters::http::eric_proxy::v3::CheckJsonLeaves;
using CheckJsonDepth = ::envoy::extensions::filters::http::eric_proxy::v3::CheckJsonDepth;
using ActionOnFailure = ::envoy::extensions::filters::http::eric_proxy::v3::ActionOnFailure;

//--------------------------------------------------------------------------------
class EricProxyFilter : public Http::PassThroughFilter, public Logger::Loggable<Logger::Id::eric_proxy> {
public:
  EricProxyFilter(EricProxyFilterConfigSharedPtr,
                  const std::chrono::time_point<std::chrono::system_clock>,
                  Random::RandomGenerator&, const EricProxyStatsSharedPtr& stats,
                  std::shared_ptr<AlarmNotifier> notifier);

  ~EricProxyFilter() override;

  // Http::StreamFilterBase
  void onDestroy() override;

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap&, bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) override;
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks&) override;

  // Http::StreamEncoderFilter
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap&, bool end_stream) override;
  Http::FilterDataStatus encodeData(Buffer::Instance& data, bool end_stream) override;
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks&) override;

  // This method is only used for testing. Once body and json are separated, this
  // function can be removed.
  // Return the Json data from <body_str> at position <json_pointer>
  static const Envoy::StatusOr<Json> readFromJsonWithPointer(const std::string& body_str,
                                                             const std::string& json_pointer,
                                                             Http::StreamDecoderFilterCallbacks* decoder_callbacks = nullptr);

  // Modify json_src **in place** with the supplied modifier function at all given json_pointers.
  // Public so that we can test it.
  static absl::Status modifyJson(
    Http::StreamDecoderFilterCallbacks* decoder_callbacks,
    std::shared_ptr<Json> json_src,
    std::vector<std::string>& json_pointers,
    std::function<std::string(const std::string&)> modifier_function,
    int error_handling_flags = 0
  );
  // overloaded to allow multiple modifications with one modifyJson call
  static absl::Status modifyJson(
    Http::StreamDecoderFilterCallbacks* decoder_callbacks,
    std::shared_ptr<Json> json_src,
    std::vector<std::string>& json_pointers,
    const std::vector<std::function<std::string(const std::string&)>>& modifier_functions,
    int error_handling_flags = 0
  );

  static std::tuple<std::string, std::string, std::string> splitUriForMapping(absl::string_view uri);

  static absl::StatusOr<std::vector<std::string>> splitLabels(absl::string_view labels);

  static absl::StatusOr<std::tuple<std::string, std::vector<std::string>, std::string, std::string>>
  splitUriForScrambling(absl::string_view uri, const std::regex& regex_valid_plmn);

  static std::vector<std::function<std::string(const std::string&)>> prepareStringModifiers(
    const StringModifiers& string_modifiers, RunContext& run_ctx,
    Http::StreamDecoderFilterCallbacks* decoder_callbacks
  );
  static std::function<std::string(const std::string&)> prepareStringModifier(
    const StringModifier& string_modifier, RunContext& run_ctx,
    Http::StreamDecoderFilterCallbacks* decoder_callbacks
  );

  static std::optional<std::string> transformAndLookup(
    absl::string_view uri, const std::string& table_name,
    const Transformation& transform, RunContext& run_ctx
  );

  static absl::StatusOr<std::string> transformAndScramble(
    absl::string_view uri, const Transformation& transform,
    RunContext& run_ctx, std::string& encryption_id
  );

  static absl::StatusOr<std::string> transformAndDescramble(
    absl::string_view uri, const Transformation& transform,
    RunContext& run_ctx, std::string& encryption_id
  );

  static std::string scramble(
    const std::string& original_string, const unsigned char* key, const unsigned char* iv,
    const std::string& generation_prefix = ""
  );

  static std::string descramble(
    const std::string& scrambled_string, const unsigned char* key,
    const unsigned char* iv
  );

  // Replace host&port in source_url with the host&port taken from new_host_port
  // If the source_url cannot be parsed (missing schema for example), then
  // the un-modified source_url is returned.
  static std::string replaceHostPortInUrl(absl::string_view source_url, absl::string_view new_host_port,
      absl::string_view scheme,Http::StreamDecoderFilterCallbacks* decoder_callbacks=nullptr);

  // The following are implemented in actions.cc, not in filter.cc:
  static std::string extractHostAndPort(absl::string_view, Http::RequestOrResponseHeaderMap&,
      bool add_scheme_header=true);

  // This is public so we can test it:
  static bool authorityIsOnlyOwnFqdn(absl::string_view authority, const std::string& own_fqdn);

  // static to be used by e.g. json_operations
  static Json varOrStringAsJson(const VarOrString& var_or_string_ref, RunContext& run_ctx,
                   Http::StreamDecoderFilterCallbacks* decoder_callbacks);
  // static to be used by e.g. json_operations
  static Json varOrJsonStringAsJson(const VarOrString& var_or_string_ref, RunContext& run_ctx,
                   Http::StreamDecoderFilterCallbacks* decoder_callbacks);
  // static to be used by e.g. json_operations
  static std::string varOrStringAsString(const VarOrString& var_or_string_ref, RunContext& run_ctx,
                   Http::StreamDecoderFilterCallbacks* decoder_callbacks);
  // Convenience shortcut for the above static function:
  std::string varOrStringAsString(const VarOrString& var_or_string_ref) {
    return varOrStringAsString(var_or_string_ref, run_ctx_, decoder_callbacks_);
  }

  static bool findInDynMetadata(
      const ::google::protobuf::Map<std::string, ::google::protobuf::Struct>* filter_metadata,
      const std::string& metadata_parent, const std::string& metadata_child,
      const std::string& value);

  static bool findInDynMetadata(
      const ::google::protobuf::Map<std::string, ::google::protobuf::Struct>* filter_metadata,
      const std::string& metadata_parent, const std::string& metadata_child);

  static bool findInDynMetadata(
      const ::google::protobuf::Map<std::string, ::google::protobuf::Struct>* filter_metadata,
      const std::string& metadata_parent);

  static std::string extractFromDynMetadata(
      const ::google::protobuf::Map<std::string, ::google::protobuf::Struct>* filter_metadata,
      const std::string& metadata_parent, const std::string& metadata_child);

  // Option D
  // Extract constraints parameters (preferred host + port and nf-set-id)
  // from NLF lookup result on reception of initial request
  static absl::StatusOr<NfInstance> selectNfOnPriority(const Json& nlf_lookup_result, const IPver& ip_version);
  // Extract list of TaRs from NLF lookup result for remote routing
  static absl::StatusOr<std::vector<std::string>> selectTarsForRemoteRouting(
    const Json& nlf_lookup_result, const uint32_t& num_reselections, const IPver& ip_version,
    const absl::optional<std::string>& nf_set_id = absl::nullopt,
    const absl::optional<uint32_t>& num_retries = absl::nullopt,
    const absl::optional<std::string>& preferred_tar = absl::nullopt
  );
  static absl::Status getHighPriorityEndpointsFromNfService(
    const Json& nf_instance, const Json& nf_service, const IPver& ip_version,
    std::pair<std::vector<NfInstance>,std::vector<uint64_t>>& high_priority_endpoints,
    std::set<std::string>& unique_hostnames, uint64_t& max_priority
  );
  static absl::Status getPriorityLevelsFromNfService(
    const Json& nf_instance, const Json& nf_service, const IPver& ip_version,
    std::map<uint64_t, std::pair<std::vector<std::string>,
    std::vector<uint64_t>>>& priority_levels, std::set<std::string>& unique_tars,
    const absl::optional<std::string>& preferred_tar = absl::nullopt
  );
  static absl::StatusOr<std::string> getSchemeForEndpoint(const Json& nf_service);
  static absl::StatusOr<std::string> getApiPrefixForEndpoint(const Json& nf_service);
  static absl::StatusOr<std::vector<std::string>> getHostnameListForEndpoints(
    const Json& nf_instance, const Json& nf_service, const IPver& ip_version,
    const absl::optional<Json>& ip_endpoint = absl::nullopt
  );
  static absl::StatusOr<std::vector<std::string>> getTarListForEndpoints(
    const std::string& scheme,const std::string& api_prefix, const Json& nf_instance, const Json& nf_service,
    const IPver& ip_version, const absl::optional<Json>& ip_endpoint = absl::nullopt
  );
  static absl::StatusOr<std::vector<std::string>> getHostListForEndpoints(
    const Json& nf_instance, const Json& nf_service, const IPver& ip_version,
    const absl::optional<Json>& ip_endpoint = absl::nullopt
  );
  static absl::StatusOr<std::string> getPortForEndpoint(
    const Json& nf_service, const absl::optional<Json>& ip_endpoint = absl::nullopt
  );
  static absl::StatusOr<std::string> getNfSetIdForEndpoint(const Json& nf_instance);
  static absl::optional<std::string> getNfInstanceIdForEndpoint(const Json& nf_instance);
  static absl::StatusOr<uint64_t> getPriorityForEndpoint(const Json& nf_instance, const Json& nf_service);
  static absl::StatusOr<uint64_t> getCapacityForEndpoint(const Json& nf_instance, const Json& nf_service);
  static absl::optional<uint32_t> randomSelectionByWeight(const std::vector<uint64_t>& cumulative_weight);

  // Populate 3gpp Sbi Service Context parameters
  static void populateServiceContext(RunContext& run_ctx, Http::StreamDecoderFilterCallbacks* decoder_callbacks);

private:
  const EricProxyFilterConfigSharedPtr config_;
  const std::chrono::time_point<std::chrono::system_clock> config_updated_at_;
  // thread safe random generator used for indirect routing TODO: also for option D?
  Random::RandomGenerator& random_;

  RunContext run_ctx_;
  // ProcessFilterCase State-Machine state variables:
  bool pfcstate_headers_changed_ = false;
  std::string pfcstate_fc_name_;
  FCState pfcstate_next_state_ = FCState::StartFilterCase;
  std::shared_ptr<FilterCaseWrapper> pfcstate_filter_case_;
  std::vector<std::shared_ptr<FilterActionWrapper>>::const_iterator pfcstate_action_it_;
  std::vector<std::shared_ptr<FilterRuleWrapper>>::const_iterator pfcstate_filter_rule_it_;

  Http::StreamDecoderFilterCallbacks* decoder_callbacks_;
  Http::StreamEncoderFilterCallbacks* encoder_callbacks_;

  Body req_body_;
  Body resp_body_;
  Body* body_;

  // The result of an action-nf-discovery, parsed JSON
  // If the parsing failed or it was never parsed, the value will be a Json null
  Json discovery_result_json_;
  // The NF set id found from the result of an action-nf-discovery with nf-selection-on-priority.
  // If NF set id can not be found from the result, then it would be nullopt.
  absl::optional<std::string> nf_set_id_;
  // The IP-version to use (4, 6, dual-stack), determined from the action_nf_discovery "ip_version"
  IPver nf_disc_ip_version_ = IPver::Default;
  // the host originally targetted in a preferred routing scenario. Used to determine
  // if TaR should be appended on the response
  absl::optional<std::string> original_hostname_ = absl::nullopt;
  // the contents of the original tar header as it came with the request
  absl::optional<std::string> original_tar_ = absl::nullopt;

  // Topology Hiding/Unhiding counters
  void updateSuccessTopologyHidingCounters();
  void updateSuccessTopologyUnhidingCounters();
  void updateFailureTopologyHidingCounters();
  void updateFailureTopologyUnhidingCounters();
  void updateFqdnMappingCounters(
    const bool& is_mapping, const EricProxyStats::FqdnCase& fqdn_case
  );
  void updateFqdnScramblingCounters(
    const bool& is_scrambling, const EricProxyStats::FqdnCase& fqdn_case,
    const std::string& encryption_id
  );

  // Temporary until we completely bypass the eric_proxy filter for N32c requests:
  bool is_n32c_request_from_rp_ = false;

  bool isTFqdnInAuthority(std::string authority);
  bool isPTFqdnInAuthority(std::string authority, std::string pseudo_fqdn);

  // encode Uri FQDN -> T-FQDN, i.e. for location header and callback-URIs
  std::string encodeTfqdnUri(std::string orig_uri);
  std::string encodeTfqdnUri(std::string orig_uri, std::string scheme);

  // Map FilterHeadersStatus to FilterDataStatus, needed because we process
  // body-less messages in decodeHeaders() and body-containing messages in
  // decodeData(), but they don't return the same types:
  std::map<Http::FilterHeadersStatus, Http::FilterDataStatus> map_filter_to_data_status_ = {
      {Http::FilterHeadersStatus::Continue, Http::FilterDataStatus::Continue},
      {Http::FilterHeadersStatus::StopIteration, Http::FilterDataStatus::StopIterationNoBuffer},
  };

  // Events
  // Map to translate protobuf enum values for event type to EventT enum values (for action_report_event)
  using ReportEventType = envoy::extensions::filters::http::eric_proxy::v3::ReportEventAction_EventType;
  std::map<ReportEventType, EricEvent::EventType> map_proto_event_type_ = {
      {ReportEventType::ReportEventAction_EventType_HTTP_SYNTAX_ERROR,
       EricEvent::EventType::HTTP_SYNTAX_ERROR},
      {ReportEventType::ReportEventAction_EventType_HTTP_HEADER_TOO_MANY,
       EricEvent::EventType::HTTP_HEADER_TOO_MANY},
      {ReportEventType::ReportEventAction_EventType_HTTP_HEADER_TOO_LONG,
       EricEvent::EventType::HTTP_HEADER_TOO_LONG},
      {ReportEventType::ReportEventAction_EventType_HTTP_HEADER_NOT_ALLOWED,
       EricEvent::EventType::HTTP_HEADER_NOT_ALLOWED},
      {ReportEventType::ReportEventAction_EventType_HTTP_BODY_TOO_LONG,
       EricEvent::EventType::HTTP_BODY_TOO_LONG},
      {ReportEventType::ReportEventAction_EventType_HTTP_BODY_EXTRA_BODIES,
       EricEvent::EventType::HTTP_BODY_EXTRA_BODIES},
      {ReportEventType::ReportEventAction_EventType_HTTP_JSON_BODY_SYNTAX_ERR,
       EricEvent::EventType::HTTP_JSON_BODY_SYNTAX_ERR},
      {ReportEventType::ReportEventAction_EventType_HTTP_JSON_BODY_TOO_MANY_LEAVES,
       EricEvent::EventType::HTTP_JSON_BODY_TOO_MANY_LEAVES},
      {ReportEventType::ReportEventAction_EventType_HTTP_JSON_BODY_MAX_DEPTH_EXCEEDED,
       EricEvent::EventType::HTTP_JSON_BODY_MAX_DEPTH_EXCEEDED},
      {ReportEventType::ReportEventAction_EventType_UNAUTHORIZED_SERVICE_OPERATION_DETECTED,
       EricEvent::EventType::UNAUTHORIZED_SERVICE_OPERATION_DETECTED},
      {ReportEventType::ReportEventAction_EventType_BARRED_HTTP1,
       EricEvent::EventType::BARRED_HTTP1},
      {ReportEventType::ReportEventAction_EventType_USER_DEFINED_EVENT,
       EricEvent::EventType::USER_DEFINED_EVENT},
  };
  // Map to translate protobuf enum values for event category to EventT enum values: (for action_report_event)
  using ReportEventCategory = envoy::extensions::filters::http::eric_proxy::v3::ReportEventAction_EventCategory;
  std::map<ReportEventCategory, EricEvent::EventCategory> map_proto_event_category_ = {
    {ReportEventCategory::ReportEventAction_EventCategory_SECURITY,
      EricEvent::EventCategory::SECURITY},
  };
  // Map to translate protobuf enum values for event severity in to EnumT enum values: (for action_report_event)
  using ReportEventSeverity = envoy::extensions::filters::http::eric_proxy::v3::ReportEventAction_EventSeverity;
  std::map<ReportEventSeverity, EricEvent::EventSeverity> map_proto_event_severity_ = {
    {ReportEventSeverity::ReportEventAction_EventSeverity_INFO,
      EricEvent::EventSeverity::INFO},
    {ReportEventSeverity::ReportEventAction_EventSeverity_DEBUG,
      EricEvent::EventSeverity::DEBUG},
    {ReportEventSeverity::ReportEventAction_EventSeverity_WARNING,
      EricEvent::EventSeverity::WARNING},
    {ReportEventSeverity::ReportEventAction_EventSeverity_ERROR,
      EricEvent::EventSeverity::ERROR},
    {ReportEventSeverity::ReportEventAction_EventSeverity_CRITICAL,
      EricEvent::EventSeverity::CRITICAL},
  };
  // Map to translate protobuf enum values for event action into EnumT enum values: (for action_report_event)
  using ReportEventAction = envoy::extensions::filters::http::eric_proxy::v3::ReportEventAction_EventAction;
  std::map<ReportEventAction, EricEvent::EventAction> map_proto_event_action_ = {
    {ReportEventAction::ReportEventAction_EventAction_REJECTED,
      EricEvent::EventAction::REJECTED},
    {ReportEventAction::ReportEventAction_EventAction_DROPPED,
      EricEvent::EventAction::DROPPED},
    {ReportEventAction::ReportEventAction_EventAction_IGNORED,
      EricEvent::EventAction::IGNORED},
    {ReportEventAction::ReportEventAction_EventAction_REPAIRED,
      EricEvent::EventAction::REPAIRED},
  };

  // Vector to translate protobuf enum values for event action into EnumT enum values: (for firewall rules)
  public:
  using FirewallEventAction = envoy::extensions::filters::http::eric_proxy::v3::ActionOnFailure::ActionSpecifierCase;
  static std::vector<EricEvent::EventAction> makeFwActionVector() {
    std::vector<EricEvent::EventAction> vec;
    // FIXME (eedala): Check if we can make this dynamic
    vec.resize(FirewallEventAction::kRemoveDeniedHeaders + 1);
    vec[FirewallEventAction::kRespondWithError] = EricEvent::EventAction::REJECTED;
    vec[FirewallEventAction::kDropMessage] = EricEvent::EventAction::DROPPED;
    vec[FirewallEventAction::kForwardUnmodifiedMessage] = EricEvent::EventAction::IGNORED;
    vec[FirewallEventAction::kRemoveDeniedHeaders] = EricEvent::EventAction::REPAIRED;
    return vec;
  };

  private:
  const static std::vector<EricEvent::EventAction> vec_proto_fw_action_;

  // For direct response/local reply/reject-message (see ratelimit filter):
  Http::ResponseHeaderMapPtr response_headers_to_add_;

  // Variables for conditions:
  VarData var_;
  VarData req_;

  // Report an event with incrementing sequence number
  void reportEvent(EricEvent::EventType type, EricEvent::EventCategory category,
                   EricEvent::EventSeverity severity, const std::string& message,
                   ActionOnFailure action, const std::string& ulid,
                   absl::optional<std::string> sub_spec = absl::nullopt);

  // Register callback functions for SlfLookup, implmemented in actions_lookup.cc
  void onSlfLookupSuccess(Http::ResponseMessagePtr&&);
  void onSlfLookupFailure(Http::AsyncClient::FailureReason);
  LookupCallbacks lookup_callbacks_ =
      LookupCallbacks(std::bind(&EricProxyFilter::onSlfLookupSuccess, this, _1),
                      std::bind(&EricProxyFilter::onSlfLookupFailure, this, _1));
  Http::AsyncClient::Request* lookup_request_ = nullptr;
  // Register callback functions for NF-discovery, implmemented in actions_discovery.cc
  void onNfDiscoverySuccess(Http::ResponseMessagePtr&&);
  void onNfDiscoveryFailure(Http::AsyncClient::FailureReason);
  LookupCallbacks discovery_callbacks_ =
      LookupCallbacks(std::bind(&EricProxyFilter::onNfDiscoverySuccess, this, _1),
                      std::bind(&EricProxyFilter::onNfDiscoveryFailure, this, _1));

  const char* filter_name_ = "envoy.filters.http.eric_proxy";
  const char* dyn_md_filtercases_namespace_ = "envoy.filters.http.eric_proxy.filter_cases";

  const char* md_key_internal_rejected_ = "internal-rejected";
  const char* md_key_internal_rejected_by_ = "internal-rejected-by";

  const Http::LowerCaseString headerKey() const;
  const std::string headerValue() const;

  Http::FilterHeadersStatus processRequest();
  Http::FilterHeadersStatus processRequestFilterPhases();
  Http::FilterHeadersStatus processOutRequestScreening();
  Http::FilterHeadersStatus processResponse();
  Http::FilterHeadersStatus processResponseFilterPhases();

  // Return the start-filter-case(s) for screening and routing
  // (only one start-filter-case is allowed for routing because
  // once a message is routed, we cannot route it again):
  std::vector<std::string> getAllStartFcForInRequestScreening();
  absl::optional<std::string> getStartFcForRouting();
  std::vector<std::string> getAllStartFcForOutRequestScreening();
  std::vector<std::string> getAllStartFcForInResponseScreening();
  std::vector<std::string> getAllStartFcForOutResponseScreening();

  // Execute the current filter case (continue or abort or park the request):
  // ProcessFcMode determines if the SM is executing for user-defined
  // message screening or for SEPP Edge Processing for topology hiding mode
  // in Screening mode : filter-data are updated after every filter-rule execution
  // in Topology Hiding mode : filter-data is updated only when a new filter-case
  //                            is loaded
  Http::FilterHeadersStatus processFilterCase(ProcessFcMode mode);

  // Continue Processing after Lookup is completed
  void continueProcessingAfterSlfResponse();
  // Cleanup activities called by onDestroy()
  void cleanup();

  void populateReqFromRequest(Http::RequestOrResponseHeaderMap&);
  void populateVarFromFilterData(Http::RequestOrResponseHeaderMap&);
  void filterDataFromHeaderWithExtractorRegex(Http::RequestOrResponseHeaderMap&, const std::string&,
                                              const re2::RE2&);
  void filterDataExtractorRegex(const std::string&, const re2::RE2&);
  std::string filterCaseDefault(Http::RequestOrResponseHeaderMap&);
  std::string logHeaders(const Http::RequestOrResponseHeaderMap&) const;
  absl::optional<std::string> getDynamicMetadata(const std::string, const std::string);
  bool setEncoderOrDecoderDynamicMetadata(const std::string name_space,
                                           std::vector<std::string> keys,
                                           std::vector<std::string> values,
                                           bool is_decoder_md);
  absl::optional<std::string> getRouteMetadata(std::string);
  void copyRouteMdToDynamicMd();
  bool isRouteMetadataPresent();
  absl::optional<std::string>
      getMetadataString(google::protobuf::Map<std::basic_string<char>, google::protobuf::Struct>,
                        std::string);
  absl::optional<double>
      getMetadataDouble(google::protobuf::Map<std::basic_string<char>, google::protobuf::Struct>,
                        std::string);

  ProtobufWkt::RepeatedPtrField<ProtobufWkt::Value>
  getMetadataList(google::protobuf::Map<std::basic_string<char>, google::protobuf::Struct> metadata,
                  std::string key);
  std::string getSourceFromHeader(const Http::RequestOrResponseHeaderMap& headers,
    const std::string& source_header);
  void updateVariables(std::shared_ptr<FilterCaseWrapper>, std::shared_ptr<FilterDataWrapper>);
  bool areVariablesUpdatedByFc(std::shared_ptr<FilterCaseWrapper>);
  void updateVariablesForFilterRule(std::vector<std::shared_ptr<FilterRuleWrapper>>::const_iterator pfcstate_filter_rule_iterator);

  ActionResultTuple executeAction(const FilterActionWrapper& action);

  void createTargetApiRootfromAuthorityHeader(Http::RequestOrResponseHeaderMap* headers);
  void createTargetApiRootfromString(std::string& new_value, Http::RequestOrResponseHeaderMap* headers);
  void createTargetApiRootfromDecodedTFqdnLabel(std::string& new_value, Http::RequestOrResponseHeaderMap* headers);
  void modifyTfqdnInNfDiscoveryResponse();
  void modifyTfqdnInNfDiscoveryResponseNfInstNfService(const Json& nf_inst, Json& nf_service);

  absl::Status modifyFqdnInNfDiscoveryResponseNfServices();
  void addTaRInResponse(Http::StreamEncoderFilterCallbacks* callback, Http::RequestOrResponseHeaderMap* map);

  // Find the RP's name where the request is originating and set it in originating_rp_name_.
  // It is sufficient to call this method once during request processing since
  // originating_rp_name_ keeps its value until after the response has been processed.
  void setOriginatingRpName();
  // The name of the RP where the request is originating from
  std::optional<std::string> originating_rp_name_;
  // Don't directly set cluster_name_ or pool_name_, use setClusterName() instead!!
  // It updates both at the same time.
  void setClusterName(const std::string& cluster);
  std::optional<std::string> cluster_name_;
  std::optional<std::string> pool_name_;
  std::optional<RoamingPartner> rp_config_;

  // Topology Hiding
  void setRpConfigFromRpName();
  void setRpConfigFromClusterName();

  // Request validation checks
  std::unique_ptr<CheckHeaders> request_headers_check_;
  std::unique_ptr<CheckJsonSyntax> request_json_syntax_check_;
  std::unique_ptr<CheckMessageBytes> request_bytes_check_;
  std::unique_ptr<CheckJsonLeaves> request_json_leaves_check_;
  std::unique_ptr<CheckJsonDepth> request_json_depth_check_;
  std::unique_ptr<CheckServiceOperations> request_unauthorized_service_operations_check_;

  // Response validation checks
  std::unique_ptr<CheckHeaders> response_headers_check_;
  std::unique_ptr<CheckJsonSyntax> response_json_syntax_check_;
  std::unique_ptr<CheckMessageBytes> response_bytes_check_;
  std::unique_ptr<CheckJsonLeaves> response_json_leaves_check_;
  std::unique_ptr<CheckJsonDepth> response_json_depth_check_;

  // These are defined in firewall.cc
  void populateRequestValidationConfig(const bool& is_global);
  void populateResponseValidationConfig(const bool& is_global);
  void setMaxRequestBytesLimit();
  void setMaxResponseBytesLimit();
  // following functions perform firewall related checks
  // returns true if filter iteration should continue
  // and false otherwise
  bool checkMaxRequestBytes();
  bool checkMaxResponseBytes();
  // Check for syntax, configured number of leaves and nesting depth for JSON body
  bool checkForConfiguredJsonFormat();
  // USFW Header checks. Returns true
  bool checkHeaders();
  // Configured action on failure (when check fails)
  bool actionOnFailure(const ActionOnFailure& action_on_failure,
                       std::vector<absl::string_view>&& offending_headers = {});

  // USFW USOC (Unauthorized Service Operations Checks)
  
  // Checks if the currently processed request
  // is an unauthorized service operation
  bool isUnauthorizedServiceOperation();
  // Returns true if the current request (service context) matches any of the given service classifiers attributes
  bool validateCurrentRequestAgainstServiceClassifiers(const std::vector<std::shared_ptr<ServiceClassifierConfigBase>>& service_classifiers);  
  // Processes a detected unauthorized service operation according 
  // to configuration (report_event and/or action_on_failure)
  bool processUnauthorizedServiceOperation();

  // Counters data and functions
  const EricProxyStatsSharedPtr stats_;
  void  incTotalInvocationsCounter();
  void  incRejectCounter();
  void  incDropCounter();
  // Create & return a retry-policy for requests to NLF/SLF:
  envoy::config::route::v3::RetryPolicy retryPolicyForLookup(
      Upstream::ThreadLocalCluster* thread_local_cluster,
    std::chrono::milliseconds& timeout);
  // The current phase the filter is in:
  FCPhase phase_ = FCPhase::Undefined;
  const std::string fcPhaseName(FCPhase phase) {
    int ph = static_cast<int>(phase);
    return (ph < 7) ? fcPhaseNames[ph] : "undefined";
  }

  // The phase to start with when the response comes in (set during request processing):
  FCPhase response_start_phase_ = FCPhase::Undefined;

  // Notifier for alarm handling channel
  AlarmNotifier notifier_;

  // following method is intentionally kept private, it is called by the public modifyJson()
  // interface, to avoid code duplication when dealing with single or multiple modifier_functions
  static absl::Status modifyJson(
    Http::StreamDecoderFilterCallbacks* decoder_callbacks,
    std::shared_ptr<Json> json_src,
    std::vector<std::string>& json_pointers,
    const std::function<std::string(const std::string&)>* modifier_functions,
    const std::size_t& modifier_functions_len,
    int error_handling_flags = 0
  );

  //-----------------------------------------------------------------------------------------------
  //-- Functions and data that belong to this class but are in other files, not inside filter.cc --
  //-----------------------------------------------------------------------------------------------
  // The following are implemented in actions_header.cc, not in filter.cc
public:
  ActionResultTuple actionAddHeader(const ActionAddHeaderWrapper& action);
  ActionResultTuple actionRemoveHeader(const FilterActionWrapper& action);
  ActionResultTuple actionModifyHeader(const ActionModifyHeaderWrapper& action);
  ActionResultTuple actionRemoveQueryParam(const FilterActionWrapper& action);
  ActionResultTuple actionModifyQueryParam(const ActionModifyQueryParamWrapper& action);
  ActionResultTuple actionTransformUri(const FilterActionWrapper& action,
                                        Http::RequestOrResponseHeaderMap& headers);
  // static to be used by other classes
  static std::string varHeaderConstValueAsString(
    const VarHeaderConstValue& header_value_ref, bool force_use_req_hdrs,
    RunContext& run_ctx, Http::StreamDecoderFilterCallbacks* decoder_callbacks
  );
  static std::vector<std::string> varHeaderConstValueAsVector(
    const VarHeaderConstValue& header_value_ref, bool force_use_req_hdrs,
    RunContext& run_ctx, Http::StreamDecoderFilterCallbacks* decoder_callbacks
  );
  // Convenience shortcut for the above static function:
  std::string varHeaderConstValueAsString(const VarHeaderConstValue& header_value_ref, bool force_use_req_hdrs) {
    return varHeaderConstValueAsString(header_value_ref, force_use_req_hdrs, run_ctx_, decoder_callbacks_);
  }
  std::vector<std::string> varHeaderConstValueAsVector(const VarHeaderConstValue& header_value_ref, bool force_use_req_hdrs) {
    return varHeaderConstValueAsVector(header_value_ref, force_use_req_hdrs, run_ctx_, decoder_callbacks_);
  }

  // The following are implemented in actions_json_body.cc, not in filter.cc
  ActionResultTuple actionModifyJsonBody(const ActionModifyJsonBodyWrapper& action);

  // The following are implemented in actions_body.cc, not in filter.cc
  ActionResultTuple actionCreateBody(const FilterActionWrapper& action);

  // The following are implemented in actions_log.cc, not in filter.cc
  ActionResultTuple actionLog(const ActionLogWrapper& action);
  ActionResultTuple actionReportEvent(const ActionReportEventWrapper& action);
  std::string textForLogAndEvent(const LogValuesT values, const unsigned long max_length);

  // The following are implemented in actions_misc.cc, not in filter.cc
  ActionResultTuple actionModifyVariable(const ActionModifyVariableWrapper& action);
  ActionResultTuple actionGotoFilterCase(const FilterActionWrapper& action);
  ActionResultTuple actionExitFilterCase();
  ActionResultTuple actionRejectMessage(const FilterActionWrapper& action);
  ActionResultTuple actionDropMessage();
  ActionResultTuple actionModifyStatusCode(const FilterActionWrapper& action);
  ActionResultTuple sendLocalReplyWithSpecificContentType(int status_code,
      const absl::optional<std::string>& content_type,
      const std::string& message,
      const absl::string_view response_code_details);
  ActionResultTuple sendLocalReplyWithSpecificContentType(absl::string_view status_code,
      const absl::optional<std::string>& content_type,
      const std::string& message,
      const absl::string_view response_code_details);
  ActionResultTuple sendLocalReplyOnResponsePathWithContentType(int status_code,
      const absl::optional<std::string>& content_type,
      const std::string& message,
      const absl::string_view response_code_details);

private:
  bool internalRejected();
  bool internal_rejected_ = false;
  bool local_reply_ = false;

  bool isReqMarkedTFqdn();
  std::optional<std::string> topo_hide_pseudo_fqdn_;
  absl::optional<std::string> reqSchemeMD();
  // TODO: remove when we can solely rely on the new flag instead (eedrak)
  bool isReqMarkedNfDiscovery();

void setIPFamilyPolicy(const IPver pref_ip_version,
                                        bool retry_multiple_addr,
                                        const RoutingBehaviour& rb,
                                        const std::string& pref_host,
                                        const std::vector<std::pair<std::shared_ptr<Envoy::Upstream::Host>, unsigned short>>& host_vector);

// This function is used to partially check the format and compare the contents of
// 3gpp-sbi-originating-network-id header with the supplied configured ones, for DND-60151
// @param header_val The header's value
// @param plmn_ids Supplied plmn ids, either belonging to originating RP or own SEPP
// @return true if a match was found, false otherwise or if the header format is not correct
static bool
performPlmnIdMatch(const Envoy::Http::HeaderMap::GetResult& header_val,
                   const ::envoy::extensions::filters::http::eric_proxy::v3::PlmnIdInfo& plmn_ids,
                   Http::StreamDecoderFilterCallbacks* decoder_callbacks);

// TH Phase2 (TH IP hiding)
// The following are implemented in sepp.cc, not in filter.cc
Http::FilterHeadersStatus hideIpAddressesInNfStatusNotifyRequestWithNfProfile();
absl::optional<bool> isThIpHidingErrorCaseInNfProfile();
Http::FilterHeadersStatus hideIpAddressesInNfProfile();
Http::FilterHeadersStatus handleThIpHidingErrorCaseInNfProfile();

Http::FilterHeadersStatus hideIpAddressesInNfStatusNotifyRequestWithProfileChanges();
absl::optional<Http::FilterHeadersStatus> findNfTypeInNfStatusNotifyRequestWithProfileChanges();
absl::optional<Http::FilterHeadersStatus>
findNfTypeForIpv4AddressesInProfileChange(const int& profile_changes_idx);
absl::optional<Http::FilterHeadersStatus>
findNfTypeForIpv6AddressesInProfileChange(const int& profile_changes_idx);
absl::optional<Http::FilterHeadersStatus> findNfTypeForIpAddressesInProfileChange(
    const absl::optional<std::map<std::string, std::vector<Network::Address::CidrRange>>>&
        ip_subnet_per_target_nf_type,
    const int& profile_changes_idx);
absl::optional<Http::FilterHeadersStatus>
findNfTypeForIpv4AddressInProfileChange(const int& profile_changes_idx);
absl::optional<Http::FilterHeadersStatus>
findNfTypeForIpv6AddressInProfileChange(const int& profile_changes_idx);
absl::optional<Http::FilterHeadersStatus> findNfTypeForIpAddressInProfileChange(
    const absl::optional<std::map<std::string, std::vector<Network::Address::CidrRange>>>&
        ip_subnet_per_target_nf_type,
    const int& profile_changes_idx);
bool isIpAddressInSubnet(const std::string& ip_address, const Network::Address::CidrRange& subnet);
Http::FilterHeadersStatus hideIpAddressesInProfileChanges();

Http::FilterHeadersStatus hideIpAddressesInNfDiscoveryResponse();
absl::optional<bool> isThIpHidingErrorCaseInNfInstances();
Http::FilterHeadersStatus hideIpAddressesInNfInstances();
Http::FilterHeadersStatus handleThIpHidingErrorCaseInNfInstances();

void respondWithError(const RejectMessageAction& response_config);
void sendLocalReplyForInvalidJsonBodyInNfStatusNotify();
void sendLocalReplyForInvalidJsonElementInNfStatusNotify();
void sendLocalReplyForInvalidJsonBodyInNfDiscovery();
void sendLocalReplyForInvalidJsonElementInNfDiscovery();
void sendLocalReplyForMissingTargetNfTypeInNfDiscovery();

bool is_req_flagged_topo_hiding_ = false;
bool is_req_flagged_th_ip_hiding_ = false;
bool is_req_flagged_nf_instance_discovery_ = false;
bool is_req_flagged_search_discovery_ = false;

bool setThIpHidingIfConfiguredForNfType(std::optional<RoamingPartner> rp,
                                        const std::string& nf_type);

absl::optional<ThActionOnFqdnAbsence> ip_hiding_action_on_fqdn_absence_;
absl::optional<std::string> ip_hiding_type_on_fqdn_absence_;
absl::optional<std::string> rp_name_topology_hiding_;
// absl::optional<::google::protobuf::Map<std::string, SubnetList>> ipv4_subnet_per_target_nf_type_;
// absl::optional<::google::protobuf::Map<std::string, SubnetList>> ipv6_subnet_per_target_nf_type_;
absl::optional<std::map<std::string /* nf-type */, std::vector<Network::Address::CidrRange>>>
    ipv4_subnet_per_target_nf_type_;
absl::optional<std::map<std::string /* nf-type */, std::vector<Network::Address::CidrRange>>>
    ipv6_subnet_per_target_nf_type_;

absl::optional<std::string> ip_hiding_profile_changes_nf_type_;
std::vector<int> ip_hiding_profile_change_indices_;

// TH Ph 2 NRF Fqdn Mapping
// Return all matched start-service-cases for all Ext-to-Int/ Int-to-Ext traffic
std::vector<std::pair<std::string, std::string>> getAllMatchedStartScForTopoHiding();
std::vector<std::pair<std::string, std::string>> getAllMatchedStartScForTopoUnhiding();

// ServiceContext Evaluator
// Evaluate if given request's service context matches one/more service-type
// defined in ServiceCaseConfig vector.
// Check whether the ServiceContext for request matched and return all
// matched start service-case and filter-case names
std::vector<std::pair<std::string, std::string>>
evalServiceContextMatch(std::vector<std::shared_ptr<ServiceCaseWrapper>>& service_case_config);
// Service Case Name matched with the current context
std::string service_case_name_;
// Flag to indicate if the SEPP edge processing for Topo-(Un)Hiding
// encountered a failure and stopped the iteration and sent a local
// reply
bool is_sepp_edge_screening_terminated_ = false;

// The following are implemented in actions_routing.cc, not in filter.cc
public:
  ActionResultTuple actionRouteToPool(const ActionRouteToPoolWrapper& action);
  ActionResultTuple actionRouteToRoamingPartner(const ActionRouteToRoamingPartnerWrapper& action);
private:
  void prepareSeppRoutingExtToInt(Http::RequestOrResponseHeaderMap& headers);
  void prepareSeppRoutingIntToExt(Http::RequestOrResponseHeaderMap& headers);

  void prepareScpStrictRoutingForDfP(Http::RequestOrResponseHeaderMap& headers,
                                     const RoutingBehaviour& behaviour);

  // The following are implemented in sepp.cc, not in filter.cc
  Http::FilterHeadersStatus seppInRequestEdgeProcessing();
  Http::FilterHeadersStatus seppOutRequestEdgeProcessing();
  Http::FilterHeadersStatus seppOutResponseEdgeProcessing();
  Http::FilterHeadersStatus seppInResponseEdgeProcessing();
  SeppReqPreProcResult n32cSeppPreprocessing();

  SeppReqPreProcResult seppRequestPreProcessing();
  void seppResponsePreProcessing();
  void scpResponsePreProcessing();

  void executeRoutingAction(const std::string& cluster_name,
                            const RoutingBehaviour& routing_behaviour,
                            const PreserveIfIndirect& preserve_if_indirect,
                            const VarHeaderConstValue& preferred_target);
  void populateResponseHeaders(Http::HeaderMap& response_headers);
  void setTargetHost(std::string host_with_port_lc, Http::RequestOrResponseHeaderMap&,
                      const RoutingBehaviour& rb);
  void applyPreserveIfIndirect(const PreserveIfIndirect& preserve_if_indirect);
  void applyPreferredTarget(Http::RequestOrResponseHeaderMap&);
  static std::string getReqApiNameForSbaCb(absl::string_view sba_cb_hdr);
  static std::string getReqApiVersionForSbaCb(absl::string_view sba_cb_hdr);
  std::string getResource(Http::RequestOrResponseHeaderMap& headers);

  std::vector<std::string> getCbUriJsonPointersForApi(const std::string& api_name);
  static Json varOrStringCommon(const VarOrString& var_or_string_ref, RunContext& run_ctx,
                   Http::StreamDecoderFilterCallbacks* decoder_callbacks);
  void executeRemoteRoutingAction(const FilterActionWrapper& action);
  // The size of the following array is = largest enum +1 in RoutingBehaviour in protobuf:
  std::array<const char*, static_cast<int>(RoutingBehaviour::REMOTE_PREFERRED)+1> routing_behaviour_str_;

  // The following are implemented/used in actions_lookup.cc, not in filter.cc
public:
  ActionResultTuple actionSlfLookup(const ActionSlfLookupWrapper& action);
private:
  ActionResultTuple doSlfLookup(const FilterActionWrapper& action, const std::string& nslf_api_root);
  void processSlfLookupBodyOK(const std::string& body);
  void processSlfLookupErrors(const absl::string_view status);
  std::unique_ptr<Http::RequestHeaderMapImpl>
  prepareSlfLookupHeaders(std::string const& query_id_type, const std::string& query_id_value,
                          const std::string& nslf_api_root, const std::string& nrf_group_name);
  ActionResultTuple deferred_lookup_result_;
  const FilterActionWrapper* deferred_lookup_action_ = nullptr;

  // Used for both SLF-Lookup and NF-Discovery:
  FilterCaseWrapper* deferred_filter_case_ptr_ = nullptr;

  // The following are implemented in actions_discovery.cc, not in filter.cc:
public:
  ActionResultTuple actionNfDiscovery(const ActionNfDiscoveryWrapper& action);
private:
  std::unique_ptr<Http::RequestHeaderMapImpl> prepareNlfRequest(const ActionNfDiscoveryWrapper& action);
  std::string prepareNlfQueryString(const ActionNfDiscoveryWrapper& action);
  void addToQueryString(std::string& query_string, absl::string_view name, absl::string_view value);
  void processNfDiscoveryOk(const std::string& body);
  void updateDestVar(const std::string& dest_var, const std::string& value,
      const std::string& var_description);
  void processNfDiscoveryErrors(absl::string_view status, const std::string& body);
  // The characters needing percent-encoding (URL-encoding) are taken from RFC7230 ch. 3.2.6 and
  // from TS29.500 ch. 5.2.3.
  // The order of the characters in this string doesn't matter, they are inserted into
  // an absl::flat_has_set.
  const std::string chars_needing_percent_encoding_ = ":/?#[]@!$&'()*+,;=\"<  >\\{}";
  // The following were generated from the OpenAPI spec with this command:
  // yq eval '.paths./nf-instances.get.parameters[] | select(. |has("content"))| .name' TS29510_Nnrf_NFDiscovery.yaml
  std::unordered_set<std::string> disc_params_needing_percent_encoding_ = {
"target-plmn-list",
"requester-plmn-list",
"snssais",
"requester-snssais",
"plmn-specific-snssai-list",
"requester-plmn-specific-snssai-list",
"ipv4-index",
"ipv6-index",
"tai",
"guami",
"pgw-ip",
"pfd-data",
"chf-supported-plmn",
"ext-preferred-locality",
"complex-query",
"atsss-capability",
"client-type",
"lmf-id",
"an-node-type",
"rat-type",
"preferred-tai",
"target-snpn",
"requester-snpn-list",
"af-ee-data",
"w-agf-info",
"tngf-info",
"twif-info",
"preferred-api-versions",
"remote-plmn-id",
"remote-snpn-id",
"preferred-vendor-specific-features",
"preferred-vendor-specific-nf-features",
"ml-analytics-info-list",
"mbs-session-id-list",
"upf-n6-ip",
"tai-list",
"v2x-capability",
"prose-capability",
"exclude-nfservinst-list",
"preferred-analytics-delays",
  };

  // NOTE: Do not put methods or variables here that are defined/used in filter.cc !!
  //       Instead, put them further up, before it starts with "The following are implemented in ... not filter.cc
  //
};
//---------------------------------------------------------------------



} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
