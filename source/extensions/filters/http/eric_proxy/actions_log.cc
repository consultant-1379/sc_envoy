#include "source/extensions/filters/http/eric_proxy/filter.h"
#include <algorithm>
#include <cstddef>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include "absl/strings/str_format.h"
#include "source/common/http/header_utility.h"
#include "source/extensions/filters/http/eric_proxy/wrappers.h"


namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// Helper function for both action-log and action-report-event that creates and returns
// the log message (string) from the given strings and variables.
// It truncates the log message to the given value if needed.
std::string EricProxyFilter::textForLogAndEvent(const LogValuesT values, const unsigned long max_length) {
  std::string text;
  text.reserve(max_length + 3);
  for (const auto& val : values)  {
    if (text.length() >= max_length) {
      text += "...";
      break;
    }
    const auto [type1, index1] =
        ActionLogWrapper::typeAndIndexForLogValue(val, run_ctx_.rootContext());
    try {
      switch (type1) {
      case ActionLogWrapper::ConditionTypeLog::BooleanConstT:
        text += absl::StrFormat("%v", run_ctx_.rootContext()->constValue(index1).get<bool>())
                    .substr(0, max_length - text.length());
        break;
      case ActionLogWrapper::ConditionTypeLog::StringConstT:
        text += run_ctx_.rootContext()->constValue(index1).get<std::string>().substr(
            0, max_length - text.length());
        break;
      case ActionLogWrapper::ConditionTypeLog::NumberConstT:
        text += absl::StrFormat("%v", run_ctx_.rootContext()->constValue(index1).get<double>())
                    .substr(0, max_length - text.length());
        break;
      case ActionLogWrapper::ConditionTypeLog::StringReqHeaderT:
        if (run_ctx_.hasHeaderValue(index1, ReqOrResp::Request)) {
          text += absl::StrJoin(run_ctx_.headerValue(index1, ReqOrResp::Request), "")
                      .substr(0, max_length - text.length());
        } else { // Header: ist not set in runContext
          const auto r = Http::HeaderUtility::getAllOfHeaderAsString(
              run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(run_ctx_.rootContext()->headerName(index1))), "");
          text += r.backingString().substr(0, max_length - text.length());
        }
        break;
      case ActionLogWrapper::ConditionTypeLog::StringRespHeaderT:
        if (run_ctx_.hasHeaderValue(index1, ReqOrResp::Response)) {
          text += absl::StrJoin(run_ctx_.headerValue(index1, ReqOrResp::Response), "")
                      .substr(0, max_length - text.length());
        } else { // Header: ist not set in runContext
          const auto r = Http::HeaderUtility::getAllOfHeaderAsString(
              run_ctx_.getReqOrRespHeaders()->get(Http::LowerCaseString(run_ctx_.rootContext()->headerName(index1))), "");
          text += r.backingString().substr(0, max_length - text.length());
        }
        break;
      case ActionLogWrapper::ConditionTypeLog::VarT:
        text += run_ctx_.varValueAsString(index1).substr(0, max_length - text.length());
        break;
      case ActionLogWrapper::ConditionTypeLog::StringReqBodyT:
        text += req_body_.getBodyAsString().substr(0, max_length - text.length());
        break;
      case ActionLogWrapper::ConditionTypeLog::StringRespBodyT:
        text += resp_body_.getBodyAsString().substr(0, max_length - text.length());
        break;
      }
    } catch (std::out_of_range& e) {
      // thrown in constValue
      continue;
    } catch (nlohmann::json::type_error& e) {
      // thrown in constValue
      continue;
    }
  }
  return text;
}


// Action Log Message
ActionResultTuple EricProxyFilter::actionLog(const ActionLogWrapper& action) {
  std::string text = textForLogAndEvent(action.protoConfig().action_log().log_values(),
    action.protoConfig().action_log().max_log_message_length());

  const auto level = action.protoConfig().action_log().log_level();
  switch (level) {
  case TRACE:
    ENVOY_STREAM_LOG(trace, "{}", *decoder_callbacks_, text);
    break;
  case DEBUG:
    ENVOY_STREAM_LOG(debug, "{}", *decoder_callbacks_, text);
    break;
  case INFO:
    ENVOY_STREAM_LOG(info, "{}", *decoder_callbacks_, text);
    break;
  case WARN:
    ENVOY_STREAM_LOG(warn, "{}", *decoder_callbacks_, text);
    break;
  case ERROR:
    ENVOY_STREAM_LOG(error, "{}", *decoder_callbacks_, text);
    break;
  default:
    ENVOY_STREAM_LOG(warn, "Unknown debug-level {}", *decoder_callbacks_, level);
  }
  return std::make_tuple(ActionResult::Next, false, std::nullopt);
}

// Action Report Event
// TODO: fix me when action-report-event is implemented
ActionResultTuple EricProxyFilter::actionReportEvent(const ActionReportEventWrapper&) {
  //   auto action_report_event = action.protoConfig().action_report_event();
  //   std::string text = textForLogAndEvent(action_report_event.event_message_values(),
  //     500 /*  action_report_event.max_event_message_length() */);

  //   ENVOY_STREAM_LOG(info, "##### Event message: {}", *decoder_callbacks_, text);

  //   reportEvent(map_proto_event_type_.at(action_report_event.event_type()),
  //       map_proto_event_category_.at(action_report_event.event_category()),
  //       map_proto_event_severity_.at(action_report_event.event_severity()),
  //       text,
  //       map_proto_event_action_.at(action_report_event.event_action()),
  //       ULID(A01));
  return std::make_tuple(ActionResult::Next, false, std::nullopt);
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
