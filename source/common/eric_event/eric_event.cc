#include "eric_event.h"

namespace Envoy {
namespace EricEvent {

// Set the static application ID once
std::string EventT::appl_id_ = std::getenv("APPLICATION_ID") ? std::getenv("APPLICATION_ID") : "";

// Map from event-tag to the value as a std::string
std::map<std::string, EventT::MemberGetter> EventT::member_map_ = {
    {"TYPE",
     [](const EventT& evnt) -> const std::string& {
       return type_str_.at(static_cast<int>(evnt.type_));
     }},
    {"CATEGORY",
     [](const EventT& evnt) -> const std::string& {
       return category_str_.at(static_cast<int>(evnt.category_));
     }},
    {"SEVERITY",
     [](const EventT& evnt) -> const std::string& {
       return severity_str_.at(static_cast<int>(evnt.severity_));
     }},
    {"MSG", [](const EventT& evnt) -> const std::string& { return evnt.message_; }},
    {"ULID", [](const EventT& evnt) -> const std::string& { return evnt.ulid_; }},
    {"RESP_MSG", [](const EventT& evnt) -> const std::string& { return evnt.resp_message_; }},
    // RESP_CODE must be a string according to ADP log format specifications
    {"RESP_CODE", [](const EventT& evnt) -> const std::string& { return evnt.resp_code_; }},
    {"ACTION",
     [](const EventT& evnt) -> const std::string& {
       return action_str_.at(static_cast<int>(evnt.action_));
     }},
    {"RP", [](const EventT& evnt) -> const std::string& { return evnt.roaming_partner_; }},
    {"SRC", [](const EventT& evnt) -> const std::string& { return evnt.source_; }},
    {"SRC_TYPE", [](const EventT& evnt) -> const std::string& { return evnt.source_type_; }},
    // the following two are constants and can also be replaced right away in the format string
    {"VERSION", [](const EventT& evnt) -> const std::string& { return evnt.version_str_; }},
    {"LOG_VERSION",
     [](const EventT& evnt) -> const std::string& { return evnt.log_version_str_; }},
    {"APPL_ID", [](const EventT&) -> const std::string& {return EventT::appl_id_; }}
};

// Map from event-tag to the value as protobuf-value
std::map<std::string, EventT::MemberValueGetter> EventT::member_value_map_ = {
    {"TYPE",
     [](const EventT& evnt, absl::optional<size_t> max_len) -> const ProtobufWkt::Value {
       return limitAndWrapString(type_str_.at(static_cast<int>(evnt.type_)), max_len);
     }},
    {"CATEGORY",
     [](const EventT& evnt, absl::optional<size_t> max_len) -> const ProtobufWkt::Value {
       return limitAndWrapString(category_str_.at(static_cast<int>(evnt.category_)), max_len);
     }},
    {"SEVERITY",
     [](const EventT& evnt, absl::optional<size_t> max_len) -> const ProtobufWkt::Value {
       return limitAndWrapString(severity_str_.at(static_cast<int>(evnt.severity_)), max_len);
     }},
    {"MSG",
     [](const EventT& evnt, absl::optional<size_t> max_len) -> const ProtobufWkt::Value {
       return limitAndWrapString(evnt.message_, max_len);
     }},
    {"ULID",
     [](const EventT& evnt, absl::optional<size_t> max_len) -> const ProtobufWkt::Value {
       return limitAndWrapString(evnt.ulid_, max_len);
     }},
    {"RESP_MSG",
     [](const EventT& evnt, absl::optional<size_t> max_len) -> const ProtobufWkt::Value {
       return limitAndWrapString(evnt.resp_message_, max_len);
     }},
    {"RESP_CODE",  // Must be a string according to ADP log format
     [](const EventT& evnt, absl::optional<size_t> max_len) -> const ProtobufWkt::Value {
       return limitAndWrapString(evnt.resp_code_, max_len);
     }},
    {"ACTION",
     [](const EventT& evnt, absl::optional<size_t> max_len) -> const ProtobufWkt::Value {
       return limitAndWrapString(action_str_.at(static_cast<int>(evnt.action_)), max_len);
     }},
    {"RP",
     [](const EventT& evnt, absl::optional<size_t> max_len) -> const ProtobufWkt::Value {
       return limitAndWrapString(evnt.roaming_partner_, max_len);
     }},
    {"SRC",
     [](const EventT& evnt, absl::optional<size_t> max_len) -> const ProtobufWkt::Value {
       return limitAndWrapString(evnt.source_, max_len);
     }},
    {"SRC_TYPE",
     [](const EventT& evnt, absl::optional<size_t> max_len) -> const ProtobufWkt::Value {
       return limitAndWrapString(evnt.source_type_, max_len);
     }},
    // the following two are constants and can also be replaced right away in the format string
    {"VERSION",
     [](const EventT& evnt, absl::optional<size_t> max_len) -> const ProtobufWkt::Value {
       return limitAndWrapString(evnt.version_str_, max_len);
     }},
    {"LOG_VERSION",
     [](const EventT& evnt, absl::optional<size_t> max_len) -> const ProtobufWkt::Value {
       return limitAndWrapString(evnt.log_version_str_, max_len);
     }},
    {"APPL_ID",
     [](const EventT&, absl::optional<size_t> max_len) -> const ProtobufWkt::Value {
        return limitAndWrapString(EventT::appl_id_, max_len);
     }},
    {"SUB_SPEC",
     [](const EventT& evnt, absl::optional<size_t>) -> const ProtobufWkt::Value {
       if (!evnt.subSpec().empty()) {
         ProtobufWkt::Struct proto_val;
         MessageUtil::loadFromJson(evnt.sub_spec_, proto_val);
         return ValueUtil::structValue(proto_val);
       } else {
         return ValueUtil::nullValue();
       }
     }}
};

ProtobufWkt::Value EventT::limitAndWrapString(const std::string& str,
                                              absl::optional<size_t> max_length) {
  // An empty string would be shown as empty string, but we want nothing to be logged
  // in case the string is empty -> return "nullValue()"
  if (str.empty()) {
    return ValueUtil::nullValue();
  }
  if (max_length) {
    std::string val = str;
    Formatter::SubstitutionFormatUtils::truncate(val, *max_length);
    return ValueUtil::stringValue(val);
  } else {
    // No length-limiting, no copy needed
    return ValueUtil::stringValue(str);
  }
}

} // namespace EricEvent
} // namespace Envoy