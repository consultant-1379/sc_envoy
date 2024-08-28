#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <map>
#include "absl/types/optional.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/wrappers.pb.h"
#include "source/common/protobuf/utility.h"
#include "source/common/formatter/substitution_format_utility.h"


namespace Envoy {
namespace EricEvent {

// IMPORTANT: if you add an element here, also add one to type_str_ below!
enum class EventType : int {
  HTTP_SYNTAX_ERROR,
  HTTP_HEADER_TOO_MANY,
  HTTP_HEADER_TOO_LONG,
  HTTP_HEADER_NOT_ALLOWED,
  HTTP_BODY_TOO_LONG,
  HTTP_BODY_EXTRA_BODIES,
  HTTP_JSON_BODY_SYNTAX_ERR,
  HTTP_JSON_BODY_TOO_MANY_LEAVES,
  HTTP_JSON_BODY_MAX_DEPTH_EXCEEDED,
  UNAUTHORIZED_SERVICE_OPERATION_DETECTED,
  BARRED_HTTP1,
  USER_DEFINED_EVENT,
  LAST_ELEMENT
};

// IMPORTANT: if you add an element here, also add one to severity_str_ below!
enum class EventSeverity : int { DEBUG, INFO, WARNING, ERROR, CRITICAL, LAST_ELEMENT };

// IMPORTANT: if you add an element here, also add one to action_str_ below!
enum class EventAction : int { REJECTED, DROPPED, IGNORED, REPAIRED, LAST_ELEMENT };

// IMPORTANT: if you add an element here, also add one to category_str_ below!
enum class EventCategory : int { SECURITY, LAST_ELEMENT };

// Data for an event. More data can be configured through the access log format.
class EventT {
public:
  // Constructor without user-type (most events don't have a user-type)
  EventT(EventType type, EventCategory category, EventSeverity severity, const std::string& message,
         EventAction action, const std::string& roaming_partner, const std::string& source,
         const std::string& source_type, const std::string& ulid,
         const absl::optional<std::string> sub_spec = absl::nullopt,
         const std::string& resp_code = "", const std::string& resp_message = "")
      : type_(type), severity_(severity), message_(message), action_(action),
        roaming_partner_(roaming_partner), source_(source), source_type_(source_type), ulid_(ulid),
        category_(category),
        resp_code_(resp_code), resp_message_(resp_message) {
          // sub-spec
          if (sub_spec) {
            sub_spec_ = std::move(*sub_spec);
          }
        };

  // Getter for string-based fields, returns strings
  const std::string& getEventField(const std::string& key) const {
    auto it = member_map_.find(key);
    if (it == member_map_.end()) {
      return EMPTY_STR;
    }
    return it->second(*this);
  }

  // Getter for all fields, returns protobuf type
  const ProtobufWkt::Value getEventFieldValue(const std::string& key, absl::optional<size_t> max_len) const {
    auto it = member_value_map_.find(key);
    if (it == member_value_map_.end()) {
      return ValueUtil::nullValue();
    }
    return it->second(*this, max_len);
  }

  // Various getter-functions

  const std::string& type() const { return type_str_.at(static_cast<int>(type_)); }

  const std::string& category() const { return category_str_.at(static_cast<int>(category_)); }

  const std::string& severity() const { return severity_str_.at(static_cast<int>(severity_)); }

  // const std::string& message() const { return message_; }

  const std::string& action() const { return action_str_.at(static_cast<int>(action_)); }

  // const std::string& roaming_partner() const { return roaming_partner_; }

  // const std::string& source() const { return source_; }

  // const std::string& source_type() const { return source_type_; }

  // const std::string& version() const { return version_str_; }

  // const std::string& log_version() const { return log_version_str_; } // ADP log version

  // const std::string& ulid() const { return ulid_; }

  const std::string subSpec() const { return sub_spec_; }

  // Given a string and a max-length, truncate the string if necessary.
  // In any case, wrap the string into a protobuf value and return it.
  static ProtobufWkt::Value limitAndWrapString(const std::string& str, absl::optional<size_t> man_length);

  // The application_id which is set by the operator through Helm into an environment variable
  static std::string appl_id_;

 private:
   using MemberGetter = std::function<const std::string&(const EventT&)>;
   static std::map<std::string, MemberGetter> member_map_;
   using MemberValueGetter = std::function<const ProtobufWkt::Value(const EventT&, absl::optional<size_t>)>;
   static std::map<std::string, MemberValueGetter> member_value_map_;

   // The name before the colon (the first word in each comment) refers
   // to the name in Sven's Excel sheet

   // eventType: The meaning of the event.
   const EventType type_;

   // eventSeverity: The importance of the event
   const EventSeverity severity_;

   // eventMessage: Describes the cause of the event
   const std::string message_;

   // eventAction: Action that has been performed, depending on the context
   const EventAction action_;

   // eventRoamingPartner: Identifier of the roaming partner as defined in
   // the YANG configuration
   const std::string roaming_partner_;

   // eventSource: Own FQDN, from the correct network (internal or external)
   const std::string source_;

   // eventSourceType: SCP or SEPP
   const std::string source_type_;

   // eventUlid: Unique Logging ID, identifies the source code location where
   // the event occurred (useful if the same event can be reported from several
   // locations.  Used for troubleshooting. No need to explain it to the customer.
   const std::string ulid_;

   // eventCategory: The grouping to which an event belongs to
   const EventCategory category_;

   // the event's sub_spec, if there is one.
   std::string sub_spec_;

   // if the action after the event is reject, included the local reply's status code and detail in
   // the event
   const std::string resp_code_;

   const std::string resp_message_;

   // String constants for the enums and versions
   inline static const std::string version_str_ = "1.0.0";

   inline static const std::string log_version_str_ = "1.2.0";
   inline static const std::string EMPTY_STR = "";

   inline static const std::array<std::string, static_cast<int>(EventType::LAST_ELEMENT) + 1>
       type_str_ = {
           "ERIC_EVENT_SC_HTTP_SYNTAX_ERROR",
           "ERIC_EVENT_SC_HTTP_HEADER_TOO_MANY",
           "ERIC_EVENT_SC_HTTP_HEADER_TOO_LONG",
           "ERIC_EVENT_SC_HTTP_HEADER_NOT_ALLOWED",
           "ERIC_EVENT_SC_HTTP_BODY_TOO_LONG",
           "ERIC_EVENT_SC_HTTP_BODY_EXTRA_BODIES",
           "ERIC_EVENT_SC_HTTP_JSON_BODY_SYNTAX_ERR",
           "ERIC_EVENT_SC_HTTP_JSON_BODY_TOO_MANY_LEAVES",
           "ERIC_EVENT_SC_HTTP_JSON_BODY_MAX_DEPTH_EXCEEDED",
           "ERIC_EVENT_SC_UNAUTHORIZED_SERVICE_OPERATION_DETECTED",
           "ERIC_EVENT_SC_BARRED_HTTP1",
           "ERIC_EVENT_SC_USER_DEFINED_EVENT",
   };

   inline static const std::array<std::string, static_cast<int>(EventSeverity::LAST_ELEMENT) + 1>
       severity_str_ = {"debug", "info", "warning", "error", "critical"};

   inline static const std::array<std::string, static_cast<int>(EventAction::LAST_ELEMENT) + 1>
       action_str_ = {"rejected", "dropped", "ignored", "repaired"};

   inline static const std::array<std::string, static_cast<int>(EventCategory::LAST_ELEMENT) + 1>
       category_str_ = {"security"};
};

} // namespace EricEvent
} // namespace Envoy
