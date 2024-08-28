#pragma once
#include <string>
#include "envoy/access_log/access_log.h"
#include "source/common/common/logger.h"
#include "source/common/eric_event/eric_event.h"
#include "source/common/eric_event/eric_event_reporter.h"
#include "source/common/stream_info/eric_event_state.h"



namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

class EventReporter : public Logger::Loggable<Logger::Id::eric_proxy> {
public:
  // Report a new event via the FilterStateObject "envoy.eric_proxy.event_state"
  static void reportEventViaFilterState(StreamInfo::StreamInfo& stream_info,
                                        EricEvent::EventT&& event) {
    // Find the filter-state object (FSO)
    const auto& filter_state = stream_info.filterState();
    auto event_fso = filter_state->getDataMutable<StreamInfo::EricEventState>(
        StreamInfo::EricEventState::key());
    if (event_fso) {
      // Add the event to the existing FSO
      event_fso->addEvent(std::move(event));
    } else {  // The FSO doesn't exist yet, create a new one...
      auto new_event_fso = std::make_unique<StreamInfo::EricEventState>();
      // .. and add the event to it
      new_event_fso->addEvent(std::move(event));
      filter_state->setData(StreamInfo::EricEventState::key(), std::move(new_event_fso),
                        StreamInfo::FilterState::StateType::Mutable,
                        StreamInfo::FilterState::LifeSpan::Request);
      // ... and set the metadata flag to indicate to the access-log filter
      //     that this request needs to be logged
      ProtobufWkt::Struct metadata;
      *(*metadata.mutable_fields())["is_event"].mutable_string_value() = "true";
      stream_info.setDynamicMetadata("eric_event", metadata);
    }
  };
};



} // EricProxy
} // HttpFilters
} // Extensions
} // Envoy
