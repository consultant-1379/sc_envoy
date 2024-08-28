#pragma once

#include "source/common/eric_event/eric_event.h"
#include "envoy/stream_info/filter_state.h"


namespace Envoy {
namespace StreamInfo {


// Filter State Object for Event-Reporting
class EricEventState: public FilterState::Object {
public:
  static const std::string& key() { CONSTRUCT_ON_FIRST_USE(std::string, "envoy.eric_event_state"); }

  void addEvent(EricEvent::EventT&& event) { events_.push_back(event); }

  const std::vector<EricEvent::EventT>& events() const { return events_; }
  const EricEvent::EventT& getCurrentEvent() const { return events_.at(indx_); }
  size_t getCurrentEventIndex() const { return indx_; }
  void processNextEvent() const { indx_ = ++indx_ % events_.size(); }

private:
  std::vector<EricEvent::EventT> events_;
  mutable size_t indx_ = 0;
};

} // namespace StreamInfo
} // namespace Envoy
