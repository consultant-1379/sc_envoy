#pragma once

#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <regex>

#include "envoy/stats/scope.h"
#include "source/common/stats/symbol_table.h"
#include "source/common/stats/utility.h"



namespace Envoy {
namespace Extensions {
namespace Common {
namespace Tap {


class EricTapStats {
    public :
        EricTapStats(Stats::Scope& scope, const std::string nf_instance_prefix, const std::string group_prefix);
        Stats::ElementVec addPrefix(const Stats::ElementVec& names);


        Stats::Counter* ctr_connection_segments_dropped_;
        Stats::Counter* ctr_event_segments_dropped_;
        Stats::Counter* ctr_connection_segments_tapped_;
        Stats::Counter* ctr_event_segments_tapped_;

        Stats::Counter* ctr_event_segments_read_tapped_;
        Stats::Counter* ctr_event_segments_write_tapped_;
        Stats::Counter* ctr_event_segments_close_tapped_;

        Stats::Counter* ctr_connection_segment_too_big_;
        Stats::Counter* ctr_event_segment_too_big_;
//TODO: Add queue length counter when counter implementation in flusher thread is available
        // Stats::Gauge* gauge_queue_len_;


//TODO (enaidev/elauspy) After arcitecture meeting
/*     std::string getNfInstance(const std::string& root_prefix);
    std::string getThreadName(const std::string& root_prefix); */

    private:
        Stats::Scope& scope_;

        Stats::StatNameSetPtr stat_name_set_;
        Stats::StatName stats_prefix_;
        Stats::StatName g3p_;
        Stats::StatName vtap_;
        Stats::StatName n8e_;
        Stats::StatName nf_instance_name_;

        Stats::StatName segment_type_;
        Stats::StatName event_type_;

        Stats::StatName connection_;
        Stats::StatName event_;

        Stats::StatName read_;
        Stats::StatName write_;
        Stats::StatName close_;

        Stats::StatName segments_dropped_;
        Stats::StatName events_tapped_;
        Stats::StatName segments_tapped_;
        Stats::StatName segments_too_big_;
//TODO: Add queue length counter when counter implementation in flusher thread is available
        // Stats::StatName queue_length_;


};





} // namespace Tap
} // namespace Common
} // namespace Extensions
} // namespace Envoy

