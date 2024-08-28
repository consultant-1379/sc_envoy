
#include "source/extensions/common/tap/eric_tap_stats.h"
#include <string>

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Tap {


EricTapStats::EricTapStats(Stats::Scope& scope, const std::string nf_instance_prefix, const std::string group_prefix):
    scope_(scope),
    stat_name_set_(scope_.symbolTable().makeSet("EricTap")),
    stats_prefix_(stat_name_set_->add(absl::string_view("eric_tap_stats"))),
    g3p_(stat_name_set_->add(absl::string_view("g3p"))),
    vtap_(stat_name_set_->add(absl::string_view(group_prefix))),
    n8e_(stat_name_set_->add(absl::string_view("n8e"))),
    nf_instance_name_(stat_name_set_->add(absl::string_view(nf_instance_prefix))),
    segment_type_(stat_name_set_->add(absl::string_view("s9e"))),
    event_type_(stat_name_set_->add(absl::string_view("e7e"))),
    connection_(stat_name_set_->add(absl::string_view("connection"))),
    event_(stat_name_set_->add(absl::string_view("event"))),
    read_(stat_name_set_->add(absl::string_view("read"))),
    write_(stat_name_set_->add(absl::string_view("write"))),
    close_(stat_name_set_->add(absl::string_view("close"))),
    segments_dropped_(stat_name_set_->add(absl::string_view("segments_dropped"))),
    events_tapped_(stat_name_set_->add(absl::string_view("events_tapped"))),
    segments_tapped_(stat_name_set_->add(absl::string_view("segments_tapped"))),
    segments_too_big_(stat_name_set_->add(absl::string_view("segments_size_too_big")))
    //TODO: Add queue length counter when counter implementation in flusher thread is available
    // queue_length_(stat_name_set_->add(absl::string_view("queue_length")))

{
    ctr_connection_segments_dropped_ = &Stats::Utility::
                                            counterFromElements(scope_
                                                                ,addPrefix({
                                                                    n8e_,nf_instance_name_,
                                                                    g3p_, vtap_,
                                                                    segment_type_,connection_,
                                                                    segments_dropped_
                                                                }));

    ctr_event_segments_dropped_ = &Stats::Utility::
                                        counterFromElements(scope_
                                                            ,addPrefix({
                                                                n8e_,nf_instance_name_,
                                                                g3p_, vtap_,
                                                                segment_type_,event_,
                                                                segments_dropped_
                                                            }));

    ctr_connection_segments_tapped_ = &Stats::Utility::
                                            counterFromElements(scope_
                                                                ,addPrefix({
                                                                    n8e_,nf_instance_name_,
                                                                    g3p_, vtap_,
                                                                    segment_type_,connection_,
                                                                    segments_tapped_
                                                                }));

    ctr_event_segments_tapped_ = &Stats::Utility::
                                            counterFromElements(scope_
                                                                ,addPrefix({
                                                                    n8e_,nf_instance_name_,
                                                                    g3p_, vtap_,
                                                                    segment_type_,event_,
                                                                    segments_tapped_
                                                                }));                                                                

    ctr_event_segments_read_tapped_ = &Stats::Utility::
                                            counterFromElements(scope_
                                                                ,addPrefix({
                                                                    n8e_,nf_instance_name_,
                                                                    g3p_, vtap_,
                                                                    event_type_,read_,
                                                                    events_tapped_
                                                                }));

    ctr_event_segments_write_tapped_ = &Stats::Utility::
                                            counterFromElements(scope_
                                                                ,addPrefix({
                                                                    n8e_,nf_instance_name_,
                                                                    g3p_, vtap_,
                                                                    event_type_,write_,
                                                                    events_tapped_
                                                                }));    
    ctr_event_segments_close_tapped_ = &Stats::Utility::
                                            counterFromElements(scope_
                                                                ,addPrefix({
                                                                    n8e_,nf_instance_name_,
                                                                    g3p_, vtap_,
                                                                    event_type_,close_,
                                                                    events_tapped_
                                                                }));                                                                                                                            

    ctr_connection_segment_too_big_ = &Stats::Utility::
                                            counterFromElements(scope_
                                                                ,addPrefix({
                                                                    n8e_,nf_instance_name_,
                                                                    g3p_, vtap_,
                                                                    segment_type_,connection_,
                                                                    segments_too_big_
                                                                }));     

    ctr_event_segment_too_big_ = &Stats::Utility::
                                            counterFromElements(scope_
                                                                ,addPrefix({
                                                                    n8e_,nf_instance_name_,
                                                                    g3p_, vtap_,
                                                                    segment_type_,event_,
                                                                    segments_too_big_
                                                                }));  

//TODO: Add queue length counter when counter implementation in flusher thread is available
    // gauge_queue_len_        =    &Stats::Utility::
    //                                         gaugeFromElements(scope_
    //                                                          ,addPrefix({
    //                                                                 n8e_,nf_instance_name_,
    //                                                                 g3p_, vtap_,
    //                                                                 queue_length_
    //                                                             }), Stats::Gauge::ImportMode::Accumulate)
    //                                                             ;                                                          



};

Stats::ElementVec EricTapStats::addPrefix(const Stats::ElementVec& names) {
  Stats::ElementVec names_with_prefix;
  names_with_prefix.reserve(1 + names.size());
  names_with_prefix.push_back(stats_prefix_);
  names_with_prefix.insert(names_with_prefix.end(), names.begin(), names.end());
  return names_with_prefix;
}






} // namespace Tap
} // namespace Common
} // namespace Extensions
} // namespace Envoy

