#include "source/extensions/access_loggers/common/file_access_log_impl.h"
#include "source/common/stream_info/eric_event_state.h"

namespace Envoy {
namespace Extensions {
namespace AccessLoggers {
namespace File {

FileAccessLog::FileAccessLog(const Filesystem::FilePathAndType& access_log_file_info,
                             AccessLog::FilterPtr&& filter, Formatter::FormatterPtr&& formatter,
                             AccessLog::AccessLogManager& log_manager)
    : ImplBase(std::move(filter)), formatter_(std::move(formatter)) {
  log_file_ = log_manager.createAccessLog(access_log_file_info);
}

void FileAccessLog::emitLog(const Formatter::HttpFormatterContext& context,
                            const StreamInfo::StreamInfo& stream_info) {

  // Events come in a vector in a filter-state object
  const auto& filter_state = stream_info.filterState();
  auto eric_events =
      filter_state.getDataReadOnly<StreamInfo::EricEventState>(StreamInfo::EricEventState::key());
  // If there is no event to log, it's normal access logging
  if (!eric_events) {
    log_file_->write(formatter_->formatWithContext(context, stream_info));
  } else { // We have events -> loop over them and report individually
    for (auto event = eric_events->events().begin(); event != eric_events->events().end();
         event++) {

      log_file_->write(formatter_->formatWithContext(context, stream_info));
      eric_events->processNextEvent();
    }
  }
}

} // namespace File
} // namespace AccessLoggers
} // namespace Extensions
} // namespace Envoy
