#include "source/extensions/filters/http/eric_proxy/alarm_notifier.h"
# include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {


AlarmNotifier::AlarmNotifier(const std::string file_name,AccessLog::AccessLogManager& log_manager) {
    if (!file_name.empty()) {
        ENVOY_LOG(debug,"Alarm Notification UDS path:'{}'" ,file_name);
        file_ = log_manager.createAccessLog(Filesystem::FilePathAndType{Filesystem::DestinationType::File,
        file_name});
    } else {
         ENVOY_LOG(debug,"Alarm Notifications not enabled");
    }
}

void AlarmNotifier::logAlarmEvent(const std::string& mesg)
{
    if (file_ != nullptr) {
    file_->write(fmt::format("{}\n", mesg));
  }

}

} // EricProxy
} // HttpFilters
} // Extensions
} // Envoy
