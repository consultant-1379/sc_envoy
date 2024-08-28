#pragma once
#include <string>
#include "envoy/access_log/access_log.h"
#include "source/common/common/logger.h"


namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

class AlarmNotifier  : public Logger::Loggable<Logger::Id::eric_proxy> {

    private:
        AccessLog::AccessLogFileSharedPtr file_ = nullptr;

   public:
        AlarmNotifier(const std::string filename, AccessLog::AccessLogManager& access_log_manager);
        ~AlarmNotifier() = default;
        void logAlarmEvent(const std::string & message);

};



} // EricProxy
} // HttpFilters
} // Extensions
} // Envoy