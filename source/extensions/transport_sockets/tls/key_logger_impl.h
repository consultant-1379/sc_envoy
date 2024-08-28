#pragma once

#include "envoy/ssl/context.h"
#include "envoy/access_log/access_log.h"


namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {


class KeyLoggerImpl : public Ssl::KeyLogger, public Logger::Loggable<Logger::Id::key_logger> {
public:
  KeyLoggerImpl(AccessLog::AccessLogManager& log_manager, const char *file_name);

  void logKey(const char* line) override;

private:
  AccessLog::AccessLogFileSharedPtr file_ = nullptr;
};

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy

