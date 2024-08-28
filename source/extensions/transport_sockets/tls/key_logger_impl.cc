#include "source/extensions/transport_sockets/tls/key_logger_impl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

KeyLoggerImpl::KeyLoggerImpl(AccessLog::AccessLogManager& log_manager, const char *file_name) {
  if (file_name != NULL) {
    ENVOY_LOG(info, "Logging SSL keys to {}", file_name);
    file_ = log_manager.createAccessLog(Filesystem::FilePathAndType{Filesystem::DestinationType::File,
     file_name});
  } else {
    ENVOY_LOG(info, "Not logging SSL keys");
  }
}

void KeyLoggerImpl::logKey(const char* line) {
  if (file_ != nullptr) {
    file_->write(fmt::format("{}\n", line));
  }
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
