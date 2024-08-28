#pragma once

#include "envoy/common/time.h"
#include "envoy/ssl/context_manager.h"

namespace Envoy {
namespace Server {

Ssl::ContextManagerPtr createContextManager(const std::string& factory_name,
                                            TimeSource& time_source,
                                            AccessLog::AccessLogManager& access_log_manager);

} // namespace Server
} // namespace Envoy
