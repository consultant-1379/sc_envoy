#pragma once

#include <string>
namespace Envoy {
namespace Extensions {
namespace Common {
namespace Tap {

struct HostPort{
    std::string host;
    std::string port;
};

class EricUtility {
    public:
    static std::string getEnvOr(const std::string& env_name,const std::string& default_val);
    static uint64_t  getEnvOrMin(const std::string& env_name,const uint64_t& default_val);
    static uint64_t  getEnvOrMax(const std::string& env_name,const uint64_t& default_val);
    static HostPort  getHostPortFromUri(const std::string uri);

};


} // namespace Tap
} // namespace Common
} // namespace Extensions
} // namespace Envoy