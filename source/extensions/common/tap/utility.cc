#include "source/extensions/common/tap/utility.h"
#include <cstdint>
#include <string>

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Tap {


std::string EricUtility::getEnvOr(const std::string& env_name,const std::string& default_val)
{
    auto val = std::getenv(env_name.c_str());
    std::string res;
    if(val != nullptr)
        {
            res = val;
        } else {
            res = default_val;
        }

        return res;
}

uint64_t EricUtility::getEnvOrMin(const std::string& env_name,const uint64_t& default_val)
{
    auto val = std::getenv(env_name.c_str());
    uint64_t res;
        if(val != nullptr)
        {
            auto var = std::stoul(val);
            if(var > default_val)
            {
                res = default_val; 
            } else {
               res = var;
            }
        } else {
            res = default_val;
        }

        return res;
}

uint64_t EricUtility::getEnvOrMax(const std::string& env_name,const uint64_t& default_val)
{
    auto val = std::getenv(env_name.c_str());
    uint64_t res;
        if(val != nullptr)
        {
            auto var = std::stoul(val);
            if(var < default_val)
            {
                res = default_val; 
            } else {
               res = var;
            }
        } else {
            res = default_val;
        }

        return res;
}

HostPort EricUtility::getHostPortFromUri(const std::string uri)
{
    const auto& port_start_pos = uri.find_last_of(std::string(":"));
    HostPort hp;

    if (port_start_pos != std::string::npos) 
    {
        const auto& len = uri.size();
        // If IPv6 sanitize the address without '[xxx]'
        const auto& temp = uri.substr(0,port_start_pos).find_last_of(std::string("]"));
        if( temp != std::string::npos)
        {   //IPv6 address
            hp.host = uri.substr(1,temp-1);
        } else {
            //IPv4 address
            hp.host = uri.substr(0,port_start_pos);
        }
        hp.port = uri.substr(port_start_pos+1,len);
    }
    return hp;
}


} // namespace Tap
} // namespace Common
} // namespace Extensions
} // namespace Envoy