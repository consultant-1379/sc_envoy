#pragma once

#include <string>
#include "envoy/http/header_map.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// Help class to work with sbi peer info header
class SbiNfPeerInfo {
public:
  static void setSrcInst(Http::RequestOrResponseHeaderMap& headers, const std::string& value);
  static void deleteSrcInst(Http::RequestOrResponseHeaderMap& headers);
  
  static void setSrcServInst(Http::RequestOrResponseHeaderMap& headers, const std::string& value);
  static void deleteSrcServInst(Http::RequestOrResponseHeaderMap& headers);
  
  static void setSrcScp(Http::RequestOrResponseHeaderMap& headers, const std::string& value);

  static void setSrcSepp(Http::RequestOrResponseHeaderMap& headers, const std::string& value);
  static void deleteSrcSepp(Http::RequestOrResponseHeaderMap& headers);

  static void setDstInst(Http::RequestOrResponseHeaderMap& headers, const std::string& value);
  
  static void setDstServInst(Http::RequestOrResponseHeaderMap& headers, const std::string& value);
  static void deleteDstServInst(Http::RequestOrResponseHeaderMap& headers);

  static void setDstScp(Http::RequestOrResponseHeaderMap& headers, const std::string& value);
  static void deleteDstScp(Http::RequestOrResponseHeaderMap& headers);
  static void setDstSepp(Http::RequestOrResponseHeaderMap& headers, const std::string& value);
  static void deleteDstSepp(Http::RequestOrResponseHeaderMap& headers); 

  static absl::optional<absl::string_view>
  getValueFromVector(const std::vector<absl::string_view>& vector, const std::string& key);

  static std::string deleteToken(const absl::string_view header, const std::string& key);

private:
  static void removeHeader(Http::RequestOrResponseHeaderMap& headers,
                           const std::string& key);
  static std::string deleteToken(const Http::HeaderMap::GetResult& old_sbi_header,
                                 const std::string& key);
  static void setHeader(Http::RequestOrResponseHeaderMap& headers, Http::HeaderString&& value);
  static void setToken(Http::RequestOrResponseHeaderMap& headers, const std::string& token,
                       const std::string& value);
  static void setHeader(Http::RequestOrResponseHeaderMap& headers, const std::string& value);
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy