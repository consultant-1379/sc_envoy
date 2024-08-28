#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info.h"
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_values.h"

#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "source/common/http/utility.h"
#include <iterator>
#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

absl::optional<absl::string_view>
SbiNfPeerInfo::getValueFromVector(const std::vector<absl::string_view>& vector,
                                  const std::string& key) {
  for (size_t i = 0; i < vector.size(); i += 2) {
    if (vector[i].compare(key) == 0) {
      return vector[i + 1];
    } else {
      continue;
    }
  }
  return absl::nullopt;
}

std::string SbiNfPeerInfo::deleteToken(const absl::string_view header, const std::string& key) {
  std::string new_header;
  for (const auto& s : StringUtil::splitToken(header, ";", false, true)) {
    if (absl::StartsWith(s, key)) {
      continue;
    } else {
      new_header.empty() ? absl::StrAppend(&new_header, s) : absl::StrAppend(&new_header, "; ", s);
    }
  }
  return new_header;
}

void SbiNfPeerInfo::removeHeader(Http::RequestOrResponseHeaderMap& headers,
                                 const std::string& key) {
  const auto old_sbi_header = headers.get(SbiNfPeerInfoHeaders::get().Root);
  if (!old_sbi_header.empty()) {
    std::string new_header = deleteToken(old_sbi_header, key);
    headers.remove(SbiNfPeerInfoHeaders::get().Root);
    setHeader(headers, new_header);
  }
}
void SbiNfPeerInfo::setToken(Http::RequestOrResponseHeaderMap& headers, const std::string& token,
                             const std::string& value) {
  const auto old_sbi_header = headers.get(SbiNfPeerInfoHeaders::get().Root);
  std::string full_value;
  absl::StrAppend(&full_value, token, "=", value);
  if (!old_sbi_header.empty()) {
    std::string new_header = deleteToken(old_sbi_header, token);
    // NB: update header only after deleteToken!
    headers.remove(SbiNfPeerInfoHeaders::get().Root);
    if (new_header.empty()) {
      setHeader(headers, full_value);
    } else {
      absl::StrAppend(&new_header, ";", full_value);
      setHeader(headers, new_header);
    }
  } else {
    setHeader(headers, full_value);
  }
}
void SbiNfPeerInfo::setSrcInst(Http::RequestOrResponseHeaderMap& headers,
                               const std::string& value) {
  setToken(headers, SbiNfPeerInfoHeaders::get().SrcInst, value);
}

void SbiNfPeerInfo::deleteSrcInst(Http::RequestOrResponseHeaderMap& headers) {
  removeHeader(headers, SbiNfPeerInfoHeaders::get().SrcInst);
}
void SbiNfPeerInfo::setSrcServInst(Http::RequestOrResponseHeaderMap& headers,
                                   const std::string& value) {
  setToken(headers, SbiNfPeerInfoHeaders::get().SrcServInst, value);
}

void SbiNfPeerInfo::deleteSrcServInst(Http::RequestOrResponseHeaderMap& headers) {
  removeHeader(headers, SbiNfPeerInfoHeaders::get().SrcServInst);
}
void SbiNfPeerInfo::setSrcScp(Http::RequestOrResponseHeaderMap& headers, const std::string& value) {
  removeHeader(headers, SbiNfPeerInfoHeaders::get().SrcSepp); // remove srcSepp
  if (!absl::StartsWith(absl::AsciiStrToLower(value), "scp-")) {
    setToken(headers, SbiNfPeerInfoHeaders::get().SrcScp, "SCP-" + value);
  } else {
    setToken(headers, SbiNfPeerInfoHeaders::get().SrcScp, value);
  }
}
void SbiNfPeerInfo::setSrcSepp(Http::RequestOrResponseHeaderMap& headers,
                               const std::string& value) {
  removeHeader(headers, SbiNfPeerInfoHeaders::get().SrcScp); // remove srcScp
  if (!absl::StartsWith(absl::AsciiStrToLower(value), "sepp-")) {
    setToken(headers, SbiNfPeerInfoHeaders::get().SrcSepp, "SEPP-" + value);
  } else {
    setToken(headers, SbiNfPeerInfoHeaders::get().SrcSepp, value);
  }
}

void SbiNfPeerInfo::deleteSrcSepp(Http::RequestOrResponseHeaderMap& headers) {
  removeHeader(headers, SbiNfPeerInfoHeaders::get().SrcSepp);
}
void SbiNfPeerInfo::setDstInst(Http::RequestOrResponseHeaderMap& headers,
                               const std::string& value) {
  setToken(headers, SbiNfPeerInfoHeaders::get().DstInst, value);
}
void SbiNfPeerInfo::setDstServInst(Http::RequestOrResponseHeaderMap& headers,
                                   const std::string& value) {
  setToken(headers, SbiNfPeerInfoHeaders::get().DstServInst, value);
}

void SbiNfPeerInfo::deleteDstServInst(Http::RequestOrResponseHeaderMap& headers) {
  removeHeader(headers, SbiNfPeerInfoHeaders::get().DstServInst);
}
void SbiNfPeerInfo::setDstScp(Http::RequestOrResponseHeaderMap& headers, const std::string& value) {
  const auto auth = Http::Utility::parseAuthority(value);
  if (!auth.is_ip_address_) {
    if (!absl::StartsWith(absl::AsciiStrToLower(value), "scp-")) {
      setToken(headers, SbiNfPeerInfoHeaders::get().DstScp, absl::StrCat("SCP-", auth.host_));

    } else {
      setToken(headers, SbiNfPeerInfoHeaders::get().DstScp, std::string(auth.host_));
    }
  } else {
    // ip address
  }
}
void SbiNfPeerInfo::deleteDstScp(Http::RequestOrResponseHeaderMap& headers) {
  removeHeader(headers, SbiNfPeerInfoHeaders::get().DstScp);
}
void SbiNfPeerInfo::setDstSepp(Http::RequestOrResponseHeaderMap& headers,
                               const std::string& value) {
  const auto auth = Http::Utility::parseAuthority(value);
  if (!auth.is_ip_address_) {
    if (!absl::StartsWith(absl::AsciiStrToLower(value), "sepp-")) {
      setToken(headers, SbiNfPeerInfoHeaders::get().DstSepp, absl::StrCat("SEPP-", auth.host_));

    } else {
      setToken(headers, SbiNfPeerInfoHeaders::get().DstSepp, std::string(auth.host_));
    }
  }
}
void SbiNfPeerInfo::deleteDstSepp(Http::RequestOrResponseHeaderMap& headers) {
  removeHeader(headers, SbiNfPeerInfoHeaders::get().DstSepp);
}
void SbiNfPeerInfo::setHeader(Http::RequestOrResponseHeaderMap& headers,
                              Http::HeaderString&& value) {
  if (headers.get(SbiNfPeerInfoHeaders::get().Root).empty()) { // no header
    headers.addViaMove(Http::HeaderString(SbiNfPeerInfoHeaders::get().Root), std::move(value));
  } else {
    headers.addViaMove(Http::HeaderString(SbiNfPeerInfoHeaders::get().Root), std::move(value));
  }
}
void SbiNfPeerInfo::setHeader(Http::RequestOrResponseHeaderMap& headers, const std::string& value) {
  Http::HeaderString header_value;
  header_value.setCopy(value);
  setHeader(headers, std::move(header_value));
}
// uses GetResult ref!, do not update header before!
std::string SbiNfPeerInfo::deleteToken(const Http::HeaderMap::GetResult& old_sbi_header,
                                       const std::string& key) {  
  if (old_sbi_header.empty() || old_sbi_header[0]->value().empty()) {
    return std::string();
  }
  return deleteToken(old_sbi_header[0]->value().getStringView(), key);
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy