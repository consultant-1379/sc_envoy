#pragma once
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_int.h"
#include "envoy/config/core/v3/base.pb.h"
#include <string>
#include "envoy/http/header_map.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// sets sbi peer info header for local responses
// all values are recovered from Metadata
class SbiNfPeerInfoHeaderLocalResponse : public SbiNfPeerInfoInterface,
                                         public Logger::Loggable<Logger::Id::eric_proxy> {
private:
  void setSrcInst(Http::RequestOrResponseHeaderMap& headers) override;
  void setSrcServInst(Http::RequestOrResponseHeaderMap& headers) override;
  void setSrcScp(Http::RequestOrResponseHeaderMap& headers) override;
  void setSrcSepp(Http::RequestOrResponseHeaderMap& headers) override;
  void setDstServInst(Http::RequestOrResponseHeaderMap& headers) override;
  void setDstInst(Http::RequestOrResponseHeaderMap& headers) override;
  void setDstScp(Http::RequestOrResponseHeaderMap& headers) override;
  void setDstSepp(Http::RequestOrResponseHeaderMap& headers) override;

  // restore original sbi peer info header and save it as original_sbi_request_header_ vector
  // called in constructor
  void parseMetaData(const envoy::config::core::v3::Metadata* cb_metadata);

  std::string own_fqdn_;
  std::string own_node_type_; // sepp or scp
  bool is_activated_ = false;

  std::vector<absl::string_view>
      original_sbi_request_header_; // original sbi peer info header saved in md from request

public:
  SbiNfPeerInfoHeaderLocalResponse(const envoy::config::core::v3::Metadata& cb_metadata);
  void setOwnFqdn(const std::string& own_fqdn) override { own_fqdn_ = own_fqdn; }
  void setAll(Http::RequestOrResponseHeaderMap& headers) override;
  void setNodeType(const std::string& node_type) override { own_node_type_ = node_type; }

  bool isActivated() override;

  std::string getNodeType() { return own_node_type_; };

  ~SbiNfPeerInfoHeaderLocalResponse() override = default;
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy