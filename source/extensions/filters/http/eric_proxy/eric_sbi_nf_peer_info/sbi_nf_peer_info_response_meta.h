#pragma once
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_int.h"
#include "envoy/config/core/v3/base.pb.h"
#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include <string>
#include "envoy/http/header_map.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
// Process response sbi nf peer info headers
// data is taken from MD
// Needs dynamic metadata
class SbiNfPeerInfoHeaderResponseMetadata : public SbiNfPeerInfoInterface,
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

  //parse md and sets original_sbi_request_header_ and updated_sbi_request_header_ vectors
  void parseMetaData(const envoy::config::core::v3::Metadata* cb_metadata);

  std::string own_fqdn_;
  std::string own_node_type_;
  bool is_activated_ = false;

  std::vector<absl::string_view> original_sbi_request_header_; // original request sbi peer info header
  std::vector<absl::string_view> updated_sbi_request_header_; // updated sbi beer info header after router phase

public:
  void setOwnFqdn(const std::string& own_fqdn) override { own_fqdn_ = own_fqdn; }
  void setAll(Http::RequestOrResponseHeaderMap& headers) override;
  void setNodeType(const std::string& node_type) override { own_node_type_ = node_type; }

  SbiNfPeerInfoHeaderResponseMetadata(const envoy::config::core::v3::Metadata& cb_metadata);

  void removeDstSepp(Http::RequestOrResponseHeaderMap& headers);
  void removeDstScp(Http::RequestOrResponseHeaderMap& headers);
  bool isActivated() override;

  std::string getNodeType() { return own_node_type_; };

  ~SbiNfPeerInfoHeaderResponseMetadata() override = default;
};
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy