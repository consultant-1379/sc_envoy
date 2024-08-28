#pragma once
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_int.h"
#include "envoy/config/core/v3/base.pb.h"
#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include <string>
#include "envoy/http/header_map.h"
#include "envoy/http/filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// Process request sbi nf peer info headers
// data is taken from metadata
// Needs host and dynamic metadata
class SbiNfPeerInfoHeaderRequestMetadata : public SbiNfPeerInfoInterface,
                                           public Logger::Loggable<Logger::Id::eric_proxy> {
private:
  std::vector<absl::string_view>
      original_sbi_request_header_; // original sbi peer info header extracted from request
  // in some use cases we modify request header, save modified header after router phase
  std::vector<absl::string_view> updated_sbi_request_header_;

  std::string selected_fqdn_;
  absl::optional<std::string> selected_nf_type_; // scp or sepp
  absl::optional<std::string> nf_instance_id_;
  absl::optional<std::string> own_node_type_;
  absl::optional<std::string> own_fqdn_;
  bool is_activated_;
  bool should_preserve_dst_serv_inst_ = false; // preserve or delete dstservinst header

  void setSrcInst(Http::RequestOrResponseHeaderMap& headers) override;
  void setSrcServInst(Http::RequestOrResponseHeaderMap& headers) override;
  void setSrcScp(Http::RequestOrResponseHeaderMap& headers) override;
  void setSrcSepp(Http::RequestOrResponseHeaderMap& headers) override;
  void setDstServInst(Http::RequestOrResponseHeaderMap& headers) override;
  void setDstInst(Http::RequestOrResponseHeaderMap& headers) override;
  void setDstScp(Http::RequestOrResponseHeaderMap& headers) override;
  void setDstSepp(Http::RequestOrResponseHeaderMap& headers) override;

  void removeDstSepp(Http::RequestOrResponseHeaderMap& headers);
  void removeDstScp(Http::RequestOrResponseHeaderMap& headers);
  void setDstForDynForwarding(Http::RequestOrResponseHeaderMap& headers);

  // help functions to extract from md
  absl::optional<std::string>
  getNodeTypeFromMd(const envoy::config::core::v3::Metadata* md) const; // extract node type from md
  absl::optional<std::string>
  getOwnFqdnFromMd(const envoy::config::core::v3::Metadata* md) const; // extract own fwdn from md
  absl::optional<std::string> getSelectedTypeFromHostMetaData(
      const envoy::config::core::v3::Metadata* md) const; // extract selected type from md
  absl::optional<std::string> getNfInstanceIdFromMd(
      const envoy::config::core::v3::Metadata* md) const; // get nf instance id from md
public:
  SbiNfPeerInfoHeaderRequestMetadata(
      const envoy::config::core::v3::Metadata& cb_metadata,
      std::shared_ptr<const envoy::config::core::v3::Metadata> host_metadata);
  // save original sbi peer info header and node data into metadata
  static void saveMetaData(const std::string& node_type, const std::string& own_fqdn,
                           Http::StreamDecoderFilterCallbacks* cb,
                           const Http::RequestOrResponseHeaderMap& headers);
  // removes old original_request_header in metadata and saves a new one
  static void updateSbiPeerInfoHeaderInMd(Http::StreamDecoderFilterCallbacks* cb,
                                          const Http::RequestOrResponseHeaderMap& headers);
  // update dstinst in md
  static void updateDstInstInMetadata(Http::StreamDecoderFilterCallbacks* cb,
                                      const std::string& selected_producer_id);
  // for action remove header in filter, if we want to delete sbi peer info request header
  // the problem that the header is set in router
  static void markSbiPeerInfoHeaderForDeletion(Http::StreamDecoderFilterCallbacks* cb);
  // delete sbi peer info header directly
  static void deleteSbiInfoHeader(Http::RequestOrResponseHeaderMap& headers);
  // save sbi peer info header into md(updated_request_header_path)
  void saveUpdatedHeaderInMetadata(Http::StreamDecoderFilterCallbacks* cb,
                                   const Http::RequestOrResponseHeaderMap& headers);

  void setAll(Http::RequestOrResponseHeaderMap& headers) override;
  void setSelectedFqdn(const std::string& fqdn);
  void setOwnFqdn(const std::string& own_fqdn) override { own_fqdn_ = own_fqdn; }
  void setNodeType(const std::string& node_type) override { own_node_type_ = node_type; }

  bool isActivated() override;

  ~SbiNfPeerInfoHeaderRequestMetadata() override = default;
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy