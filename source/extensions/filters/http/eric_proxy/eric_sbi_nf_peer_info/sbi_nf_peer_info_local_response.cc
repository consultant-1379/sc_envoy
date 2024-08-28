#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_local_response.h"
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info.h"
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_values.h"
#include "source/common/config/metadata.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
void SbiNfPeerInfoHeaderLocalResponse::setSrcInst(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "removing SrcInst for Local Reply");
  SbiNfPeerInfo::deleteSrcInst(headers);
}

void SbiNfPeerInfoHeaderLocalResponse::setSrcServInst(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "removing SrcServInst for Local Reply");
  SbiNfPeerInfo::deleteSrcServInst(headers);
}

void SbiNfPeerInfoHeaderLocalResponse::setSrcScp(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "set SrcScp for Local Reply with value: {}", own_fqdn_);

  if (!own_fqdn_.empty()) {
    SbiNfPeerInfo::setSrcScp(headers, own_fqdn_);
  }
}

void SbiNfPeerInfoHeaderLocalResponse::setSrcSepp(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "set SrcSepp for Local Reply with value: {}", own_fqdn_);

  if (!own_fqdn_.empty()) {
    SbiNfPeerInfo::setSrcSepp(headers, own_fqdn_);
  }
}

void SbiNfPeerInfoHeaderLocalResponse::setDstServInst(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "set DstServInst for Local Reply");

  const auto value = SbiNfPeerInfo::getValueFromVector(original_sbi_request_header_,
                                                       SbiNfPeerInfoHeaders::get().SrcServInst);
  ENVOY_LOG(trace, "value: {}", value.value_or("empty"));
  if (value.has_value()) {
    SbiNfPeerInfo::setDstServInst(headers, std::string(value.value()));
  }
}

void SbiNfPeerInfoHeaderLocalResponse::setDstInst(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "set DstInst for Local Reply");
  const auto value = SbiNfPeerInfo::getValueFromVector(original_sbi_request_header_,
                                                       SbiNfPeerInfoHeaders::get().SrcInst);
  ENVOY_LOG(trace, "value: {}", value.value_or("empty"));
  if (value.has_value()) {
    SbiNfPeerInfo::setDstInst(headers, std::string(value.value()));
  }
}

void SbiNfPeerInfoHeaderLocalResponse::setDstScp(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "set DstScp for Local Reply");
  const auto value = SbiNfPeerInfo::getValueFromVector(original_sbi_request_header_,
                                                       SbiNfPeerInfoHeaders::get().SrcScp);
  ENVOY_LOG(trace, "value: {}", value.value_or("empty"));
  if (value.has_value()) {
    SbiNfPeerInfo::setDstScp(headers, std::string(value.value()));
  } else {
    ENVOY_LOG(trace, "Delete dstScp");
    SbiNfPeerInfo::deleteDstScp(headers);
  }
}

void SbiNfPeerInfoHeaderLocalResponse::setDstSepp(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "setDstSepp for Local Reply");
  const auto value = SbiNfPeerInfo::getValueFromVector(original_sbi_request_header_,
                                                       SbiNfPeerInfoHeaders::get().SrcSepp);

  ENVOY_LOG(trace, "value: {}", value.value_or("empty"));
  if (value.has_value()) {
    SbiNfPeerInfo::setDstSepp(headers, std::string(value.value()));
  } else {
    ENVOY_LOG(trace, "Delete dstSepp");
    SbiNfPeerInfo::deleteDstSepp(headers);
  }
}

void SbiNfPeerInfoHeaderLocalResponse::parseMetaData(
    const envoy::config::core::v3::Metadata* cb_metadata) {
  const auto& sbi_request_meta_or =
      Envoy::Config::Metadata::metadataValue(cb_metadata, SbiMetadataKeys::get().filter,
                                             SbiMetadataKeys::get().original_request_header_path);

  original_sbi_request_header_ = absl::StrSplit(sbi_request_meta_or.string_value(),
                                                absl::ByAnyChar("=; "), absl::SkipWhitespace());
}

SbiNfPeerInfoHeaderLocalResponse::SbiNfPeerInfoHeaderLocalResponse(
    const envoy::config::core::v3::Metadata& cb_metadata) {
  is_activated_ =
      Envoy::Config::Metadata::metadataValue(&cb_metadata, SbiMetadataKeys::get().filter,
                                             SbiMetadataKeys::get().nf_peer_info_handling_is_on)
              .has_bool_value()
          ? Envoy::Config::Metadata::metadataValue(
                &cb_metadata, SbiMetadataKeys::get().filter,
                SbiMetadataKeys::get().nf_peer_info_handling_is_on)
                .bool_value()
          : false;
  if (is_activated_) {
    parseMetaData(&cb_metadata);
  }
}

void SbiNfPeerInfoHeaderLocalResponse::setAll(Http::RequestOrResponseHeaderMap& headers) {
  if (!isActivated()) {
    return;
  }
  ENVOY_LOG(trace, "set all headers for Local Reply");

  setSrcInst(headers);
  setSrcServInst(headers);

  getNodeType() == "scp" ? setSrcScp(headers) : setSrcSepp(headers);

  setDstInst(headers);
  setDstServInst(headers);
  setDstScp(headers);
  setDstSepp(headers);
}

bool SbiNfPeerInfoHeaderLocalResponse::isActivated() { return is_activated_; }

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy