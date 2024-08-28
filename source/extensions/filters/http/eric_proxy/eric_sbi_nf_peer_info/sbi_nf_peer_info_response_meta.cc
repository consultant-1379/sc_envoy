#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_response_meta.h"
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info.h"
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_values.h"
#include "source/common/config/metadata.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

void SbiNfPeerInfoHeaderResponseMetadata::parseMetaData(
    const envoy::config::core::v3::Metadata* cb_metadata) {
  const auto& sbi_request_meta_or =
      Envoy::Config::Metadata::metadataValue(cb_metadata, SbiMetadataKeys::get().filter,
                                             SbiMetadataKeys::get().original_request_header_path);
  const auto& sbi_request_meta_up =
      Envoy::Config::Metadata::metadataValue(cb_metadata, SbiMetadataKeys::get().filter,
                                             SbiMetadataKeys::get().updated_request_header_path);

  original_sbi_request_header_ = absl::StrSplit(sbi_request_meta_or.string_value(),
                                                absl::ByAnyChar("=; "), absl::SkipWhitespace());
  updated_sbi_request_header_ = absl::StrSplit(sbi_request_meta_up.string_value(),
                                               absl::ByAnyChar("=; "), absl::SkipWhitespace());
}
void SbiNfPeerInfoHeaderResponseMetadata::setAll(Http::RequestOrResponseHeaderMap& headers) {
  if (!isActivated()) {
    return;
  }
  ENVOY_LOG(trace, "set all headers for Response");
  setSrcInst(headers);
  setSrcServInst(headers);

  if (getNodeType() == "scp") {
    // When request header is forwarded by SCP(envoy) to SEPP, srcsepp should be removed from the
    // response header
    SbiNfPeerInfo::deleteSrcSepp(headers);
    setSrcScp(headers);
  } else {
    setSrcSepp(headers);
  }

  setDstInst(headers);
  setDstServInst(headers);
  setDstScp(headers);
  setDstSepp(headers);
}
void SbiNfPeerInfoHeaderResponseMetadata::setSrcInst(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "setSrcInst for Response");

  const auto value = SbiNfPeerInfo::getValueFromVector(updated_sbi_request_header_,
                                                       SbiNfPeerInfoHeaders::get().DstInst);
  ENVOY_LOG(trace, "value: {}", value.value_or("empty"));
  if (value.has_value()) {
    SbiNfPeerInfo::setSrcInst(headers, std::string(value.value()));
  }
}

void SbiNfPeerInfoHeaderResponseMetadata::setSrcServInst(
    Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "set SrcServInst for Response");
  const auto value = SbiNfPeerInfo::getValueFromVector(updated_sbi_request_header_,
                                                       SbiNfPeerInfoHeaders::get().DstServInst);
  ENVOY_LOG(trace, "value: {}", value.value_or("empty"));
  if (value.has_value()) {
    Http::HeaderString header_value;
    header_value.setCopy(value.value());
    SbiNfPeerInfo::setSrcServInst(headers, std::string(value.value()));
  }
}

void SbiNfPeerInfoHeaderResponseMetadata::setSrcScp(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "set SrcScp for Response with value: {}", own_fqdn_);

  if (!own_fqdn_.empty()) {
    SbiNfPeerInfo::setSrcScp(headers, own_fqdn_);
  }
}

void SbiNfPeerInfoHeaderResponseMetadata::setSrcSepp(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "set SrcSepp for Response with value: {}", own_fqdn_);

  if (!own_fqdn_.empty()) {
    SbiNfPeerInfo::setSrcSepp(headers, own_fqdn_);
  }
}

void SbiNfPeerInfoHeaderResponseMetadata::setDstInst(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "setDstInst for Response");
  const auto value = SbiNfPeerInfo::getValueFromVector(original_sbi_request_header_,
                                                       SbiNfPeerInfoHeaders::get().SrcInst);
  ENVOY_LOG(trace, "value: {}", value.value_or("empty"));
  if (value.has_value()) {
    SbiNfPeerInfo::setDstInst(headers, std::string(value.value()));
  }
}

void SbiNfPeerInfoHeaderResponseMetadata::setDstServInst(
    Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "setDstServInst for Response");
  const auto value = SbiNfPeerInfo::getValueFromVector(original_sbi_request_header_,
                                                       SbiNfPeerInfoHeaders::get().SrcServInst);
  ENVOY_LOG(trace, "value: {}", value.value_or("empty"));
  if (value.has_value()) {
    SbiNfPeerInfo::setDstServInst(headers, std::string(value.value()));
  }
}
SbiNfPeerInfoHeaderResponseMetadata::SbiNfPeerInfoHeaderResponseMetadata(
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

void SbiNfPeerInfoHeaderResponseMetadata::setDstScp(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "setDstScp for Response");
  const auto value = SbiNfPeerInfo::getValueFromVector(original_sbi_request_header_,
                                                       SbiNfPeerInfoHeaders::get().SrcScp);
  ENVOY_LOG(trace, "value: {}", value.value_or("empty"));
  if (value.has_value()) {
    SbiNfPeerInfo::setDstScp(headers, std::string(value.value()));
  } else {
    ENVOY_LOG(trace, "Delete dstScp");
    removeDstScp(headers);
  }
}

void SbiNfPeerInfoHeaderResponseMetadata::setDstSepp(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "setDstSepp for Response");
  const auto value = SbiNfPeerInfo::getValueFromVector(original_sbi_request_header_,
                                                       SbiNfPeerInfoHeaders::get().SrcSepp);

  ENVOY_LOG(trace, "value: {}", value.value_or("empty"));
  if (value.has_value()) {
    SbiNfPeerInfo::setDstSepp(headers, std::string(value.value()));
  } else {
    ENVOY_LOG(trace, "Delete dstSepp");
    removeDstSepp(headers);
  }
}
void SbiNfPeerInfoHeaderResponseMetadata::removeDstSepp(Http::RequestOrResponseHeaderMap& headers) {
  SbiNfPeerInfo::deleteDstSepp(headers);
}
void SbiNfPeerInfoHeaderResponseMetadata::removeDstScp(Http::RequestOrResponseHeaderMap& headers) {
  SbiNfPeerInfo::deleteDstScp(headers);
}

bool SbiNfPeerInfoHeaderResponseMetadata::isActivated() { return is_activated_; }

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy