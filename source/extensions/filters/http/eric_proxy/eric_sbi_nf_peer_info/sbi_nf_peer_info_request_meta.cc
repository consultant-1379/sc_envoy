#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_request_meta.h"
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info.h"
#include "source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info/sbi_nf_peer_info_values.h"
#include "source/common/config/metadata.h"
#include "source/common/http/header_utility.h"
#include <algorithm>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

void SbiNfPeerInfoHeaderRequestMetadata::setSrcInst(Http::RequestOrResponseHeaderMap& headers) {
  const auto value = SbiNfPeerInfo::getValueFromVector(original_sbi_request_header_,
                                                       SbiNfPeerInfoHeaders::get().SrcInst);
  ENVOY_LOG(trace, "set SrcInst for request with value: {}", value.value_or("empty"));
  if (value.has_value()) {
    SbiNfPeerInfo::setSrcInst(headers, std::string(value.value()));
  }
}
void SbiNfPeerInfoHeaderRequestMetadata::setSrcServInst(Http::RequestOrResponseHeaderMap& headers) {
  const auto value = SbiNfPeerInfo::getValueFromVector(original_sbi_request_header_,
                                                       SbiNfPeerInfoHeaders::get().SrcServInst);
  ENVOY_LOG(trace, "set SrcServInst for request with value: {}", value.value_or("empty"));
  if (value.has_value()) {
    SbiNfPeerInfo::setSrcServInst(headers, std::string(value.value()));
  }
}
// should preserve dstservinst, if dstinst is not updated. Otherwise, dstservinst should be deleted
// from the header
void SbiNfPeerInfoHeaderRequestMetadata::setDstServInst(Http::RequestOrResponseHeaderMap& headers) {
  if (should_preserve_dst_serv_inst_) {
    const auto value = SbiNfPeerInfo::getValueFromVector(original_sbi_request_header_,
                                                         SbiNfPeerInfoHeaders::get().DstServInst);
    ENVOY_LOG(trace, "set DstServInst for request with value: {}", value.value_or("empty"));
    if (value.has_value()) {
      SbiNfPeerInfo::setDstServInst(headers, std::string(value.value()));
    }
  } else {
    ENVOY_LOG(trace, "delete DstServInst for request");
    SbiNfPeerInfo::deleteDstServInst(headers);
  }
}
void SbiNfPeerInfoHeaderRequestMetadata::setAll(Http::RequestOrResponseHeaderMap& headers) {
  if (!isActivated()) {
    return;
  }
  ENVOY_LOG(trace, "Setting Sbi Peer Info Headers for Request");

  ENVOY_LOG(trace, "Nf type: {}", selected_nf_type_.value_or("empty"));
  own_node_type_.value_or("empty") == "scp" ? setSrcScp(headers) : setSrcSepp(headers);

  if (selected_nf_type_ == "scp") {
    setDstScp(headers);
  } else if (selected_nf_type_ == "sepp") {
    setDstSepp(headers);
  } else if (selected_nf_type_ == "nf") {
    ENVOY_LOG(trace, "Removing DstSepp and DstScp");
    removeDstScp(headers);
    removeDstSepp(headers);
  } else {
    ENVOY_LOG(trace, "Probably dynamic forwarding");
    setDstForDynForwarding(headers);
  }
  setDstInst(headers);
  setSrcInst(headers);
  setSrcServInst(headers);
  setDstServInst(headers); // depends on setDstInst
}
// should preserve dstservinst, if dstinst is not updated.
void SbiNfPeerInfoHeaderRequestMetadata::setDstInst(Http::RequestOrResponseHeaderMap& headers) {
  const auto req_dstinst_original = SbiNfPeerInfo::getValueFromVector(
      original_sbi_request_header_, SbiNfPeerInfoHeaders::get().DstInst);
  if (selected_nf_type_ == "nf") {
    ENVOY_LOG(trace, "set DstInst for Request with value: {}", nf_instance_id_.value_or("empty"));
    if (nf_instance_id_.has_value()) {
      should_preserve_dst_serv_inst_ =
          nf_instance_id_.value() == req_dstinst_original.value_or("empty_req_dstinst");
      SbiNfPeerInfo::setDstInst(headers, nf_instance_id_.value());
    }
  } else {
    const auto dst_inst_discovered = SbiNfPeerInfo::getValueFromVector(
        updated_sbi_request_header_, SbiNfPeerInfoHeaders::get().DstInst);
    ENVOY_LOG(trace, "dst_inst_discovered: {}", dst_inst_discovered.value_or("empty"));
    if (dst_inst_discovered.has_value()) {
      ENVOY_LOG(trace, "set DstInst for Request with value: {}",
                dst_inst_discovered.value_or("empty"));
      SbiNfPeerInfo::setDstInst(headers, std::string(dst_inst_discovered.value()));
      should_preserve_dst_serv_inst_ =
          dst_inst_discovered.value() == req_dstinst_original.value_or("empty_req_dstinst");
    } else {
      ENVOY_LOG(trace, "set DstInst for Request with value: {}",
                req_dstinst_original.value_or("empty"));
      if (req_dstinst_original.has_value()) {
        should_preserve_dst_serv_inst_ = true; // DstInst is not updated
        SbiNfPeerInfo::setDstInst(headers, std::string(req_dstinst_original.value()));
      } else {
        should_preserve_dst_serv_inst_ = false; // Have no DstInst
      }
    }
  }
}
void SbiNfPeerInfoHeaderRequestMetadata::setDstSepp(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "setDstSepp for Request with value: {}", selected_fqdn_);

  if (!selected_fqdn_.empty()) {
    SbiNfPeerInfo::setDstSepp(headers, selected_fqdn_);
  }
}
void SbiNfPeerInfoHeaderRequestMetadata::setDstScp(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "setDstScp for Request with value: {}", selected_fqdn_);
  if (!selected_fqdn_.empty()) {
    SbiNfPeerInfo::setDstScp(headers, selected_fqdn_);
  }
}
void SbiNfPeerInfoHeaderRequestMetadata::setSrcScp(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "setSrcScp for Request with value: {}", own_fqdn_.value_or("empty"));
  if (own_fqdn_.has_value()) {
    SbiNfPeerInfo::setSrcScp(headers, own_fqdn_.value());
  }
}
void SbiNfPeerInfoHeaderRequestMetadata::setSrcSepp(Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "setSrcSepp for Request with value: {}", own_fqdn_.value_or("empty"));
  if (own_fqdn_.has_value()) {
    SbiNfPeerInfo::setSrcSepp(headers, own_fqdn_.value());
  }
}
absl::optional<std::string> SbiNfPeerInfoHeaderRequestMetadata::getNodeTypeFromMd(
    const envoy::config::core::v3::Metadata* md) const {
  const auto& value = Envoy::Config::Metadata::metadataValue(md, SbiMetadataKeys::get().filter,
                                                             SbiMetadataKeys::get().node_type_path);
  if (value.kind_case() != ProtobufWkt::Value::kStringValue) {
    ENVOY_LOG(trace, "NodeType is not a string");
    return absl::nullopt;
  } else {
    return absl::AsciiStrToLower(value.string_value());
  }
}
absl::optional<std::string> SbiNfPeerInfoHeaderRequestMetadata::getOwnFqdnFromMd(
    const envoy::config::core::v3::Metadata* md) const {
  const auto& value = Envoy::Config::Metadata::metadataValue(md, SbiMetadataKeys::get().filter,
                                                             SbiMetadataKeys::get().own_fqdn);
  if (value.kind_case() != ProtobufWkt::Value::kStringValue) {
    ENVOY_LOG(trace, "NodeType is not a string");
    return absl::nullopt;
  } else {
    return value.string_value();
  }
}
absl::optional<std::string> SbiNfPeerInfoHeaderRequestMetadata::getSelectedTypeFromHostMetaData(
    const envoy::config::core::v3::Metadata* md) const {
  const auto& value = Envoy::Config::Metadata::metadataValue(
      md, SbiMetadataKeys::get().host_meta_root_, SbiMetadataKeys::get().selected_node_type_path_);

  if (value.kind_case() != ProtobufWkt::Value::kListValue) {
    ENVOY_LOG(trace, "nf_type is not a list");
    return absl::nullopt;
  } else {
    return absl::AsciiStrToLower(value.list_value().values(0).string_value());
  }
}
absl::optional<std::string> SbiNfPeerInfoHeaderRequestMetadata::getNfInstanceIdFromMd(
    const envoy::config::core::v3::Metadata* md) const {
  const auto& value = Envoy::Config::Metadata::metadataValue(
      md, SbiMetadataKeys::get().host_meta_root_, SbiMetadataKeys::get().nf_instance_id_path_);

  if (value.kind_case() != ProtobufWkt::Value::kListValue) {
    ENVOY_LOG(trace, "nf_instance_id is not a list");
    return absl::nullopt;
  } else {
    return value.list_value().values(0).string_value();
  }
}
void SbiNfPeerInfoHeaderRequestMetadata::setSelectedFqdn(const std::string& name) {
  selected_fqdn_ = name;
}
void SbiNfPeerInfoHeaderRequestMetadata::saveUpdatedHeaderInMetadata(
    Http::StreamDecoderFilterCallbacks* cb, const Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "Save updated request header into md");

  try {
    ProtobufWkt::Struct dynMD;
    const auto get_as_string =
        Http::HeaderUtility::getAllOfHeaderAsString(headers, SbiNfPeerInfoHeaders::get().Root, ";");
    if (get_as_string.result()) {
      *(*dynMD.mutable_fields())[SbiMetadataKeys::get().updated_request_header_path]
           .mutable_string_value() = std::string(get_as_string.result().value());
    }
    cb->streamInfo().setDynamicMetadata(SbiMetadataKeys::get().filter, dynMD);
  } catch (std::exception e) {
    // ENVOY_STREAM_LOG(debug, "Error in setting Dyn MD, in namespace:'{}'.", *cb, filter_);
    // ENVOY_STREAM_LOG(debug, "Exception e:'{}'", *cb, e.what());
  }
}
SbiNfPeerInfoHeaderRequestMetadata::SbiNfPeerInfoHeaderRequestMetadata(
    const envoy::config::core::v3::Metadata& cb_metadata,
    std::shared_ptr<const envoy::config::core::v3::Metadata> host_metadata) {

  const bool is_activated_in_md =
      Envoy::Config::Metadata::metadataValue(&cb_metadata, SbiMetadataKeys::get().filter,
                                             SbiMetadataKeys::get().nf_peer_info_handling_is_on)
              .has_bool_value()
          ? Envoy::Config::Metadata::metadataValue(
                &cb_metadata, SbiMetadataKeys::get().filter,
                SbiMetadataKeys::get().nf_peer_info_handling_is_on)
                .bool_value()
          : false;

  const bool is_marked_to_be_deleted =
      Envoy::Config::Metadata::metadataValue(&cb_metadata, SbiMetadataKeys::get().filter,
                                             SbiMetadataKeys::get().request_out_screening_is_on)
              .has_bool_value()
          ? Envoy::Config::Metadata::metadataValue(
                &cb_metadata, SbiMetadataKeys::get().filter,
                SbiMetadataKeys::get().request_out_screening_is_on)
                .bool_value()
          : false;

  is_activated_ = is_activated_in_md & !is_marked_to_be_deleted;

  if (is_activated_) {
    selected_fqdn_ = "";
    selected_nf_type_ = getSelectedTypeFromHostMetaData(host_metadata.get());
    nf_instance_id_ = getNfInstanceIdFromMd(host_metadata.get());
    own_node_type_ = getNodeTypeFromMd(&cb_metadata);
    own_fqdn_ = getOwnFqdnFromMd(&cb_metadata);

    const auto& sbi_request_meta_or =
        Envoy::Config::Metadata::metadataValue(&cb_metadata, SbiMetadataKeys::get().filter,
                                               SbiMetadataKeys::get().original_request_header_path);
    const auto& sbi_request_meta_up =
        Envoy::Config::Metadata::metadataValue(&cb_metadata, SbiMetadataKeys::get().filter,
                                               SbiMetadataKeys::get().updated_request_header_path);

    original_sbi_request_header_ = absl::StrSplit(sbi_request_meta_or.string_value(),
                                                  absl::ByAnyChar("=; "), absl::SkipWhitespace());
    updated_sbi_request_header_ = absl::StrSplit(sbi_request_meta_up.string_value(),
                                                 absl::ByAnyChar("=; "), absl::SkipWhitespace());
  }
}
void SbiNfPeerInfoHeaderRequestMetadata::saveMetaData(
    const std::string& node_type, const std::string& own_fqdn,
    Http::StreamDecoderFilterCallbacks* cb, const Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "saving request metadata");
  try {
    ProtobufWkt::Struct dynMD;
    const auto get_as_string =
        Http::HeaderUtility::getAllOfHeaderAsString(headers, SbiNfPeerInfoHeaders::get().Root, ";");
    ENVOY_LOG(trace, "sbi peer info header: {}", get_as_string.result().value_or("empty"));
    if (get_as_string.result()) {
      *(*dynMD.mutable_fields())[SbiMetadataKeys::get().original_request_header_path]
           .mutable_string_value() = std::string(get_as_string.result().value());
    }
    if (node_type == "scp") {
      *(*dynMD.mutable_fields())[SbiMetadataKeys::get().node_type_path].mutable_string_value() =
          "scp";
    } else if (node_type == "sepp") {
      *(*dynMD.mutable_fields())[SbiMetadataKeys::get().node_type_path].mutable_string_value() =
          "sepp";
    }
    *(*dynMD.mutable_fields())[SbiMetadataKeys::get().own_fqdn].mutable_string_value() = own_fqdn;
    (*dynMD.mutable_fields())[SbiMetadataKeys::get().nf_peer_info_handling_is_on].set_bool_value(
        true);
    (*dynMD.mutable_fields())[SbiMetadataKeys::get().request_out_screening_is_on].set_bool_value(
        false);

    cb->streamInfo().setDynamicMetadata(SbiMetadataKeys::get().filter, dynMD);
  } catch (std::exception e) {
    // ENVOY_STREAM_LOG(debug, "Error in setting Dyn MD, in namespace:'{}'.", *cb, filter_);
    // ENVOY_STREAM_LOG(debug, "Exception e:'{}'", *cb, e.what());
  }
}

void SbiNfPeerInfoHeaderRequestMetadata::updateSbiPeerInfoHeaderInMd(
    Http::StreamDecoderFilterCallbacks* cb, const Http::RequestOrResponseHeaderMap& headers) {
  ENVOY_LOG(trace, "updating request metadata");
  try {
    ProtobufWkt::Struct dynMD;
    const auto get_as_string =
        Http::HeaderUtility::getAllOfHeaderAsString(headers, SbiNfPeerInfoHeaders::get().Root, ";");
    ENVOY_LOG(trace, "sbi peer info header: {}", get_as_string.result().value_or("empty"));

    // delete old metadata
    (*cb->streamInfo().dynamicMetadata().mutable_filter_metadata())[SbiMetadataKeys::get().filter]
        .mutable_fields()
        ->erase(SbiMetadataKeys::get().original_request_header_path);

    if (get_as_string.result()) {
      *(*dynMD.mutable_fields())[SbiMetadataKeys::get().original_request_header_path]
           .mutable_string_value() = std::string(get_as_string.result().value());
      cb->streamInfo().setDynamicMetadata(SbiMetadataKeys::get().filter, dynMD);
    }

  } catch (std::exception e) {
    // ENVOY_STREAM_LOG(debug, "Error in setting Dyn MD, in namespace:'{}'.", *cb, filter_);
    // ENVOY_STREAM_LOG(debug, "Exception e:'{}'", *cb, e.what());
  }
}

void SbiNfPeerInfoHeaderRequestMetadata::updateDstInstInMetadata(
    Http::StreamDecoderFilterCallbacks* cb, const std::string& selected_producer_id) {
  if (selected_producer_id.empty()) {
    ENVOY_LOG(trace, "selected_producer_id is empty");
    return;
  }
  ENVOY_LOG(trace, "Updating Meta with selected DstInst for Request");

  std::string new_meta;
  absl::StrAppend(&new_meta, SbiNfPeerInfoHeaders::get().DstInst, "=", selected_producer_id);
  try {
    ProtobufWkt::Struct dynMD;
    *(*dynMD.mutable_fields())[SbiMetadataKeys::get().updated_request_header_path]
         .mutable_string_value() = std::string(new_meta);
    cb->streamInfo().setDynamicMetadata(SbiMetadataKeys::get().filter, dynMD);
  } catch (std::exception e) {
    // ENVOY_STREAM_LOG(debug, "Error in setting Dyn MD, in namespace:'{}'.", *cb, filter_);
    // ENVOY_STREAM_LOG(debug, "Exception e:'{}'", *cb, e.what());
  }
}

void SbiNfPeerInfoHeaderRequestMetadata::markSbiPeerInfoHeaderForDeletion(
    Http::StreamDecoderFilterCallbacks* cb) {
  ENVOY_LOG(trace, "mark sbi peer info request header for deletion");
  ProtobufWkt::Struct dynMD;
  (*dynMD.mutable_fields())[SbiMetadataKeys::get().request_out_screening_is_on].set_bool_value(
      true);
  cb->streamInfo().setDynamicMetadata(SbiMetadataKeys::get().filter, dynMD);
}
void SbiNfPeerInfoHeaderRequestMetadata::deleteSbiInfoHeader(
    Http::RequestOrResponseHeaderMap& headers) {
  headers.remove(SbiNfPeerInfoHeaders::get().Root);
}
bool SbiNfPeerInfoHeaderRequestMetadata::isActivated() { return is_activated_; }
void SbiNfPeerInfoHeaderRequestMetadata::removeDstScp(Http::RequestOrResponseHeaderMap& headers) {
  SbiNfPeerInfo::deleteDstScp(headers);
}
void SbiNfPeerInfoHeaderRequestMetadata::setDstForDynForwarding(
    Http::RequestOrResponseHeaderMap& headers) {
  if (std::find(original_sbi_request_header_.begin(), original_sbi_request_header_.end(),
                SbiNfPeerInfoHeaders::get().DstScp) != original_sbi_request_header_.end()) {
    ENVOY_LOG(trace, "Found DstScp");
    setDstScp(headers);
  } else if (std::find(original_sbi_request_header_.begin(), original_sbi_request_header_.end(),
                       SbiNfPeerInfoHeaders::get().DstSepp) != original_sbi_request_header_.end()) {
    ENVOY_LOG(trace, "Found DstSepp");
    setDstSepp(headers);
  }
}
void SbiNfPeerInfoHeaderRequestMetadata::removeDstSepp(Http::RequestOrResponseHeaderMap& headers) {
  SbiNfPeerInfo::deleteDstSepp(headers);
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy