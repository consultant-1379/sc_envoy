#include "source/common/router/router.h"
#include "source/extensions/filters/http/eric_proxy/filter.h"

namespace Envoy {
namespace Router {

void TarList::setTarValuesFromMd(
    const ::google::protobuf::Map<std::string, ::google::protobuf::Struct>* cb_filter_md) {
  ENVOY_STREAM_LOG(trace, "setTarValuesFromMd()", *callbacks_);
  if (!Extensions::HttpFilters::EricProxy::EricProxyFilter::findInDynMetadata(
          cb_filter_md, "eric_proxy", "target-api-root-values"))
    return;

  auto target_api_root_values = cb_filter_md->find("eric_proxy")
                                    ->second.fields()
                                    .find("target-api-root-values")
                                    ->second.list_value();
  for (auto tar_value : target_api_root_values.values()) {
    ENVOY_STREAM_LOG(trace, "read 3gpp-Sbi-target-apiRoot value={} from dyn.MD", *callbacks_,
                     tar_value.string_value());
    tar_api_root_values_.push_back(tar_value.string_value());
  }
}

// get the next TaR value for remote-round-robin (eedrak) and update the index to the next value
std::string TarList::getNextTarValue() {
  ENVOY_STREAM_LOG(trace, "getNextTarValue()", *callbacks_);
  if (tar_api_root_values_.size() == 0)
    return "";

  if (current_tar_api_root_values_idx_ >= tar_api_root_values_.size()) {
    current_tar_api_root_values_idx_ = 0;
  }
  current_tar_api_root_values_idx_++;
  return tar_api_root_values_[current_tar_api_root_values_idx_ - 1];
}

//--------------------------------------------------------
// eric-proxy methods declared in /source/common/router.h
//--------------------------------------------------------

void Filter::saveDiscoveryHeadersToBePreserved(
    const ::google::protobuf::Map<std::string, ::google::protobuf::Struct>* cb_filter_md) {
  ENVOY_STREAM_LOG(trace, "saveDiscoveryHeadersToBePreserved()", *callbacks_);

  if ((!Extensions::HttpFilters::EricProxy::EricProxyFilter::findInDynMetadata(
          cb_filter_md, "eric_proxy", "disc-parameters-to-be-preserved-if-indirect")) &&
      (!Extensions::HttpFilters::EricProxy::EricProxyFilter::findInDynMetadata(
          cb_filter_md, "eric_proxy", "preserve-all-disc-parameters-if-indirect"))) {
    ENVOY_STREAM_LOG(trace, "no dyn. MD indication to preserve disc-parameters any", *callbacks_);
    return;
  }

  /**
  /  save headernames and values  to be preserved in a map
  /  only received headers will be considered
  **/
  if (Extensions::HttpFilters::EricProxy::EricProxyFilter::findInDynMetadata(
          cb_filter_md, "eric_proxy", "disc-parameters-to-be-preserved-if-indirect")) {
    auto disc_params_to_preserved = cb_filter_md->find("eric_proxy")
                                        ->second.fields()
                                        .find("disc-parameters-to-be-preserved-if-indirect")
                                        ->second.list_value();

    for (auto& disc_param : disc_params_to_preserved.values()) {
      // prefix the disc-param with "3gpp-Sbi-Discovery-"
      const auto& disc_param_header = absl::StrCat("3gpp-Sbi-Discovery-", disc_param.string_value());
      if (!downstream_headers_->get(Http::LowerCaseString(disc_param_header)).empty()) {
        auto header_to_be_preserved =
            downstream_headers_->get(Http::LowerCaseString(disc_param_header));
        preserved_disc_headers_->addCopy(Http::LowerCaseString(disc_param_header),
                                         header_to_be_preserved[0]->value().getStringView());
        ENVOY_STREAM_LOG(trace, "stored disc_param_header ='{}' from dyn.MD", *callbacks_,
                         disc_param_header);
      }
    }
    ENVOY_STREAM_LOG(trace, "removing disc headers not to be preserved", *callbacks_);
    downstream_headers_->removeIf([&](const Http::HeaderEntry& header) -> bool {
      auto header_name = Http::LowerCaseString(header.key().getStringView());
      if (!isDiscoveryHeader(header)) {
        return false;
      }
      if (preserved_disc_headers_->get(header_name).empty()) {
        ENVOY_STREAM_LOG(trace, "removing disc header '{}'", *callbacks_, header_name);
        return true;
      }
      return false;
    });
    // Store all received discovery headers
  } else if (Extensions::HttpFilters::EricProxy::EricProxyFilter::findInDynMetadata(
                 cb_filter_md, "eric_proxy", "preserve-all-disc-parameters-if-indirect")) {
    downstream_headers_->iterate([&](const Http::HeaderEntry& header) -> Http::HeaderMap::Iterate {
      if (isDiscoveryHeader(header)) {
        preserved_disc_headers_->addCopy(Http::LowerCaseString(header.key().getStringView()),
                                         header.value().getStringView());
      }
      return Http::HeaderMap::Iterate::Continue;
    });
  }
  are_discovery_headers_preserved_ = true;
}

/**
/ restore (preserve) dicovery headers previously stored in preserved_disc_headers_
**/
void Filter::preserveDiscoveryHeaders(
    const ::google::protobuf::Map<std::string, ::google::protobuf::Struct>* cb_filter_md) {
  ENVOY_STREAM_LOG(trace, "preserveDiscoveryHeaders()", *callbacks_);
  if ((!Extensions::HttpFilters::EricProxy::EricProxyFilter::findInDynMetadata(
          cb_filter_md, "eric_proxy", "disc-parameters-to-be-preserved-if-indirect")) &&
      (!Extensions::HttpFilters::EricProxy::EricProxyFilter::findInDynMetadata(
          cb_filter_md, "eric_proxy", "preserve-all-disc-parameters-if-indirect"))) {
    ENVOY_STREAM_LOG(trace, "no dyn. MD indication to preserve disc-parameters any", *callbacks_);
    return;
  }
  if (!are_discovery_headers_preserved_) {
    preserved_disc_headers_->iterate([&](const Http::HeaderEntry& header)
                                         -> Http::HeaderMap::Iterate {
      if (downstream_headers_->get(Http::LowerCaseString(header.key().getStringView())).empty()) {
        downstream_headers_->setCopy(Http::LowerCaseString(header.key().getStringView()),
                                     header.value().getStringView());
      }
      return Http::HeaderMap::Iterate::Continue;
    });
  }
  are_discovery_headers_preserved_ = true;
}

// remove all discovery headers from downstream_headers_
void Filter::removeAllDiscoveryHeaders() {
  ENVOY_STREAM_LOG(trace, "removeAllDiscoveryHeaders()", *callbacks_);
  downstream_headers_->removeIf(
      [&](const Http::HeaderEntry& header) -> bool { return isDiscoveryHeader(header); });
  are_discovery_headers_preserved_ = false;
}

bool Filter::isDiscoveryHeader(const Http::HeaderEntry& header) {
  return absl::StartsWith(Http::LowerCaseString(header.key().getStringView()),
                          Http::LowerCaseString("3gpp-Sbi-Discovery-"));
}

} // namespace Router
} // namespace Envoy
