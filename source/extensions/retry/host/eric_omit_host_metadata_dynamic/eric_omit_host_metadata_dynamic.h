#pragma once

#include "envoy/upstream/retry.h"
#include "envoy/upstream/upstream.h"
#include "source/common/config/metadata.h"
#include "source/common/config/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace Retry {
namespace Host {
class OmitHostsDynamicRetryPredicate : public Upstream::RetryHostPredicate,
                                       public Logger::Loggable<Logger::Id::upstream> {
public:
  OmitHostsDynamicRetryPredicate() = default;

  bool shouldSelectAnotherHost(const Upstream::Host& host,
                               const std::vector<absl::string_view>&) override {
    return !labelSet_.empty() && Envoy::Config::Metadata::metadataLabelMatch(
                                     labelSet_, host.metadata().get(),
                                     Envoy::Config::MetadataFilters::get().ENVOY_LB, true);
  }
  void onHostAttempted(Upstream::HostDescriptionConstSharedPtr attempted_host) override {
    if (labelSet_.empty()) {
      ENVOY_LOG(debug, "pushing back metadada for host: {}", attempted_host->hostname());
      const ProtobufWkt::Value& val = Envoy::Config::Metadata::metadataValue(
          attempted_host->metadata().get(), Config::MetadataFilters::get().ENVOY_LB, "host");
      labelSet_.push_back({"host", val});
    }
  }

private:
  std::vector<std::pair<std::string, ProtobufWkt::Value>> labelSet_;
};
} // namespace Host
} // namespace Retry
} // namespace Extensions
} // namespace Envoy