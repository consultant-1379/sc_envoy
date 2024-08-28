#pragma once

#include "envoy/upstream/retry.h"
#include "source/extensions/retry/host/eric_omit_host_metadata_dynamic/eric_omit_host_metadata_dynamic.h"
#include "envoy/extensions/retry/host/eric_omit_host_metadata_dynamic/v3/eric_omit_host_metadata_dynamic_config.pb.validate.h"
#include "envoy/extensions/retry/host/eric_omit_host_metadata_dynamic/v3/eric_omit_host_metadata_dynamic_config.pb.h"

namespace Envoy {
namespace Extensions {
namespace Retry {
namespace Host {

class OmitHostsDynamicRetryPredicateFactory : public Upstream::RetryHostPredicateFactory {
public:
  Upstream::RetryHostPredicateSharedPtr createHostPredicate(const Protobuf::Message&,
                                                            uint32_t) override {
    return std::make_shared<OmitHostsDynamicRetryPredicate>();
  }

  std::string name() const override {
    return "envoy.retry_host_predicates.eric_omit_host_metadata_dynamic";
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<envoy::extensions::retry::host::eric_omit_host_metadata_dynamic::v3::
                                OmitHostDynamicMetadataConfig>();
  }
};

} // namespace Host
} // namespace Retry
} // namespace Extensions
} // namespace Envoy
