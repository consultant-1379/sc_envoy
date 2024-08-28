#pragma once
#include "envoy/upstream/retry.h"
#include "source/extensions/retry/host/eric_loop_prevention/eric_loop_prevention.h"
#include "envoy/extensions/retry/host/eric_loop_prevention/v3/eric_loop_prevention_config.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace Retry {
namespace Host {

class LoopPreventionRetryPredicateFactory : public Upstream::RetryHostPredicateFactory {
public:
  Upstream::RetryHostPredicateSharedPtr createHostPredicate(const Protobuf::Message&,
                                                            uint32_t) override {
    return std::make_shared<LoopPreventionRetryPredicate>();
  }

  std::string name() const override { return "envoy.retry_host_predicates.eric_loop_prevention"; }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<
        envoy::extensions::retry::host::eric_loop_prevention::v3::EricLoopPreventionConfig>();
  }
};

} // namespace Host
} // namespace Retry
} // namespace Extensions
} // namespace Envoy