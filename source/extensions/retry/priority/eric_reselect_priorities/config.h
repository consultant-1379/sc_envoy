#pragma once
#include "envoy/upstream/retry.h"

#include "source/common/protobuf/protobuf.h"
#include "source/extensions/retry/priority/eric_reselect_priorities/eric_reselect_priorities.h"
#include "envoy/extensions/retry/priority/eric_reselect_priorities/v3/eric_reselect_priorities_config.pb.h"

namespace Envoy {
namespace Extensions {
namespace Retry {
namespace Priority {

class EricReselectPrioritiesFactory : public Upstream::RetryPriorityFactory {
public:
  Upstream::RetryPrioritySharedPtr

  createRetryPriority(const Protobuf::Message& config,
                      ProtobufMessage::ValidationVisitor& validation_visitor,
                      uint32_t max_retries) override;

  std::string name() const override { return "envoy.retry_priorities.eric_reselect_priorities"; }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr(
        new envoy::extensions::retry::priority::eric_reselect_priorities::v3::
            EricReselectPrioritiesConfig());
  }
};

} // namespace Priority
} // namespace Retry
} // namespace Extensions
} // namespace Envoy