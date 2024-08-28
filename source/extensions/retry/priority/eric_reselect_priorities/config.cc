#include "source/extensions/retry/priority/eric_reselect_priorities/config.h"

#include "envoy/extensions/retry/priority/eric_reselect_priorities/v3/eric_reselect_priorities_config.pb.h"
#include "envoy/extensions/retry/priority/eric_reselect_priorities/v3/eric_reselect_priorities_config.pb.validate.h"

#include "envoy/registry/registry.h"
#include "envoy/upstream/retry.h"

namespace Envoy {
namespace Extensions {
namespace Retry {
namespace Priority {

Upstream::RetryPrioritySharedPtr EricReselectPrioritiesFactory::createRetryPriority(
    const Protobuf::Message& config, ProtobufMessage::ValidationVisitor& validation_visitor,

    uint32_t max_retries) {
  auto proto_config = MessageUtil::downcastAndValidate<
      const envoy::extensions::retry::priority::eric_reselect_priorities::v3::
          EricReselectPrioritiesConfig&>(config, validation_visitor);

  return std::make_shared<EricReselectRetryPriority>(
      proto_config.preferred_host_retries(), proto_config.failover_reselects(),
      proto_config.last_resort_reselects(), proto_config.support_temporary_blocking(),
      proto_config.support_loop_prevention(), max_retries);
}

REGISTER_FACTORY(EricReselectPrioritiesFactory, Upstream::RetryPriorityFactory);

} // namespace Priority
} // namespace Retry
} // namespace Extensions
} // namespace Envoy
