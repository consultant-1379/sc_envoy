#include "source/extensions/retry/host/eric_loop_prevention/config.h"

#include "envoy/registry/registry.h"
#include "envoy/upstream/retry.h"

namespace Envoy {
namespace Extensions {
namespace Retry {
namespace Host {

REGISTER_FACTORY(LoopPreventionRetryPredicateFactory, Upstream::RetryHostPredicateFactory);

}
} // namespace Retry
} // namespace Extensions
} // namespace Envoy
