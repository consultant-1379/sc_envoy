#include "source/extensions/retry/host/eric_omit_host_metadata_dynamic/config.h"

#include "envoy/registry/registry.h"
#include "envoy/upstream/retry.h"

namespace Envoy {
namespace Extensions {
namespace Retry {
namespace Host {

REGISTER_FACTORY(OmitHostsDynamicRetryPredicateFactory, Upstream::RetryHostPredicateFactory);

}
} // namespace Retry
} // namespace Extensions
} // namespace Envoy
