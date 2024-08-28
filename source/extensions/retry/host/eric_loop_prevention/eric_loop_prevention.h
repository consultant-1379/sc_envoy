#pragma once

#include "envoy/upstream/retry.h"
#include "envoy/upstream/upstream.h"
#include <algorithm>

namespace Envoy {
class LoopPreventionRetryPredicate : public Upstream::RetryHostPredicate {
public:
  bool shouldSelectAnotherHost(const Upstream::Host& candidate_host,
                               const std::vector<absl::string_view>& via_header_hosts) override {
    return std::find_if(via_header_hosts.begin(), via_header_hosts.end(),
                        [&](const absl::string_view via_host) {
                          return candidate_host.hostname() == via_host ||
                                 candidate_host.address()->asStringView() == via_host;
                        }) != via_header_hosts.end();
  }

  void onHostAttempted(Upstream::HostDescriptionConstSharedPtr) override {}
};
} // namespace Envoy