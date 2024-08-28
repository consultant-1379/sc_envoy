#pragma once

namespace Envoy {
namespace Upstream {

class ClusterTrafficPerNfStatsInt {
public:
  virtual ~ClusterTrafficPerNfStatsInt() = default;
  virtual void upstreamRqTotalPerNfInc() const = 0;
  virtual void upstreamRqTimeoutPerNfInc() const = 0;
  virtual void upstreamRqRxResetPerNfInc() const = 0;
  virtual void upstreamRqTxResetPerNfInc() const = 0;
  virtual void upstreamRqPendingFailureEjectPerNfInc() const = 0;
  virtual void upstreamRqAfterRetryPerNfInc() const = 0;
  virtual void upstreamRqAfterReselectPerNfInc() const = 0;
  virtual void upstreamRq1xxPerNfInc() const = 0;
  virtual void upstreamRq2xxPerNfInc() const = 0;
  virtual void upstreamRq3xxPerNfInc() const = 0;
  virtual void upstreamRq4xxPerNfInc() const = 0;
  virtual void upstreamRq5xxPerNfInc() const = 0;
};

} // namespace Upstream
} // namespace Envoy