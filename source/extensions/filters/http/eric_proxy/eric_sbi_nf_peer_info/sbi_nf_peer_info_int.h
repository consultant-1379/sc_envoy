#pragma once

#include <string>
#include "envoy/http/header_map.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// Product interface to handle SbiNfPeerInfo headers
// Main idea to set values for each product
class SbiNfPeerInfoInterface {
public:
  // set srcinst header
  virtual void setSrcInst(Http::RequestOrResponseHeaderMap& headers) PURE;
  // set srcservinst header
  virtual void setSrcServInst(Http::RequestOrResponseHeaderMap& headers) PURE;
  // set srcscp header
  virtual void setSrcScp(Http::RequestOrResponseHeaderMap& headers) PURE;
  // set srcsepp header
  virtual void setSrcSepp(Http::RequestOrResponseHeaderMap& headers) PURE;
  // set dstinst header
  virtual void setDstInst(Http::RequestOrResponseHeaderMap& headers) PURE;
  // set dstservinst header
  virtual void setDstServInst(Http::RequestOrResponseHeaderMap& headers) PURE;
  // set dstscp header
  virtual void setDstScp(Http::RequestOrResponseHeaderMap& headers) PURE;
  // set dstsepp header
  virtual void setDstSepp(Http::RequestOrResponseHeaderMap& headers) PURE;
  // is nf peer info header feature activated
  virtual bool isActivated() PURE;
  // set all headers (see headers above).
  // you can set the headers one by one or all together
  virtual void setAll(Http::RequestOrResponseHeaderMap& headers) PURE;

  // save ownfqdn, need this for headers
  virtual void setOwnFqdn(const std::string& own_fqdn) PURE;
  // save node type, scp or sepp
  virtual void setNodeType(const std::string& node_type) PURE;

  virtual ~SbiNfPeerInfoInterface() = default;
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy