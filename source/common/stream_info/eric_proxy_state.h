#pragma once

#include "envoy/stream_info/filter_state.h"

#include "absl/container/flat_hash_set.h"
#include <string>

// TODO(enaidev,echaias)
// maybe consider having a extensions/../eric_proxy/stream_info folder
// and having our eric_proxy_state file moved there 


namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
class RunContext;
} } } }

namespace Envoy {
namespace StreamInfo {

using EricRunContextPtr = Extensions::HttpFilters::EricProxy::RunContext*;
/*
 * A FilterState object to be used for string data shared by eric_proxy with the router.
 */
class EricProxyState : public FilterState::Object {
public:
  static const std::string& key() {
    CONSTRUCT_ON_FIRST_USE(std::string, "envoy.eric_proxy.eric_proxy_state");
  }

  enum StringValues { InterplmnFqdn, NUM_VALS };

  void setStrValueForKey(StringValues key, const std::string& val) { string_vals_.at(key) = val; }

  void setStrValueForKey(StringValues key, const std::string&& val) {
    string_vals_.at(key) = std::move(val);
  }

  const std::string& getStrValueForKey(StringValues key) const { return string_vals_.at(key); }


  void setEricRunContextPtr(EricRunContextPtr run_ctx_ptr){
    run_ctx_ = run_ctx_ptr;
  }

  EricRunContextPtr getEricRunContextPtr() const {
    return run_ctx_;
  }

private:
  std::array<std::string, (StringValues::NUM_VALS)> string_vals_; 
  EricRunContextPtr run_ctx_ ;
};

class EricProxySeppState: public FilterState::Object {
public:

  static const std::string& key() {
    CONSTRUCT_ON_FIRST_USE(std::string,"envoy.eric_proxy.sepp_routing_state");
  }
  
  enum RoutingDirection {
    ExtToInt = 0,
    IntToExt = 1,
  };

  void setOriginalBody(const std::string&& body) { 
    tfqdn_original_body_ = body ; 
    tfqdn_original_body_len_ =  tfqdn_original_body_.length();
  }

  void setModifiedBody(const std::string&& body) { 
    tfqdn_modified_body_ = body ; 
    tfqdn_modified_body_len_ = tfqdn_modified_body_.length();
  }

   std::string& getOriginalBody() {
    return tfqdn_original_body_;
  }

   std::string& getModifiedBody() {
    return tfqdn_modified_body_;
  }

  void setIsReqHttps(bool is_https){
    is_req_https_ = is_https;
  }

  bool isReqHttps()  {
    return is_req_https_;
  }


  void setIsTfqdnRequest(bool needs_tfqdn){
    is_tfqdn_request_ = needs_tfqdn;
  }

  bool isTfqdnRequest()  {
    return is_tfqdn_request_;
  }

  void setBodyModifiedForTqfdnFlag(bool is_modified) { 
    tfqdn_body_was_replaced_ = is_modified; 
  }

  bool wasBodyModifiedForTfqdn() {
    return tfqdn_body_was_replaced_;
  }

  void setNfTypeRequiresTfqdn(bool needs_tfqdn){
    nf_type_requires_tfqdn_ = needs_tfqdn;
  }

  bool doesNfTypeRequireTfqdn()  {
    return nf_type_requires_tfqdn_;
  }

  void setRoutingDirection(RoutingDirection direction){
    routing_direction_ = direction;
  }

  RoutingDirection getRoutingDirection()  {
    return routing_direction_;
  }


   uint64_t& getOriginalBodyLen() {
    return tfqdn_original_body_len_;
  }

   uint64_t& getModifiedBodyLen()  {
    return tfqdn_modified_body_len_;
  } 


private:
  std::string tfqdn_original_body_;
  std::string tfqdn_modified_body_;
  // TODO(enaidev) : Consider moving it to common state once we have multi-vpn support in SCP
  enum RoutingDirection routing_direction_ ;
  bool is_req_https_{false};
  bool is_tfqdn_request_{false};
  bool tfqdn_body_was_replaced_ {false};
  bool nf_type_requires_tfqdn_ {false};
  uint64_t tfqdn_original_body_len_;
  uint64_t tfqdn_modified_body_len_;

};

} // namespace StreamInfo
} // namespace Envoy
