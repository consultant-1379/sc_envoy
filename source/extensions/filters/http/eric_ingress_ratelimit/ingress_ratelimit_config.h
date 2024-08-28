#pragma once

#include <map>
#include <string>
#include "envoy/extensions/filters/http/eric_ingress_ratelimit/v3/eric_ingress_ratelimit.pb.h"
#include "source/common/common/logger.h"
#include "envoy/upstream/cluster_manager.h"
#include "re2/re2.h"
#include "source/common/http/message_impl.h"



namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IngressRateLimitFilter {

using MapValue = envoy::extensions::filters::http::eric_ingress_ratelimit::v3::MapEntry;
using Namespace = ::envoy::extensions::filters::http::eric_ingress_ratelimit::v3::Namespace;
using RetryAfterFormat = ::envoy::extensions::filters::http::eric_ingress_ratelimit::v3::RetryAfterHeaderFormat;
using MapProto = google::protobuf::Map<std::string,MapValue>;
using ActionProfile = envoy::extensions::filters::http::eric_ingress_ratelimit::v3::ActionProfile;
using BucketActionPair = envoy::extensions::filters::http::eric_ingress_ratelimit::v3::BucketActionPair;

/**
 * Global configuration for the HTTP rate limit filter.
 */

class EricIngressRateLimitConfig : public Logger::Loggable<Logger::Id::eric_ingress_ratelimit> {
public:
  EricIngressRateLimitConfig(const envoy::extensions::filters::http::eric_ingress_ratelimit::v3::IngressRateLimit& proto_config, Upstream::ClusterManager& cluster_manager);

  //const std::string& name() const { return proto_config_.name(); }
   ::envoy::extensions::filters::http::eric_ingress_ratelimit::v3::Namespace myNs() {return proto_config_.namespace_();}
  const std::string nameSpace() const { return (proto_config_.namespace_() == Namespace::SCP)? "scp": "sepp" ;}
  const std::string& clusterName() const {return proto_config_.rate_limit_service().service_cluster_name(); }
  const ActionProfile& rlfServiceUnreachableAction() const {return proto_config_.rate_limit_service().service_error_action(); }
  //const ActionProfile& rpNotFoundAction() const {return proto_config_.rate_limit_service().service_unreachable_action(); }
  Upstream::ClusterManager& clusterManager() const { return cluster_manager_;  }

  const google::protobuf::RepeatedPtrField<::envoy::extensions::filters::http::eric_ingress_ratelimit::v3::RateLimit>& limits()  const { return proto_config_.limits(); }
  std::map<std::string, BucketActionPair>& getRpBucketActionTable()  {return rp_bucket_action_pair_table_;}
  std::map<std::string, std::string>& getDnToRpTable()  {return dn_to_rp_table_;}
  std::map<const std::string, const  RE2>& getDnToRegexTable()  {return dn_to_re2_regex_table_;}
  absl::string_view getRlfServicePathHeader() {return rlf_service_path_header_;}; 
  absl::string_view getNetworkName() {return network_name_;}; 

  std::optional<const BucketActionPair> fetchBucketActionPairFromTable(const MapValue&);
 
private:
  std::string network_name_;
  std::string rlf_service_path_header_;
  const envoy::extensions::filters::http::eric_ingress_ratelimit::v3::IngressRateLimit proto_config_;
  Upstream::ClusterManager& cluster_manager_;
  void precompileRegexforDn(const std::string);
  std::map<std::string, std::string> dn_to_rp_table_;
  std::map<std::string, BucketActionPair> rp_bucket_action_pair_table_;

  std::map<const std::string,  const RE2> dn_to_re2_regex_table_;



};


} // namespace IngressRateLimitFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy