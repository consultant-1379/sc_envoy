#pragma once

#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <regex>

#include "contexts.h"
#include "envoy/stats/scope.h"

#include "source/extensions/filters/http/eric_proxy/proxy_filter_config.h"
#include "source/common/http/utility.h"
#include "source/common/http/codes.h"
#include "source/common/stats/symbol_table.h"
#include "source/common/stats/utility.h"
#include "source/common/common/logger.h"
#include "source/common/singleton/const_singleton.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// using this const singleton to have initialized once and have it available for any matching after
class ConstantValues {
public:
  const std::regex PATTERN{"n8e\\.(.+?)\\.", std::regex::optimize};
};

using SpecifierConstants = ConstSingleton<ConstantValues>;
using EricProxyFilterConfigSharedPtr = std::shared_ptr<EricProxyFilterConfig>;

class EricProxyStats : public Logger::Loggable<Logger::Id::eric_proxy> {
public:
  enum class FqdnCase {
    Success = 0,
    Failure = 1,
    DoNothing = 2,
    InvalidFqdn = 3,
    EncryptionIdNotFound = 4,
    IncorrectEncryptionId = 5,
    ForwardedUnmodifiedFqdn = 6,
    ForwardedUnmodifiedIp = 7
  };
  EricProxyStats(EricProxyFilterConfigSharedPtr config, Stats::Scope& scope,
                 const std::string& fetched_prefix);

  Stats::Counter&
  buildScreeningCounter(const std::string& sc_name, const std::string& sr_name,
                        const Stats::StatName& counter_name,
                        Http::StreamDecoderFilterCallbacks* decoder_callbacks = nullptr);
  Stats::Counter& buildRoamingInterfaceCounter(const std::string& sc_name,
                                               const std::string& sr_name);

  Stats::Counter&
  buildSlfFailureCounters(const std::string& next_action_name, const Stats::StatName& counter_name,
                          Http::StreamDecoderFilterCallbacks* decoder_callbacks = nullptr);

  Stats::Counter& buildTHcounters(const std::string& rp_name, const std::string& target_type,
                                  const Stats::StatName& svc_prefix,
                                  const Stats::StatName& req_or_resp,
                                  const Stats::StatName& counter_name);

  Stats::Counter& buildFqdnMappingCounters(
    const std::string& rp_name, const std::string& service, const Stats::StatName& origin,
    const ReqOrResp& req_or_resp, const bool is_mapping, const FqdnCase& fqdn_case
  );

  Stats::Counter& buildFqdnScramblingCounters(
    const std::string& rp_name, const std::string& service, const Stats::StatName& origin,
    const ReqOrResp& req_or_resp, const bool is_mapping, const FqdnCase& fqdn_case,
    const std::string& encryption_id
  );

  virtual ~EricProxyStats() = default;

  Stats::Counter&
  buildEgressScreeningCounter(const std::string& sc_name, const std::string& sr_name,
                              const Stats::StatName& counter_name, const std::string& pool_name,
                              Http::StreamDecoderFilterCallbacks* decoder_callbacks);
  std::string extractNfInstance();

private:
  Stats::ElementVec addPrefix(const Stats::ElementVec& names);
  Stats::StatNameVec addIngressPrefix(const Stats::StatNameVec& names);
  void buildIngressRoamingPartnerCounters();
  void rememberRoamingPartnersForTopologyHiding();
  void rememberServices();
  void rememberEncryptionIds();

  EricProxyFilterConfigSharedPtr config_;
  Stats::Scope& scope_;
  const std::string fetched_prefix_;
  Stats::StatNameSetPtr stat_name_set_;
  const Stats::StatName stats_prefix_;
  const Stats::StatName stats_ingress_prefix_;
  const Stats::StatName s8c3_;
  const Stats::StatName s8r3_;
  const Stats::StatName n8e_;
  const Stats::StatName p2l_;
  const Stats::StatName ctr_drop_message_in_;
  const Stats::StatName ctr_drop_message_out_;
  const Stats::StatName ctr_reject_message_in_;
  const Stats::StatName ctr_reject_message_out_;
  const Stats::StatName ctr_total_invocations_in_req_;
  const Stats::StatName ctr_total_invocations_out_req_;
  const Stats::StatName ctr_total_invocations_in_resp_;
  const Stats::StatName ctr_total_invocations_out_resp_;

  const Stats::StatName ctr_slf_lookup_failure_;
  const Stats::StatName ctr_slf_lookup_identity_missing_;
  const Stats::StatName ctr_slf_lookup_identity_not_found_;
  const Stats::StatName ctr_slf_lookup_destination_unknown_;
  const Stats::StatName ctr_slf_lookup_service_unreachable_;

  const Stats::StatName nf_instance_name_; // in http connection manager config
  // to be implemented: phase 2 routing counters
  // const Stats::StatName ctr_reject_message_routing_;
  // const Stats::StatName ctr_drop_message_routing_;
  const Stats::StatName r12r_;
  const Stats::StatName g3p_;
  const Stats::StatName th_;
  const Stats::StatName t8e_;
  const Stats::StatName t2e_; // type
  const Stats::StatName s5e_; // service
  const Stats::StatName unknown_rp_;
  const Stats::StatName unknown_target_type_;
  const Stats::StatName undefined_service_;
  const Stats::StatName o4n_;
  const Stats::StatName nrf_;
  const Stats::StatName e10d_;
  const Stats::StatName unknown_id_;
  const Stats::StatName nf_management_;
  const Stats::StatName bootstrapping_;

  const Stats::StatName th_fqdn_mapping_req_map_success_total_;
  const Stats::StatName th_fqdn_mapping_req_demap_success_total_;
  const Stats::StatName th_fqdn_mapping_resp_map_success_total_;
  const Stats::StatName th_fqdn_mapping_resp_demap_success_total_;
  const Stats::StatName th_fqdn_mapping_req_forwarded_unmodified_total_;
  const Stats::StatName th_fqdn_mapping_resp_forwarded_unmodified_total_;
  const Stats::StatName th_fqdn_mapping_req_demap_failure_total_;
  const Stats::StatName th_fqdn_mapping_resp_demap_failure_total_;
  const Stats::StatName th_fqdn_mapping_req_map_failure_total_;
  const Stats::StatName th_fqdn_mapping_resp_map_failure_total_;

  const Stats::StatName internal_;
  const Stats::StatName external_;

  const Stats::StatName th_fqdn_scrambling_req_scramble_success_total_;
  const Stats::StatName th_fqdn_scrambling_req_descramble_success_total_;
  const Stats::StatName th_fqdn_scrambling_resp_scramble_success_total_;
  const Stats::StatName th_fqdn_scrambling_resp_descramble_success_total_;
  const Stats::StatName th_fqdn_scrambling_req_forwarded_unmodified_fqdn_total_;
  const Stats::StatName th_fqdn_scrambling_resp_forwarded_unmodified_fqdn_total_;
  const Stats::StatName th_fqdn_scrambling_req_forwarded_unmodified_ip_total_;
  const Stats::StatName th_fqdn_scrambling_resp_forwarded_unmodified_ip_total_;
  const Stats::StatName th_fqdn_scrambling_req_scramble_invalid_fqdn_total_;
  const Stats::StatName th_fqdn_scrambling_req_descramble_invalid_fqdn_total_;
  const Stats::StatName th_fqdn_scrambling_resp_scramble_invalid_fqdn_total_;
  const Stats::StatName th_fqdn_scrambling_resp_descramble_invalid_fqdn_total_;
  const Stats::StatName th_fqdn_scrambling_req_scramble_encryption_id_not_found_total_;
  const Stats::StatName th_fqdn_scrambling_req_descramble_encryption_id_not_found_total_;
  const Stats::StatName th_fqdn_scrambling_resp_scramble_encryption_id_not_found_total_;
  const Stats::StatName th_fqdn_scrambling_resp_descramble_encryption_id_not_found_total_;
  const Stats::StatName th_fqdn_scrambling_req_scramble_incorrect_encryption_id_total_;
  const Stats::StatName th_fqdn_scrambling_req_descramble_incorrect_encryption_id_total_;
  const Stats::StatName th_fqdn_scrambling_resp_scramble_incorrect_encryption_id_total_;
  const Stats::StatName th_fqdn_scrambling_resp_descramble_incorrect_encryption_id_total_;

  const Stats::StatName ip_address_hiding_applied_success_;
  const Stats::StatName ip_address_hiding_fqdn_missing_;
  const Stats::StatName ip_address_hiding_configuration_error_;
  const Stats::StatName th_pseudo_search_result_;
  const Stats::StatName notify_;
  const Stats::StatName nf_discovery_;

  std::unordered_map<std::string, std::optional<Stats::Counter*>> ingress_rp_rq_total_;
  std::unordered_map<std::string, std::optional<Stats::Counter*>> ingress_rp_rq_1xx_;
  std::unordered_map<std::string, std::optional<Stats::Counter*>> ingress_rp_rq_2xx_;
  std::unordered_map<std::string, std::optional<Stats::Counter*>> ingress_rp_rq_3xx_;
  std::unordered_map<std::string, std::optional<Stats::Counter*>> ingress_rp_rq_4xx_;
  std::unordered_map<std::string, std::optional<Stats::Counter*>> ingress_rp_rq_5xx_;


public:
  const Stats::StatName& dropIn() { return ctr_drop_message_in_; }
  const Stats::StatName& dropOut() { return ctr_drop_message_out_; }
  const Stats::StatName& invInReq() { return ctr_total_invocations_in_req_; }
  const Stats::StatName& invOutReq() { return ctr_total_invocations_out_req_; }
  const Stats::StatName& invInResp() { return ctr_total_invocations_in_resp_; }
  const Stats::StatName& invOutResp() { return ctr_total_invocations_out_resp_; }
  const Stats::StatName& rejectIn() { return ctr_reject_message_in_; }
  const Stats::StatName& rejectOut() { return ctr_reject_message_out_; }
  const Stats::StatName& slfLookupFailure() { return ctr_slf_lookup_failure_; }
  const Stats::StatName& slfLookupIdentityMissing() { return ctr_slf_lookup_identity_missing_; }
  const Stats::StatName& slfLookupIdentityNotFound() { return ctr_slf_lookup_identity_not_found_; }
  const Stats::StatName& slfLookupDestinationUnknown() {
    return ctr_slf_lookup_destination_unknown_;
  }
  const Stats::StatName& slfLookupServiceUnreachable() {
    return ctr_slf_lookup_service_unreachable_;
  }

  const Stats::StatName& svcPrefix() { return s5e_; }
  const Stats::StatName& typePrefix() { return t2e_; }
  const Stats::StatName& request() { return notify_; }
  const Stats::StatName& response() { return nf_discovery_; }
  const Stats::StatName& appliedSuccess() { return ip_address_hiding_applied_success_; }
  const Stats::StatName& fqdnMissing() { return ip_address_hiding_fqdn_missing_; }
  const Stats::StatName& configurationError() { return ip_address_hiding_configuration_error_; }
  const Stats::StatName& thPseudoSearchResult() { return th_pseudo_search_result_; }

  // const Stats::StatName& rejectRouting() { return ctr_reject_message_routing_; }
  // const Stats::StatName& dropRouting() { return ctr_drop_message_routing_; }
  void incIngressRpRqXx(std::string rp_name, uint64_t nf_discovery_code);
  void incIngressRpRqTotal(const std::string& rp_name);

  const Stats::StatName& getOrigin(const bool is_origin_int) const noexcept;
};

using EricProxyStatsSharedPtr = std::shared_ptr<EricProxyStats>;

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
