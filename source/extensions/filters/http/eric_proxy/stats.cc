#include "source/extensions/filters/http/eric_proxy/stats.h"

#include <memory>
#include <optional>
#include <string>

#include "envoy/stats/scope.h"
#include "absl/strings/str_replace.h"
#include "source/common/stats/symbol_table.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

EricProxyStats::EricProxyStats(EricProxyFilterConfigSharedPtr config, Stats::Scope& scope,
                               const std::string& fetched_prefix)
    : config_(config), scope_(scope), fetched_prefix_(fetched_prefix),
      stat_name_set_(scope.symbolTable().makeSet("EricProxy")),
      stats_prefix_(stat_name_set_->add(absl::string_view("http.eric_proxy"))),
      stats_ingress_prefix_(stat_name_set_->add(absl::string_view("http.ingress"))),
      s8c3_(stat_name_set_->add(absl::string_view("s8c3"))),
      s8r3_(stat_name_set_->add(absl::string_view("s8r3"))),
      n8e_(stat_name_set_->add(absl::string_view("n8e"))),
      p2l_(stat_name_set_->add(absl::string_view("p2l"))),
      ctr_drop_message_in_(stat_name_set_->add("ms_drop_message_in_req_total")),
      ctr_drop_message_out_(stat_name_set_->add("ms_drop_message_out_req_total")),
      ctr_reject_message_in_(stat_name_set_->add("ms_reject_message_in_req_total")),
      ctr_reject_message_out_(stat_name_set_->add("ms_reject_message_out_req_total")),
      ctr_total_invocations_in_req_(stat_name_set_->add("ms_invocations_in_req_total")),
      ctr_total_invocations_out_req_(stat_name_set_->add("ms_invocations_out_req_total")),
      ctr_total_invocations_in_resp_(stat_name_set_->add("ms_invocations_in_resp_total")),
      ctr_total_invocations_out_resp_(stat_name_set_->add("ms_invocations_out_resp_total")),
      ctr_slf_lookup_failure_(stat_name_set_->add("slf_lookup_lookup_failure")),
      ctr_slf_lookup_identity_missing_(stat_name_set_->add("slf_lookup_identity_missing")),
      ctr_slf_lookup_identity_not_found_(stat_name_set_->add("slf_lookup_identity_not_found")),
      ctr_slf_lookup_destination_unknown_(stat_name_set_->add("slf_lookup_destination_unknown")),
      ctr_slf_lookup_service_unreachable_(stat_name_set_->add("slf_lookup_service_unreachable")),
      nf_instance_name_(stat_name_set_->add(extractNfInstance())),
      r12r_(stat_name_set_->add("r12r")), g3p_(stat_name_set_->add("g3p")),
      th_(stat_name_set_->add("topology_hiding")), t8e_(stat_name_set_->add("t8e")),
      t2e_(stat_name_set_->add("t2e")), s5e_(stat_name_set_->add("s5e")),
      unknown_rp_(stat_name_set_->add("unknown_rp")),
      unknown_target_type_(stat_name_set_->add("unknown_target_type")),
      undefined_service_(stat_name_set_->add("undefined_service")),
      o4n_(stat_name_set_->add("o4n")), nrf_(stat_name_set_->add("nrf")),
      e10d_(stat_name_set_->add("e10d")), unknown_id_(stat_name_set_->add("unknown_id")),
      nf_management_(stat_name_set_->add("nf_management")),
      bootstrapping_(stat_name_set_->add("bootstrapping")),
      th_fqdn_mapping_req_map_success_total_(
          stat_name_set_->add("th_fqdn_mapping_req_map_success_total")),
      th_fqdn_mapping_req_demap_success_total_(
          stat_name_set_->add("th_fqdn_mapping_req_demap_success_total")),
      th_fqdn_mapping_resp_map_success_total_(
          stat_name_set_->add("th_fqdn_mapping_resp_map_success_total")),
      th_fqdn_mapping_resp_demap_success_total_(
          stat_name_set_->add("th_fqdn_mapping_resp_demap_success_total")),
      th_fqdn_mapping_req_forwarded_unmodified_total_(
          stat_name_set_->add("th_fqdn_mapping_req_forwarded_unmodified_total")),
      th_fqdn_mapping_resp_forwarded_unmodified_total_(
          stat_name_set_->add("th_fqdn_mapping_resp_forwarded_unmodified_total")),
      th_fqdn_mapping_req_demap_failure_total_(
          stat_name_set_->add("th_fqdn_mapping_req_demap_failure_total")),
      th_fqdn_mapping_resp_demap_failure_total_(
          stat_name_set_->add("th_fqdn_mapping_resp_demap_failure_total")),
      th_fqdn_mapping_req_map_failure_total_(
          stat_name_set_->add("th_fqdn_mapping_req_map_failure_total")),
      th_fqdn_mapping_resp_map_failure_total_(
          stat_name_set_->add("th_fqdn_mapping_resp_map_failure_total")),
      internal_(stat_name_set_->add("internal")), external_(stat_name_set_->add("external")),
      th_fqdn_scrambling_req_scramble_success_total_(
          stat_name_set_->add("th_fqdn_scrambling_req_scramble_success_total")),
      th_fqdn_scrambling_req_descramble_success_total_(
          stat_name_set_->add("th_fqdn_scrambling_req_descramble_success_total")),
      th_fqdn_scrambling_resp_scramble_success_total_(
          stat_name_set_->add("th_fqdn_scrambling_resp_scramble_success_total")),
      th_fqdn_scrambling_resp_descramble_success_total_(
          stat_name_set_->add("th_fqdn_scrambling_resp_descramble_success_total")),
      th_fqdn_scrambling_req_forwarded_unmodified_fqdn_total_(
          stat_name_set_->add("th_fqdn_scrambling_req_forwarded_unmodified_fqdn_total")),
      th_fqdn_scrambling_resp_forwarded_unmodified_fqdn_total_(
          stat_name_set_->add("th_fqdn_scrambling_resp_forwarded_unmodified_fqdn_total")),
      th_fqdn_scrambling_req_forwarded_unmodified_ip_total_(
          stat_name_set_->add("th_fqdn_scrambling_req_forwarded_unmodified_ip_total")),
      th_fqdn_scrambling_resp_forwarded_unmodified_ip_total_(
          stat_name_set_->add("th_fqdn_scrambling_resp_forwarded_unmodified_ip_total")),
      th_fqdn_scrambling_req_scramble_invalid_fqdn_total_(
          stat_name_set_->add("th_fqdn_scrambling_req_scramble_invalid_fqdn_total")),
      th_fqdn_scrambling_req_descramble_invalid_fqdn_total_(
          stat_name_set_->add("th_fqdn_scrambling_req_descramble_invalid_fqdn_total")),
      th_fqdn_scrambling_resp_scramble_invalid_fqdn_total_(
          stat_name_set_->add("th_fqdn_scrambling_resp_scramble_invalid_fqdn_total")),
      th_fqdn_scrambling_resp_descramble_invalid_fqdn_total_(
          stat_name_set_->add("th_fqdn_scrambling_resp_descramble_invalid_fqdn_total")),
      th_fqdn_scrambling_req_scramble_encryption_id_not_found_total_(
          stat_name_set_->add("th_fqdn_scrambling_req_scramble_encryption_id_not_found_total")),
      th_fqdn_scrambling_req_descramble_encryption_id_not_found_total_(
          stat_name_set_->add("th_fqdn_scrambling_req_descramble_encryption_id_not_found_total")),
      th_fqdn_scrambling_resp_scramble_encryption_id_not_found_total_(
          stat_name_set_->add("th_fqdn_scrambling_resp_scramble_encryption_id_not_found_total")),
      th_fqdn_scrambling_resp_descramble_encryption_id_not_found_total_(
          stat_name_set_->add("th_fqdn_scrambling_resp_descramble_encryption_id_not_found_total")),
      th_fqdn_scrambling_req_scramble_incorrect_encryption_id_total_(
          stat_name_set_->add("th_fqdn_scrambling_req_scramble_incorrect_encryption_id_total")),
      th_fqdn_scrambling_req_descramble_incorrect_encryption_id_total_(
          stat_name_set_->add("th_fqdn_scrambling_req_descramble_incorrect_encryption_id_total")),
      th_fqdn_scrambling_resp_scramble_incorrect_encryption_id_total_(
          stat_name_set_->add("th_fqdn_scrambling_resp_scramble_incorrect_encryption_id_total")),
      th_fqdn_scrambling_resp_descramble_incorrect_encryption_id_total_(
          stat_name_set_->add("th_fqdn_scrambling_resp_descramble_incorrect_encryption_id_total")),
      ip_address_hiding_applied_success_(stat_name_set_->add("ip_address_hiding_applied_success")),
      ip_address_hiding_fqdn_missing_(stat_name_set_->add("ip_address_hiding_fqdn_missing")),
      ip_address_hiding_configuration_error_(
          stat_name_set_->add("ip_address_hiding_configuration_error")),
      th_pseudo_search_result_(stat_name_set_->add("th_pseudo_search_result_total")),
      notify_(stat_name_set_->add("nf_status_notify")),
      nf_discovery_(stat_name_set_->add("nf_discovery")) {
  ENVOY_LOG(debug, "EricProxyStats instantiated");
  buildIngressRoamingPartnerCounters();
  rememberRoamingPartnersForTopologyHiding();
  rememberServices();
  rememberEncryptionIds();
  ENVOY_LOG(trace, "EricProxyStats Ingress RP Counters built");
}

void EricProxyStats::rememberRoamingPartnersForTopologyHiding() {
  if (config_ != nullptr) {
    for (const auto& rp : config_->protoConfig().roaming_partners()) {
      stat_name_set_->rememberBuiltin(rp.name());
      for (const auto& type : rp.topology_hiding().ip_hiding().ip_hiding_per_target_nf_type()) {
        stat_name_set_->rememberBuiltin(type.first);
      }
    }
  }
  stat_name_set_->rememberBuiltin("UDM");
  stat_name_set_->rememberBuiltin("AUSF");
}

void EricProxyStats::rememberServices() {
  if (config_ != nullptr) {
    for (const auto& rp : config_->protoConfig().roaming_partners()) {
      if (rp.has_topology_hiding() && rp.topology_hiding().has_service_profile()) {
        for (const auto& t : rp.topology_hiding().service_profile().topology_hiding_service_cases()) {
          if (t.service_type().api_name().empty()) {
            continue;
          }
          const auto modified_service_name = absl::StrReplaceAll(t.service_type().api_name(), {{"-", "_"}});
          stat_name_set_->rememberBuiltin(modified_service_name);
        }
        for (const auto& t : rp.topology_hiding().service_profile().topology_unhiding_service_cases()) {
          if (t.service_type().api_name().empty()) {
            continue;
          }
          const auto modified_service_name = absl::StrReplaceAll(t.service_type().api_name(), {{"-", "_"}});
          stat_name_set_->rememberBuiltin(modified_service_name);
        }
      }
    }
  }
}

void EricProxyStats::rememberEncryptionIds() {
  if (config_ != nullptr) {
    for (const auto& rp : config_->protoConfig().roaming_partners()) {
      if (rp.has_topology_hiding()) {
        for (const auto& ep : rp.topology_hiding().encryption_profiles()) {
          if (ep.encryption_identifier().empty()) {
            continue;
          }
          stat_name_set_->rememberBuiltin(ep.encryption_identifier().substr(1));
        }
      }
    }
  }
}

const Stats::StatName& EricProxyStats::getOrigin(const bool is_origin_int) const noexcept
{
  if (is_origin_int) {
    return internal_;
  } else {
    return external_;
  }
}

void EricProxyStats::buildIngressRoamingPartnerCounters() {
  if (config_ != nullptr && !config_->protoConfig().rp_name_table().empty()) {
    auto dn_to_rp_table = config_->rootContext().kvTable(config_->protoConfig().rp_name_table());
    if (!dn_to_rp_table.empty()) {
      for (std::map<std::basic_string<char>, std::basic_string<char>>::const_iterator rp_name_it =
               dn_to_rp_table.begin();
           rp_name_it != dn_to_rp_table.end(); rp_name_it++) {
        ingress_rp_rq_total_[rp_name_it->second] =
            std::optional<Stats::Counter*>{&buildRoamingInterfaceCounter(
                rp_name_it->second, "downstream_rq_total_per_roaming_partner")};
        ingress_rp_rq_1xx_[rp_name_it->second] =
            std::optional<Stats::Counter*>{&buildRoamingInterfaceCounter(
                rp_name_it->second, "downstream_rq_1xx_per_roaming_partner")};
        ingress_rp_rq_2xx_[rp_name_it->second] =
            std::optional<Stats::Counter*>{&buildRoamingInterfaceCounter(
                rp_name_it->second, "downstream_rq_2xx_per_roaming_partner")};
        ingress_rp_rq_3xx_[rp_name_it->second] =
            std::optional<Stats::Counter*>{&buildRoamingInterfaceCounter(
                rp_name_it->second, "downstream_rq_3xx_per_roaming_partner")};
        ingress_rp_rq_4xx_[rp_name_it->second] =
            std::optional<Stats::Counter*>{&buildRoamingInterfaceCounter(
                rp_name_it->second, "downstream_rq_4xx_per_roaming_partner")};
        ingress_rp_rq_5xx_[rp_name_it->second] =
            std::optional<Stats::Counter*>{&buildRoamingInterfaceCounter(
                rp_name_it->second, "downstream_rq_5xx_per_roaming_partner")};
      }
    }
  }
}

Stats::ElementVec EricProxyStats::addPrefix(const Stats::ElementVec& names) {
  Stats::ElementVec names_with_prefix;
  names_with_prefix.reserve(1 + names.size());
  names_with_prefix.push_back(stats_prefix_);
  names_with_prefix.insert(names_with_prefix.end(), names.begin(), names.end());
  return names_with_prefix;
}

Stats::StatNameVec EricProxyStats::addIngressPrefix(const Stats::StatNameVec& names) {
  Stats::StatNameVec names_with_prefix;
  names_with_prefix.reserve(1 + names.size());
  names_with_prefix.push_back(stats_ingress_prefix_);
  names_with_prefix.insert(names_with_prefix.end(), names.begin(), names.end());
  return names_with_prefix;
}

Stats::Counter&
EricProxyStats::buildSlfFailureCounters(const std::string&, const Stats::StatName& counter_name,
                                        Http::StreamDecoderFilterCallbacks* decoder_callbacks) {
  if (decoder_callbacks != nullptr) {
    ENVOY_STREAM_LOG(debug, "Build Slf Failure Counters: {}.{}.{}.{} ", *decoder_callbacks,
                     scope_.symbolTable().toString(stats_prefix_),
                     scope_.symbolTable().toString(nf_instance_name_), "g3p.slf_lookup",
                     scope_.symbolTable().toString(counter_name));
  } else {
    ENVOY_LOG(debug, "Build Slf Failure Counter: {}.{}.{}.{} ",
              scope_.symbolTable().toString(stats_prefix_),
              scope_.symbolTable().toString(nf_instance_name_), "g3p.slf_lookup",
              scope_.symbolTable().toString(counter_name));
  }
  return Stats::Utility::counterFromElements(
      scope_, addPrefix({n8e_, nf_instance_name_, Stats::StatName(stat_name_set_->add("g3p")),
                         Stats::StatName(stat_name_set_->add("slf_lookup")), counter_name}));
}

Stats::Counter& EricProxyStats::buildEgressScreeningCounter(
    const std::string& sc_name, const std::string& sr_name, const Stats::StatName& counter_name,
    const std::string& pool_name, Http::StreamDecoderFilterCallbacks* decoder_callbacks) {
  if (decoder_callbacks != nullptr) {
    ENVOY_STREAM_LOG(debug, "Build Egress screening counter: {}.{}.{}.{}.{}.{}", *decoder_callbacks,
                     scope_.symbolTable().toString(stats_prefix_),
                     scope_.symbolTable().toString(nf_instance_name_), pool_name, sc_name, sr_name,
                     scope_.symbolTable().toString(counter_name));
  } else {
    ENVOY_LOG(debug, "Build screening counter: {}.{}.{}.{}.{}.{}",
              scope_.symbolTable().toString(stats_prefix_),
              scope_.symbolTable().toString(nf_instance_name_), pool_name, sc_name, sr_name,
              scope_.symbolTable().toString(counter_name));
  }
  return Stats::Utility::counterFromElements(
      scope_,
      addPrefix({n8e_, nf_instance_name_, p2l_, Stats::DynamicName(pool_name), s8c3_,
                 Stats::DynamicName(sc_name), s8r3_, Stats::DynamicName(sr_name), counter_name}));
}

Stats::Counter&
EricProxyStats::buildScreeningCounter(const std::string& sc_name, const std::string& sr_name,
                                      const Stats::StatName& counter_name,
                                      Http::StreamDecoderFilterCallbacks* decoder_callbacks) {
  if (decoder_callbacks != nullptr) {
    ENVOY_STREAM_LOG(debug, "Build screening counter: {}.{}.{}.{}.{}", *decoder_callbacks,
                     scope_.symbolTable().toString(stats_prefix_),
                     scope_.symbolTable().toString(nf_instance_name_), sc_name, sr_name,
                     scope_.symbolTable().toString(counter_name));
  } else {
    ENVOY_LOG(debug, "Build screening counter: {}.{}.{}.{}.{}",
              scope_.symbolTable().toString(stats_prefix_),
              scope_.symbolTable().toString(nf_instance_name_), sc_name, sr_name,
              scope_.symbolTable().toString(counter_name));
  }
  return Stats::Utility::counterFromElements(
      scope_, addPrefix({n8e_, nf_instance_name_, s8c3_, Stats::DynamicName(sc_name), s8r3_,
                         Stats::DynamicName(sr_name), counter_name}));
}

Stats::Counter& EricProxyStats::buildTHcounters(const std::string& rp_name,
                                                const std::string& target_type,
                                                const Stats::StatName& svc_prefix,
                                                const Stats::StatName& req_or_resp,
                                                const Stats::StatName& counter_name) {
  return Stats::Utility::counterFromStatNames(
      scope_, addIngressPrefix({n8e_, nf_instance_name_, g3p_, th_, r12r_,
                                stat_name_set_->getBuiltin(rp_name, unknown_rp_), t8e_,
                                stat_name_set_->getBuiltin(target_type, unknown_target_type_), svc_prefix,
                                req_or_resp, counter_name}));
}

Stats::Counter& EricProxyStats::buildFqdnMappingCounters(
  const std::string& rp_name, const std::string& service_name, const Stats::StatName& origin,
  const ReqOrResp& req_or_resp, const bool is_mapping, const FqdnCase& fqdn_case
) {
  const auto modified_service_name =
    service_name.empty() ? "undefined_service" : absl::StrReplaceAll(service_name, {{"-", "_"}});
  Stats::StatName counter_name;
  switch (fqdn_case) {
  case FqdnCase::Success:
    if (req_or_resp == ReqOrResp::Request) {
      counter_name = is_mapping ? th_fqdn_mapping_req_map_success_total_
                                : th_fqdn_mapping_req_demap_success_total_;
    } else { // response
      counter_name = is_mapping ? th_fqdn_mapping_resp_map_success_total_
                                : th_fqdn_mapping_resp_demap_success_total_;
    }
    break;
  case FqdnCase::Failure:
    if (req_or_resp == ReqOrResp::Request) {
      counter_name = is_mapping ? th_fqdn_mapping_req_map_failure_total_
                                : th_fqdn_mapping_req_demap_failure_total_;
    } else { // response
      counter_name = is_mapping ? th_fqdn_mapping_resp_map_failure_total_
                                : th_fqdn_mapping_resp_demap_failure_total_;
    }
    break;
  case FqdnCase::DoNothing:
    if (req_or_resp == ReqOrResp::Request) {
      counter_name = th_fqdn_mapping_req_forwarded_unmodified_total_;
    } else {
      counter_name = th_fqdn_mapping_resp_forwarded_unmodified_total_;
    }
    break;
  default:
    break;
  }

  ENVOY_LOG(trace, "Build FQDN Mapping counter: {}.{}.{}.{}", rp_name, modified_service_name,
            scope_.symbolTable().toString(origin), scope_.symbolTable().toString(counter_name));

  return Stats::Utility::counterFromStatNames(
    scope_,
    addIngressPrefix({
      n8e_, nf_instance_name_, g3p_, th_, r12r_,
      stat_name_set_->getBuiltin(rp_name, unknown_rp_), t8e_, nrf_, s5e_,
      stat_name_set_->getBuiltin(modified_service_name, undefined_service_), o4n_,
      origin, counter_name
    })
  );
}

Stats::Counter& EricProxyStats::buildFqdnScramblingCounters(
  const std::string& rp_name, const std::string& service_name, const Stats::StatName& origin,
  const ReqOrResp& req_or_resp, const bool is_scrambling, const FqdnCase& fqdn_case,
  const std::string& encryption_id
) {
  const auto modified_service_name =
    service_name.empty() ? "undefined_service" : absl::StrReplaceAll(service_name, {{"-", "_"}});
  Stats::StatName counter_name;
  switch (fqdn_case) {
  case FqdnCase::Success:
    if (req_or_resp == ReqOrResp::Request) {
      counter_name = is_scrambling ? th_fqdn_scrambling_req_scramble_success_total_
                                   : th_fqdn_scrambling_req_descramble_success_total_;
    } else { // response
      counter_name = is_scrambling ? th_fqdn_scrambling_resp_scramble_success_total_
                                   : th_fqdn_scrambling_resp_descramble_success_total_;
    }
    break;
  case FqdnCase::InvalidFqdn:
    if (req_or_resp == ReqOrResp::Request) {
      counter_name = is_scrambling ? th_fqdn_scrambling_req_scramble_invalid_fqdn_total_
                                   : th_fqdn_scrambling_req_descramble_invalid_fqdn_total_;
    } else { // response
      counter_name = is_scrambling ? th_fqdn_scrambling_resp_scramble_invalid_fqdn_total_
                                   : th_fqdn_scrambling_resp_descramble_invalid_fqdn_total_;
    }
    break;
  case FqdnCase::EncryptionIdNotFound:
    if (req_or_resp == ReqOrResp::Request) {
      counter_name = is_scrambling ? th_fqdn_scrambling_req_scramble_encryption_id_not_found_total_
                                   : th_fqdn_scrambling_req_descramble_encryption_id_not_found_total_;
    } else { // response
      counter_name = is_scrambling ? th_fqdn_scrambling_resp_scramble_encryption_id_not_found_total_
                                   : th_fqdn_scrambling_resp_descramble_encryption_id_not_found_total_;
    }
    break;
  case FqdnCase::IncorrectEncryptionId:
    if (req_or_resp == ReqOrResp::Request) {
      counter_name = is_scrambling ? th_fqdn_scrambling_req_scramble_incorrect_encryption_id_total_
                                   : th_fqdn_scrambling_req_descramble_incorrect_encryption_id_total_;
    } else { // response
      counter_name = is_scrambling ? th_fqdn_scrambling_resp_scramble_incorrect_encryption_id_total_
                                   : th_fqdn_scrambling_resp_descramble_incorrect_encryption_id_total_;
    }
    break;
  case FqdnCase::ForwardedUnmodifiedFqdn:
    if (req_or_resp == ReqOrResp::Request) {
      counter_name = th_fqdn_scrambling_req_forwarded_unmodified_fqdn_total_;
    } else { // response
      counter_name = th_fqdn_scrambling_resp_forwarded_unmodified_fqdn_total_;
    }
    break;
  case FqdnCase::ForwardedUnmodifiedIp:
    if (req_or_resp == ReqOrResp::Request) {
      counter_name = th_fqdn_scrambling_req_forwarded_unmodified_ip_total_;
    } else { // response
      counter_name = th_fqdn_scrambling_resp_forwarded_unmodified_ip_total_;
    }
    break;
  default:
    break;
  }

  ENVOY_LOG(trace, "Build FQDN Scrambling counter: {}.{}.{}.{}.{}", rp_name, modified_service_name,
            scope_.symbolTable().toString(origin), encryption_id, scope_.symbolTable().toString(counter_name));

  return Stats::Utility::counterFromStatNames(
    scope_,
    addIngressPrefix({
      n8e_, nf_instance_name_, g3p_, th_, r12r_,
      stat_name_set_->getBuiltin(rp_name, unknown_rp_), s5e_,
      stat_name_set_->getBuiltin(modified_service_name, undefined_service_),
      o4n_, origin, e10d_, stat_name_set_->getBuiltin(encryption_id, unknown_id_), counter_name
    })
  );
}

Stats::Counter& EricProxyStats::buildRoamingInterfaceCounter(const std::string& rp_name,
                                                             const std::string& counter_name) {
  ENVOY_LOG(debug, "Build screening counter: n8e.{}.g3p.ingress.r12r.{}.{}",
            scope_.symbolTable().toString(nf_instance_name_), rp_name, counter_name);
  return Stats::Utility::counterFromStatNames(
      scope_,
      addIngressPrefix({n8e_, nf_instance_name_, Stats::StatName(stat_name_set_->add("g3p")),
                        Stats::StatName(stat_name_set_->add("ingress")),
                        Stats::StatName(stat_name_set_->add("r12r")),
                        Stats::StatName(stat_name_set_->add(rp_name)),
                        Stats::StatName(stat_name_set_->add(counter_name))}));
}

std::string EricProxyStats::extractNfInstance() {
  std::smatch m;
  std::regex_search(fetched_prefix_, m, SpecifierConstants::get().PATTERN);
  ENVOY_LOG(trace,
            "Extracting NF-Instance with pattern '{}' from fetched prefix '{}'. Result: '{}'",
            "n8e\\.(.+?)\\.", fetched_prefix_, m.str(1));
  return m.str(1);
}

void EricProxyStats::incIngressRpRqXx(std::string rp_name, uint64_t response_code) {
  if (Http::CodeUtility::is1xx(response_code)) {
    if (!ingress_rp_rq_1xx_.empty() && ingress_rp_rq_1xx_[rp_name].has_value() &&
        !(ingress_rp_rq_1xx_.find(rp_name) == ingress_rp_rq_1xx_.end())) {
      ingress_rp_rq_1xx_[rp_name].value()->inc();
    }
  } else if (Http::CodeUtility::is2xx(response_code)) {
    if (!ingress_rp_rq_2xx_.empty() && ingress_rp_rq_2xx_[rp_name].has_value() &&
        !(ingress_rp_rq_2xx_.find(rp_name) == ingress_rp_rq_2xx_.end())) {
      ingress_rp_rq_2xx_[rp_name].value()->inc();
    }
  } else if (Http::CodeUtility::is3xx(response_code)) {
    if (!ingress_rp_rq_3xx_.empty() && ingress_rp_rq_3xx_[rp_name].has_value() &&
        !(ingress_rp_rq_3xx_.find(rp_name) == ingress_rp_rq_3xx_.end())) {
      ingress_rp_rq_3xx_[rp_name].value()->inc();
    }
  } else if (Http::CodeUtility::is4xx(response_code)) {
    if (!ingress_rp_rq_4xx_.empty() && ingress_rp_rq_4xx_[rp_name].has_value() &&
        !(ingress_rp_rq_4xx_.find(rp_name) == ingress_rp_rq_4xx_.end())) {
      ingress_rp_rq_4xx_[rp_name].value()->inc();
    }
  } else if (Http::CodeUtility::is5xx(response_code)) {
    if (!ingress_rp_rq_5xx_.empty() && ingress_rp_rq_5xx_[rp_name].has_value() &&
        !(ingress_rp_rq_5xx_.find(rp_name) == ingress_rp_rq_5xx_.end())) {
      ingress_rp_rq_5xx_[rp_name].value()->inc();
    }
  }
}

void EricProxyStats::incIngressRpRqTotal(const std::string& rp_name) {
  if (!ingress_rp_rq_total_.empty() && ingress_rp_rq_total_[rp_name].has_value() &&
      !(ingress_rp_rq_total_.find(rp_name) == ingress_rp_rq_total_.end())) {
    ingress_rp_rq_total_[rp_name].value()->inc();
  }
}


} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
