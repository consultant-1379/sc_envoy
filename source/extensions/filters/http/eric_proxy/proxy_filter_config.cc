#include "source/extensions/filters/http/eric_proxy/proxy_filter_config.h"
#include "contexts.h"
#include "source/extensions/filters/http/eric_proxy/wrappers.h"
#include "source/extensions/common/tap/utility.h"
#include <memory>
#include <utility>
#include <vector>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

EricProxyFilterConfig::EricProxyFilterConfig(const EricProxyConfig& proto_config,
                                             Upstream::ClusterManager& cm)
    : proto_config_(proto_config), filter_cases_(proto_config.filter_cases()),
      cluster_manager_(cm), own_fqdn_lc_{absl::AsciiStrToLower(proto_config.own_fqdn())},
      own_fqdn_with_int_port_lc_{absl::StrCat(own_fqdn_lc_, ":", proto_config.own_internal_port())},
      own_fqdn_with_ext_port_lc_{absl::StrCat(own_fqdn_lc_, ":", proto_config.own_external_port())},
      network_id_header_val_{
          (isSeppNode() && isOriginInt() && proto_config_.has_plmn_ids())
              ? absl::StrCat(" ", proto_config_.plmn_ids().primary_plmn_id().mcc(), "-",
                             proto_config_.plmn_ids().primary_plmn_id().mnc(), "; src: SEPP-",
                             own_fqdn_lc_)
              : ""} {
  ENVOY_LOG(debug, "EricProxyFilterConfig instantiated");
  populateRootContext();
  populateRpPoolMap();
  populateNfTypesTFqdn();
  populateAllFilterPhaseData();
  populateRegexThIpHiding();
  populateCidrRangePerNfTypePerRp();
  populateServiceCaseConfig();
  populateUsfwServiceValidationConfig();
  populateUsfwActionsAfterThreshold();
  populateViaHeaderCtx();
  is_tfqdn_configured_ = root_ctx_.hasKlvt(proto_config_.callback_uri_klv_table());
  switch (proto_config.ip_version()) {
  case envoy::extensions::filters::http::eric_proxy::v3::IPFamily::Default:
  case envoy::extensions::filters::http::eric_proxy::v3::IPFamily::IPv4:
    ip_version_ = IPver::IPv4;
    break;
  case envoy::extensions::filters::http::eric_proxy::v3::IPFamily::IPv6:
    ip_version_ = IPver::IPv6;
    break;
  case envoy::extensions::filters::http::eric_proxy::v3::IPFamily::DualStack:
    ip_version_ = IPver::DualStack;
    break;
  default:
    break;
  }
}

// Configuration processing hints from EricProxy Blueprint
// 1         [Filter-Data] Foreach Filter-Case
// 1.1       Foreach Filter-Data
// 1.1.1     If the destination-variable is an extractor-regex:
// 1.1.1.1   Foreach named capture-group
// 1.1.1.1.1 Create a new var_configmap entry
// 1.1.1.1.2 Create a new var_capturegroup entry
// 1.1.1.1.3 Pre-compile the regex
// 1.1.1.1.4 Create a new var_filterdata entry in this Filter-Case
//           containing the mapping of each variable to this Filter-Data
// 1.1.2     If the destination-variable is a name
// 1.1.2.1   Create a new var_capturegroup entry (for “name”-type destination-variables
//           there is always only one entry)
// 1.1.2.2   Create a new var_filterdata entry in this Filter-Case containing
// the mapping of this variable to this Filter-Data
// 2      [conditions] Foreach Filter-Case
// 2.1     Foreach Filter-Rule: Read condition
// 2.1.1   Set up operator-tree
// 2.1.1.1 Create new const_configmap entries
// 2.1.1.2 Create new const_value entries
// 2.1.1.3 Create new header_configmap and header_configmap_reverse entries
// 2.1.1.4 Create operator objects, using the indices from all *_configmap tables
// 2.1.1.5 Return the operator-tree, the list of header-value-index, and var-value-index
//         required for this condition
// 2.1.2   Append the header-value-index list from 2.1.1.5 to the header_value_indices_required
//         list in this condition
// 2.1.3   Foreach var-value-index returned by 2.1.1.5, find the Filter-Data from this
//         Filter-Case that sets this variable by looking up var_filterdata in this
//         Filter-Case. Append the Filter-Data ID to the filterdata-required list in
//         this condition
void EricProxyFilterConfig::populateRootContext() {
  // 1. Filter-Data
  for (auto fc : proto_config_.filter_cases()) {
    ENVOY_LOG(debug, "-- Processing filter case: {}", fc.name());
    auto fcWrapper = std::make_shared<FilterCaseWrapper>(fc);
    fc_by_name_map_[fcWrapper->name()] = fcWrapper;
    for (auto fd : fc.filter_data()) {
      ENVOY_LOG(debug, "----Processing filter_data: {}, for filter case: {}.", fd.name(),
                fc.name());
      auto fdWrapper = std::make_shared<FilterDataWrapper>(fd);
      populateRootContextForFilterData(fdWrapper);
      for (auto var_capturegroup_entry : fdWrapper->varCaptureGroups()) {
        // 1.1.1.1.4 & 1.1.2.2  Create a new var_filterdata entry in this
        // Filter-Case  containing the mapping of each variable to this
        // Filter-Data
        fcWrapper->insertVarFilterData(var_capturegroup_entry.second, fdWrapper);
      }
    }
  }
  // 2. Conditions
  for (const auto& fc : proto_config_.filter_cases()) {
    ENVOY_LOG(debug, "++ Processing filter case: {}.", fc.name());
    for (auto fr : fc.filter_rules()) {
      auto fcWrapper = fc_by_name_map_[fc.name()];
      auto frWrapper = std::make_shared<FilterRuleWrapper>(fcWrapper, fr);
      frWrapper->insertCompiledCondition(root_ctx_);
      frWrapper->insertActions(root_ctx_);
      fcWrapper->addFilterRule(frWrapper);
    }
    ENVOY_LOG(trace, fc_by_name_map_[fc.name()]->rulesAndFilterdataAsString());
  }

  // 3. Key Value Tables
  root_ctx_.populateKvTables(proto_config_.key_value_tables());

  // 4. Key List Value Tables
  root_ctx_.populateKlvTables(proto_config_.key_list_value_tables());

  // 5. After all the maps have been populated, pre-compile domain name regexp
  populateDnToRe2KvTable();

  // 6. Populate root context with the flag indicating if the config has external listener
  root_ctx_.populateIsOriginExt(isOriginExt());

  // 7. Populate root context with scrambling and descrambling encryption profile(s)
  std::map<std::string, std::tuple<std::string, const unsigned char*, const unsigned char*>>
    scrambling_encryption_profile;
  std::map<std::string, std::map<std::string, std::pair<const unsigned char*, const unsigned char*>>>
    descrambling_encryption_profiles;
  for (const auto& rp : proto_config_.roaming_partners()) {
    std::map<std::string, std::pair<const unsigned char*, const unsigned char*>> descrambling_encryption_profile;
    for (const auto& ep : rp.topology_hiding().encryption_profiles()) {
      const unsigned char* key = reinterpret_cast<const unsigned char*>(ep.scrambling_key().c_str());
      const unsigned char* iv = reinterpret_cast<const unsigned char*>(ep.initial_vector().c_str());
      if (ep.encryption_identifier() == rp.topology_hiding().active_encryption_identifier()) {
        scrambling_encryption_profile[rp.name()] = std::make_tuple(ep.encryption_identifier(), key, iv);
      }
      descrambling_encryption_profile[ep.encryption_identifier()] = std::make_pair(key, iv);
    }
    descrambling_encryption_profiles[rp.name()] = descrambling_encryption_profile;
  }
  root_ctx_.populateScramblingEncryptionProfile(scrambling_encryption_profile);
  root_ctx_.populateDescramblingEncryptionProfiles(descrambling_encryption_profiles);

  // 8. Populate root context with regex for valid plmn
  root_ctx_.populateRegexValidPlmn();
}

// If a domain to RP name table is supplied from the configuration,
// constuct a map of domain names to precompiled RE2 regexes that
// facilitates wildcard certificate matching. That way we don't need
// to compile said regexes at runtime.
// The domain names are taken from the key set of the kvtable pointed
// to by the 'rp_name_table' variable inside eric_proxy.proto.
// The table is stored in the kv_tables_ following the convention of the rest of the tables
void EricProxyFilterConfig::populateDnToRe2KvTable() {
  if ((!proto_config_.rp_name_table().empty()) && root_ctx_.hasKvt(proto_config_.rp_name_table())) {
    for (auto& it : root_ctx_.kvTable(proto_config_.rp_name_table())) {
      auto& dn = it.first;
      const std::string wildcard_quoted = "\\*";
      auto pattern_regex = RE2::QuoteMeta(dn);
      auto wildcard_start_pos = pattern_regex.find(wildcard_quoted);
      if (wildcard_start_pos != std::string::npos) {
        auto wildcard_in_regex = "[^.]*";
        if (absl::StartsWith(pattern_regex, wildcard_quoted)) {
          // We do not want to match e.g. *.ericsson.se with .ericsson.se.
          wildcard_in_regex = "[^.]+";
        }
        pattern_regex =
            pattern_regex.replace(wildcard_start_pos, wildcard_quoted.length(), wildcard_in_regex);
      }
      dn_to_re2_regex_table_.emplace(dn,absl::AsciiStrToLower(pattern_regex));
    }
  }
};


// Provide the pool/cluster for the given pool
std::string EricProxyFilterConfig::rpPoolName(std::string rp) {
  ENVOY_LOG(trace, "rpPoolName({}): {}", rp, rp_pool_map_[rp]);
  return rp_pool_map_[rp];
}

void EricProxyFilterConfig::populateRpPoolMap() {
  for (const auto& rp : proto_config_.roaming_partners()) {
    rp_pool_map_[rp.name()] = rp.pool_name();
  }
}

void EricProxyFilterConfig::populateRootContextForFilterData(
    std::shared_ptr<FilterDataWrapper> fd_wrapper) {
  ENVOY_LOG(trace, "EricProxyFilterConfig::populateRootContextForFilterData()");
  if (!fd_wrapper->extractorRegex().empty()) { // 1.1.1
    ENVOY_LOG(debug, "adding filter_data.extractor_regex :{}.", fd_wrapper->extractorRegex());
    // 1.1.1.1  Foreach named capture-group
    auto capt_group_names = fd_wrapper->re2ExtractorRegex().CapturingGroupNames();
    for (auto const& capt_group : capt_group_names) {
      if (!capt_group.second.empty()) // we only care about named groups
      {
        int group_idx = capt_group.first;
        auto var_name = capt_group.second;
        ENVOY_LOG(debug, "capt_group_name[{}]={}.", group_idx, var_name);
        // 1.1.1.1.1  Create a new var_configmap entry
        auto var_value_idx = root_ctx_.findOrInsertVarName(var_name);
        // 1.1.1.1.2  Create a new var_capturegroup entry
        fd_wrapper->insertCaptureGroupAtIndex(group_idx, var_value_idx);
        // var_capture_groups_[group_idx]=var_value_idx;
      }
    }
  } else if (!fd_wrapper->variableName().empty()) { // 1.1.2
    auto var_value_idx = root_ctx_.findOrInsertVarName(fd_wrapper->variableName());
    // 1.1.2.1  Create a new var_capturegroup entry (for “name”-type
    //          destination-variables there is always only one entry)
    // var_capture_groups_[0] = var_value_idx;
    fd_wrapper->insertCaptureGroupAtIndex(0, var_value_idx);
  }
}

// Create lower-case versions of all nf-types requiring T-FQDN. This allows quick
// case-insensitive comparisons at runtime:
void EricProxyFilterConfig::populateNfTypesTFqdn() {
  for (auto nftype: proto_config_.nf_types_requiring_t_fqdn()) {
    nf_types_requiring_tfqdn_.emplace_back(nftype);
  }
}

//--- Filter Phase Handling (= start-filter-cases for screening and routing) ------
// Prepare data structures here at config-time for improved request-time efficiency
void EricProxyFilterConfig::populateAllFilterPhaseData() {
  // Request path:
  // Initialize shared pointers here (outside if-conditions)
  // to ensure that they are all initialized to empty regardless
  // of the configuration:
  fp_in_req_screening_ = std::make_shared<FilterPhaseWrapper>();
  fp_routing_ = std::make_shared<FilterPhaseWrapper>();
  fp_out_req_screening_ = std::make_shared<FilterPhaseWrapper>();
  if (proto_config_.has_request_filter_cases()) {
    // Phase 1: In-Request Screening
    if (proto_config_.request_filter_cases().has_in_request_screening()) {
      const auto& config_in_request_screening = proto_config_.request_filter_cases().in_request_screening();
      populateRoutingScreening16FilterPhaseData(config_in_request_screening, fp_in_req_screening_);
    }
    // Phase 2: Routing
    if (proto_config_.request_filter_cases().has_routing()) {
      const auto& routing = proto_config_.request_filter_cases().routing();
      populateRoutingScreening16FilterPhaseData(routing, fp_routing_);
    }
    // Phase 3: Out-Request Screening
    if (proto_config_.request_filter_cases().has_out_request_screening()) {
      const auto& config_out_request_screening = proto_config_.request_filter_cases().out_request_screening();
      populateScreening34FilterPhaseData(config_out_request_screening, fp_out_req_screening_);
    }
  }
  // Response path:
  fp_in_resp_screening_ = std::make_shared<FilterPhaseWrapper>();
  fp_out_resp_screening_ = std::make_shared<FilterPhaseWrapper>();
  if (proto_config_.has_response_filter_cases()) {
    // Phase 4: In-Response Screening
    if (proto_config_.response_filter_cases().has_in_response_screening()) {
      const auto& config_in_response_screening = proto_config_.response_filter_cases().in_response_screening();
      populateScreening34FilterPhaseData(config_in_response_screening, fp_in_resp_screening_);
    }
    // Phase 6: Out-Response Screening
    if (proto_config_.response_filter_cases().has_out_response_screening()) {
      const auto& config_out_response_screening = proto_config_.response_filter_cases().out_response_screening();
      populateRoutingScreening16FilterPhaseData(config_out_response_screening, fp_out_resp_screening_);
    }
  }
}

// Helper-function to process NetworkFilterPhaseConfig from the configuration
// into the filter-phase wrapper object.
// This is used for screening 1, 6, and routing.
void EricProxyFilterConfig::populateRoutingScreening16FilterPhaseData(const NetworkFilterPhaseConfig& fp_config, FilterPhaseWrapperSharedPtr fp_wrapper) {
  if (fp_config.has_ext_nw()) {
    auto& ext_nw = fp_config.ext_nw();
    fp_wrapper->nw_name =  ext_nw.name();
    // First pass: only collect the names of all RP and insert them
    // into the map ext_nw_per_rp_fc_
    for (const auto& ext_nw_fc_config: ext_nw.ext_nw_fc_config_list()) {
      if (ext_nw_fc_config.has_per_rp_fc_config()) {
        for (const auto& rp_to_fc_iter: ext_nw_fc_config.per_rp_fc_config().rp_to_fc_map()) {
          // This will create the key with the new RP name and an empty
          // vector if the RP name does not exist yet (side-effect
          // of the [] operator on unordered_map).
          // If it does exist, nothing happens.
          fp_wrapper->ext_nw_per_rp_fc_[rp_to_fc_iter.first];
        }
      }
    }
    // Second pass: set the filter-cases per roaming partner and the
    // default filter-case for when there is a roaming partner without
    // specific configuration
    size_t expected_num_elements = 0;
    for (const auto& ext_nw_fc_config: ext_nw.ext_nw_fc_config_list()) {
      expected_num_elements++;
      // Choice: per-RP configuration
      if (ext_nw_fc_config.has_per_rp_fc_config()) {
        // Per-RP filter-cases:
        for (const auto& rp_to_fc_iter: ext_nw_fc_config.per_rp_fc_config().rp_to_fc_map()) {
          fp_wrapper->ext_nw_per_rp_fc_[rp_to_fc_iter.first].emplace_back(rp_to_fc_iter.second);
        }
        if (!ext_nw_fc_config.per_rp_fc_config().default_fc_for_rp_not_found().empty()) {
          // Ensure that all RPs in the map fp_wrapper->ext_nw_per_rp_fc_ have
          // expected_num_elements. If not, then append the default filter-case
          // for when the RP is not found
          for (const auto& ext_nw_per_rp_fc_iter: fp_wrapper->ext_nw_per_rp_fc_) {
            if (fp_wrapper->ext_nw_per_rp_fc_[ext_nw_per_rp_fc_iter.first].size() < expected_num_elements) {
              fp_wrapper->ext_nw_per_rp_fc_[ext_nw_per_rp_fc_iter.first].emplace_back(ext_nw_fc_config.per_rp_fc_config().default_fc_for_rp_not_found());
            }
          }
          // The default filter-case for RP without specific configuration:
          fp_wrapper->ext_nw_fc_default_.emplace_back(ext_nw_fc_config.per_rp_fc_config().default_fc_for_rp_not_found());
        }
      // Choice: generic configuration = same start FC for all RP
      } else if (ext_nw_fc_config.has_start_fc_for_all_rp()) {
        // Append to all RP
        for (const auto& ext_nw_per_rp_fc_iter: fp_wrapper->ext_nw_per_rp_fc_) {
          fp_wrapper->ext_nw_per_rp_fc_[ext_nw_per_rp_fc_iter.first].emplace_back(ext_nw_fc_config.start_fc_for_all_rp());
        }
        // Set the default for a RP without specific configuration
        if (ext_nw_fc_config.has_start_fc_for_all_rp()) {
          fp_wrapper->ext_nw_fc_default_.emplace_back(ext_nw_fc_config.start_fc_for_all_rp());
        }
      }
    }
  }
  if (fp_config.has_own_nw()) {
    auto& own_nw = fp_config.own_nw();
    fp_wrapper->nw_name =  own_nw.name();
    for (const auto& start_fc: own_nw.start_fc_list()) {
      fp_wrapper->own_nw_fc_.emplace_back(start_fc);
    }
  }
}

// Helper-function to transform the filter configuration from ClusterFilterPhaseConfig
// into the FilterPhaseWrapper.
// This is used for egress screening (3 and 4).
void EricProxyFilterConfig::populateScreening34FilterPhaseData(const ClusterFilterPhaseConfig& fp_config, FilterPhaseWrapperSharedPtr fp_wrapper) {
  for (const auto& cluster_fc_config: fp_config.cluster_fc_config_list()) {
    for (const auto& cluster_to_fc_map_iter: cluster_fc_config.cluster_to_fc_map()) {
      fp_wrapper->cluster_fc_[cluster_to_fc_map_iter.first].emplace_back(cluster_to_fc_map_iter.second);
    }
  }
}

// SEPP Topology Hiding Phase 2
// IP Hiding
// Populate regular expressions for TH IP Hiding
void EricProxyFilterConfig::populateRegexThIpHiding() {
  regex_ipv4_addresses_ = std::regex(".*ipv4Addresses$");
  regex_ipv6_addresses_ = std::regex(".*ipv6Addresses$");
  regex_ipv4_address_ = std::regex(".*ipv4Addresses/\\d*$|.*ipv4Address$");
  regex_ipv6_address_ = std::regex(".*ipv6Addresses/\\d*$|.*ipv6Address$");
}

// Return CidrMap
std::map<std::string,std::map<std::string,std::vector<Network::Address::CidrRange>>>
EricProxyFilterConfig::getSubnetCidrNfTypePerRp(bool ipv4) {
  if (ipv4) {
    return ipv4_subnet_cidr_per_target_nf_type_;
  } else {
    return ipv6_subnet_cidr_per_target_nf_type_;
  }
}

// Constuct the CidrRangeMap for TH IP hiding for Notifications
void EricProxyFilterConfig::populateCidrRangePerNfTypePerRp() {
  if(!isSeppNode()) {
    return;
  } else {
    for (const auto& rp : proto_config_.roaming_partners()) {
      std::map<std::string /* nf-type */,
        std::vector<Network::Address::CidrRange>> nf_type_subnet4_map;
      std::map<std::string /* nf-type */,
        std::vector<Network::Address::CidrRange>> nf_type_subnet6_map;
      if (rp.has_topology_hiding() &&
          rp.topology_hiding().has_ip_hiding()) {
        if (rp.topology_hiding().ip_hiding().ipv4_subnet_per_target_nf_type().empty() &&
            rp.topology_hiding().ip_hiding().ipv6_subnet_per_target_nf_type().empty()) {
          return;
        }

        if (! rp.topology_hiding().ip_hiding().ipv4_subnet_per_target_nf_type().empty()) {
          // IPv4 Subnet hiding is configured for this RP
          for (const auto& subnet_per_nf_type :
              rp.topology_hiding().ip_hiding().ipv4_subnet_per_target_nf_type()) {
            std::vector<Network::Address::CidrRange> subnet_per_nf_type_list;
            for (const auto& subnet: subnet_per_nf_type.second.subnet_list()) {
              subnet_per_nf_type_list.emplace_back(Network::Address::CidrRange
                  ::create(subnet));
            }

            nf_type_subnet4_map[subnet_per_nf_type.first] = subnet_per_nf_type_list;
          }
          ipv4_subnet_cidr_per_target_nf_type_[rp.name()] = nf_type_subnet4_map;
        }
      }
      if (! rp.topology_hiding().ip_hiding().ipv6_subnet_per_target_nf_type().empty()) {
        // IPv4 Subnet hiding is configured for this RP
        for (const auto& subnet_per_nf_type :
            rp.topology_hiding().ip_hiding().ipv6_subnet_per_target_nf_type()) {
          std::vector<Network::Address::CidrRange> subnet_per_nf_type_list;
          for (const auto& subnet: subnet_per_nf_type.second.subnet_list()) {
            subnet_per_nf_type_list.emplace_back(Network::Address::CidrRange
                ::create(subnet));
          }

          nf_type_subnet6_map[subnet_per_nf_type.first] = subnet_per_nf_type_list;
        }
        ipv6_subnet_cidr_per_target_nf_type_[rp.name()] = nf_type_subnet6_map;
      }
    }
  }
}

// Topology Hiding based on State Machine
// NRF FQDN Mapping & FQDN scrambling
// Helper function for obtaining Filter Case from
// RP Name, Service Case name and Filter Case name
std::shared_ptr<FilterCaseWrapper>
EricProxyFilterConfig::getFilterCaseByNameForServiceCaseForRP(
  const std::string& rp_name, const std::string& sc_name, const std::string& fc_name,
  const bool& is_req, const bool& is_topo_hiding
) {
  if (is_topo_hiding) {
    if (is_req) {
      return topo_hide_req_filter_case_by_sc_name_for_rp_map_[rp_name][sc_name][fc_name];
    } else {
      return topo_hide_resp_filter_case_by_sc_name_for_rp_map_[rp_name][sc_name][fc_name];
    }
  } else {
    if (is_req) {
      return topo_unhide_req_filter_case_by_sc_name_for_rp_map_[rp_name][sc_name][fc_name];
    } else {
      return topo_unhide_resp_filter_case_by_sc_name_for_rp_map_[rp_name][sc_name][fc_name];
    }
  }
}

// Helper function for obtaining Service Case from RP name
std::vector<std::shared_ptr<ServiceCaseWrapper>>
EricProxyFilterConfig::getServiceCaseVectorForRP(
  const std::string& rp_name, const bool& is_req,
  const bool& is_topo_hiding
) {
  if (is_topo_hiding) {
    if (is_req) {
      return svc_ctx_th_req_rp_map_[rp_name];
    } else {
      return svc_ctx_th_resp_rp_map_[rp_name];
    }
  } else {
    if (is_req) {
      return svc_ctx_tuh_req_rp_map_[rp_name];
    } else {
      return svc_ctx_tuh_resp_rp_map_[rp_name];
    }
  }
}

// Helper function for obtaining custom allowed "Service Class" Wrappers for USFW USOC from api_name and RP name
std::vector<std::shared_ptr<ServiceClassifierConfigBase>>
EricProxyFilterConfig::getCustomAllowedServiceOperationsPerApiNameForRp(const std::string& rp_name, const std::string& api_name) {
  return custom_allowed_service_operations_per_api_name_for_rp_map_[rp_name][api_name];
}

// Helper function for obtaining custom denied "Service Class" Wrappers for USFW USOC from api_name and RP name
std::vector<std::shared_ptr<ServiceClassifierConfigBase>>
EricProxyFilterConfig::getCustomDeniedServiceOperationsPerApiNameForRp(const std::string& rp_name, const std::string& api_name) {
  return custom_denied_service_operations_per_api_name_for_rp_map_[rp_name][api_name];
}

// Helper function for obtaining default allowed "Service Class" Wrappers for USFW USOC from api_name
std::vector<std::shared_ptr<ServiceClassifierConfigBase>>
EricProxyFilterConfig::getDefaultAllowedServiceOperationsPerApiName(const std::string& api_name) {
  return default_allowed_service_operations_per_api_name_map_[api_name];
}

// Populate Service Case Configs for NRF FQDN Mapping & FQDN scrambling
void EricProxyFilterConfig::populateServiceCaseConfig() {
  if (!isSeppNode()) {
    return;
  }
  for (const auto& rp : proto_config_.roaming_partners()) {
    if (rp.has_topology_hiding() && rp.topology_hiding().has_service_profile()) {
      populateTopoHidingServiceCases(rp.topology_hiding().service_profile(), rp.name());
      populateTopoUnhidingServiceCases(rp.topology_hiding().service_profile(), rp.name());
      populateSvcContextPerRPMap(rp.topology_hiding().service_profile(), rp.name());
    }
  }
}

void EricProxyFilterConfig::populateSvcContextPerRPMap(
  const TopologyHidingServiceProfile& service_profile,
  const std::string& rp_name
) {
  if (!service_profile.topology_hiding_service_cases().empty()) {
    std::vector<std::shared_ptr<ServiceCaseWrapper>> req_svc;
    std::vector<std::shared_ptr<ServiceCaseWrapper>> resp_svc;
    for (const auto& svc : service_profile.topology_hiding_service_cases()) {
      if (svc.service_type().direction() == ServiceContext::REQUEST) {
        req_svc.emplace_back(std::make_shared<ServiceCaseWrapper>(svc));
      } else if (svc.service_type().direction() == ServiceContext::RESPONSE) {
        resp_svc.emplace_back(std::make_shared<ServiceCaseWrapper>(svc));
      }
    }
    if (!req_svc.empty()) {
      svc_ctx_th_req_rp_map_[rp_name] = req_svc;
    }
    if (!resp_svc.empty()) {
      svc_ctx_th_resp_rp_map_[rp_name] = resp_svc;
    }
  }
  if (!service_profile.topology_unhiding_service_cases().empty()) {
    std::vector<std::shared_ptr<ServiceCaseWrapper>> req_svc;
    std::vector<std::shared_ptr<ServiceCaseWrapper>> resp_svc;
    for (const auto& svc : service_profile.topology_unhiding_service_cases()) {
      if (svc.service_type().direction() == ServiceContext::REQUEST) {
        req_svc.emplace_back(std::make_shared<ServiceCaseWrapper>(svc));
      } else if (svc.service_type().direction() == ServiceContext::RESPONSE) {
        resp_svc.emplace_back(std::make_shared<ServiceCaseWrapper>(svc));
      }
    }
    if (!req_svc.empty()) {
      svc_ctx_tuh_req_rp_map_[rp_name] = req_svc;
    }
    if (!resp_svc.empty()) {
      svc_ctx_tuh_resp_rp_map_[rp_name] = resp_svc;
    }
  }
}

void EricProxyFilterConfig::populateTopoHidingServiceCases(
  const TopologyHidingServiceProfile& service_profile, const std::string& rp_name
) {
  if (!service_profile.topology_hiding_service_cases().empty()) {
    std::map<std::string, std::map<std::string, std::shared_ptr<FilterCaseWrapper>>> req_fc_by_name_for_sc;
    std::map<std::string, std::map<std::string, std::shared_ptr<FilterCaseWrapper>>> resp_fc_by_name_for_sc;
    for (const auto& svc_case : service_profile.topology_hiding_service_cases()) {
      ENVOY_LOG(debug, "-- Processing service case: {}", svc_case.service_case_name());
      if (
        svc_case.service_type().direction() == ServiceContext::REQUEST ||
        (svc_case.service_type().is_notification() && isOriginInt())
      ) {
        std::map<std::string, std::shared_ptr<FilterCaseWrapper>> fc_by_name;
        if (req_fc_by_name_for_sc.find(svc_case.service_case_name()) ==
            req_fc_by_name_for_sc.end()) {
          // Create FC Wrapper for main filter case
          ENVOY_LOG(debug, "-- Processing filter case: {}", svc_case.filter_case().name());
          auto fcWrapper = std::make_shared<FilterCaseWrapper>(svc_case.filter_case());
          fc_by_name[fcWrapper->name()] = fcWrapper;
          for (auto fd : svc_case.filter_case().filter_data()) {
            auto fdWrapper = std::make_shared<FilterDataWrapper>(fd);
            populateRootContextForFilterData(fdWrapper);
            for (auto var_cg_entry : fdWrapper->varCaptureGroups()) {
              fcWrapper->insertVarFilterData(var_cg_entry.second, fdWrapper);
            }
          }
          // Create FC Wrapper for failure filter cases
          if (!service_profile.unsuccessful_operation_filter_cases().empty()) {
            // Append failure FC's to existing map
            for (auto fc : service_profile.unsuccessful_operation_filter_cases()) {
              ENVOY_LOG(debug, "-- Processing filter case: {}", fc.name());
              auto fcWrapper = std::make_shared<FilterCaseWrapper>(fc);
              fc_by_name[fcWrapper->name()] = fcWrapper;
              for (auto fd : fc.filter_data()) {
                auto fdWrapper = std::make_shared<FilterDataWrapper>(fd);
                populateRootContextForFilterData(fdWrapper);
                for (auto var_cg_entry : fdWrapper->varCaptureGroups()) {
                  fcWrapper->insertVarFilterData(var_cg_entry.second, fdWrapper);
                }
              }
            }
          }
          // Create FR Wrappers for filter case of this service case
          ENVOY_LOG(debug, "++ Processing filter case: {}.", svc_case.filter_case().name());
          for (auto fr : svc_case.filter_case().filter_rules()) {
            auto fc_wrapper = fc_by_name[svc_case.filter_case().name()];
            auto frWrapper = std::make_shared<FilterRuleWrapper>(fc_wrapper, fr);
            frWrapper->insertCompiledCondition(root_ctx_);
            frWrapper->insertActions(root_ctx_);
            fc_wrapper->addFilterRule(frWrapper);
          }
          // Create FRWapper for failure filter cases of this service case
          for (const auto& fc : service_profile.unsuccessful_operation_filter_cases()) {
            ENVOY_LOG(debug, "++ Processing filter case: {}.", fc.name());
            for (auto fr : fc.filter_rules()) {
              auto fc_wrapper = fc_by_name[fc.name()];
              auto frWrapper = std::make_shared<FilterRuleWrapper>(fc_wrapper, fr);
              frWrapper->insertCompiledCondition(root_ctx_);
              frWrapper->insertActions(root_ctx_);
              fc_wrapper->addFilterRule(frWrapper);
            }
          }
          // Couldn't find the service case in map then add it
          req_fc_by_name_for_sc[svc_case.service_case_name()] = fc_by_name;
        }
      } else {
        if (resp_fc_by_name_for_sc.find(svc_case.service_case_name()) ==
            resp_fc_by_name_for_sc.end()) {
          std::map<std::string, std::shared_ptr<FilterCaseWrapper>> fc_by_name;
          // Create FC Wrapper for main filter case
          ENVOY_LOG(debug, "-- Processing filter case: {}", svc_case.filter_case().name());
          auto fcWrapper = std::make_shared<FilterCaseWrapper>(svc_case.filter_case());
          fc_by_name[svc_case.filter_case().name()] = fcWrapper;
          for (auto fd: svc_case.filter_case().filter_data()) {
            auto fdWrapper = std::make_shared<FilterDataWrapper>(fd);
            populateRootContextForFilterData(fdWrapper);
            for (auto var_cg_entry : fdWrapper->varCaptureGroups()) {
              fcWrapper->insertVarFilterData(var_cg_entry.second, fdWrapper);
            }
          }
          // Create FC Wrapper for failure filter cases
          if (!service_profile.unsuccessful_operation_filter_cases().empty()) {
            // Append failure FC's to existing map
            for (auto fc : service_profile.unsuccessful_operation_filter_cases()) {
              ENVOY_LOG(debug, "-- Processing filter case: {}", fc.name());
              auto fcWrapper = std::make_shared<FilterCaseWrapper>(fc);
              fc_by_name[fcWrapper->name()] = fcWrapper;
              for (auto fd : svc_case.filter_case().filter_data()) {
                auto fdWrapper = std::make_shared<FilterDataWrapper>(fd);
                populateRootContextForFilterData(fdWrapper);
                for (auto var_cg_entry : fdWrapper->varCaptureGroups()) {
                  fcWrapper->insertVarFilterData(var_cg_entry.second, fdWrapper);
                }
              }
            }
          }
          // Create FR Wrappers for all filter cases of this service case
          ENVOY_LOG(debug, "++ Processing filter case: {}.", svc_case.filter_case().name());
          for (auto fr : svc_case.filter_case().filter_rules()) {
            auto fc_wrapper = fc_by_name[svc_case.filter_case().name()];
            auto frWrapper = std::make_shared<FilterRuleWrapper>(fc_wrapper, fr);
            frWrapper->insertCompiledCondition(root_ctx_);
            frWrapper->insertActions(root_ctx_);
            fc_wrapper->addFilterRule(frWrapper);
          }
          // Create FRWapper for failure filter cases of this service case
          for (const auto& fc : service_profile.unsuccessful_operation_filter_cases()) {
            ENVOY_LOG(debug, "++ Processing filter case: {}.", fc.name());
            for (auto fr : fc.filter_rules()) {
              auto fc_wrapper = fc_by_name[fc.name()];
              auto frWrapper = std::make_shared<FilterRuleWrapper>(fc_wrapper, fr);
              frWrapper->insertCompiledCondition(root_ctx_);
              frWrapper->insertActions(root_ctx_);
              fc_wrapper->addFilterRule(frWrapper);
            }
          }
          // Couldn't find the service case in map then add it
          resp_fc_by_name_for_sc[svc_case.service_case_name()] = fc_by_name;
        }
      }
    }
    if (!req_fc_by_name_for_sc.empty()) {
      topo_hide_req_filter_case_by_sc_name_for_rp_map_[rp_name] = req_fc_by_name_for_sc;
    }
    if (!resp_fc_by_name_for_sc.empty()) {
      topo_hide_resp_filter_case_by_sc_name_for_rp_map_[rp_name] = resp_fc_by_name_for_sc;
    }
  }
}

void EricProxyFilterConfig::populateTopoUnhidingServiceCases(
  const TopologyHidingServiceProfile& service_profile, const std::string& rp_name
) {
  if (!service_profile.topology_unhiding_service_cases().empty()) {
    std::map<std::string, std::map<std::string, std::shared_ptr<FilterCaseWrapper>>> req_fc_by_name_for_sc;
    std::map<std::string, std::map<std::string, std::shared_ptr<FilterCaseWrapper>>> resp_fc_by_name_for_sc;
    for (const auto& svc_case : service_profile.topology_unhiding_service_cases()) {
      ENVOY_LOG(debug, "-- Processing service case: {}", svc_case.service_case_name());
      if (
        svc_case.service_type().direction() == ServiceContext::REQUEST ||
        (svc_case.service_type().is_notification() && isOriginExt())
      ) {
        std::map<std::string, std::shared_ptr<FilterCaseWrapper>> fc_by_name;
        if (req_fc_by_name_for_sc.find(svc_case.service_case_name()) ==
            req_fc_by_name_for_sc.end()) {
          // Create FC Wrapper for main filter case
          ENVOY_LOG(debug, "-- Processing filter case: {}", svc_case.filter_case().name());
          auto fcWrapper = std::make_shared<FilterCaseWrapper>(svc_case.filter_case());
          fc_by_name[fcWrapper->name()] = fcWrapper;
          for (auto fd : svc_case.filter_case().filter_data()) {
            auto fdWrapper = std::make_shared<FilterDataWrapper>(fd);
            populateRootContextForFilterData(fdWrapper);
            for (auto var_cg_entry : fdWrapper->varCaptureGroups()) {
              fcWrapper->insertVarFilterData(var_cg_entry.second, fdWrapper);
            }
          }
          // Create FC Wrapper for failure filter cases
          if (!service_profile.unsuccessful_operation_filter_cases().empty()) {
            // Append failure FC's to existing map
            for (auto fc : service_profile.unsuccessful_operation_filter_cases()) {
              ENVOY_LOG(debug, "-- Processing filter case: {}", fc.name());
              auto fcWrapper = std::make_shared<FilterCaseWrapper>(fc);
              fc_by_name[fcWrapper->name()] = fcWrapper;
              for (auto fd : fc.filter_data()) {
                auto fdWrapper = std::make_shared<FilterDataWrapper>(fd);
                populateRootContextForFilterData(fdWrapper);
                for (auto var_cg_entry : fdWrapper->varCaptureGroups()) {
                  fcWrapper->insertVarFilterData(var_cg_entry.second, fdWrapper);
                }
              }
            }
          }
          // Create FR Wrappers for filter case of this service case
          ENVOY_LOG(debug, "++ Processing filter case: {}.", svc_case.filter_case().name());
          for (auto fr : svc_case.filter_case().filter_rules()) {
            auto fc_wrapper = fc_by_name[svc_case.filter_case().name()];
            auto frWrapper = std::make_shared<FilterRuleWrapper>(fc_wrapper, fr);
            frWrapper->insertCompiledCondition(root_ctx_);
            frWrapper->insertActions(root_ctx_);
            fc_wrapper->addFilterRule(frWrapper);
          }
          // Create FRWapper for failure filter cases of this service case
          for (const auto& fc : service_profile.unsuccessful_operation_filter_cases()) {
            ENVOY_LOG(debug, "++ Processing filter case: {}.", fc.name());
            for (auto fr : fc.filter_rules()) {
              auto fc_wrapper = fc_by_name[fc.name()];
              auto frWrapper = std::make_shared<FilterRuleWrapper>(fc_wrapper, fr);
              frWrapper->insertCompiledCondition(root_ctx_);
              frWrapper->insertActions(root_ctx_);
              fc_wrapper->addFilterRule(frWrapper);
            }
          }
          // Couldn't find the service case in map then add it
          req_fc_by_name_for_sc[svc_case.service_case_name()] = fc_by_name;
        }
      } else {
        if (resp_fc_by_name_for_sc.find(svc_case.service_case_name()) ==
            resp_fc_by_name_for_sc.end()) {
          std::map<std::string, std::shared_ptr<FilterCaseWrapper>> fc_by_name;
          // Create FC Wrapper for main filter case
          ENVOY_LOG(debug, "-- Processing filter case: {}", svc_case.filter_case().name());
          auto fcWrapper = std::make_shared<FilterCaseWrapper>(svc_case.filter_case());
          fc_by_name[fcWrapper->name()] = fcWrapper;
          for (auto fd : svc_case.filter_case().filter_data()) {
            auto fdWrapper = std::make_shared<FilterDataWrapper>(fd);
            populateRootContextForFilterData(fdWrapper);
            for (auto var_cg_entry : fdWrapper->varCaptureGroups()) {
              fcWrapper->insertVarFilterData(var_cg_entry.second,fdWrapper);
            }
          }
          // Create FC Wrapper for failure filter cases
          if (!service_profile.unsuccessful_operation_filter_cases().empty()) {
            // Append failure FC's to existing map
            for (auto fc : service_profile.unsuccessful_operation_filter_cases()) {
              ENVOY_LOG(debug, "-- Processing filter case: {}", fc.name());
              auto fcWrapper = std::make_shared<FilterCaseWrapper>(fc);
              fc_by_name[fcWrapper->name()] = fcWrapper;
              for (auto fd : svc_case.filter_case().filter_data()) {
                auto fdWrapper = std::make_shared<FilterDataWrapper>(fd);
                populateRootContextForFilterData(fdWrapper);
                for (auto var_cg_entry : fdWrapper->varCaptureGroups()) {
                  fcWrapper->insertVarFilterData(var_cg_entry.second, fdWrapper);
                }
              }
            }
          }
          // Create FR Wrappers for all filter cases of this service case
          ENVOY_LOG(debug, "++ Processing filter case: {}.", svc_case.filter_case().name());
          for (auto fr : svc_case.filter_case().filter_rules()) {
            auto fc_wrapper = fc_by_name[svc_case.filter_case().name()];
            auto frWrapper = std::make_shared<FilterRuleWrapper>(fc_wrapper, fr);
            frWrapper->insertCompiledCondition(root_ctx_);
            frWrapper->insertActions(root_ctx_);
            fc_wrapper->addFilterRule(frWrapper);
          }
          // Create FRWapper for failure filter cases of this service case
          for (const auto& fc : service_profile.unsuccessful_operation_filter_cases()) {
            ENVOY_LOG(debug, "++ Processing filter case: {}.", fc.name());
            for (auto fr : fc.filter_rules()) {
              auto fc_wrapper = fc_by_name[fc.name()];
              auto frWrapper = std::make_shared<FilterRuleWrapper>(fc_wrapper, fr);
              frWrapper->insertCompiledCondition(root_ctx_);
              frWrapper->insertActions(root_ctx_);
              fc_wrapper->addFilterRule(frWrapper);
            }
          }
          // Couldn't find the service case in map then add it
          resp_fc_by_name_for_sc[svc_case.service_case_name()] = fc_by_name;
        }
      }
    }
    if (!req_fc_by_name_for_sc.empty()) {
      topo_unhide_req_filter_case_by_sc_name_for_rp_map_[rp_name] = req_fc_by_name_for_sc;
    }
    if (!resp_fc_by_name_for_sc.empty()) {
      topo_unhide_resp_filter_case_by_sc_name_for_rp_map_[rp_name] = resp_fc_by_name_for_sc;
    }
  }
}

// At config time, populate the via-header-context with the correct FQDN.
// For an internal listener, it's the *external* own FQDN,
// for an external listener, it's the *internal* own FQDN.
// The manager sends us these already correctly.
void EricProxyFilterConfig::populateViaHeaderCtx() {
  for(const auto& rp : proto_config_.roaming_partners()) {
      via_header_entries_[rp.name()] = rp.own_network_fqdn();
  }
}

// Basically only used for SEPP because of other limitations in model
std::string EricProxyFilterConfig::getFqdnForViaHeader(std::string rp_name) {
  const auto it = via_header_entries_.find(rp_name);
  if(it != via_header_entries_.end()) {
    return it->second;
  } else {
    return "";
  }
}

// Populate config for USFW USOC
void EricProxyFilterConfig::populateUsfwServiceValidationConfig() {
  if (!isSeppNode()) {
    return;
  }

  for (const auto& rp : proto_config_.roaming_partners()) {
    if (rp.has_request_validation() && rp.request_validation().has_check_service_operations()) {
      // Populate custom allowed service operation list
      if (!rp.request_validation().check_service_operations().custom_allowed_service_operations().empty()) {
        std::map<std::string, std::vector<std::shared_ptr<ServiceClassifierConfigBase>>> custom_allowed_service_operations_per_api_name;
        for (const auto& service_operation : rp.request_validation().check_service_operations().custom_allowed_service_operations()) {
          std::string service_name = "";
          if (service_operation.api_names().empty()) {
            if (custom_allowed_service_operations_per_api_name.find(service_name) == custom_allowed_service_operations_per_api_name.end()) {
              custom_allowed_service_operations_per_api_name.insert({service_name, std::vector<std::shared_ptr<ServiceClassifierConfigBase>> {}});
            }
            custom_allowed_service_operations_per_api_name.at(service_name).emplace_back(std::make_shared<MessageSelectorWrapper>(service_operation, service_name));
          } else {
            for (const auto& api_name : service_operation.api_names()) {
              if (!api_name.empty()) {
                service_name = api_name;
              }
              if (custom_allowed_service_operations_per_api_name.find(service_name) == custom_allowed_service_operations_per_api_name.end()) {
                custom_allowed_service_operations_per_api_name.insert({service_name, std::vector<std::shared_ptr<ServiceClassifierConfigBase>> {}});
              }
              custom_allowed_service_operations_per_api_name.at(service_name).emplace_back(std::make_shared<MessageSelectorWrapper>(service_operation, service_name));
            }
          }
        }
        custom_allowed_service_operations_per_api_name_for_rp_map_[rp.name()] = custom_allowed_service_operations_per_api_name;
      }

      // Populate custom denied service operation list
      if (!rp.request_validation().check_service_operations().custom_denied_service_operations().empty()) {
        std::map<std::string, std::vector<std::shared_ptr<ServiceClassifierConfigBase>>> custom_denied_service_operations_per_api_name;
        for (const auto& service_operation : rp.request_validation().check_service_operations().custom_denied_service_operations()) {
          std::string service_name = "";
          if (service_operation.api_names().empty()) {
            if (custom_denied_service_operations_per_api_name.find(service_name) == custom_denied_service_operations_per_api_name.end()) {
              custom_denied_service_operations_per_api_name.insert({service_name, std::vector<std::shared_ptr<ServiceClassifierConfigBase>> {}});
            }
            custom_denied_service_operations_per_api_name.at(service_name).emplace_back(std::make_shared<MessageSelectorWrapper>(service_operation, service_name));
          } else {
            for (const auto& api_name : service_operation.api_names()) {
              if (!api_name.empty()) {
                service_name = api_name;
              }
              if (custom_denied_service_operations_per_api_name.find(service_name) == custom_denied_service_operations_per_api_name.end()) {
                custom_denied_service_operations_per_api_name.insert({service_name, std::vector<std::shared_ptr<ServiceClassifierConfigBase>> {}});
              }
              custom_denied_service_operations_per_api_name.at(service_name).emplace_back(std::make_shared<MessageSelectorWrapper>(service_operation, service_name));
            }
          }
        }
        custom_denied_service_operations_per_api_name_for_rp_map_[rp.name()] = custom_denied_service_operations_per_api_name;
      }
    }
  }

  // Populate default allowed service operation list
  if (!proto_config_.default_allowed_service_operations().empty()) {
    for (const auto& service_operation : proto_config_.default_allowed_service_operations()) {
      std::string service_name = "";
      if (service_operation.api_names().empty()) {
        if (default_allowed_service_operations_per_api_name_map_.find(service_name) == default_allowed_service_operations_per_api_name_map_.end()) {
          default_allowed_service_operations_per_api_name_map_.insert({service_name, std::vector<std::shared_ptr<ServiceClassifierConfigBase>> {}});
        }
        default_allowed_service_operations_per_api_name_map_.at(service_name).emplace_back(std::make_shared<MessageSelectorWrapper>(service_operation, service_name));
      } else {
        for (const auto& api_name : service_operation.api_names()) {
          if (!api_name.empty()) {
            service_name = api_name;
          }
          if (default_allowed_service_operations_per_api_name_map_.find(service_name) == default_allowed_service_operations_per_api_name_map_.end()) {
            default_allowed_service_operations_per_api_name_map_.insert({service_name, std::vector<std::shared_ptr<ServiceClassifierConfigBase>> {}});
          }
          default_allowed_service_operations_per_api_name_map_.at(service_name).emplace_back(std::make_shared<MessageSelectorWrapper>(service_operation, service_name));
        }
      }
    }
  }
}

void EricProxyFilterConfig::populateUsfwActionsAfterThreshold() {
  // deletion of this pointer is handled by the ProtoMessage taking ownership
  // i.e request_action_after_threshold_ destructor deletes this pointer
  auto req_action = new RejectMessageAction();
  req_action->set_cause("UNSPECIFIED_MSG_FAILURE");
  req_action->set_detail("rejected_by_firewall");
  req_action->set_status(400);
  req_action->set_title("Bad Request");
  req_action->set_message_format(
      ::envoy::extensions::filters::http::eric_proxy::v3::MessageBodyType::JSON);
  request_action_after_threshold_.set_allocated_respond_with_error(req_action);

  auto resp_action = new RejectMessageAction();
  resp_action->set_cause("SYSTEM_FAILURE");
  resp_action->set_detail("too_many_offending_headers");
  resp_action->set_status(500);
  resp_action->set_title("Internal Server Error");
  resp_action->set_message_format(
      ::envoy::extensions::filters::http::eric_proxy::v3::MessageBodyType::JSON);
  response_action_after_threshold_.set_allocated_respond_with_error(resp_action);
}
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
