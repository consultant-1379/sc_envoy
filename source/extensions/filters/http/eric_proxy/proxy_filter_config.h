#pragma once

#include <list>
#include <memory>
#include <string>
#include <optional>
#include <tuple>
#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "source/common/common/logger.h"

#include "source/extensions/filters/http/eric_proxy/contexts.h"
#include "envoy/upstream/cluster_manager.h"
#include "re2/re2.h"


namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

class FilterPhaseWrapper;
class FilterCaseWrapper;
class FilterDataWrapper;
class FilterRuleWrapper;
class ServiceCaseWrapper;
class MessageSelectorWrapper;
class ServiceClassifierConfigBase;

using namespace google::protobuf;
using namespace ::envoy::extensions::filters::http::eric_proxy::v3;

using FilterCase = ::envoy::extensions::filters::http::eric_proxy::v3::FilterCase;
using KlvTable = ::envoy::extensions::filters::http::eric_proxy::v3::KlvTable;
using KvTable = ::envoy::extensions::filters::http::eric_proxy::v3::KvTable;
using FilterCaseProtoConfig = google::protobuf::RepeatedPtrField<FilterCase>;
using ConditionProtoConfig = envoy::extensions::filters::http::eric_proxy::v3::Condition;
using NetworkFilterPhaseConfig = ::envoy::extensions::filters::http::eric_proxy::v3::NetworkFilterPhaseConfig;
using FilterPhaseWrapperSharedPtr = std::shared_ptr<FilterPhaseWrapper>;
using MessageValidation = ::envoy::extensions::filters::http::eric_proxy::v3::MessageValidation;
using ServiceContext = ::envoy::extensions::filters::http::eric_proxy::v3::TopologyHidingServiceProfile::ServiceContext;
using ServiceCaseConfig = ::envoy::extensions::filters::http::eric_proxy::v3::TopologyHidingServiceProfile::ServiceCase;
using TopologyHidingServiceProfile = ::envoy::extensions::filters::http::eric_proxy::v3::TopologyHidingServiceProfile;

using ValueIndex = std::uint16_t;
using CaptureGroup = std::uint16_t;

enum class IPver {
  Default,
  IPv4,
  IPv6,
  DualStack // currently unsupported
};

// Cluster Typed Metadata Object and Factory for EricProxy
struct EricProxyClusterTypedMetadataObject : public Envoy::Config::TypedMetadata::Object {
  EricProxyClusterTypedMetadataObject(std::map<std::string, std::vector<std::tuple<std::string, std::string,IPver>>> md,
                                      IPver ip_family, bool preferred_host_retry_multiple_address) 
  : producer_proxy_map(md) , preferred_ip_family_(ip_family), preferred_host_retry_multiple_address_(preferred_host_retry_multiple_address){}
  std::map<std::string, std::vector<std::tuple<std::string, std::string,IPver>>> producer_proxy_map;
  IPver preferred_ip_family_;
  bool preferred_host_retry_multiple_address_;
};

class EricProxyClusterTypedMetadataFactory : public Upstream::ClusterTypedMetadataFactory {
public:
  std::string name() const override { return "envoy.eric_proxy.cluster"; }
  // Returns nullptr (conversion failure) if md is empty.
  std::unique_ptr<const Envoy::Config::TypedMetadata::Object>
  parse(const ProtobufWkt::Struct& md) const override {
    ENVOY_LOG_MISC(trace, "EricProxyClusterTypedMetadataFactory: parsing md to typed class object (EricProxyClusterTypedMetadataObject)");
    if (!md.fields().empty()) {
      try {
        std::map<std::string, std::vector<std::tuple<std::string, std::string,IPver>>> producer_proxy_map;
        IPver preferred_ip_family = IPver::Default;
        bool retry_multiple_address = false;

        for (auto& producer_proxy : md.fields()) {
          ENVOY_LOG_MISC(trace, "field key: '{}'", producer_proxy.first); // prod_proxy.first : producer
          std::vector<std::tuple<std::string, std::string,IPver>> proxy_list; // fqdn and ip of gateway(s) to producer
          for (auto& proxy : producer_proxy.second.list_value().values()) { 
            std::string fqdn{""};
            if (proxy.struct_value().fields().contains("fqdn")) {
              fqdn = proxy.struct_value().fields().at("fqdn").string_value();
            }
            std::string ip{""};
            if (proxy.struct_value().fields().contains("ip")) {
              ip = proxy.struct_value().fields().at("ip").string_value();
            }
            IPver ip_fam = IPver::Default;
            if(proxy.struct_value().fields().contains("ip_family")){
              if(proxy.struct_value().fields().at("ip_family").string_value() == "IPv4") {
                ip_fam = IPver::IPv4;
                ENVOY_LOG_MISC(debug, "IP family:IPv4");
              } else if(proxy.struct_value().fields().at("ip_family").string_value() == "IPv6") {
                ip_fam = IPver::IPv6;
                ENVOY_LOG_MISC(debug, "IP family:IPv6");
              }
            }
            if(! fqdn.empty() || !ip.empty()){
              ENVOY_LOG_MISC(trace, "proxy: fqdn: '{}', ip: '{}'", fqdn, ip);
              proxy_list.push_back(std::tuple<std::string,std::string,IPver>(fqdn, ip,ip_fam));
            }
          }
          // EndpointPolicy begins
          if (producer_proxy.first == "endpoint_policy") {
            if(producer_proxy.second.struct_value().fields().contains("preferred_ip_family")){
              if (producer_proxy.second.struct_value()
                      .fields()
                      .at("preferred_ip_family")
                      .string_value() == "IPv4") {
                preferred_ip_family = IPver::IPv4;
                ENVOY_LOG_MISC(debug, "Preferred IP family:IPv4");
              } else if (producer_proxy.second.struct_value()
                             .fields()
                             .at("preferred_ip_family")
                             .string_value() == "IPv6") {
                preferred_ip_family = IPver::IPv6;
                ENVOY_LOG_MISC(debug, "Preferred IP family:IPv6");
              }
            }
            if(producer_proxy.second.struct_value().fields().contains("preferred_host_retry_multiple_address")){
              if (producer_proxy.second.struct_value()
                      .fields()
                      .at("preferred_host_retry_multiple_address")
                      .has_string_value() &&
                  producer_proxy.second.struct_value()
                          .fields()
                          .at("preferred_host_retry_multiple_address")
                          .string_value() == "true") {
                retry_multiple_address = true;
                ENVOY_LOG_MISC(debug, "Retry policy:{}", fmt::format("{}", retry_multiple_address));
              } else {
                retry_multiple_address = false;
                ENVOY_LOG_MISC(debug, "Retry policy:{}", fmt::format("{}", retry_multiple_address));
              }
            }
          }
          producer_proxy_map.emplace(producer_proxy.first, proxy_list);
        }
        return std::make_unique<EricProxyClusterTypedMetadataObject>(producer_proxy_map,
                                                                      preferred_ip_family,
                                                                      retry_multiple_address);
      } catch (...) {
        throw EnvoyException("Parsing error while creating a EricProxyClusterTypedMetadataObject.");
      }
    }
    throw EnvoyException("Cannot create a EricProxyClusterTypedMetadataObject when metadata is empty.");
  }

  std::unique_ptr<const Envoy::Config::TypedMetadata::Object>
  parse(const ProtobufWkt::Any&) const override {
    return nullptr;
  }
};

class EricProxyFilterConfig : public Logger::Loggable<Logger::Id::eric_proxy> {
public:
  EricProxyFilterConfig(const EricProxyConfig& proto_config, Upstream::ClusterManager& cluster_manager);

  const FilterCaseProtoConfig& filterCases() const { return filter_cases_; }

  const EricProxyConfig& protoConfig() const { return proto_config_; }
  const std::string nodeTypeLc() const { return isScpNode() ? "scp": "sepp"; }
  const std::string nodeTypeUc() const { return isScpNode() ? "SCP": "SEPP"; }
  bool isSeppNode() const { return (proto_config_.node_type() == SEPP); }
  bool isScpNode() const { return (proto_config_.node_type() == SCP); }
  bool isOriginInt() const { return (proto_config_.own_internal_port() != 0); }
  bool isOriginExt() const { return (proto_config_.own_external_port() != 0); }
  // Control plane means request comes from the manager. This is for the n32c dedicated listener
  // where eric_proxy is is configured for egress screening
  bool isOriginControlPlane() const { return proto_config_.control_plane(); }
  std::map<const std::string, const  RE2>& getDnToRegexTable()  {return dn_to_re2_regex_table_;}

  // All configured NF-types that require TFQDN, all lowercase:
  std::vector<Http::LowerCaseString> nfTypesRequiringTFqdnLc() const { return nf_types_requiring_tfqdn_; }
  // The own FQDN, all lowercase is guaranteed:
  const std::string& ownFqdnLc() const { return own_fqdn_lc_; }
  const std::string& ownFqdnWithIntPortLc() const { return own_fqdn_with_int_port_lc_; }
  const std::string& ownFqdnWithExtPortLc() const { return own_fqdn_with_ext_port_lc_; }
  const std::string& networkIdHeaderValue() const { return network_id_header_val_; }
  const bool& isTFqdnConfigured() const { return is_tfqdn_configured_; }
  Upstream::ClusterManager& clusterManager() const { return cluster_manager_; }
  RootContext& rootContext() { return root_ctx_; }
  bool isNfPeerinfoActivated() const { return proto_config_.nf_peer_info_handling() == envoy::extensions::filters::http::eric_proxy::v3::ON; }

  // Return the pool/cluster for the given pool
  std::string rpPoolName(std::string);
  std::shared_ptr<FilterPhaseWrapper> fp_routing_;
  std::shared_ptr<FilterPhaseWrapper> fp_in_req_screening_;
  std::shared_ptr<FilterPhaseWrapper> fp_out_resp_screening_;
  std::shared_ptr<FilterPhaseWrapper> fp_out_req_screening_;
  std::shared_ptr<FilterPhaseWrapper> fp_in_resp_screening_;
  void populateAllFilterPhaseData();
  void populateRoutingScreening16FilterPhaseData(const NetworkFilterPhaseConfig& fp_config, FilterPhaseWrapperSharedPtr fp_wrapper);
  void populateScreening34FilterPhaseData(const ClusterFilterPhaseConfig& fp_config,
                                          FilterPhaseWrapperSharedPtr fp_wrapper);
  std::shared_ptr<FilterCaseWrapper> filterCaseByName(std::string& fc_name) {
    return fc_by_name_map_[fc_name];
  };

  void populateRootContextForFilterData(std::shared_ptr<FilterDataWrapper>);

  // The IP-version to use (4, 6, dual-stack), determined from the environment variable "IP_VERSION"
  IPver ip_version_;

  // Return regular expressions for TH IP Hiding
  std::regex regexIpv4Addresses() { return regex_ipv4_addresses_; };
  std::regex regexIpv6Addresses() { return regex_ipv6_addresses_; };
  std::regex regexIpv4Address() { return regex_ipv4_address_; };
  std::regex regexIpv6Address() { return regex_ipv6_address_; };
  std::map<std::string,std::map<std::string,std::vector<Network::Address::CidrRange>>>
    getSubnetCidrNfTypePerRp(bool ipv4);

  // Helper functions for NRF FQDN Mapping & FQDN scrambling
  std::shared_ptr<FilterCaseWrapper> getFilterCaseByNameForServiceCaseForRP(
    const std::string& rp_name, const std::string& sc_name, const std::string& fc_name,
    const bool& is_req, const bool& is_topo_hiding
  );
  std::vector<std::shared_ptr<ServiceCaseWrapper>> getServiceCaseVectorForRP(
    const std::string& rp_name, const bool& is_req,
    const bool& is_topo_hiding
  );

  // Helper functions for USFW USOC
  std::vector<std::shared_ptr<ServiceClassifierConfigBase>>
      getCustomAllowedServiceOperationsPerApiNameForRp(const std::string& rp_name, const std::string& api_name);
  std::vector<std::shared_ptr<ServiceClassifierConfigBase>>
      getCustomDeniedServiceOperationsPerApiNameForRp(const std::string& rp_name, const std::string& api_name);
  std::vector<std::shared_ptr<ServiceClassifierConfigBase>>
      getDefaultAllowedServiceOperationsPerApiName(const std::string& api_name);

 // Helper functions for integration tests only
 // Not used within the code
 // Use the other helper function to get easy access to FilterCaseWrapers 
  std::map<std::string, std::map<std::string, std::map<std::string, std::shared_ptr<FilterCaseWrapper>>>>
    getThReqServiceCases()
  { return topo_hide_req_filter_case_by_sc_name_for_rp_map_; }
  std::map<std::string, std::map<std::string, std::map<std::string, std::shared_ptr<FilterCaseWrapper>>>>
    getThRespServiceCases()
  { return topo_hide_resp_filter_case_by_sc_name_for_rp_map_; }
  std::map<std::string, std::map<std::string, std::map<std::string, std::shared_ptr<FilterCaseWrapper>>>>
    getTuhReqServiceCases()
  { return topo_unhide_req_filter_case_by_sc_name_for_rp_map_; }
  std::map<std::string, std::map<std::string, std::map<std::string, std::shared_ptr<FilterCaseWrapper>>>>
    getTuhRespServiceCases()
  { return topo_unhide_resp_filter_case_by_sc_name_for_rp_map_; }
  
  std::map<std::string, std::vector<std::shared_ptr<ServiceCaseWrapper>>>
    getThReqServiceCtx()
  { return svc_ctx_th_req_rp_map_; }
  std::map<std::string, std::vector<std::shared_ptr<ServiceCaseWrapper>>>
    getThRespServiceCtx()
  { return svc_ctx_th_resp_rp_map_; }
  std::map<std::string, std::vector<std::shared_ptr<ServiceCaseWrapper>>>
    getTuhReqServiceCtx()
  { return svc_ctx_tuh_req_rp_map_; }
  std::map<std::string, std::vector<std::shared_ptr<ServiceCaseWrapper>>>
    getTuhRespServiceCtx()
  { return svc_ctx_tuh_resp_rp_map_; }

  ActionOnFailure request_action_after_threshold_;
  ActionOnFailure response_action_after_threshold_;

  void populateViaHeaderCtx() ;
 
  std::string getFqdnForViaHeader(std::string rp_name);
  
private:
  const EricProxyConfig proto_config_;
  const RepeatedPtrField<FilterCase> filter_cases_;
  Upstream::ClusterManager& cluster_manager_;

  // Regular expressions for TH IP Hiding
  std::regex regex_ipv4_addresses_;
  std::regex regex_ipv6_addresses_;
  std::regex regex_ipv4_address_;
  std::regex regex_ipv6_address_;

  // Subnet Cidr Map for TH IP Hiding for Notify Messages
  std::map<std::string /* RP Name */,std::map<std::string/* nf-type */,
                                              std::vector<Network::Address::CidrRange>>> 
                                              ipv4_subnet_cidr_per_target_nf_type_;
  std::map<std::string /* RP Name */,std::map<std::string/* nf-type */,
                                              std::vector<Network::Address::CidrRange>>> 
                                              ipv6_subnet_cidr_per_target_nf_type_;

  std::vector<Http::LowerCaseString> nf_types_requiring_tfqdn_;
  const std::string own_fqdn_lc_; // always lowercase because FQDNs are case-insensitive
  const std::string own_fqdn_with_int_port_lc_;
  const std::string own_fqdn_with_ext_port_lc_;
  // DND-601513: gpp-sbi-originating-network-id header handling. Hardcoded header value for when the
  // SEPP adds the header, instead of constructing it repeatedly on runtime
  const std::string network_id_header_val_;
  bool is_tfqdn_configured_ = false;
  RootContext root_ctx_; // common for all requests

  std::map<std::string, std::string> rp_pool_map_;

  // A map containing domain names mapped to their precompiled re2 regexes.
  // to be used in wildcard certificate matching for sepp
  std::map<const std::string, const RE2> dn_to_re2_regex_table_;
  std::map<std::string, std::shared_ptr<FilterCaseWrapper>> fc_by_name_map_;
  // Read variable and header header names
  // and place them in the root context
  void populateRootContext();
  void populateRpPoolMap();
  void populateNfTypesTFqdn();
  void populateDnToRe2KvTable();

  // Populate regular expressions for TH IP Hiding
  void populateRegexThIpHiding();

  // Convert the protobuf config map<nf-type,subnetRange> per RP
  // to map<rp,map<nf-type,Network::Address:CidrRange>>
  void populateCidrRangePerNfTypePerRp();

  // Populate Service Case Configs for NRF FQDN Mapping & FQDN scrambling
  void populateServiceCaseConfig();

  // Populate USFW USOC service validation config
  void populateUsfwServiceValidationConfig();

  // Populate USFW actions after threshold is reached for header checks
  void populateUsfwActionsAfterThreshold();

  // map<rp-name, map<sc-name, map<fc-name, fc-wrapper>>>
  std::map<std::string,
           std::map<std::string, std::map<std::string, std::shared_ptr<FilterCaseWrapper>>>>
      topo_hide_req_filter_case_by_sc_name_for_rp_map_;
  std::map<std::string,
           std::map<std::string, std::map<std::string, std::shared_ptr<FilterCaseWrapper>>>>
      topo_hide_resp_filter_case_by_sc_name_for_rp_map_;
  std::map<std::string,
           std::map<std::string, std::map<std::string, std::shared_ptr<FilterCaseWrapper>>>>
      topo_unhide_req_filter_case_by_sc_name_for_rp_map_;
  std::map<std::string,
           std::map<std::string, std::map<std::string, std::shared_ptr<FilterCaseWrapper>>>>
      topo_unhide_resp_filter_case_by_sc_name_for_rp_map_;

  void populateTopoHidingServiceCases(const TopologyHidingServiceProfile& service_profile,
                                      const std::string& rp_name);
  void populateTopoUnhidingServiceCases(const TopologyHidingServiceProfile& service_profile,
                                        const std::string& rp_name);
  void populateSvcContextPerRPMap(const TopologyHidingServiceProfile& service_profile,
                                  const std::string& rp_name);

  // RP Name to Service Case Config
  std::map<std::string, std::vector<std::shared_ptr<ServiceCaseWrapper>>> svc_ctx_th_req_rp_map_;
  std::map<std::string, std::vector<std::shared_ptr<ServiceCaseWrapper>>> svc_ctx_th_resp_rp_map_;
  std::map<std::string, std::vector<std::shared_ptr<ServiceCaseWrapper>>> svc_ctx_tuh_req_rp_map_;
  std::map<std::string, std::vector<std::shared_ptr<ServiceCaseWrapper>>> svc_ctx_tuh_resp_rp_map_;

  // Data Structures needed for USFW USOC
  std::map<std::string, std::map<std::string, std::vector<std::shared_ptr<ServiceClassifierConfigBase>>>>
      custom_allowed_service_operations_per_api_name_for_rp_map_;
  std::map<std::string, std::map<std::string, std::vector<std::shared_ptr<ServiceClassifierConfigBase>>>>
      custom_denied_service_operations_per_api_name_for_rp_map_;
  std::map<std::string, std::vector<std::shared_ptr<ServiceClassifierConfigBase>>>
      default_allowed_service_operations_per_api_name_map_;

  //Via header entries for the SEPP per roaming partner
  std::map<std::string,std::string> via_header_entries_;
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
