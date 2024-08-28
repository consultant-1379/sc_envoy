#pragma once

#include <memory>
#include <string>

#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "google/protobuf/message.h"
#include "source/common/common/logger.h"
#include "source/common/common/statusor.h"
#include "source/extensions/filters/http/eric_proxy/contexts.h"
#include "source/extensions/filters/http/eric_proxy/condition_config.h"

#include "re2/re2.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using namespace re2;
using namespace google::protobuf;
using namespace ::envoy::extensions::filters::http::eric_proxy::v3;

using FilterData = ::envoy::extensions::filters::http::eric_proxy::v3::FilterData;
using FilterCase = ::envoy::extensions::filters::http::eric_proxy::v3::FilterCase;
using SeppTHServiceCase = ::envoy::extensions::filters::http::eric_proxy::v3::TopologyHidingServiceProfile::ServiceCase;
using FilterCaseProtoConfig = google::protobuf::RepeatedPtrField<FilterCase>;
using Action = ::envoy::extensions::filters::http::eric_proxy::v3::Action;
using ConditionLogValue = envoy::extensions::filters::http::eric_proxy::v3::LogValue;

using CheckServiceOperations = ::envoy::extensions::filters::http::eric_proxy::v3::CheckServiceOperations;
using MessageSelectorConfig = ::envoy::extensions::filters::http::eric_proxy::v3::MessageSelector;

using VarHeaderConstValue = envoy::extensions::filters::http::eric_proxy::v3::VarHeaderConstValue;
using ValueIndex = std::uint16_t;
using CaptureGroup = std::uint16_t;


//------- Filter Data Wrapper -----------------------------------------------
class FilterDataWrapper : public Logger::Loggable<Logger::Id::eric_proxy> {
public:
  FilterDataWrapper(const FilterData fd_proto_config);
  const std::map<CaptureGroup, ValueIndex>& varCaptureGroups() const { return var_capture_groups_; }

  const std::string& name() const { return fd_proto_config_.name(); }
  const std::string& extractorRegex() const { return fd_proto_config_.extractor_regex(); }
  const std::string& variableName() const { return fd_proto_config_.variable_name(); }

  bool sourceIsPath() const { return fd_proto_config_.path(); }

  bool sourceIsHeader() const { return fd_proto_config_.has_header(); }
  const std::string sourceHeader() const { return fd_proto_config_.header(); }

  bool sourceIsReqHeader() const { return fd_proto_config_.has_request_header(); }
  const std::string sourceReqHeader() const { return fd_proto_config_.request_header(); }

  bool sourceIsRespHeader() const { return fd_proto_config_.has_response_header(); }
  const std::string sourceRespHeader() const { return fd_proto_config_.response_header(); }

  bool sourceIsBodyJsonPointer() const { return fd_proto_config_.has_body_json_pointer(); }
  const std::string sourceBodyJsonPointer() const { return fd_proto_config_.body_json_pointer(); }

  const RE2& re2ExtractorRegex() const { return extractor_regex_re2_; }
  void insertCaptureGroupAtIndex(CaptureGroup, ValueIndex);

private:
  const FilterData fd_proto_config_;
  const RE2 extractor_regex_re2_;
  std::map<CaptureGroup, ValueIndex> var_capture_groups_;
};

//------- Service Classifier Config Base --------------------------------------
class ServiceClassifierConfigBase : public Logger::Loggable<Logger::Id::eric_proxy> {
public:
  // Method to evaluate the comparison between configured
  // service context and request service context
  bool eval(RunContext* run_ctx);

  // A string representation for debugging
  std::string debugString();

protected:
  std::string api_name_;
  std::vector<std::string> api_versions_;
  std::vector<std::string> methods_;
  bool is_notification_ = false;
  std::vector<std::pair<std::string, std::regex>> resource_matchers_;

private:
  bool evalApiName(const std::string& req_api_name);
  bool evalApiVersions(const std::string& req_api_version);
  bool evalMethods(const std::string& req_method);
  bool evalIsNotification(const bool& is_notification_req);
  bool evalResourceMatchers(const std::string& req_resource);
};

//------- Service Case Wrapper -----------------------------------------------
// A wrapper to support helper attributes over a service case for a 
// service classifier 
// Evaluate if a given service case matches the sbi information of a given
// request stored in the filter's run_ctx_
class ServiceCaseWrapper : public  ServiceClassifierConfigBase {
public:
  ServiceCaseWrapper(const ServiceCaseConfig& config) : proto_config_(config) {
    sc_name_ = proto_config_.service_case_name();
    api_name_ = proto_config_.service_type().api_name();
    api_versions_.push_back(proto_config_.service_type().api_version());
    methods_.push_back(proto_config_.service_type().http_method());
    is_notification_ = proto_config_.service_type().is_notification();
    resource_matchers_.push_back(std::make_pair(proto_config_.service_type().resource_matcher(),
        std::regex(proto_config_.service_type().resource_matcher())));
  }

  std::string getServiceCaseName() { return sc_name_; }
  std::string getMainFilterCaseName() { return proto_config_.filter_case().name(); }

private:
  std::string sc_name_;
  const ServiceCaseConfig proto_config_;
};

//------- Message Selector Wrapper --------------------------------------------
class MessageSelectorWrapper : public ServiceClassifierConfigBase {
public:
  MessageSelectorWrapper(const MessageSelectorConfig& config, const std::string& api_name) {
    api_name_ = api_name;
    for (const auto& api_version : config.api_versions()) {
      api_versions_.push_back(api_version);
    }
    for (const auto& method : config.http_methods()) {
      methods_.push_back(method);
    }
    is_notification_ = config.is_notification();
    for (const auto& resource_matcher : config.resource_matchers()) {
      resource_matchers_.push_back(std::make_pair(resource_matcher, std::regex(resource_matcher)));
    }
  }
};

//------- Filter Action Wrapper -----------------------------------------------
// This is the base-class that only holds the data of the original action.
// Some actions need to sub-class this and implement specialized methods
// for updateRequiredVars() if:
// - the action uses variables -> implement updateRequiredVars()
// - there is data in an action that can be pre-calculated at config-time
class FilterActionWrapper : public Logger::Loggable<Logger::Id::eric_proxy> {
public:
  FilterActionWrapper(const Action fa_proto_config, FilterRuleWrapper* parent)
    : parent_(parent),
      fa_proto_config_(fa_proto_config) {};
  virtual ~FilterActionWrapper() = default;

  const Action& protoConfig() const {return fa_proto_config_;}

  // Mark the variables and headers required by an action to be
  // pre-loaded into the run-context
  virtual void updateRequiredVars(RootContext&) {};

  // Helper for updateRequiredVars for VarHeaderConstValue-type
  // parameters to register the variable/header
  void updateTermVarHeader(RootContext&, const VarHeaderConstValue&);

  virtual void preCompiledData(RootContext&) {};

  FilterRuleWrapper* parent_;

private:
  const Action fa_proto_config_;
};


// Action Route To Pool Wrapper
class ActionRouteToPoolWrapper : public FilterActionWrapper {
public:
  ActionRouteToPoolWrapper(const Action fa_proto_config, FilterRuleWrapper* parent)
      : FilterActionWrapper(fa_proto_config, parent) {};
  void updateRequiredVars(RootContext& root_ctx) override;
};

// Action Route To RoamingPartner Wrapper
class ActionRouteToRoamingPartnerWrapper : public FilterActionWrapper {
public:
  ActionRouteToRoamingPartnerWrapper(const Action fa_proto_config, FilterRuleWrapper* parent)
      : FilterActionWrapper(fa_proto_config, parent) {};
  void updateRequiredVars(RootContext& root_ctx) override;
};

// Action Add Header Wrapper
class ActionAddHeaderWrapper : public FilterActionWrapper {
public:
  ActionAddHeaderWrapper(const Action fa_proto_config, FilterRuleWrapper* parent)
      : FilterActionWrapper(fa_proto_config, parent) {};
  void updateRequiredVars(RootContext& root_ctx) override;
};

// Action Modify Header Wrapper
class ActionModifyHeaderWrapper : public FilterActionWrapper {
public:
  ActionModifyHeaderWrapper(const Action fa_proto_config, FilterRuleWrapper* parent)
      : FilterActionWrapper(fa_proto_config, parent) {};
  void updateRequiredVars(RootContext& root_ctx) override;
  void preCompiledData(RootContext& root_ctx) override;
};

// Action Modify Query Param
class ActionModifyQueryParamWrapper : public FilterActionWrapper {
public:
  ActionModifyQueryParamWrapper(const Action fa_proto_config, FilterRuleWrapper* parent)
      : FilterActionWrapper(fa_proto_config, parent) {};
  void updateRequiredVars(RootContext& root_ctx) override;
  void preCompiledData(RootContext& root_ctx) override;
};

// Action SLF Lookup Wrapper
class ActionSlfLookupWrapper : public FilterActionWrapper {
public:
  ActionSlfLookupWrapper(const Action fa_proto_config, FilterRuleWrapper* parent)
      : FilterActionWrapper(fa_proto_config, parent) {};
  void updateRequiredVars(RootContext& root_ctx) override;
  std::string nSlfApiRoot() const { return nslf_req_api_root_; };
  std::string queryIdType() const { return query_id_type_; };
  int sourceVarIdx() const { return source_var_idx_; };
  int destinationVarIdx() const { return destination_var_idx_; };
private:
  std::string nslf_req_api_root_;
  std::string query_id_type_ = "";
  int source_var_idx_ = -1;
  int destination_var_idx_;
};

// Action NF Discovery Wrapper
class ActionNfDiscoveryWrapper : public FilterActionWrapper {
public:
  ActionNfDiscoveryWrapper(const Action fa_proto_config, FilterRuleWrapper* parent)
      : FilterActionWrapper(fa_proto_config, parent) {};
  void updateRequiredVars(RootContext& root_ctx) override;
  int prefHostVarIdx() const { return pref_host_var_idx_; };
  int nfsetVarIdx() const { return nfset_var_idx_; };
  std::optional<int> paramToAddIdx(const std::string& key) const {
    auto it = params_to_add_.find(key);
    return (it == params_to_add_.end()) ? std::nullopt : std::optional<int>{it->second};
  }
private:
  int pref_host_var_idx_ = -1;
  int nfset_var_idx_ = -1;
  std::map<std::string, ValueIndex> params_to_add_;
};

// Action Modify Variable Wrapper
class ActionModifyVariableWrapper : public FilterActionWrapper {
public:
  ActionModifyVariableWrapper(const Action fa_proto_config, FilterRuleWrapper* parent)
      : FilterActionWrapper(fa_proto_config, parent) {};
  void updateRequiredVars(RootContext& root_ctx) override;
};

// Action Modify Json Body Wrapper
class ActionModifyJsonBodyWrapper : public FilterActionWrapper {
public:
  ActionModifyJsonBodyWrapper(const Action fa_proto_config, FilterRuleWrapper* parent)
      : FilterActionWrapper(fa_proto_config, parent) {};
  void updateRequiredVars(RootContext& root_ctx) override;
  void preCompiledData(RootContext& root_ctx) override;
};

//------- Filter Rule Wrapper -----------------------------------------------
class FilterRuleWrapper : public Logger::Loggable<Logger::Id::eric_proxy> {
public:
  FilterRuleWrapper(std::shared_ptr<FilterCaseWrapper> fc_wrapper,
                     const FilterRule fr_proto_config);

  const std::string& name() const { return fr_proto_config_.name(); }

  //const google::protobuf::RepeatedPtrField<Action>& actions()  const { return fr_proto_config_.actions(); }
  const std::vector<std::shared_ptr<FilterActionWrapper>>& actions()  const {
    return filter_actions_;
  }

  // Tests: Return the condition configured from the protobuf:
  const Condition& condition() const {
    return fr_proto_config_.condition();
  }

  // Config-time: Go through all actions in this filter-rule and
  // create a wrapper for each one. Store them inside this filter-rule.
  // Also update the required variables and headers so that they are
  // loaded/present when the action is executed.
  void insertActions(RootContext&);

  // Config-time: Compile the condition (from the protobuf) of this rule into an
  // object-tree for fast evaluation during run-time. Also updates filterdata_required_ and
  // header_value_indices_required_.
  void insertCompiledCondition(RootContext& root_ctx);

  // Return the compiled condition
  std::shared_ptr<Operator> compiledCondition() { return compiled_condition_; };

  // If the variable with index "var_idx" is not yet registered as required
  // filterdata, do it:
  void updateFilterdataRequired(ValueIndex var_idx);
  // Return all required filterdata for this rule:
  const std::vector<std::weak_ptr<FilterDataWrapper>>& filterdataRequired() {
    return filterdata_required_;
  }
  // Debug: Return all required filterdata for this rule as string
  std::string filterdataRequiredAsString() const {
    std::string str;
    for (const auto& fd_wrapper : filterdata_required_) {
      if (std::shared_ptr<FilterDataWrapper> fd = fd_wrapper.lock()) {
        str += absl::StrCat(" ", fd->name(), ",");
      }
    }
    return str;
  }

  void addRequiredHeader(ValueIndex hdr_idx) {
    header_value_indices_required_.insert(hdr_idx);
  }

  const std::set<ValueIndex>& headerValueIndicesRequired() const {
    return header_value_indices_required_;
  }

  const std::set<ValueIndex>& queryParamValueIndicesRequired() const {
    return query_param_value_indices_required_;
  }

private:
  const FilterRule fr_proto_config_;
  std::weak_ptr<FilterCaseWrapper> fc_wrapper_;
  std::vector<std::weak_ptr<FilterDataWrapper>> filterdata_required_;
  std::vector<std::shared_ptr<FilterActionWrapper>> filter_actions_;
  std::set<ValueIndex> header_value_indices_required_;
  std::set<ValueIndex> query_param_value_indices_required_;
  std::shared_ptr<Operator> compiled_condition_;
};

//------- Filter Case Wrapper -----------------------------------------------
class FilterCaseWrapper : public Logger::Loggable<Logger::Id::eric_proxy> {
public:
  FilterCaseWrapper(const FilterCase fc_proto_config);
  const std::string& name() const { return fc_proto_config_.name(); }

  const std::map<ValueIndex, std::vector<std::shared_ptr<FilterDataWrapper>>>& varFilterData() const {
    return var_filterdata_;
  }
  void insertVarFilterData(ValueIndex idx, const std::shared_ptr<FilterDataWrapper> fd);

  // Given an index for a var, return the filter-data-wrappers that sets this variable
  StatusOr<const std::vector<std::shared_ptr<FilterDataWrapper>>> filterdataForVarIndex(ValueIndex index);

  const std::vector<std::shared_ptr<FilterRuleWrapper>>& filterRules() const {
    return filter_rules_;
  }

  StatusOr<std::shared_ptr<FilterRuleWrapper>> filterRuleByName(std::string& fr_name);

  void addFilterRule(std::shared_ptr<FilterRuleWrapper> fr) { filter_rules_.push_back(fr); };

  // Debug: dump all filter rules with their required filterdata
  std::string rulesAndFilterdataAsString() {
    std::string str{absl::StrCat("\nFilter case: ", name())};
    for (const auto& fr : filter_rules_) {
      str += absl::StrCat("; Filter rule:", fr->name());
      str += absl::StrCat(", Required filter-data:", fr->filterdataRequiredAsString());
    }
    return str;
  }

private:
  const FilterCase fc_proto_config_;
  // var_filterdata_: given a variable-valueIndex, var_filterdata_ tells you which
  // filter-data rules you have to execute to fill that variable 
  std::map<ValueIndex, std::vector<std::shared_ptr<FilterDataWrapper>>> var_filterdata_;
  std::vector<std::shared_ptr<FilterRuleWrapper>> filter_rules_;
};

//---------- Filter Phase Wrapper ----------------------------------------
class FilterPhaseWrapper : public Logger::Loggable<Logger::Id::eric_proxy> {
public:
  // The configured name, either for the own or the external network
  std::string nw_name;
  // A) Ingress screening:

  // Given a roaming-partner name, return the start-filter-cases
  std::unordered_map<std::string, std::vector<std::string>> ext_nw_per_rp_fc_;

  // When the request comes from a roaming-partner for which there
  // is no mapping in ext_nw_fc, this list of start-filter-cases
  // has to be used:
  std::vector<std::string> ext_nw_fc_default_;  // If RP not found in ext_nw_fc_

  // For requests coming from the own network: The list of start-filter
  // cases
  std::vector<std::string> own_nw_fc_;  // For own NW

  // B) Egress screening:

  // Given a cluster-name, return the start-filter-cases
  std::unordered_map<std::string, std::vector<std::string>> cluster_fc_; // per cluster (key = cluster name)

private:

};

class ActionLogWrapper : public FilterActionWrapper {
public:
  ActionLogWrapper(const Action fa_proto_config, FilterRuleWrapper* parent)
      : FilterActionWrapper(fa_proto_config, parent){};
  enum class ConditionTypeLog {
    StringConstT,
    StringReqHeaderT,
    StringRespHeaderT,
    VarT,
    NumberConstT,
    BooleanConstT,
    StringReqBodyT,
    StringRespBodyT
  };

  // Given a log value, return its type and index
  // from the correct configmap.
  // If the value doesn't exist, add it to the correct configmap.
  // This is also used by ActionReportEventWrapper
  static std::tuple<ConditionTypeLog, ValueIndex>
  typeAndIndexForLogValue(const ConditionLogValue& val, RootContext* root_ctx);

  void updateRequiredVars(RootContext& root_ctx) override;
};


class ActionReportEventWrapper : public FilterActionWrapper {
public:
  ActionReportEventWrapper(const Action fa_proto_config, FilterRuleWrapper* parent)
      : FilterActionWrapper(fa_proto_config, parent){};
  enum class ConditionTypeLog {
    StringConstT,
    StringReqHeaderT,
    StringRespHeaderT,
    VarT,
    NumberConstT,
    BooleanConstT,
    StringReqBodyT,
    StringRespBodyT
  };

  void updateRequiredVars(RootContext& root_ctx) override;
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
