#include "source/extensions/filters/http/eric_proxy/wrappers.h"
#include "source/extensions/filters/http/eric_proxy/contexts.h"
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/extensions/filters/http/eric_proxy/proxy_filter_config.h"
#include "absl/status/status.h"
#include <elf.h>
#include <regex>

using ProtoAction = envoy::extensions::filters::http::eric_proxy::v3::Action;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// --------------------ServiceClassifierConfigBase -------------------------

// Method to evaluate the comparison between configured
// service context and request service context.
// Returns true if match is found for all attributes.
// Returns false if any of the attributes does not match.
bool ServiceClassifierConfigBase::eval(RunContext* run_ctx) {
  if (run_ctx) {
    if (!evalApiName(run_ctx->getServiceClassifierCtx().getApiName())) {
      return false;
    }

    if (!evalApiVersions(run_ctx->getServiceClassifierCtx().getApiVersion())) {
      return false;
    }

    if (!evalMethods(run_ctx->getServiceClassifierCtx().getMethod())) {
      return false;
    }

    if (!evalIsNotification(run_ctx->getServiceClassifierCtx().isNotify())) {
      return false;
    }

    if (!evalResourceMatchers(run_ctx->getServiceClassifierCtx().getResource())) {
      return false;
    }
  }
  ENVOY_LOG(trace, "eval() = true");
  return true;
}

bool ServiceClassifierConfigBase::evalApiName(const std::string& req_api_name) {
  if (!api_name_.empty() && api_name_ != req_api_name) {
    ENVOY_LOG(trace, "evalApiName() = false");
    return false;
  }
  return true;
}

bool ServiceClassifierConfigBase::evalApiVersions(const std::string& req_api_version) {
  if (!api_versions_.empty()) {
    for (const auto& api_version : api_versions_) {
      if (api_version.empty() || api_version == req_api_version) {
        return true;
      }
    }
    ENVOY_LOG(trace, "evalApiVersions() = false");
    return false;
  }
  return true;
}

bool ServiceClassifierConfigBase::evalMethods(const std::string& req_method) {
  if (!methods_.empty()) {
    for (const auto& method : methods_) {
      if (method.empty() || StringUtil::toUpper(method) == StringUtil::toUpper(req_method)) {
        return true;
      }
    }
    ENVOY_LOG(trace, "evalMethods() = false");
    return false;
  }
  return true;
}

bool ServiceClassifierConfigBase::evalIsNotification(const bool& is_notification_req) {
  if (is_notification_^is_notification_req) {
    ENVOY_LOG(trace,"evalIsNotification() = false");
    return false;
  }
  return true;
}

bool ServiceClassifierConfigBase::evalResourceMatchers(const std::string& req_resource) {
  if (!resource_matchers_.empty()) {
    for (const auto& resource_matcher : resource_matchers_) {
      if (resource_matcher.first.empty() || std::regex_match(req_resource, resource_matcher.second)) {
        return true;
      }
    }
    ENVOY_LOG(trace, "evalResourceMatchers() = false");
    return false;
  }
  return true;
}

// A string representation for debugging
std::string ServiceClassifierConfigBase::debugString() {
  std::string api_versions = "";
  for (const auto& api_version : api_versions_) {
    if (api_versions.empty()) {
      api_versions = absl::StrCat("'", api_version, "'");
    } else {
      absl::StrAppend(&api_versions, ", '", api_version, "'");
    }
  }

  std::string resource_matchers = "";
  for (const auto& resource_matcher : resource_matchers_) {
    if (resource_matchers.empty()) {
      resource_matchers = absl::StrCat("'", resource_matcher.first, "'");
    } else {
      absl::StrAppend(&resource_matchers, ", '", resource_matcher.first, "'");
    }
  }

  std::string methods = "";
  for (const auto& method : methods_) {
    if (methods.empty()) {
      methods = absl::StrCat("'", method, "'");
    } else {
      absl::StrAppend(&methods, ", '", method, "'");
    }
  }

  return absl::StrCat(
      "api_name_ = '", api_name_, "'; api_versions_ = [", api_versions,
      "]; resource_matchers_ = [", resource_matchers, "]; http_methods_ = [", methods,
      "]; is_notification = ", (is_notification_ ? "'true'" : "'false'")
  );
}

// --------------------FilterDataWrapper ---------------------------

FilterDataWrapper::FilterDataWrapper(const FilterData fd_proto_config)
    : fd_proto_config_(fd_proto_config), extractor_regex_re2_(fd_proto_config_.extractor_regex()) {
  ENVOY_LOG(trace, "FilterDataWrapper object instantiated");
}

void FilterDataWrapper::insertCaptureGroupAtIndex(CaptureGroup capt_group,
                                                   ValueIndex var_value_index) {
  ENVOY_LOG(trace, "FilterDataWrapper::insertCaptureGroupAtIndex({}.{})", capt_group,
            var_value_index);
  var_capture_groups_[capt_group] = var_value_index;
}

// --------------------FilterActionWrapper ---------------------------
// Base class methods

void FilterActionWrapper::updateTermVarHeader(RootContext& root_ctx,
                                              const VarHeaderConstValue& var_header) {
  switch (var_header.val_case()) {
  case VarHeaderConstValue::kTermVar: {
    const auto& var_name = var_header.term_var();
    if (!var_name.empty()) {
      auto idx = root_ctx.findOrInsertVarName(var_name);
      parent_->updateFilterdataRequired(idx);
    }
    break;
  }
  case VarHeaderConstValue::kTermHeader: {
    const auto& header_name = var_header.term_header();
    auto idx = root_ctx.findOrInsertHeaderName(header_name);
    parent_->addRequiredHeader(idx);
    break;
  }
  default:
    break;
  }
}

// Action Route To Pool Wrapper
void ActionRouteToPoolWrapper::updateRequiredVars(RootContext& root_ctx) {
  updateTermVarHeader(root_ctx, protoConfig().action_route_to_pool().preferred_target());
}

// Action Route To RoamingPartner Wrapper
void ActionRouteToRoamingPartnerWrapper::updateRequiredVars(RootContext& root_ctx) {
    updateTermVarHeader(root_ctx, protoConfig().action_route_to_roaming_partner().preferred_target());
}

// Action Add Header Wrapper
void ActionAddHeaderWrapper::updateRequiredVars(RootContext& root_ctx) {
  updateTermVarHeader(root_ctx, protoConfig().action_add_header().value());
}

// Action Modify Header Wrapper
void ActionModifyHeaderWrapper::updateRequiredVars(RootContext& root_ctx) {
  updateTermVarHeader(root_ctx, protoConfig().action_modify_header().replace_value());
  updateTermVarHeader(root_ctx, protoConfig().action_modify_header().append_value());
  updateTermVarHeader(root_ctx, protoConfig().action_modify_header().prepend_value());

  // check modifiers for term_var
  const auto& modifiers =
    protoConfig().action_modify_header().use_string_modifiers().string_modifiers();
  for (const auto& modifier : modifiers) {
    if (modifier.has_prepend()) {
      updateTermVarHeader(root_ctx, modifier.prepend());
    } else if (modifier.has_append()) {
      updateTermVarHeader(root_ctx, modifier.append());
    } else if (modifier.has_search_and_replace()) {
      updateTermVarHeader(root_ctx, modifier.search_and_replace().search_value());
      updateTermVarHeader(root_ctx, modifier.search_and_replace().replace_value());
    }
  }
}

void ActionModifyHeaderWrapper::preCompiledData(RootContext& root_ctx) {
  const auto& modifiers =
    protoConfig().action_modify_header().use_string_modifiers().string_modifiers();
  for (const auto& modifier : modifiers) {
    if (
      modifier.search_and_replace().search_options().regex_search() &&
      modifier.search_and_replace().search_value().has_term_string()
    ) {
      const std::string& string_regex = modifier.search_and_replace().search_value().term_string();
      root_ctx.populatePrecompiledRegex(string_regex);
    }
  }
}

// Action Modify Query-Param Wrapper
void ActionModifyQueryParamWrapper::updateRequiredVars(RootContext& root_ctx) {
  const auto& var_name = protoConfig().action_modify_query_param().key_name();
  if (!var_name.empty()) {
    auto idx = root_ctx.findOrInsertQueryParamName(var_name);
    parent_->updateFilterdataRequired(idx);
  }

  if (protoConfig().action_modify_query_param().has_replace_value()) {
    updateTermVarHeader(root_ctx, protoConfig().action_modify_query_param().replace_value());
  } else if (protoConfig().action_modify_query_param().has_use_string_modifiers()) {
    // check modifiers for term_var
    const auto& modifiers =
      protoConfig().action_modify_query_param().use_string_modifiers().string_modifiers();
    for (const auto& modifier : modifiers) {
      if (modifier.has_prepend()) {
        updateTermVarHeader(root_ctx, modifier.prepend());
      } else if (modifier.has_append()) {
        updateTermVarHeader(root_ctx, modifier.append());
      } else if (modifier.has_search_and_replace()) {
        updateTermVarHeader(root_ctx, modifier.search_and_replace().search_value());
        updateTermVarHeader(root_ctx, modifier.search_and_replace().replace_value());
      }
    }
  }
}

void ActionModifyQueryParamWrapper::preCompiledData(RootContext& root_ctx) {
  const auto& modifiers =
    protoConfig().action_modify_query_param().use_string_modifiers().string_modifiers();
  for (const auto& modifier : modifiers) {
    if (
      modifier.search_and_replace().search_options().regex_search() &&
      modifier.search_and_replace().search_value().has_term_string()
    ) {
      const std::string& string_regex = modifier.search_and_replace().search_value().term_string();
      root_ctx.populatePrecompiledRegex(string_regex);
    }
  }
}

// Action SLF Lookup Wrapper
// Not only set the required variables but also remember which type to look up
// (SUPI, SUCI, GPSI) and build the path for the request to the SLF.
void ActionSlfLookupWrapper::updateRequiredVars(RootContext& root_ctx) {
  if (!protoConfig().action_slf_lookup().supi_var().empty()) {
    query_id_type_ = "supi";
    const auto& var_name = protoConfig().action_slf_lookup().supi_var();
    source_var_idx_ = root_ctx.findOrInsertVarName(var_name);
    parent_->updateFilterdataRequired(source_var_idx_);
  }
  if (!protoConfig().action_slf_lookup().suci_var().empty()) {
    query_id_type_ = "suci";
    const auto& var_name = protoConfig().action_slf_lookup().suci_var();
    source_var_idx_ = root_ctx.findOrInsertVarName(var_name);
    parent_->updateFilterdataRequired(source_var_idx_);
  }
  if (!protoConfig().action_slf_lookup().gpsi_var().empty()) {
    query_id_type_ = "gpsi";
    const auto& var_name = protoConfig().action_slf_lookup().gpsi_var();
    source_var_idx_ = root_ctx.findOrInsertVarName(var_name);
    parent_->updateFilterdataRequired(source_var_idx_);
  }
  if (!protoConfig().action_slf_lookup().destination_variable().empty()) {
    const auto& var_name = protoConfig().action_slf_lookup().destination_variable();
    destination_var_idx_ = root_ctx.findOrInsertVarName(var_name);
    parent_->updateFilterdataRequired(destination_var_idx_);
  }
  std::string req_nf_type = "SCP";
  std::string target_nf_type = "CHF";
  if (!protoConfig().action_slf_lookup().req_nf_type().empty()) {
    req_nf_type = protoConfig().action_slf_lookup().req_nf_type();
  }
  if (!protoConfig().action_slf_lookup().target_nf_type().empty()) {
    target_nf_type = protoConfig().action_slf_lookup().target_nf_type();
  }
  nslf_req_api_root_ = absl::StrCat("/nslf-disc/v0/addresses?requester-nf-type=",
      req_nf_type, "&target-nf-type=", target_nf_type, "&");
}

// Action NF Discovery Wrapper
void ActionNfDiscoveryWrapper::updateRequiredVars(RootContext& root_ctx) {
  if (! protoConfig().action_nf_discovery().add_parameters_if_missing().empty()) {
    // If a parameter value comes from a variable, find and store its index:
    for (const auto& param : protoConfig().action_nf_discovery().add_parameters_if_missing()) {
      // No term_header here because the YANG model doesn't allow it
      if (! param.value().term_var().empty()) {
        const auto& var_name = param.value().term_var();
        auto idx = root_ctx.findOrInsertVarName(var_name);
        parent_->updateFilterdataRequired(idx);
        // Store the parameter-name -> index  mapping for later use
        params_to_add_.insert({{var_name, idx}});
      }
    }
    if (protoConfig().action_nf_discovery().has_nf_selection_on_priority()) {
      const auto& nf_sel_prio = protoConfig().action_nf_discovery().nf_selection_on_priority();
      if (!nf_sel_prio.var_name_preferred_host().empty()) {
        const auto& var_name = nf_sel_prio.var_name_preferred_host();
        auto pref_host_var_idx_ = root_ctx.findOrInsertVarName(var_name);
        parent_->updateFilterdataRequired(pref_host_var_idx_);
      }
      if (!nf_sel_prio.var_name_nf_set().empty()) {
        const auto& var_name = nf_sel_prio.var_name_nf_set();
        auto nfset_var_idx_ = root_ctx.findOrInsertVarName(var_name);
        parent_->updateFilterdataRequired(nfset_var_idx_);
      }
    }
  }
}

// Action Modify Variable Wrapper
void ActionModifyVariableWrapper::updateRequiredVars(RootContext& root_ctx) {
  if (!protoConfig().action_modify_variable().name().empty()) {
    const auto& var_name = protoConfig().action_modify_variable().name();
    auto idx = root_ctx.findOrInsertVarName(var_name);
    parent_->updateFilterdataRequired(idx);
  }
  if (protoConfig().action_modify_variable().has_table_lookup()) {
    updateTermVarHeader(root_ctx, protoConfig().action_modify_variable().table_lookup().key());
  }
}

// Action Modify JSON Body Wrapper
void ActionModifyJsonBodyWrapper::updateRequiredVars(RootContext& root_ctx) {
  if (protoConfig().action_modify_json_body().json_operation().has_add_to_json()) {
    // No header value possible here, only string constant or variable
    const auto& var_name =
      protoConfig().action_modify_json_body().json_operation().add_to_json().value().term_var();
    if (!var_name.empty()) {
      auto idx = root_ctx.findOrInsertVarName(var_name);
      parent_->updateFilterdataRequired(idx);
    }
  }
  if (protoConfig().action_modify_json_body().json_operation().has_replace_in_json()) {
    // No header value possible here, only string constant or variable
    const auto& var_name =
      protoConfig().action_modify_json_body().json_operation().replace_in_json().value().term_var();
    if (!var_name.empty()) {
      auto idx = root_ctx.findOrInsertVarName(var_name);
      parent_->updateFilterdataRequired(idx);
    }
  }
  if (protoConfig().action_modify_json_body().json_operation().has_modify_json_value()) {
    // Check JSON pointer for term_var
    // No header value possible here, only string constant or variable
    const auto& var_name =
      protoConfig().action_modify_json_body().json_operation().modify_json_value().json_pointer().term_var();
    if (!var_name.empty()) {
      auto idx = root_ctx.findOrInsertVarName(var_name);
      parent_->updateFilterdataRequired(idx);
    }
    // check modifiers for term_var
    const auto& modifiers =
      protoConfig().action_modify_json_body().json_operation().modify_json_value().string_modifiers();
    for (const auto& modifier : modifiers) {
      if (modifier.has_prepend()) {
        updateTermVarHeader(root_ctx, modifier.prepend());
      } else if (modifier.has_append()) {
        updateTermVarHeader(root_ctx, modifier.append());
      } else if (modifier.has_search_and_replace()) {
        updateTermVarHeader(root_ctx, modifier.search_and_replace().search_value());
        updateTermVarHeader(root_ctx, modifier.search_and_replace().replace_value());
      }
    }
  }
}

void ActionModifyJsonBodyWrapper::preCompiledData(RootContext& root_ctx) {
  const auto& modifiers =
    protoConfig().action_modify_json_body().json_operation().modify_json_value().string_modifiers();
  for (const auto& modifier : modifiers) {
    if (
      modifier.search_and_replace().search_options().regex_search() &&
      modifier.search_and_replace().search_value().has_term_string()
    ) {
      const std::string& string_regex = modifier.search_and_replace().search_value().term_string();
      root_ctx.populatePrecompiledRegex(string_regex);
    }
  }
}

void ActionLogWrapper::updateRequiredVars(RootContext& root_ctx) {
  for (const auto& val : protoConfig().action_log().log_values()) {
    switch (val.val_case()) {
    case ConditionLogValue::kTermVar: {
      const auto idx = root_ctx.findOrInsertVarName(val.term_var());
      parent_->updateFilterdataRequired(idx);
      break;
    }
    default:
      continue;
    }
  }
}

void ActionReportEventWrapper::updateRequiredVars(RootContext& root_ctx) {
  for (const auto& val : protoConfig().action_report_event().event_message_values()) {
    switch (val.val_case()) {
    case ConditionLogValue::kTermVar: {
      const auto idx = root_ctx.findOrInsertVarName(val.term_var());
      parent_->updateFilterdataRequired(idx);
      break;
    }
    default:
      continue;
    }
  }
}

// --------------------FilterRuleWrapper ---------------------------
FilterRuleWrapper::FilterRuleWrapper(std::shared_ptr<FilterCaseWrapper> fc_wrapper,
                                       const FilterRule fr_proto_config)
    : fr_proto_config_(fr_proto_config), fc_wrapper_(fc_wrapper) {
  ENVOY_LOG(trace, "FilterRuleWrapper object '{}' instantiated.", name());
}

// Actions that use variables need to register them here. If not, the variable will not
// have a value unless the same variable is also used in a condition.
void FilterRuleWrapper::insertActions(RootContext& root_ctx) {
  for (const auto& proto_action : fr_proto_config_.actions()) {
    switch (proto_action.action_case()) {
      //----- Header Actions ------------------------------------------------------------
      // Add Header (actions_header.cc)
      case ProtoAction::kActionAddHeader:
        filter_actions_.emplace_back(std::make_shared<ActionAddHeaderWrapper>(proto_action,
            this));
      break;
      // Remove Header (actions_header.cc)
      case ProtoAction::kActionRemoveHeader:
        filter_actions_.emplace_back(std::make_shared<FilterActionWrapper>(proto_action,
            this));
      break;
      // Modify Header (actions_header.cc)
      case ProtoAction::kActionModifyHeader:
        filter_actions_.emplace_back(std::make_shared<ActionModifyHeaderWrapper>(proto_action,
            this));
      break;

      //----- Query-Parameter Actions ------------------------------------------------------------
      // Modify Query-Parameter (actions_query.cc)
      case ProtoAction::kActionModifyQueryParam:
        filter_actions_.emplace_back(std::make_shared<ActionModifyQueryParamWrapper>(proto_action,
            this));
      break;

      //----- Body Actions ---------------------------------------------------------------
      // Modify Body (actions_json_body.cc)
      case ProtoAction::kActionModifyJsonBody:
        filter_actions_.emplace_back(std::make_shared<ActionModifyJsonBodyWrapper>(proto_action,
            this));
      break;
      // Create Body (actions_body.cc)
      case ProtoAction::kActionCreateBody:
        filter_actions_.emplace_back(std::make_shared<FilterActionWrapper>(proto_action,
            this));
      break;

      //----- Lookup Actions -------------------------------------------------------------
      // Perform an SLF lookup to get the region for a SUPI (actions_lookup.cc)
      case ProtoAction::kActionSlfLookup:
        filter_actions_.emplace_back(std::make_shared<ActionSlfLookupWrapper>(proto_action,
            this));
      break;

      ///----- Discovery Actions -----------------------------------------------------------
      // Perform a delegated discovery (Option D) at the NRF (through the NLF).
      // (actions_discovery.cc)
      case ProtoAction::kActionNfDiscovery:
        filter_actions_.emplace_back(std::make_shared<ActionNfDiscoveryWrapper>(proto_action,
            this));
      break;

      //----- Misc Actions ----------------------------------------------------------------
      // Write a log message to Envoy's log (actions_log.cc)
      case ProtoAction::kActionLog:
        filter_actions_.emplace_back(std::make_shared<ActionLogWrapper>(proto_action,
            this));
      break;
      // Report an event (actions_log.cc)
      case ProtoAction::kActionReportEvent:
        filter_actions_.emplace_back(std::make_shared<ActionReportEventWrapper>(proto_action,
            this));
      break;
      // Change a variable value (actions_misc.cc)
      case ProtoAction::kActionModifyVariable:
        filter_actions_.emplace_back(std::make_shared<ActionModifyVariableWrapper>(proto_action,
            this));
      break;

      //----- Control-Flow Actions --------------------------------------------------------
      // Go-To another Filter-Case (actions_misc.cc)
      case ProtoAction::kActionGotoFilterCase:
        filter_actions_.emplace_back(std::make_shared<FilterActionWrapper>(proto_action,
            this));
      break;
      // Exit the filter case and go to the next filter (actions_misc.cc)
      case ProtoAction::kActionExitFilterCase:
        filter_actions_.emplace_back(std::make_shared<FilterActionWrapper>(proto_action,
            this));
      break;

      //----- Terminal Actions ------------------------------------------------------------
      // Reject the request (send a direct response) (actions_misc.cc)
      case ProtoAction::kActionRejectMessage:
        filter_actions_.emplace_back(std::make_shared<FilterActionWrapper>(proto_action,
            this));
      break;
      // Modify the status code and body of a response (basically reject in the
      // response path) (actions_misc.cc)
      case ProtoAction::kActionModifyStatusCode:
        filter_actions_.emplace_back(std::make_shared<FilterActionWrapper>(proto_action,
            this));
      break;
      // Drop message by sending a HTTP2 RESET_STREAM frame (actions_misc.cc)
      case ProtoAction::kActionDropMessage:
        filter_actions_.emplace_back(std::make_shared<FilterActionWrapper>(proto_action,
            this));
      break;
      // Route To Pool (actions_routing.cc)
      case ProtoAction::kActionRouteToPool:
        filter_actions_.emplace_back(std::make_shared<ActionRouteToPoolWrapper>(proto_action,
            this));
      break;
      // Route To Roaming Partner (actions_routing.cc)
      case ProtoAction::kActionRouteToRoamingPartner:
        filter_actions_.emplace_back(std::make_shared<ActionRouteToRoamingPartnerWrapper>(proto_action,
            this));
      break;
      default:
        // This may crash Envoy, but it's ok since it's a fatal thing
        ENVOY_LOG(error, "Unknown Action");
    }
    // Update the variable indices in the root context for the just-created
    // action:
    filter_actions_.back()->updateRequiredVars(root_ctx);
    // Update the precompiled data in the root context for the just-created
    // action:
    filter_actions_.back()->preCompiledData(root_ctx);
  }
}


// 2.1.1   Set up he operator-tree, the list of header-value-index, and var-value-index
//         required for this condition
// 2.1.2   Append the header-value-index list from 2.1.1.5 to the header_value_indices_required
//         list in this condition
// 2.1.3   Foreach var-value-index returned by 2.1.1.5, find the Filter-Data from this
//         Filter-Case that sets this variable by looking up var_filterdata in this
//         Filter-Case. Append the Filter-Data ID to the filterdata-required list in
//         this condition
void FilterRuleWrapper::insertCompiledCondition(RootContext& root_ctx) {
  std::set<ValueIndex> var_required;
  compiled_condition_ =
      setUpCondition(root_ctx, condition(), var_required, header_value_indices_required_, query_param_value_indices_required_);
  for (auto var_idx : var_required) {
    updateFilterdataRequired(var_idx);
  }
}

void FilterRuleWrapper::updateFilterdataRequired(ValueIndex var_idx) {
  ENVOY_LOG(trace, "Marking var_idx {} as required for this filter-rule {}", var_idx, name());
  if (std::shared_ptr<FilterCaseWrapper> fc_wrapper_shared = fc_wrapper_.lock()) {

    auto fd_list = fc_wrapper_shared->filterdataForVarIndex(var_idx);
    if (fd_list.ok()) {
      for (auto& fd : *fd_list) {
        ENVOY_LOG(trace, "   Checking filterdata");
        // Append only if not in the list already (= first entry wins)
        std::weak_ptr<FilterDataWrapper> fd_weak = fd;
        // Own imlementation of find because I couldn't make std::find working with
        // the shared_ptr (eedala)
        bool found = false;
        for (const std::weak_ptr<FilterDataWrapper>& fd_elem_weak : filterdata_required_) {
          if (std::shared_ptr<FilterDataWrapper> fd_shared = fd_elem_weak.lock()) {
            if (fd_shared.get() == fd.get()) {
              found = true;
              break;
            }
          }
        }

        if (!found) {
          filterdata_required_.push_back(fd_weak);
          ENVOY_LOG(trace, "  Inserting into filterdata");
        }
      }
    }
  }
}

// --------------------FilterCaseWrapper ---------------------------
FilterCaseWrapper::FilterCaseWrapper(const FilterCase fc_proto_config)
    : fc_proto_config_(fc_proto_config) {
  ENVOY_LOG(trace, "FilterCaseWrapper object instantiated");
}

void FilterCaseWrapper::insertVarFilterData(ValueIndex idx,
                                              const std::shared_ptr<FilterDataWrapper> fd) {
  ENVOY_LOG(trace, "FilterCaseWrapper::insertVarFilterData({},{})", idx, fd->name());
  var_filterdata_[idx].push_back(fd);
}

// Given an index for a var, return the filter-data-wrapper that sets this variable.
// It can happen that the filter-data-wrapper is in a different filter case
// or that it doesn't exist.
StatusOr<const std::vector<std::shared_ptr<FilterDataWrapper>>>
FilterCaseWrapper::filterdataForVarIndex(ValueIndex index) {
  auto iterator = var_filterdata_.find(index);
  if (iterator != var_filterdata_.end()) {
    return iterator->second;
  } else {
    return absl::NotFoundError("No filter-data wrapper found");
  }
}

// Given the name of a filter-rule, return the filter-rule-wrapper.
StatusOr<std::shared_ptr<FilterRuleWrapper>>
FilterCaseWrapper::filterRuleByName(std::string& fr_name) {
  auto fr = std::find_if(std::begin(filter_rules_), std::end(filter_rules_),
                         [fr_name](auto& r) -> bool { return (*r).name() == fr_name; });
  if (fr != std::end(filter_rules_)) {
    return *fr;
  } else {
    return absl::NotFoundError("Routing data wrapper not found");
  }
}

std::tuple<ActionLogWrapper::ConditionTypeLog, ValueIndex> ActionLogWrapper::typeAndIndexForLogValue(const ConditionLogValue& val, RootContext* root_ctx) {
switch (val.val_case()) {
  case ConditionLogValue::kTermString: {
    auto const_index = root_ctx->findOrInsertConstValue(val.term_string());
    return {ConditionTypeLog::StringConstT, const_index};
  }
  case ConditionLogValue::kTermVar: {
    auto var_index = root_ctx->findOrInsertVarName(val.term_var());
    return {ConditionTypeLog::VarT, var_index};
  }
  case ConditionLogValue::kTermReqheader: {
    auto header_index = root_ctx->findOrInsertHeaderName(val.term_reqheader());
    return {ConditionTypeLog::StringReqHeaderT, header_index};
  }
  case ConditionLogValue::kTermRespheader: {
    auto header_index = root_ctx->findOrInsertHeaderName(val.term_respheader());
    return {ConditionTypeLog::StringRespHeaderT, header_index};
  }
  case ConditionLogValue::kTermBoolean: {
    auto const_index = root_ctx->findOrInsertConstValue(val.term_boolean());
    return {ConditionTypeLog::BooleanConstT, const_index};
  }
  case ConditionLogValue::kTermNumber: {
    auto const_index = root_ctx->findOrInsertConstValue(val.term_number());
    return {ConditionTypeLog::NumberConstT, const_index};
  }
  case ConditionLogValue::kTermBody: {
    if (val.term_body() == "request") {
      return {ConditionTypeLog::StringReqBodyT, 0};
    } else if (val.term_body() == "response") {
      return {ConditionTypeLog::StringRespBodyT, 0};
    } else {
      ExceptionUtil::throwEnvoyException("Unknown condition value");
    }
  }
  default:
    ExceptionUtil::throwEnvoyException("Unknown condition value");
  }
}


} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
