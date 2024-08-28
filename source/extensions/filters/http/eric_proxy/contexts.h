#pragma once

#include <array>
#include <map>
#include <string>
#include <tuple>
#include <vector>
#include <set>
#include "absl/strings/string_view.h"
#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "include/nlohmann/json.hpp"
#include "source/common/common/logger.h"
#include "source/common/http/utility.h"
#include "absl/strings/str_join.h"
#include "re2/re2.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using Json = nlohmann::json;
using ValueIndex = std::uint16_t;
using ConditionValue = envoy::extensions::filters::http::eric_proxy::v3::Value;
using ApiContextValue = envoy::extensions::filters::http::eric_proxy::v3::Value::ApiContext;
using KeyValueTable = envoy::extensions::filters::http::eric_proxy::v3::KvTable;
using KeyValueTablesProto = google::protobuf::RepeatedPtrField<KeyValueTable>;
using KeyListValueTable = envoy::extensions::filters::http::eric_proxy::v3::KlvTable;
using KeyListValueTablesProto = google::protobuf::RepeatedPtrField<KeyListValueTable>;

// a custom comparator function for the header_configmap_, so that comparisons are case insensitive
struct CaseInsensitiveComparator {
  bool operator()(const std::string& a, const std::string& b) const noexcept {
    return ::strcasecmp(a.c_str(), b.c_str()) < 0;
  }
};
using CaseInsensitiveMap = std::map<std::string, ValueIndex, CaseInsensitiveComparator>;

// Indicator if we are processing a request or a response.
// !! Also used as index into arrays, so don't change the order or the values!!
enum class ReqOrResp {
  Request = 0,        // We are processing a request (= decoder in Envoy terms)
  Response = 1,       // We are processing a response (= encoder)
};

enum class Origin {
  INT = 0,
  EXT = 1,
};

class FilterCaseWrapper;
class Body;

//--------------------------------------------------------------------------------------
class ServiceClassifierCtx {
public:
  ServiceClassifierCtx() = default;
  // Check if the context in arg matches the current request context 
  // populated in service_ctx_;
  void setApiName(const std::string api_name) { api_name_ = api_name ;}
  void setApiVersion(const std::string api_version ) { api_version_ = api_version; }
  void setResource(const std::string& resource) { resource_ = resource;};
  void setTargetNfType(const std::string& nf_type) { target_nf_type_ = nf_type;}
  void setRequesterNfType(const std::string& nf_type) { requester_nf_type_ = nf_type;}
  void setIsNotify(bool is_notify) { is_notify_ = is_notify ;}
  void setMethod(const std::string& method) { method_ = method ;};
  void setOperation(const std::string& op) { operation_ = op; }

  std::string& getApiName() noexcept { return api_name_; }
  std::string& getApiVersion() { return api_version_; }
  std::string& getResource() { return resource_; }
  bool isNotify() { return is_notify_; }
  std::string getMethod() { return method_; }
  std::string getRequesterNfType() { return requester_nf_type_; }
  std::string getTargetNfType() { return target_nf_type_; }

private:
  std::string api_name_;
  std::string api_version_;
  std::string resource_;
  std::string operation_;
  std::string method_; //TODO maybe should be an enum
  std::string target_nf_type_;
  std::string requester_nf_type_;
  bool is_notify_ = false;
};

//--------------------------------------------------------------------------------------
class StringModifierContext {
public:
  StringModifierContext() :
  mapping_unsuccessful_filter_case_(""),
  scrambling_unsuccessful_filter_case_(""),
  scrambling_success_({}),
  scrambling_forwarded_unmodified_fqdn_({}),
  scrambling_forwarded_unmodified_ip_({}),
  scrambling_invalid_fqdn_({}),
  scrambling_encryption_id_not_found_({}),
  scrambling_incorrect_encryption_id_({}) {}

  void setMappingUnsuccessfulFilterCase(const std::string& mapping_unsuccessful_filter_case) {
    mapping_unsuccessful_filter_case_ = mapping_unsuccessful_filter_case;
  }
  void setIsMappingSuccess(const bool& is_mapping_success) {
    is_mapping_success_ = is_mapping_success;
  }
  void setIsMappingForwardedUnmodified(const bool& is_mapping_forwarded_unmodified) {
    is_mapping_forwarded_unmodified_ = is_mapping_forwarded_unmodified;
  }

  std::string getMappingUnsuccessfulFilterCase() { return mapping_unsuccessful_filter_case_; }
  bool isMappingSuccess() { return is_mapping_success_; }
  bool isMappingForwardedUnmodified() { return is_mapping_forwarded_unmodified_; }

  void setScramblingUnsuccessfulFilterCase(const std::string& scrambling_unsuccessful_filter_case) {
    scrambling_unsuccessful_filter_case_ = scrambling_unsuccessful_filter_case;
  }
  void populateScramblingSuccess(const std::string& encryption_id) {
    scrambling_success_.insert(encryption_id);
  }
  void populateScramblingForwardedUnmodifiedFqdn(const std::string& encryption_id) {
    scrambling_forwarded_unmodified_fqdn_.insert(encryption_id);
  }
  void populateScramblingForwardedUnmodifiedIp(const std::string& encryption_id) {
    scrambling_forwarded_unmodified_ip_.insert(encryption_id);
  }
  void populateScramblingInvalidFqdn(const std::string& encryption_id) {
    scrambling_invalid_fqdn_.insert(encryption_id);
  }
  void populateScramblingEncryptionIdNotFound(const std::string& encryption_id) {
    scrambling_encryption_id_not_found_.insert(encryption_id);
  }
  void populateScramblingIncorrectEncryptionId(const std::string& encryption_id) {
    scrambling_incorrect_encryption_id_.insert(encryption_id);
  }

  std::string getScramblingUnsuccessfulFilterCase() { return scrambling_unsuccessful_filter_case_; }
  std::set<std::string> getScramblingSuccess() { return scrambling_success_; }
  std::set<std::string> getScramblingForwardedUnmodifiedFqdn() { return scrambling_forwarded_unmodified_fqdn_; }
  std::set<std::string> getScramblingForwardedUnmodifiedIp() { return scrambling_forwarded_unmodified_ip_; }
  std::set<std::string> getScramblingInvalidFqdn() { return scrambling_invalid_fqdn_; }
  std::set<std::string> getScramblingEncryptionIdNotFound() { return scrambling_encryption_id_not_found_; }
  std::set<std::string> getScramblingIncorrectEncryptionId() { return scrambling_incorrect_encryption_id_; }

private:
  std::string mapping_unsuccessful_filter_case_;
  bool is_mapping_success_{false};
  bool is_mapping_forwarded_unmodified_{false};

  std::string scrambling_unsuccessful_filter_case_;
  std::set<std::string> scrambling_success_;
  std::set<std::string> scrambling_forwarded_unmodified_fqdn_;
  std::set<std::string> scrambling_forwarded_unmodified_ip_;
  std::set<std::string> scrambling_invalid_fqdn_;
  std::set<std::string> scrambling_encryption_id_not_found_;
  std::set<std::string> scrambling_incorrect_encryption_id_;
};

//--------------------------------------------------------------------------------------
// The RootContext is global for all request and based on configuration data.
// Its values are not changed after configuration is over.
class RootContext : public Logger::Loggable<Logger::Id::eric_proxy> {
public:
  enum class ConditionType {
    StringConstT,
    StringReqHeaderT,
    StringRespHeaderT,
    StringQueryParamT,
    StringApiContextNameT,
    VarT,
    NumberConstT,
    BooleanConstT,
  };

  // Return how many headers are used:
  ValueIndex numHeaders() { return header_configmap_.size(); };

  // Return how many query parameters are used:
  ValueIndex numQueryParams() { return query_param_configmap_.size(); };

  // Return how many vars are used:
  ValueIndex numVars() { return var_configmap_.size(); };

  // Return a const_value at a given index
  Json constValue(ValueIndex index) { return const_value_.at(index); };

  // Return a header name for a given header-value-index
  absl::string_view headerName(ValueIndex index) { return header_configmap_reverse_.at(index); };

  // Return a query parameter name for a given query-param-value-index
  absl::string_view queryParamName(ValueIndex index) { return query_param_configmap_reverse_.at(index); };

  // Return a variable name for a given var-value-index
  absl::string_view variableName(ValueIndex index) { return var_configmap_reverse_.at(index); };

  // Given a condition value, return its type and index
  // from the correct configmap.
  // If the value doesn't exist, add it to the correct configmap.
  std::tuple<ConditionType, ValueIndex> typeAndIndexForValue(const ConditionValue& val);

  // Find a const value and return its index. If it doesn't exist
  // yet, store it and then return its index. Additionally, store
  // the constant value.
  ValueIndex findOrInsertConstValue(const Json& value);

  // Find a header name and return its index. If it doesn't exist
  // yet, store it and then return its index. The value is not stored
  // in the root context but in the run context, because it's different
  // for every request.
  ValueIndex findOrInsertHeaderName(const std::string& name);

  // Find a query parameter name and return its index. If it doesn't exist
  // yet, store it and then return its index. The value is not stored
  // in the root context but in the run context, because it's different
  // for every request.
  ValueIndex findOrInsertQueryParamName(const std::string& name);

  // Find a var name and return its index. If it doesn't exist
  // yet, store it and then return its index. The value is not stored
  // in the root context but in the run context, because it's different
  // for every request.
  ValueIndex findOrInsertVarName(const std::string& name,
                                 Http::StreamDecoderFilterCallbacks* decoder_callbacks = nullptr);

  // Log the contents of the var_configmap_ (for debugging)
  void logVarConfigmap() {
    ENVOY_LOG(trace, "Contents of var_configmap:");
    for (const auto& [key, value] : var_configmap_) {
      ENVOY_LOG(trace, "{}: {}", key, value);
    }
  }
  // Search a header name and return true if found.
  bool hasHeaderName(const std::string& name);

  // Search a query parameter name and return true if found.
  bool hasQueryParamName(const std::string& name);

  // Search a var name and return true if found.
  bool hasVarName(const std::string& name);

  // Log everything of the root-context
  void logRootContext(Http::StreamDecoderFilterCallbacks* decoder_callbacks);

  // Return a debug string containing the const_value_
  std::string debugStringConstValue();

  // Return a debug string containing the const_configmap_
  std::string debugStringConstConfigmap();

  // Return a debug string containing the header_configmap_
  std::string debugStringHeaderConfigmap();

  // Return a debug string containing the query_param_configmap_
  std::string debugStringQueryParamConfigmap();

  // Return a debug string containing the var_configmap_
  std::string debugStringVarConfigmap();

  // Return a debug string containing all kv_tables_ and klv_tables_
  std::string debugStringKvTables();
  std::string debugStringKlvTables();

  // Support for Key Value Tables
  void populateKvTables(KeyValueTablesProto key_value_tables);
  std::map<std::string, std::string> kvTable(const std::string& table_name);
  absl::optional<std::string> kvtValue(const std::string& table_name, const std::string& key);
  bool hasKvt(const std::string& table_name);

  // Support for Key List Value Tables
  void populateKlvTables(KeyListValueTablesProto key_list_value_tables);
  std::vector<std::string>
  klvtValues(const std::string& table_name, const std::string& key,
             Http::StreamDecoderFilterCallbacks* decoder_callbacks = nullptr);
  bool hasKlvt(const std::string& table_name);

  // Populate precompiled regex
  void populatePrecompiledRegex(const std::string& string_regex) {
    const auto& precompiled_regex = precompiled_regexs_.find(string_regex);
    if (precompiled_regex == precompiled_regexs_.end()) { // not found
      precompiled_regexs_.emplace(string_regex, string_regex);
    }
  }

  // Get all precompiled regexs
  std::map<std::string, re2::RE2>& getPrecompiledRegexs() {
    return precompiled_regexs_;
  }

  // Populate the flag indicating if the config has external listener
  void populateIsOriginExt(const bool& is_origin_ext) { is_origin_ext_ = is_origin_ext; }
  // Get the flag indicating if the config has external listener
  bool isOriginExt() { return is_origin_ext_; }

  // Populate root context with scrambling encryption profile
  void populateScramblingEncryptionProfile(
    const std::map<std::string, std::tuple<std::string, const unsigned char*, const unsigned char*>>&
    scrambling_encryption_profile
  ) { scrambling_encryption_profile_ = scrambling_encryption_profile; }
  // Populate root context with descrambling encryption profiles
  void populateDescramblingEncryptionProfiles(
    const std::map<std::string, std::map<std::string, std::pair<const unsigned char*, const unsigned char*>>>&
    descrambling_encryption_profiles
  ) { descrambling_encryption_profiles_ = descrambling_encryption_profiles; }
  // Get the scrambling encryption profile
  std::map<std::string, std::tuple<std::string, const unsigned char*, const unsigned char*>>
    scramblingEncryptionProfile() { return scrambling_encryption_profile_; }
  // Get the descrambling encryption profiles
  std::map<std::string, std::map<std::string, std::pair<const unsigned char*, const unsigned char*>>>
    descramblingEncryptionProfiles() { return descrambling_encryption_profiles_; }

  // Populate regex for valid PLMN
  void populateRegexValidPlmn() { 
    regex_valid_plmn_ = std::regex("(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  }
  // Get regex for valid PLMN
  std::regex getRegexValidPlmn() { return regex_valid_plmn_; }

  // RE for extracting apiName and apiVersion for regular services and NR bootstrapping
  // and Service Access tokens
  RE2& getApiContextsRE() { return api_ctx_re_ ;}
  RE2& getBootstrapContextRE() { return api_ctx_nrf_bootstrap_re_; }
  RE2& getServiceTokenContextRE() { return api_ctx_nrf_ouath_re_; }

private:
  // The *_configmap map a name for (variables|headers|constants)
  // to an index in the corresponding *_value vectors. Only they
  // vector const_value is in the root context, because variables
  // and headers are different for each incoming request (their
  // values are in the run-context).
  std::map<std::string, ValueIndex> const_configmap_;
  CaseInsensitiveMap header_configmap_;
  std::map<ValueIndex, std::string>
      header_configmap_reverse_; // TODO(eedala): why not a vector<std::string>?
  std::map<std::string, ValueIndex> query_param_configmap_;
  std::map<ValueIndex, std::string> 
      query_param_configmap_reverse_; // TODO(eedala): why not a vector<std::string>?
  std::map<std::string, ValueIndex> var_configmap_;
  std::map<ValueIndex, std::string>
      var_configmap_reverse_; // TODO(eedala): why not a vector<std::string>?
  ValueIndex next_header_index_ = 0;
  ValueIndex next_query_param_index_ = 0;
  ValueIndex next_var_index_ = 0;

  // Const values are stored in the root context because they are identical
  // for all requests. Header and variable values are stored in the run
  // context of an individual request.
  std::vector<Json> const_value_;

  std::map<std::string, std::map<std::string, std::string>> kv_tables_;
  std::map<std::string, std::map<std::string, std::vector<std::string>>> klv_tables_;

  // Map for precompiled regexes
  std::map<std::string, re2::RE2> precompiled_regexs_;

  // Flag indicating if the config has external listener
  bool is_origin_ext_;

  // Scrambling and descrambling encryption profile(s)
  std::map<std::string, std::tuple<std::string, const unsigned char*, const unsigned char*>>
    scrambling_encryption_profile_;
  std::map<std::string, std::map<std::string, std::pair<const unsigned char*, const unsigned char*>>>
    descrambling_encryption_profiles_;

  // Regex for valid PLMN
  std::regex regex_valid_plmn_;

  // Regexs for extracting different api contexts from request
  RE2 api_ctx_re_ = RE2(".*/(?P<apiName>.*)/(?P<apiVersion>v[\\d])/(?P<resource>.*)");
  RE2 api_ctx_nrf_bootstrap_re_ = RE2(".*/bootstrapping$|.*/bootstrapping/(?P<resource>.*)");
  RE2 api_ctx_nrf_ouath_re_ = RE2(".*/oauth2$|.*/oauth2/(?P<resource>.*)");
};

//--------------------------------------------------------------------------------------
// The RunContext holds data that is specific per request
class RunContext : public Logger::Loggable<Logger::Id::eric_proxy> {
public:
  RunContext(RootContext* root_ctx);

  //---- Helper Functions -------------------------------------------------------
  // Split comma-separated header values into separate values
  std::vector<absl::string_view> splitHeaderValues(ValueIndex index,
                                                   std::vector<absl::string_view> values) {
    if (root_ctx_->headerName(index) == "set-cookie") {
      return values;
    }

    std::vector<absl::string_view> result;
    for (const auto& value : values) {
      auto comma_separated = absl::StrSplit(value, ',');
      result.insert(result.end(), comma_separated.begin(), comma_separated.end());
    }

    return result;
  }

  //---- Const ------------------------------------------------------------------
  // Return a const_value at a given index
  Json constValue(ValueIndex index) { return root_ctx_->constValue(index); };



  //---- Header ------------------------------------------------------------------
  // Checks if a given header exists in the request (regardless if it has a value):
  bool hasHeaderValue(ValueIndex index, ReqOrResp req_or_resp) {
    return hasHeaderValue(index, static_cast<int>(req_or_resp));
  }
  bool hasHeaderValue(ValueIndex index, int req_or_resp) {
    if (!header_value_.at(req_or_resp).empty() && header_value_.at(req_or_resp).size() > index) {
      return header_value_.at(req_or_resp).at(index).data() != nullptr;
    } else {
      return false;
    }
  };

  // Removes a header (needed for action-remove-header to remove it also here)
  void removeHeader(ValueIndex index, int req_or_resp) {
    header_value_.at(req_or_resp).at(index) = std::vector<absl::string_view>();
  };
  void removeHeader(std::string& name, int req_or_resp) {
    removeHeader(root_ctx_->findOrInsertHeaderName(name), req_or_resp);
  }

  // Checks if a given header exists and is empty. If it doesn't exist, it counts
  // as empty as well.
  bool headerValueIsEmpty(ValueIndex index, ReqOrResp req_or_resp) {
    return headerValueIsEmpty(index, static_cast<int>(req_or_resp));
  }
  bool headerValueIsEmpty(ValueIndex index, int req_or_resp) {
    if (hasHeaderValue(index, req_or_resp)) {
      for (const auto& value : headerValue(index, req_or_resp)) {
        if (!value.empty()) {
          return false;
        }
      }
    }
    return true;
  };


  std::size_t headerSize(const int req_or_resp) const { return header_value_.at(req_or_resp).size(); }

  // Return a header_value at a given index as vector of string_view
  std::vector<absl::string_view> headerValue(ValueIndex index, ReqOrResp req_or_resp);
  std::vector<absl::string_view> headerValue(ValueIndex index, int req_or_resp);
  // Return a header value at a given index as vector of strings
  std::vector<std::string> headerValueStrings(ValueIndex index, ReqOrResp req_or_resp) {
    return headerValueStrings(index, static_cast<int>(req_or_resp));
  }
  std::vector<std::string> headerValueStrings(ValueIndex index, int req_or_resp) {
    std::vector<std::string> ret;
    for (const auto& val : header_value_.at(req_or_resp).at(index)) {
      ret.push_back(std::string(val));
    }
    return ret;
  };

  // Update a header value at a given index
  // NOTE: There is a corresponding function updateHeaderValueForTest() that does the same but
  // logs differently. Change both functions when you make a change!
  void updateHeaderValue(ValueIndex index, std::vector<absl::string_view> values, ReqOrResp req_or_resp) {
    return updateHeaderValue(index, values, static_cast<int>(req_or_resp));
  }
  void updateHeaderValue(ValueIndex index, std::vector<absl::string_view> values, int req_or_resp) {
    ENVOY_STREAM_LOG(trace, "updateHeaderValue at index {} with {}", *decoder_callbacks_, index,
                     absl::StrJoin(values, ","));
    header_value_.at(req_or_resp).at(index) = splitHeaderValues(index, values);
  }

  // Test only: Update a header value at a given index
  // NOTE: There is a corresponding function updateHeaderValue() that does the same but
  // logs differently. Change both functions when you make a change!
  void updateHeaderValueForTest(ValueIndex index, std::vector<absl::string_view> values,
      int req_or_resp) {
    ENVOY_LOG(trace, "updateHeaderValue at index {} with {}", index, absl::StrJoin(values, ","));
    header_value_.at(req_or_resp).at(index) = splitHeaderValues(index, values);
  }

  // Set/insert a header name+value, updates it if already known
  // NOTE: There is a corresponding function setHeaderValueForTest() that does the same but
  // logs differently. Change both functions when you make a change!
  ValueIndex setHeaderValue(std::string name, std::vector<absl::string_view> values,
      int req_or_resp) {
    auto idx = root_ctx_->findOrInsertHeaderName(name);
    ENVOY_STREAM_LOG(trace, "setHeaderValue name={}, value={}, idx={}", *decoder_callbacks_, name,
                     absl::StrJoin(values, ","), idx);
    updateHeaderValue(idx, values, req_or_resp);
    return idx;
  };

  // Test only: Set/insert a header name+value, updates it if already known
  // NOTE: There is a corresponding function setHeaderValue() that does the same but
  // logs differently. Change both functions when you make a change!
  ValueIndex setHeaderValueForTest(std::string name, std::vector<absl::string_view> values,
      int req_or_resp) {
    auto idx = root_ctx_->findOrInsertHeaderName(name);
    ENVOY_LOG(trace, "setHeaderValue name={}, value={}, idx={}", name, absl::StrJoin(values, ","), idx);
    updateHeaderValueForTest(idx, values, req_or_resp);
    return idx;
  };
  ValueIndex setHeaderValueForTest(std::string name, absl::string_view value, ReqOrResp req_or_resp) {
    return setHeaderValueForTest(name, value, static_cast<int>(req_or_resp));
  }
  ValueIndex setHeaderValueForTest(std::string name, absl::string_view value, int req_or_resp) {
    auto idx = root_ctx_->findOrInsertHeaderName(name);
    ENVOY_LOG(trace, "setHeaderValue name={}, value={}, idx={}", name, value, idx);
    std::vector<absl::string_view> values(1);
    values.push_back(value);
    updateHeaderValueForTest(idx, values, req_or_resp);
    return idx;
  };

  //---- Query Parameter -----------------------------------------------------------
  // Checks if a given query parameter exists in the request (regardless if it has a value):
  bool hasQueryParamValue(ValueIndex index) {
    return query_param_value_.at(index).data() != nullptr;
  };

  // Checks if a given query parameter exists and is empty. If it doesn't exist, it counts
  // as empty as well.
  bool queryParamValueIsEmpty(ValueIndex index) {
    if (hasQueryParamValue(index)) {
      if (!queryParamValue(index).empty()) {
        return false;
      }
    }
    return true;
  };

  // Return a query parameter value at a given index as string_view
  absl::string_view queryParamValue(ValueIndex index) {
    return query_param_value_.at(index);
  };

  // Update a query parameter value at a given index
  void updateQueryParamValue(ValueIndex index, absl::string_view value) {
    ENVOY_STREAM_LOG(trace, "updateQueryParamValue at index {} with {}", *decoder_callbacks_, index, value);
    query_param_value_.at(index) = value;
  };

  // Set/insert a query parameter name+value, updates it if already known
  ValueIndex setQueryParamValue(std::string name, absl::string_view value) {
    auto idx = root_ctx_->findOrInsertQueryParamName(name);
    ENVOY_STREAM_LOG(trace, "setQueryParamValue name={}, value={}, idx={}", *decoder_callbacks_, name,
                     value, idx);
    updateQueryParamValue(idx, value);
    return idx;
  };

  //---- Var ------------------------------------------------------------------
  // Checks if a given variable exists for this request:
  bool hasVarValue(ValueIndex index) { return var_updated_by_.at(index) != nullptr; };

  // Checks if a given variable is empty.
  // If the variable doesn't exist, it is empty.
  // If the variable exists, but is not yet set, it is empty.
  // These types can be empty: string, array, object
  // These types cannot be empty: number, boolean, null
  bool varValueIsEmpty(ValueIndex index) {
    // Does the variable exist?
    if (index >= var_value_.size()) {
      ENVOY_LOG(debug, "Variable at index '{}' does not exist", index);
      return true;
    }
    // Does the variable have a value?
    if (!hasVarValue(index)) {
      return true;
    }
    auto val = varValue(index);
    // String
    if (val.is_string()) {
      return val.get<std::string>().empty();
    }
    // Array, object variable:
    if (val.is_array() || val.is_object()) {
      return val.empty();
    }
    // All other types: number, boolean, null are not empty if they exist and have a value
    return false;
  };

  // Return a var_value at a given index
  const Json varValue(ValueIndex index) { return var_value_.at(index); };

  // Return a var_value converted to std::string at a given index
  const std::string varValueAsString(ValueIndex index) {
    // Special treatment for strings, because dump() surrounds strings with double quotes:
    if (varValue(index).is_string()) {
      return varValue(index).get<std::string>();
    } else {
      return varValue(index).dump();
    }
  };

  // Return a pointer to the filtercase that updated a variable at the given index
  FilterCaseWrapper* varUpdatedBy(ValueIndex index) { return var_updated_by_.at(index); };

  // Update a variable value at a given index
  void updateVarValue(ValueIndex index, Json value, FilterCaseWrapper * fc) {
    // If the variable does not exist, make space for it first
    if (index >= var_value_.size()) {
      var_value_.resize(index + 1);
      var_updated_by_.resize(index + 1);
    }
    var_value_.at(index) = value;
    var_updated_by_.at(index) = fc;
  }

  // Set/insert a var name+value, updates it if alreday known
  // Used for tests, production code uses updateVarValue() because the variable exists
  ValueIndex setVarValueForTest(std::string name, Json value, FilterCaseWrapper * fc) {
    auto idx = root_ctx_->findOrInsertVarName(name);
    updateVarValue(idx, value, fc);
    return idx;
  };

  // Update the  var_updated_by fc_wrapper pointer at a given index
  void updateVarUpdatedBy(ValueIndex index, FilterCaseWrapper * fc_wrapper_ptr) {
    var_updated_by_.at(index) = fc_wrapper_ptr;
  }

  //---- ReqOrResp ----------------------------------------------------------------

  // Set the flag to indicate request or response direction
  void setReqOrResp(ReqOrResp req_or_resp) { req_or_resp_ = req_or_resp; }

  // Get the flag to indicate request or response direction
  ReqOrResp getReqOrResp() const { return req_or_resp_; }
  bool isRequest() const { return req_or_resp_ == ReqOrResp::Request; }
  bool isResponse() const { return !isRequest(); }

  //---- Header -------------------------------------------------------------------

  // Set the respective header map for request or response
  void setReqOrRespHeaders(Http::RequestOrResponseHeaderMap* headers) { req_or_resp_headers_ = headers; }

  // Set the respective header map for request
  void setReqHeaders(Http::RequestOrResponseHeaderMap* req_headers) { req_headers_ = req_headers; }

  // Get the respective header map for request or response
  Http::RequestOrResponseHeaderMap* getReqOrRespHeaders() { return req_or_resp_headers_; }

  // Get the request header map
  Http::RequestOrResponseHeaderMap* getReqHeaders() { return req_headers_; }

  //---- Body ---------------------------------------------------------------------
  // Set the request body
  void setRequestBody(Body* body) { req_body_ = body; }

  // Set the response body
  void setResponseBody(Body* body) { resp_body_ = body; }

  // Get the request body
  Body* getRequestBody() { return req_body_; }

  // Get the response body
  Body* getResponseBody() { return resp_body_; }

  //---- Logging ------------------------------------------------------------------
  // Log the var_configmap
  void logVarConfigmap() { root_ctx_->logVarConfigmap(); };

  // Log all variables
  void logVariables(Http::StreamDecoderFilterCallbacks* decoder_callbacks);

  // Log everything of the run-context (includes the root context)
  void logRunContext(Http::StreamDecoderFilterCallbacks* decoder_callbacks);

  // Return a debug string containing all variable values (var_value_)
  std::string debugStringVarValue();

  // Return a debug string containing all header values (header_value_)
  std::string debugStringHeaderValue();
  std::string stringHeaderValues(int req_or_resp, const absl::string_view label); // helper func.

  // Return a debug string containing information which variable is updated per filter case
  // (var_updated_by_)
  std::string debugStringVarUpdatedBy();

  //------ Other ------------------------------------------------------------------
  // Return the root-context
  RootContext* rootContext() { return root_ctx_; };

  // Set the decoder callbacks for ENVOY_STREAM_LOG:
  void setDecoderCallbacks(Http::StreamDecoderFilterCallbacks * cb) { decoder_callbacks_ = cb; }

  // support for Service Classifier
  ServiceClassifierCtx& getServiceClassifierCtx() { return service_ctx_;  }

  // Returns the reference of unique pointer to StringModifierContext
  std::unique_ptr<StringModifierContext>& stringModifierContext() { return string_modifier_ctx_; }

  // Set the Roaming Partner name
  void setRoamingPartnerName(const std::string& rp_name) { rp_name_ = rp_name; }

  // Get the Roaming Partner name
  std::string getRoamingPartnerName() { return rp_name_; }

  enum UpstreamHostScheme { Http, Https };

  void setSelectedHostScheme(UpstreamHostScheme scheme) { selected_host_scheme_ = scheme ;}

  UpstreamHostScheme getSelectedHostScheme() { return selected_host_scheme_; }

  std::string& getSelectedHostApiPrefix() { return selected_host_api_prefix_; }

  void setSelectedHostApiPrefix(const std::string& apiroot) { selected_host_api_prefix_ = apiroot; }
  
  std::string& getSelectedHostAuthority() { return selected_host_authority_; }

  void setSelectedHostAuthority(const std::string& authority) { selected_host_authority_ = authority; }

private:
  RootContext* root_ctx_;

  // Service Context based on 3gpp specs
  ServiceClassifierCtx service_ctx_;
  std::unique_ptr<StringModifierContext> string_modifier_ctx_;
  std::vector<Json> var_value_;
  std::vector<FilterCaseWrapper*> var_updated_by_;
  // 
  // header_value_ is used for header["name"] in conditions,
  // not when a header is copied into a variable
  // Since we have request AND response headers, header_value_ is an array
  // where the first element contains the request header values and the
  // second element contains the response header values. It is intended to
  // access the request or response headers via the enum values or ReqOrResp
  // defined in filter.h
  std::array<std::vector<std::vector<absl::string_view>>, 2> header_value_;
  // query_param_value_ is used for query.param["name"] in conditions
  std::vector<absl::string_view> query_param_value_;
  // Decoder callbacks are needed for ENVOY_STREAM_LOG():
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_;
  // req_body_ and resp_body_ pointers are used to access request 
  // and response body objects respectively.
  Body* req_body_;
  Body* resp_body_;

  // Store headers so that we have them when processing the body and in the state machine
  // The first (req_or_resp_headers_) is always pointing to the current headers.
  // That it, in a request, it's pointing to the request headers, while during response
  // processing, it's pointing to the response headers.
  // The second (req_headers_) is always pointing to the request headers, regardless
  // if it is a request or response. This is so that it's possible to explicitly access
  // the request headers during response processing.
  Http::RequestOrResponseHeaderMap* req_or_resp_headers_;
  Http::RequestOrResponseHeaderMap* req_headers_;
  // Flag to indicate if we are in the decoder or encoder path. Also used as index into arrays.
  ReqOrResp req_or_resp_;

  // Store Roaming Partner name
  std::string rp_name_;

  // Store the scheme of the current selected host in router onUpstreamHostSelected()
  UpstreamHostScheme selected_host_scheme_ = UpstreamHostScheme::Http;

  // Store the fqdn:port of the host which is selected, to be stored in onUpstreamHostSelected()
  // for usage in listener filters to get information about reselected host
  std::string selected_host_authority_;

  // Store the api prefix of the selected host in onUpstreamHostSelected()
  // Stores "" if no endpoint MD for api prefix for host
  std::string selected_host_api_prefix_="";

  // Stores the api prefix of the preferred host (can be used for any downstream/upstream checks)
  // Currently unused
  std::string preferred_host_api_prefix_="";
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
