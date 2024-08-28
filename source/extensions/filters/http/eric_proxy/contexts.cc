#include "source/common/common/utility.h"

#include "source/extensions/filters/http/eric_proxy/contexts.h"
#include "source/extensions/filters/http/eric_proxy/proxy_filter_config.h"
#include "source/extensions/filters/http/eric_proxy/wrappers.h"
#include <cctype>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// Given a condition Value, return its type and index from the
// correct configmap.
std::tuple<RootContext::ConditionType, ValueIndex>
RootContext::typeAndIndexForValue(const ConditionValue& val) {
  switch (val.val_case()) {
  case ConditionValue::kTermString: {
    auto const_index = findOrInsertConstValue(val.term_string());
    return {ConditionType::StringConstT, const_index};
  }
  case ConditionValue::kTermVar: {
    auto var_index = findOrInsertVarName(val.term_var());
    return {ConditionType::VarT, var_index};
  }
  case ConditionValue::kTermReqheader: {
    auto header_index = findOrInsertHeaderName(val.term_reqheader());
    return {ConditionType::StringReqHeaderT, header_index};
  }
  case ConditionValue::kTermRespheader: {
    auto header_index = findOrInsertHeaderName(val.term_respheader());
    return {ConditionType::StringRespHeaderT, header_index};
  }
  case ConditionValue::kTermApicontext: {
    switch (val.term_apicontext()) {
    case ApiContextValue::Value_ApiContext_API_NAME: {
      // the index is not used in this case as the param
      // is retrieved from the service classifier context
      return {ConditionType::StringApiContextNameT, 0};
    }
    // extra cases when more api context values are introduced
    default: {
      ExceptionUtil::throwEnvoyException("Unknown condition value for term_apicontext");
    }
    }
  }
  case ConditionValue::kTermQueryparam: {
    auto query_param_index = findOrInsertQueryParamName(val.term_queryparam());
    return {ConditionType::StringQueryParamT, query_param_index};
  }
  case ConditionValue::kTermBoolean:{
    auto const_index = findOrInsertConstValue(val.term_boolean());
    return {ConditionType::BooleanConstT, const_index};
  }
  case ConditionValue::kTermNumber: {
    auto const_index = findOrInsertConstValue(val.term_number());
    return {ConditionType::NumberConstT, const_index};
  }
  default:
    ExceptionUtil::throwEnvoyException("Unknown condition value");
  }
}

// A to_string function for Json objects. It uses dump() for all types
// except string, because we don't want the quotes around the string.
static std::string jsonToString(const Json& j)
{
     if (j.is_string()) {
      return j.get<std::string>();
    } else {
      return j.dump();
    }
}

// Find a const value and return its index. If it doesn't exist
// yet, store it and then return its index. The name of the
// constant is the value prefixed with the Json-internal type
ValueIndex RootContext::findOrInsertConstValue(const Json& value) {
  std::string name = absl::StrCat(value.type_name(), "_", jsonToString(value));
  auto search = const_configmap_.find(name);
  if (search != const_configmap_.end()) // found
  {
    return search->second;
  } else { // not found -> insert, then return it
    const_value_.push_back(value);
    auto index = const_value_.size() - 1;
    const_configmap_[name] = index;
    return index;
  }
}

// Find a header name and return its index. If it doesn't exist
// yet, store it and then return its index.
ValueIndex RootContext::findOrInsertHeaderName(const std::string& name) {
  auto search = header_configmap_.find(name);
  if (search != header_configmap_.end()) // found
  {
    return search->second;
  } else { // not found -> insert, then return it
    header_configmap_[name] = next_header_index_;
    header_configmap_reverse_[next_header_index_] = name;
    next_header_index_++;
    return next_header_index_ - 1;
  }
}

// Find a query parameter name and return its index. If it doesn't exist
// yet, store it and then return its index.
ValueIndex RootContext::findOrInsertQueryParamName(const std::string& name) {
  auto search = query_param_configmap_.find(name);
  if (search != query_param_configmap_.end()) // found
  {
    return search->second;
  } else { // not found -> insert, then return it
    query_param_configmap_[name] = next_query_param_index_;
    query_param_configmap_reverse_[next_query_param_index_] = name;
    next_query_param_index_++;
    return next_query_param_index_ - 1;
  }
}
std::vector<absl::string_view> RunContext::headerValue(ValueIndex index, int req_or_resp) {
  if (!header_value_.at(req_or_resp).empty() && header_value_.at(req_or_resp).size() > index) {
    return header_value_.at(req_or_resp).at(index);
  } else {
    return {{""}};
  }
}
std::vector<absl::string_view> RunContext::headerValue(ValueIndex index, ReqOrResp req_or_resp) {
  return headerValue(index, static_cast<int>(req_or_resp));
}

// Find a var name and return its index. If it doesn't exist
// yet, store it and then return its index.
ValueIndex RootContext::findOrInsertVarName(const std::string& name, Http::StreamDecoderFilterCallbacks* cb) {
  auto search = var_configmap_.find(name);
  if (search != var_configmap_.end()) // found
  {
    if(cb != nullptr){
      ENVOY_STREAM_LOG(trace, "Find or insert var '{}': found! {}", *cb, name, search->second);
    }else{
      ENVOY_LOG(trace, "Find or insert var '{}': found! {}", name, search->second);
    }
    return search->second;
  } else { // not found -> insert, then return it
    var_configmap_[name] = next_var_index_;
    var_configmap_reverse_[next_var_index_] = name;
    if(cb != nullptr){
      ENVOY_STREAM_LOG(trace, "Find or insert var '{}': inserted at {}", *cb, name, next_var_index_);
    }else {
      ENVOY_LOG(trace, "Find or insert var '{}': inserted at {}", name, next_var_index_);
    }
    next_var_index_++;
    return next_var_index_ - 1;
  }
}

bool RootContext::hasHeaderName(const std::string& name) {
  auto search = header_configmap_.find(name);
  return search != header_configmap_.end();
}

bool RootContext::hasQueryParamName(const std::string& name) {
  auto search = query_param_configmap_.find(name);
  return search != query_param_configmap_.end();
}

bool RootContext::hasVarName(const std::string& name) {
  auto search = var_configmap_.find(name);
  return search != var_configmap_.end();
}

void RootContext::populateKvTables(KeyValueTablesProto key_value_tables) {
  for (const auto& table : key_value_tables) {
    std::map<std::string, std::string> entries;
    for (const auto& entry : table.entries()) {
      entries[entry.key()]=entry.value();
    }
    kv_tables_[table.name()]=entries;
  }
}

std::map<std::string, std::string> RootContext::kvTable(const std::string& table_name){
  return kv_tables_[table_name];
}

absl::optional <std::string> RootContext::kvtValue(const std::string& table_name, const std::string& key) {
  if (kv_tables_.find(table_name) == kv_tables_.end()){
    ENVOY_LOG(debug, "kvtValue(), table '{}' does not exist", table_name);
    return {};
  }
  if (kv_tables_[table_name].empty()){
    ENVOY_LOG(debug, "kvtValue(), table '{}' is empty.", table_name);
    return {};
  }
  if (kv_tables_[table_name].find(key) == kv_tables_[table_name].end()){
    ENVOY_LOG(debug, "kvtValue(), key '{}' does not exist in table '{}'", key, table_name);
    return {};
  }
  return kv_tables_[table_name][key];
}

bool RootContext::hasKvt(const std::string& table_name) {
  return kv_tables_.find(table_name) != kv_tables_.end();
}

// Key List Value Tables
void RootContext::populateKlvTables(KeyListValueTablesProto key_list_value_tables) {
  for (const auto& klv_table : key_list_value_tables) {
    std::map<std::string, std::vector<std::string>> entries;
    for (const auto& klv_entry : klv_table.entries()) {
      std::vector<std::string> values;
      for (const auto& value: klv_entry.value()){
        values.push_back(value);
      }
      entries[klv_entry.key()]=values;
    }
    klv_tables_[klv_table.name()]=entries;
  }
}

std::vector<std::string> RootContext::klvtValues(const std::string& table_name,
    const std::string& key, Http::StreamDecoderFilterCallbacks* cb) {
  std::vector<std::string> values;
  if (klv_tables_.find(table_name) == klv_tables_.end()){
    if(cb != nullptr){ ENVOY_STREAM_LOG(trace, "klvtValue(), table '{}' does not exist", *cb, table_name); }
    return values;
  }
  if (klv_tables_[table_name].empty()){
    if(cb != nullptr){ ENVOY_STREAM_LOG(trace, "klvtValue(), table '{}' is empty.", *cb, table_name);}
    return values; 
  }
  if (klv_tables_[table_name].find(key) == klv_tables_[table_name].end()){
    if(cb != nullptr){ ENVOY_STREAM_LOG(trace, "klvtValue(), key '{}' does not exist in table {}", *cb, key, table_name);}
    return values;
  }
  return klv_tables_[table_name][key];
}

bool RootContext::hasKlvt(const std::string& table_name) {
  return klv_tables_.find(table_name) != klv_tables_.end();
}


//-------- Debug Helpers --------------------------------------------
// Log root-context data structures
void RootContext::logRootContext(Http::StreamDecoderFilterCallbacks* cb) {
  ENVOY_STREAM_LOG(trace, "{}", *cb, debugStringConstConfigmap());
  ENVOY_STREAM_LOG(trace, "{}", *cb, debugStringConstValue());
  ENVOY_STREAM_LOG(trace, "{}", *cb, debugStringHeaderConfigmap());
  ENVOY_STREAM_LOG(trace, "{}", *cb, debugStringQueryParamConfigmap());
  ENVOY_STREAM_LOG(trace, "{}", *cb, debugStringVarConfigmap());
  ENVOY_STREAM_LOG(trace, "{}", *cb, debugStringKvTables());
  ENVOY_STREAM_LOG(trace, "{}", *cb, debugStringKlvTables());
}

// Return a debug string containing all const values (const_value_)
std::string RootContext::debugStringConstValue() {
  std::string s = "root_ctx.const_value_\n";
  if (const_value_.empty()) {
    s += " (none)\n";
  }
  else {
    for (ValueIndex i = 0; i < const_value_.size(); i++) {
      s += absl::StrCat(" ", std::to_string(i), ": ", const_value_.at(i).dump(), "\n");
    }
  }
  return s;
}
  // Return a debug string containing the const_configmap_
std::string RootContext::debugStringConstConfigmap() {
  std::string s = "root_ctx.const_configmap_\n";
  if (const_configmap_.empty()) {
    s += " (none)\n";
  }
  else {
    for (const auto& [key, value] : const_configmap_) {
      s += absl::StrCat("  ", key, ": ", value, "\n");
    }
  }
  return s;
}

  // Return a debug string containing the header_configmap_
std::string RootContext::debugStringHeaderConfigmap() {
  std::string s = "root_ctx.header_configmap_\n";
  if (header_configmap_.empty()) {
    s += " (none)\n";
  }
  else {
    for (const auto& [key, value] : header_configmap_) {
      s += absl::StrCat("  ", key, ": ", value, "\n");
    }
  }
  return s;
}

  // Return a debug string containing the query_param_configmap_
std::string RootContext::debugStringQueryParamConfigmap() {
  std::string s = "root_ctx.query_param_configmap_\n";
  if (query_param_configmap_.empty()) {
    s += " (none)\n";
  }
  else {
    for (const auto& [key, value] : query_param_configmap_) {
      s += absl::StrCat("  ", key, ": ", value, "\n");
    }
  }
  return s;
}

  // Return a debug string containing the var_configmap_
std::string RootContext::debugStringVarConfigmap() {
  std::string s = "root_ctx.var_configmap_\n";
  if (var_configmap_.empty()) {
    s += " (none)\n";
  }
  else {
    for (const auto& [key, value] : var_configmap_) {
      s += absl::StrCat("  ", key, ": ", value, "\n");
    }
  }
  return s;
}

// Return a debug string containing all KV-Tables
std::string RootContext::debugStringKvTables() {
  std::string s = "root_ctx.kv_tables_";
  if (kv_tables_.empty()) {
    s += "\n (no tables defined)\n";
    return s;
  }
  // Iterate over all tables:
  for (const auto& [table_name, kv_table] : kv_tables_) {
    s += absl::StrCat("\nTable '", table_name, "':\n");
    for (const auto& [key, val] : kv_table) {
      s += absl::StrCat(key, ": ", val, "\n");
    }
  }
  return s;
}

// Return a debug string containing all KV-Tables
std::string RootContext::debugStringKlvTables() {
  std::string s = "root_ctx.kv_tables_";
  if (kv_tables_.empty()) {
    s += "\n (no tables defined)\n";
    return s;
  }
  // Iterate over all tables:
  for (const auto& [table_name, klv_table] : klv_tables_) {
    s += absl::StrCat("\nTable '", table_name, "':\n");
    for (const auto& [key, values] : klv_table) {
      s += absl::StrCat(key, ": ", absl::StrJoin(values, ", "), "\n");
    }
  }
  return s;
}

//-------------------------------------------------------------------------------
RunContext::RunContext(RootContext* root_ctx) : root_ctx_(root_ctx) {
  // We know how many elements the arrays will have -> set correct size
  // now instead of growing them.  Do it for both, request- and response-
  // direction:
  header_value_[0] = std::vector<std::vector<absl::string_view>>(root_ctx_->numHeaders());
  header_value_[1] = std::vector<std::vector<absl::string_view>>(root_ctx_->numHeaders());
  // We know how many elements the array will have for query parameters -> set correct size
  // now instead of growing them.
  query_param_value_ = std::vector<absl::string_view>(root_ctx_->numQueryParams());
  // Pre-allocate/resize the var_updated_by table in the run-context to the number of elements
  // in the var_configmap Set the updated_by column to null to indicate the value is invalid.
  var_value_ = std::vector<Json>(root_ctx_->numVars());
  var_updated_by_ = std::vector<FilterCaseWrapper*>(root_ctx_->numVars()); 
  for (int i = 0 ; i < root_ctx_->numVars(); i++) {
      updateVarUpdatedBy(i, nullptr);
  }
}

// Log all variables
void RunContext::logVariables(Http::StreamDecoderFilterCallbacks* cb) {
  ENVOY_STREAM_LOG(trace, "Variables:{}", *cb, debugStringVarValue());
}

// Log everything of the run-context (includes the root context)
void RunContext::logRunContext(Http::StreamDecoderFilterCallbacks* cb) {
  ENVOY_STREAM_LOG(trace, "run_ctx.var_value_:{}", *cb, debugStringVarValue());
  ENVOY_STREAM_LOG(trace, "{}", *cb, debugStringHeaderValue());
  ENVOY_STREAM_LOG(trace, "{}", *cb, debugStringVarUpdatedBy());
  root_ctx_->logRootContext(cb);
}

// Return a debug string containing all variable values (var_value_)
std::string RunContext::debugStringVarValue() {
  std::string s;
  if (var_value_.empty()) {
    absl::StrAppend(&s, " (none)");
  }
  else {
    for (ValueIndex i = 0; i < var_value_.size(); i++) {
      absl::StrAppend(&s, "\n  ", root_ctx_->variableName(i), ": ", varValueAsString(i));
    }
  }
  return s;
}

// Return a debug string containing all header values (header_value_)
std::string RunContext::debugStringHeaderValue() {
  return absl::StrCat("\n", stringHeaderValues(0, "request"), "\n", stringHeaderValues(1, "response"), "\n");
}

std::string RunContext::stringHeaderValues(int req_or_resp, const absl::string_view label) {
  auto s = absl::StrCat("run_ctx.header_value_ (", label, ", for conditions)\n");
  if (header_value_.empty()) {
    absl::StrAppend(&s, " (none)");
  }
  else {
    for (ValueIndex i = 0; i < headerSize(req_or_resp); i++) {
      for(const auto& value: headerValue(i, req_or_resp)) {
        absl::StrAppend(&s, "\n  ", root_ctx_->headerName(i), ": ", value);
      }
    }
  }
  return s;
}

// Return a debug string containing information which variable is updated per filter case
// (var_updated_by_)
std::string RunContext::debugStringVarUpdatedBy() {
  std::string s = "run_ctx.var_updated_by_ (Variables updated by filtercase)\n";
  if (var_updated_by_.empty()) {
    s += " (none)\n";
  }
  else {
    for (ValueIndex i = 0; i < var_updated_by_.size(); i++) {
      auto fc_ptr = varUpdatedBy(i);
      s += absl::StrCat("  ", root_ctx_->variableName(i), ": ",
        fc_ptr == nullptr ? "(not set)" : fc_ptr->name(), "\n");
    }
  }
  return s;

}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
