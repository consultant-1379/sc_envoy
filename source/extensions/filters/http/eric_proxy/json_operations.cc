#include "source/extensions/filters/http/eric_proxy/json_operations.h"
#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "source/extensions/filters/http/eric_proxy/json_utils.h"
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>

//using ProtoAction = envoy::extensions::filters::http::eric_proxy::v3::Action;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// --------------------JsonOperation Wrapper ---------------------------

JsonOpWrapper::JsonOpWrapper(const JsonOperation& json_op_proto_config, const json& json_source, 
                    Http::StreamDecoderFilterCallbacks* decoder_callbacks,
                    RunContext& run_ctx)
    : json_op_proto_config_(json_op_proto_config), json_source_(json_source),
                            decoder_callbacks_(decoder_callbacks),
                            run_ctx_(run_ctx) {
  ENVOY_STREAM_LOG(trace, "JsonOpWrapper instantiated", *decoder_callbacks_);
  json_source_ptr_ = std::make_shared<json>(json_source_);
}

absl::StatusOr<std::shared_ptr<json>> JsonOpWrapper::execute() {
  ENVOY_STREAM_LOG(trace, "executing JsonOperation", *decoder_callbacks_);

  try {
    if (json_op_proto_config_.has_json_patch()) {
      auto json_patch = json_op_proto_config_.json_patch();
      ENVOY_STREAM_LOG(trace, "execute json_patch, {}", *decoder_callbacks_, json_patch);
      json patch = json::parse(json_patch);
      return applyJsonPatch(patch, json_source_);
    } else if (json_op_proto_config_.has_add_to_json()) {      
      return executeAddToJson(json_op_proto_config_.add_to_json());  
    } else if (json_op_proto_config_.has_replace_in_json()) {
      return executeReplaceInJson(json_op_proto_config_.replace_in_json());
    } else if (json_op_proto_config_.has_remove_from_json()) {
      return executeRemoveFromJson(json_op_proto_config_.remove_from_json());
    } else if (json_op_proto_config_.has_modify_json_value()) {
      return executeModifyJsonValue(json_op_proto_config_.modify_json_value());
    } else {
      ENVOY_STREAM_LOG(error, "unsupported JsonOperation", *decoder_callbacks_);
    }
  } catch (json::exception& e) {
    ENVOY_STREAM_LOG(trace, " json::exception in execute() {}", *decoder_callbacks_, e.what());
    absl::Status status(absl::StatusCode::kInternal, absl::string_view("e.what()"));
    return status;
  }
  return json_source_ptr_;
}

absl::StatusOr<std::shared_ptr<json>> JsonOpWrapper::executeAddToJson(const AddToJson& add_to_json) {
  ENVOY_STREAM_LOG(trace, "executeAddToJson()", *decoder_callbacks_);
  try {
    json add_patch = R"([{ "op": "add", "path": "default_path", "value": "default_value"}])"_json;
    auto json_pointer = EricProxyFilter::varOrStringAsString(add_to_json.json_pointer(), run_ctx_,
                                                             decoder_callbacks_);
    add_patch.at(0).at("path") = json_pointer;
    auto json_value =
        EricProxyFilter::varOrJsonStringAsJson(add_to_json.value(), run_ctx_, decoder_callbacks_);
    add_patch.at(0).at("value") = json_value;

    auto j_ptr = json::json_pointer(json_pointer);

    if (elementExists(j_ptr, json_source_)) {
      ENVOY_STREAM_LOG(trace, "elements exists at \"{}\"", *decoder_callbacks_, json_pointer);
      // REPLACE
      if (add_to_json.if_element_exists() == AddToJson_IfJsonElementExists_REPLACE) {
        ENVOY_STREAM_LOG(trace, "replace element with prepared add_patch {}", *decoder_callbacks_,
                         add_patch.dump());
        return applyJsonPatch(add_patch, json_source_);
        // NO ACTION
      } else if (add_to_json.if_element_exists() == AddToJson_IfJsonElementExists_NO_ACTION) {
        return absl::StatusOr<std::shared_ptr<json>>(json_source_ptr_);
      }
    }
    // ELEMENT DOES NOT EXIST
    if (pathToElementExists(j_ptr, json_source_)) {
      ENVOY_STREAM_LOG(trace, "path to elements exists", *decoder_callbacks_);
      // this will replace the whole json doc.
      if (j_ptr.empty()) {
        ENVOY_STREAM_LOG(trace, "replace the whole json doc with \"{}\"", *decoder_callbacks_,
                         json_value);
        return std::make_shared<json>(json_value);
      }

      // do not apply json patch, if we expect "out of range"
      if ((j_ptr.back() != "-") && json_source_.at(j_ptr.parent_pointer()).is_array()) {
        try {
          auto target_idx = std::stoul(j_ptr.back());
          if (target_idx > json_source_.at(j_ptr.parent_pointer()).size()) {
            // json patch would through an excetion here
            ENVOY_STREAM_LOG(trace, "index out of range, do not add array element",
                             *decoder_callbacks_);
            return json_source_ptr_;
          }
        } catch (std::exception& e) {
          ENVOY_STREAM_LOG(trace, "exception in executeAddToJson{}", *decoder_callbacks_,
                           e.what());
          absl::Status status(absl::StatusCode::kInternal, absl::string_view("e.what()"));
          return status;
        }
      }
      ENVOY_STREAM_LOG(trace, "prepared add_patch {}", *decoder_callbacks_, add_patch.dump());
      return applyJsonPatch(add_patch, json_source_);
    }
    // PATH DOES NOT EXIST
    // DO NOTHING
    if (add_to_json.if_path_not_exists() == AddToJson_IfJsonPathNotExists_DO_NOTHING) {
      ENVOY_STREAM_LOG(trace, "path to element does not exists, do nothing", *decoder_callbacks_);
      return json_source_ptr_;
      // CREATE
    } else if (add_to_json.if_path_not_exists() == AddToJson_IfJsonPathNotExists_CREATE) {
      ENVOY_STREAM_LOG(trace, "path to element does not exists, create path", *decoder_callbacks_);
      return createPathAndAddElement(j_ptr, json_value, json_source_);
    }

  } catch (json::exception& e) {
    ENVOY_STREAM_LOG(trace, " json::exception in executeAddToJson{}", *decoder_callbacks_,
                     e.what());
    absl::Status status(absl::StatusCode::kInternal, absl::string_view("e.what()"));
    return status;
  }
  ENVOY_STREAM_LOG(trace, "internal error during executeAddToJson", *decoder_callbacks_);
  absl::Status status(absl::StatusCode::kInternal,
                      absl::string_view("internal error during executeAddToJson"));
  return status;
}

// new with json::json_pointer as arg
bool JsonOpWrapper::elementExists(const json::json_pointer& json_pointer, const json& json_doc) {
  ENVOY_STREAM_LOG(trace, "elementExists()", *decoder_callbacks_);
  try {
    auto element = json_doc.at(json_pointer);

    if (element != nullptr) {
      auto parent_ptr = json_pointer.parent_pointer();
      ENVOY_STREAM_LOG(trace, "json::json_pointer(json_pointer).back() \"{}\"", *decoder_callbacks_,
                       json_pointer.back());
      if ((json_pointer.back() == "-") && json_doc.at(parent_ptr).is_array()) {
        // allow and element to be inserted to an array, if an index is provided
        return false;
      }
    }
    return true;
  } catch (std::exception& e) {
    ENVOY_STREAM_LOG(trace, "exception {}, element does not exist", *decoder_callbacks_,
                     e.what());
    return false;
  }
}

bool JsonOpWrapper::pathToElementExists(const json::json_pointer& json_pointer, const json& json_doc) {
  ENVOY_STREAM_LOG(trace, "pathToElementExists()", *decoder_callbacks_);
  try {
    auto parent_ptr = json_pointer.parent_pointer();

    // element is under "root"
    if (parent_ptr.empty()) {
      if (json_doc != "\"\""_json) {
        // if the json doc is not empty , the path exists
        return true;
      } else {
        return false;
      }
    }
    return (json_doc.at(parent_ptr) != nullptr);

  } catch (json::exception& e) {
    ENVOY_STREAM_LOG(trace, "exception {}, path to element does not exist", *decoder_callbacks_,
                     e.what());
    return false;
  }
}

json JsonOpWrapper::createPathToElement(const std::string& json_pointer, const json& json_doc) {
  ENVOY_STREAM_LOG(trace, "createPathToElement()", *decoder_callbacks_);
  try {
    auto parent_ptr = json::json_pointer(json_pointer).parent_pointer();
    // element is under "root"
    if (parent_ptr.empty() && (json_doc == "\"\""_json)) {
      ENVOY_STREAM_LOG(trace, "element is at root, created and empty object\"{}\"", *decoder_callbacks_);
      return "{}"_json;
    }
    // check if the grand-parent of the element exists
    if ((json_doc.at(parent_ptr.parent_pointer()) != nullptr) &&
        !(parent_ptr.parent_pointer().empty())) {
      // grand parent exists, "json add patch" will take care of creating the object holding the element
      ENVOY_STREAM_LOG(trace, "grandparent of element exists, path will be created automatically by json patch", *decoder_callbacks_);
      return json_doc;
    }

  } catch (json::out_of_range& e) {
    ENVOY_STREAM_LOG(trace, "out_of_range {}, path to element does not exist", *decoder_callbacks_,
                     e.what());

  }
  // create path using flatten + add element + unflatten
  // OPEN Q, we have no clue, what type unexisting path elements should have.  
  // i.e. "1" or "-" are valid JSON keys
  json expanded_json_flat = json_doc.flatten();
  ENVOY_STREAM_LOG(trace, "expanded_json_flat \"{}\"", *decoder_callbacks_,
                   expanded_json_flat.dump());
  expanded_json_flat.emplace(json_pointer, "");
  ENVOY_STREAM_LOG(trace, "expanded_json_flat after path creation \"{}\"", *decoder_callbacks_,
                   expanded_json_flat.dump());
  return expanded_json_flat.unflatten();
}

absl::StatusOr<std::shared_ptr<json>> JsonOpWrapper::createPathAndAddElement(const json::json_pointer& json_pointer, const json& json_value, const json& json_doc) {
  ENVOY_STREAM_LOG(trace, "createPathToElement()", *decoder_callbacks_);
  //try {
    auto parent_ptr = json_pointer.parent_pointer();
    // element is under "root"
    if (parent_ptr.empty() && (json_doc == "\"\""_json)) {
      ENVOY_STREAM_LOG(trace, "element is at root, created and empty object\"{}\"", *decoder_callbacks_);
      json mod_json = "{}"_json;
      mod_json[json_pointer] = json_value;
      return std::make_shared<json>(mod_json);
    }
    json mod_json =   json_doc;
    mod_json[json_pointer] = json_value;
    ENVOY_STREAM_LOG(trace, "created path by adding value, mod_json {}", *decoder_callbacks_, mod_json.dump());
    return std::make_shared<json>(mod_json);

}

absl::StatusOr<std::shared_ptr<json>>
JsonOpWrapper::executeReplaceInJson(const ReplaceInJson& replace_in_json) {
  ENVOY_STREAM_LOG(trace, "executeReplaceInJson()", *decoder_callbacks_);
  try {
    json replace_patch = R"([{ "op": "replace", "path": "default_path", "value": "default_value"}])"_json;
    auto json_pointer = EricProxyFilter::varOrStringAsString(replace_in_json.json_pointer(),
                                                             run_ctx_, decoder_callbacks_);
    replace_patch.at(0).at("path") = json_pointer;
    auto j_ptr = json::json_pointer(json_pointer);
    const auto& json_value = EricProxyFilter::varOrJsonStringAsJson(replace_in_json.value(), run_ctx_, decoder_callbacks_);
    replace_patch.at(0).at("value") = json_value;

    // this will replace the whole json doc.
    if (j_ptr.empty()) {
      ENVOY_STREAM_LOG(trace, "replace the whole json doc with \"{}\"", *decoder_callbacks_, json_value);
      return std::make_shared<json>(json_value);
    }
    if (elementExists(j_ptr, json_source_)) {
      ENVOY_STREAM_LOG(trace, "prepared replace_patch {}", *decoder_callbacks_, replace_patch.dump());
      return applyJsonPatch(replace_patch, json_source_);
    } else if (pathToElementExists(j_ptr, json_source_)) {
      ENVOY_STREAM_LOG(trace, "element does not exists, path exists", *decoder_callbacks_);
      // check special array handling
      // non-standard json patch, we allow "-" to replace the last array element
      if ((j_ptr.back() == "-") && json_source_.at(j_ptr.parent_pointer()).is_array()) {
        if (!json_source_.at(j_ptr.parent_pointer()).empty()) {
          ENVOY_STREAM_LOG(trace, "last array element should be replaced.", *decoder_callbacks_);
          auto last_idx = json_source_.at(j_ptr.parent_pointer()).size() - 1;
          j_ptr.pop_back();
          j_ptr.push_back(std::to_string(last_idx));
          replace_patch.at(0).at("path") = j_ptr.to_string();
          ENVOY_STREAM_LOG(trace, "prepared replace_patch {}", *decoder_callbacks_, replace_patch.dump());
          return applyJsonPatch(replace_patch, json_source_);
        }
      }
    }
  } catch (json::exception& e) {
    ENVOY_STREAM_LOG(trace, "json::exception in executeReplaceInJson{}", *decoder_callbacks_, e.what());
    absl::Status status(absl::StatusCode::kInternal, absl::string_view("e.what()"));
    return status;
  }
  // if we get here, do not replace anything
  return std::make_shared<json>(json_source_);
}

absl::StatusOr<std::shared_ptr<json>> JsonOpWrapper::executeRemoveFromJson(const RemoveFromJson& remove_from_json) {
  ENVOY_STREAM_LOG(trace, "executeRemoveFromJson()", *decoder_callbacks_);
  try {
    json remove_patch = R"([{ "op": "remove", "path": "default_path"}])"_json;
    auto json_pointer = EricProxyFilter::varOrStringAsString(remove_from_json.json_pointer(),
                                                             run_ctx_, decoder_callbacks_);
    remove_patch.at(0).at("path") = json_pointer;
    auto j_ptr = json::json_pointer(json_pointer);
    
    // nlohmann throws "[json.exception.out_of_range.405] JSON pointer has no parent",
    // if the pointer is empty for the remove patch, we have to return "null" 
    if (j_ptr.empty()){
      ENVOY_STREAM_LOG(trace, "whole json removed", *decoder_callbacks_ );
      return std::make_shared<json>("null"_json);
    }

    if (elementExists(j_ptr, json_source_)) {
      ENVOY_STREAM_LOG(trace, "prepared remove_patch {}", *decoder_callbacks_, remove_patch.dump());
      return applyJsonPatch(remove_patch, json_source_);
    } else {
      ENVOY_STREAM_LOG(trace, "path does not exists, remove nothing", *decoder_callbacks_);
      return json_source_ptr_;
    }

  } catch (json::exception& e) {
    ENVOY_STREAM_LOG(trace, " json::exception in executeRemoveFromJson{}", *decoder_callbacks_, e.what());
    absl::Status status(absl::StatusCode::kInternal, absl::string_view("e.what()"));
    return status;
  }
}

absl::StatusOr<std::shared_ptr<json>> JsonOpWrapper::executeModifyJsonValue(const ModifyJsonValue& modify_json_value) {
  ENVOY_STREAM_LOG(trace, "executeModifyJsonValue()", *decoder_callbacks_);
  try {
    auto json_pointer = EricProxyFilter::varOrStringAsString(modify_json_value.json_pointer(),
                                                             run_ctx_, decoder_callbacks_);
    auto j_ptr = json::json_pointer(json_pointer);
    
    // nlohmann throws "[json.exception.out_of_range.405] JSON pointer has no parent",
    // if the pointer is empty for the remove patch, we have to return "null" 
    if (j_ptr.empty()){
      ENVOY_STREAM_LOG(trace, "empty json pointer, modify nothing", *decoder_callbacks_ );
      return json_source_ptr_;
    }
    if (json_pointer.find("/*") != std::string::npos) {
      ENVOY_STREAM_LOG(trace, "extended json pointer found, element check skipped", *decoder_callbacks_);
    } else if (!elementExists(j_ptr, json_source_)) {
      ENVOY_STREAM_LOG(trace, "element does not exists, modify nothing", *decoder_callbacks_);
      return json_source_ptr_;
    }

    if (modify_json_value.string_modifiers().size() > 0) {
      auto string_modifiers = modify_json_value.string_modifiers();
      auto modified_body = std::make_shared<Json>(json_source_);
      std::vector<std::string> targets{json_pointer};

      if (modify_json_value.enable_exception_handling()) {
        ENVOY_STREAM_LOG(trace, "exception handling is on for string_modifiers", *decoder_callbacks_);
        if (string_modifiers.size() > 1) {
          auto mod_operation = EricProxyFilter::modifyJson(
            decoder_callbacks_, modified_body, targets,
            EricProxyFilter::prepareStringModifiers(string_modifiers, run_ctx_, decoder_callbacks_),
            EricProxyJsonUtils::ThrowExceptionOnInvalid::TYPE
          );
          if (!mod_operation.ok()) {
            return mod_operation;
          }
        } else {
          auto mod_operation = EricProxyFilter::modifyJson(
            decoder_callbacks_, modified_body, targets,
            EricProxyFilter::prepareStringModifier(string_modifiers[0], run_ctx_, decoder_callbacks_),
            EricProxyJsonUtils::ThrowExceptionOnInvalid::TYPE
          );
          if (!mod_operation.ok()) {
            return mod_operation;
          }
        }
      } else {
        ENVOY_STREAM_LOG(trace, "exception handling is off for string_modifiers", *decoder_callbacks_);
        if (string_modifiers.size() > 1) {
          auto mod_operation = EricProxyFilter::modifyJson(
            decoder_callbacks_, modified_body, targets,
            EricProxyFilter::prepareStringModifiers(string_modifiers, run_ctx_, decoder_callbacks_)
          );
          if (!mod_operation.ok()) {
            return mod_operation;
          }
        } else {
          auto mod_operation = EricProxyFilter::modifyJson(
            decoder_callbacks_, modified_body, targets,
            EricProxyFilter::prepareStringModifier(string_modifiers[0], run_ctx_, decoder_callbacks_)
          );
          if (!mod_operation.ok()) {
            return mod_operation;
          }
        }
      }

      return modified_body;
    }

    return json_source_ptr_;

  } catch (json::exception& e) {
    ENVOY_STREAM_LOG(trace, "json::exception in executeModifyJsonValue: '{}'", *decoder_callbacks_, e.what());
    absl::Status status(absl::StatusCode::kInternal, absl::string_view("e.what()"));
    return status;
  } catch (const std::string& e) {
    ENVOY_STREAM_LOG(trace, "string modifier exception in executeModifyJsonValue: '{}'", *decoder_callbacks_, e);
    return absl::Status(absl::StatusCode::kInternal, e);
  } catch (...) {
    ENVOY_STREAM_LOG(trace, "unknown exception in executeModifyJsonValue", *decoder_callbacks_);
    return absl::Status(absl::StatusCode::kUnknown, "unknown exception");
  }
}

absl::StatusOr<std::shared_ptr<json>> JsonOpWrapper::applyJsonPatch(const json& json_patch, const json& json_src_doc) {
  try {
    ENVOY_STREAM_LOG(debug, "applyJsonPatch()", *decoder_callbacks_);
    ENVOY_STREAM_LOG(trace, "applying JSON patch {} on json_source {}", *decoder_callbacks_,
                     json_patch.dump(), json_src_doc.dump());

    auto patched_json = std::make_shared<json>(json_src_doc.patch(json_patch));
    ENVOY_STREAM_LOG(trace, "modified JSON is: {}", *decoder_callbacks_, patched_json->dump()); 

    return patched_json;

  } catch (json::exception& e) {
    ENVOY_STREAM_LOG(trace, " json::exception in applyJsonPatch() {}", *decoder_callbacks_, e.what());
    absl::Status status(absl::StatusCode::kInternal, absl::string_view("e.what()"));
    return status;
  }
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
