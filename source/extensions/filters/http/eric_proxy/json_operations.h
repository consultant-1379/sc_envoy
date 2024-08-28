#pragma once

#include <string>
#include <memory>
#include <type_traits>

#include "source/extensions/filters/http/common/pass_through_filter.h"
#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "source/common/common/logger.h"
#include "include/nlohmann/json.hpp"
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/common/common/statusor.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using namespace google::protobuf;
using namespace ::envoy::extensions::filters::http::eric_proxy::v3;

using json = nlohmann::json;

//------- JsonOperation Wrapper -----------------------------------------------
class JsonOpWrapper : public Logger::Loggable<Logger::Id::eric_proxy> {
public:
    JsonOpWrapper(const JsonOperation& json_op_proto_config, const json& json_source,
                  Http::StreamDecoderFilterCallbacks* decoder_callbacks, RunContext& run_ctx);

  absl::StatusOr<std::shared_ptr<json>> execute();
private:
  const JsonOperation& json_op_proto_config_;
  const json& json_source_;
  //TODO move const ref. to shared_ptr everywhere in this class
  std::shared_ptr<json> json_source_ptr_; 
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_;
  RunContext& run_ctx_;

  absl::StatusOr<std::shared_ptr<json>> executeAddToJson(const AddToJson& add_to_json);
  absl::StatusOr<std::shared_ptr<json>> executeReplaceInJson(const ReplaceInJson& replace_in_json);
  absl::StatusOr<std::shared_ptr<json>> executeRemoveFromJson(const RemoveFromJson& remove_from_json);
  absl::StatusOr<std::shared_ptr<json>> executeModifyJsonValue(const ModifyJsonValue& modify_json_value);

  absl::StatusOr<std::shared_ptr<json>> applyJsonPatch(const json& json_patch, const json& json_src_doc);
  absl::StatusOr<std::shared_ptr<json>> createPathAndAddElement(const json::json_pointer& json_pointer, const json& json_value, const json& json_doc);

  /**
   * try to parse the input value as json, if it fails, try again after enclosing
   * the input in double quotes.
   **/
  json tryToParseValueAsJson(const std::string& value_as_string);

  bool elementExists(const json::json_pointer& json_pointer, const json& json_doc);
  bool pathToElementExists(const json::json_pointer& json_pointer, const json& json_doc);

  json createPathToElement(const std::string& json_pointer, const json& json_doc);

};

} // namespace EricProxy
} // namespace HttpFilterss
} // namespace Extensions
} // namespace Envoy
