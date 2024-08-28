#include <algorithm>
#include <memory>
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/common/common/logger.h"
#include "absl/strings/string_view.h"
#include "absl/strings/str_format.h"


// Methods in this file are all in the EricProxyFilter class.
// They are stored in a separate file to keep action processing
// separate.

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

//-------- Body Actions ---------------------------------------------------------------

// Create Body Action
ActionResultTuple EricProxyFilter::actionCreateBody(
  const FilterActionWrapper& action
) {
  const auto proto_config = action.protoConfig().action_create_body();
  ENVOY_STREAM_LOG(debug, "Action-Create-Body, applying action: '{}'", *decoder_callbacks_,
                    proto_config.name());

  const std::string& body = proto_config.content();
  body_->setBodyFromString(body);

  const std::string& header_value = proto_config.content_type();
  const auto& header_name = Http::LowerCaseString("content-type");
  auto hdr = run_ctx_.getReqOrRespHeaders()->get(header_name);
  if (hdr.empty()) {
    ENVOY_STREAM_LOG(trace, "Adding new header: content-type, new value: {}",
        *decoder_callbacks_, header_value);
  } else {
    ENVOY_STREAM_LOG(trace, "Replacing header: content-type, new value: {}",
        *decoder_callbacks_, header_value);
    run_ctx_.getReqOrRespHeaders()->remove(header_name);
  }
  run_ctx_.getReqOrRespHeaders()->addCopy(header_name, header_value);

  return std::make_tuple(ActionResult::Next, true, std::nullopt);
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
