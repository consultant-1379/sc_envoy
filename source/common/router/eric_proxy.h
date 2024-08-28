#pragma once

#include <vector>

#include "source/common/protobuf/protobuf.h"
#include "envoy/config/route/v3/route_components.pb.h"
#include "envoy/router/router.h"

namespace Envoy {
namespace Router {

class TarList: Logger::Loggable<Logger::Id::router> {
  public:
    TarList(Http::StreamDecoderFilterCallbacks* callbacks): callbacks_(callbacks){};
    void setTarValuesFromMd(const ::google::protobuf::Map<std::string, ::google::protobuf::Struct>*);
    std::string getNextTarValue();
  private:
    // data structures for remote-round-robin support
  std::vector<std::string> tar_api_root_values_;
  uint32_t current_tar_api_root_values_idx_{0};
  Http::StreamDecoderFilterCallbacks* callbacks_{};
};



} // namespace Router
} // namespace Envoy
