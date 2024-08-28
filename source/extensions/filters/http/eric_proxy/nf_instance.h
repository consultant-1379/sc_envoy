#pragma once

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
  
struct NfInstance {
  absl::optional<std::string> hostname;
  absl::optional<std::string> set_id;
  absl::optional<std::string> nfInstanceId;
}; 

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy