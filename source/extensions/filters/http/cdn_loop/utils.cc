#include "source/extensions/filters/http/cdn_loop/utils.h"

#include <algorithm>

#include "source/common/common/statusor.h"
#include "source/extensions/filters/http/cdn_loop/parser.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace CdnLoop {

StatusOr<int> countCdnLoopOccurrences(absl::string_view header, absl::string_view cdn_id) {
  if (cdn_id.empty()) {
    return absl::InvalidArgumentError("cdn_id cannot be empty");
  }

  if (absl::StatusOr<Parser::ParsedCdnInfoList> parsed = Parser::parseCdnInfoList(header);
      parsed.ok()) {
    auto count = std::count(parsed->cdnIds().begin(), parsed->cdnIds().end(), cdn_id);
    return count;
  } else {
    return parsed.status();
  }
}

StatusOr<std::vector<absl::string_view>> parseViaHeaderContents(absl::string_view header,
                                                                absl::string_view cdn_id) {
  if (cdn_id.empty()) {
    return absl::InvalidArgumentError("cdn_id cannot be empty");
  }
  if (absl::StatusOr<Parser::ParsedCdnInfoList> parsed = Parser::parseCdnInfoList(header);
      parsed.ok()) {
    return parsed->cdnIds();
  } else {
    return parsed.status();
  }
}

} // namespace CdnLoop
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
