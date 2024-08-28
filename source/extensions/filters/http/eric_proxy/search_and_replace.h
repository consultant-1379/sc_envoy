#pragma once

#include <cstddef>
#include <functional>
#include <string>

#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/common/common/logger.h"
#include "re2/re2.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using SearchAndReplace = envoy::extensions::filters::http::eric_proxy::v3::SearchAndReplace;

class EricProxySearchAndReplace : public Logger::Loggable<Logger::Id::eric_proxy> {
public:
  /*
  searchAndReplaceFunction
  returns the best suited searchAndReplace-function based on the provided
  search_and_replace configuration

  const SearchAndReplace& search_and_replace

  */
  static std::function<std::string(const std::string&)>
  searchAndReplaceFunction(const SearchAndReplace&,
                           Http::StreamDecoderFilterCallbacks* decoder_callbacks,
                           RunContext& run_ctx);

  /*
  searchAndReplaceStd
  returns a searchAndReplace function using std::string library support
    for partial_match, search from beginning
  */
  static std::function<std::string(const std::string&)> searchAndReplace(const std::string& search_value,
                                                                  const std::string& replace_value,
                                                                  const bool& search_from_end,
                                                                  const bool& replace_all = false);

  /*
  searchAndReplaceStdCaseInsensitive
  returns a searchAndReplace function using std::string library support
    for partial_match, search from beginning
  */
  static std::function<std::string(const std::string&)>
  searchAndReplaceCaseInsensitive(const std::string& search_value, const std::string& replace_value,
                                  const bool& search_from_end, const bool& replace_all = false);

  /*
  searchAndReplaceStdFull
  returns a searchAndReplace function using std::string library support
    for full_match on string equality
  */
  static std::function<std::string(const std::string&)>
  searchAndReplaceFullMatch(const std::string& search_value, const std::string& replace_value);

  /*
  searchAndReplaceStdFullMatchCaseInsensitive
  returns a searchAndReplace function using std::string library support
    for full_match on string equality, after lower case conversion
  */
  static std::function<std::string(const std::string&)>
  searchAndReplaceFullMatchCaseInsensitive(const std::string& search_value,
                                           const std::string& replace_value);

  /*
  searchAndReplaceRegex
  returns a searchAndReplace function using RE2 regexlibrary support
  */
  static std::function<std::string(const std::string&)>
  searchAndReplaceRegex(const std::string& search_value, const std::string& replace_value);

  /*
  searchAndReplaceRegexPrecompiled
  returns a searchAndReplace function using RE2 regexlibrary support
  with precompiled regex
  */
  static std::function<std::string(const std::string&)>
  searchAndReplaceRegexPrecompiled(
    const std::map<std::string, re2::RE2>::const_iterator& search_value, const std::string& replace_value
  );
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
