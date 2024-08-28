#include <algorithm>
#include <cctype>
#include <cstddef>
#include <functional>
#include <string>
#include <utility>
#include <vector>
#include "source/common/common/logger.h"
#include "re2/re2.h"
#include "source/extensions/filters/http/eric_proxy/search_and_replace.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

std::function<std::string(const std::string&)>
EricProxySearchAndReplace::searchAndReplaceFunction(const SearchAndReplace& search_and_replace,
                         Http::StreamDecoderFilterCallbacks* decoder_callbacks,
                         RunContext& run_ctx) {
  ENVOY_STREAM_LOG(trace, "searchAndReplaceFunction()", *decoder_callbacks);
  auto search_value = EricProxyFilter::varHeaderConstValueAsString(
      search_and_replace.search_value(), false, run_ctx, decoder_callbacks);
  auto replace_value = EricProxyFilter::varHeaderConstValueAsString(
      search_and_replace.replace_value(), false, run_ctx, decoder_callbacks);
  ENVOY_STREAM_LOG(trace, "search_value='{}'", *decoder_callbacks, search_value);
  ENVOY_STREAM_LOG(trace, "replace_value='{}'", *decoder_callbacks, replace_value);

  if (search_value .empty()) {
    return ([decoder_callbacks](auto& str) {
      ENVOY_STREAM_LOG(trace, "empty search_value(), search and replace will be skipped.", *decoder_callbacks);
      return str;
    });
  }

  if (search_and_replace.search_options().regex_search()) {
    const auto& precompiled_regexs = run_ctx.rootContext()->getPrecompiledRegexs();
    const auto& precompiled_regex = precompiled_regexs.find(search_value);
    if (precompiled_regex != precompiled_regexs.end()) { // found
      return EricProxySearchAndReplace::searchAndReplaceRegexPrecompiled(precompiled_regex, replace_value);
    }
    return EricProxySearchAndReplace::searchAndReplaceRegex(search_value, replace_value);

  } else { // use std library
    if (search_and_replace.search_options().full_match()) {
      // full match
      if (!search_and_replace.search_options().case_sensitive()) {
        return EricProxySearchAndReplace::searchAndReplaceFullMatchCaseInsensitive(search_value, replace_value);
      }
      return EricProxySearchAndReplace::searchAndReplaceFullMatch(search_value, replace_value);

    } else {
      // partial match
      if (!search_and_replace.search_options().case_sensitive()) {
        return searchAndReplaceCaseInsensitive(
            search_value, replace_value, 
            search_and_replace.search_options().search_from_end(), 
            search_and_replace.replace_options().replace_all_occurances());
      }
    }
  }
  return EricProxySearchAndReplace::searchAndReplace(search_value, replace_value,
                          search_and_replace.search_options().search_from_end(),
                          search_and_replace.replace_options().replace_all_occurances());
}

std::function<std::string(const std::string&)> EricProxySearchAndReplace::searchAndReplace(const std::string& search_value,
                                                                const std::string& replace_value,
                                                                const bool& search_from_end,
                                                                const bool& replace_all) {
  return ([search_value, replace_value, search_from_end, replace_all](auto& str) {
    ENVOY_LOG(trace, "searchAndReplace()");
    std::string str_mod = str;
    auto pos = search_from_end ? str_mod.rfind(search_value) : str_mod.find(search_value);
    while (pos != std::string::npos) {
      str_mod.replace(pos, search_value.length(), replace_value);
      if (!replace_all) {
        break;
      }
      pos = search_from_end ? str_mod.rfind(search_value, pos)
                            : str_mod.find(search_value, pos + replace_value.length());
    }
    return str_mod;
  });
}

std::function<std::string(const std::string&)>
EricProxySearchAndReplace::searchAndReplaceCaseInsensitive(const std::string& search_value, const std::string& replace_value,
                                const bool& search_from_end, const bool& replace_all) {
  return ([search_value, replace_value, search_from_end, replace_all](auto& str) {
    ENVOY_LOG(trace, "searchAndReplace()");
    std::string str_mod = str;
    auto caseInsentiveCharCompare = [](unsigned char ch1, unsigned char ch2) {
      return std::tolower(ch1) == std::tolower(ch2);
    };
    auto search_it = search_from_end
                         ? std::find_end(str_mod.begin(), str_mod.end(), search_value.begin(),
                                         search_value.end(), caseInsentiveCharCompare)
                         : std::search(str_mod.begin(), str_mod.end(), search_value.begin(),
                                       search_value.end(), caseInsentiveCharCompare);

    auto search_end = search_from_end ? str_mod.begin() : str_mod.end();

    while (search_it != search_end) {

      str_mod.replace(search_it, search_it + search_value.length(), replace_value);
      if (!replace_all) {
        break;
      }
      search_end = search_from_end ? str_mod.begin() : str_mod.end();
      auto search_pos = search_it;
      search_it = search_from_end ? std::find_end(str_mod.begin(), search_pos, search_value.begin(),
                                                  search_value.end(), caseInsentiveCharCompare)
                                  : std::search(search_pos + replace_value.length(), str_mod.end(),
                                                search_value.begin(), search_value.end(),
                                                caseInsentiveCharCompare);
      if (search_from_end && (search_it == search_end)) {
        // Do a last replace for backward search
        str_mod.replace(search_it, search_it + search_value.length(), replace_value);
        break;
      }
    }
    return str_mod;
  });
}

std::function<std::string(const std::string&)>
EricProxySearchAndReplace::searchAndReplaceFullMatch(const std::string& search_value, const std::string& replace_value) {
  return ([search_value, replace_value](auto& str) {
    ENVOY_LOG(trace, "searchAndReplaceFullMatch()");
    if (str == search_value) {
      return replace_value;
    }
    return str;
  });
}

// Do we need this one ???
std::function<std::string(const std::string&)>
EricProxySearchAndReplace::searchAndReplaceFullMatchCaseInsensitive(const std::string& search_value,
                                         const std::string& replace_value) {
  return ([search_value, replace_value](auto& str) {
    ENVOY_LOG(trace, "searchAndReplaceFullMatchCaseInsensitive()");
    std::string str_lc = str;
    std::transform(str_lc.begin(), str_lc.end(), str_lc.begin(), ::tolower);

    std::string search_value_lc = search_value;
    std::transform(search_value_lc.begin(), search_value_lc.end(), search_value_lc.begin(),
                   ::tolower);

    if (str_lc == search_value_lc) {
      return replace_value;
    }
    return str;
  });
}

std::function<std::string(const std::string&)>
EricProxySearchAndReplace::searchAndReplaceRegex(const std::string& search_value, const std::string& replace_value) {
  return ([search_value, replace_value](auto& str) {
    ENVOY_LOG(trace, "searchAndReplaceRegex()");

    std::string str_mod = str;
    bool did_replace = re2::RE2::Replace(&str_mod, search_value, replace_value);
    if (!did_replace) {
      // TODO: error handling if needed at some point ?
    }
    return str_mod;
  });
}

std::function<std::string(const std::string&)>
EricProxySearchAndReplace::searchAndReplaceRegexPrecompiled(
  const std::map<std::string, re2::RE2>::const_iterator& search_value, const std::string& replace_value
) {
  return ([search_value, replace_value](auto& str) {
    ENVOY_LOG(trace, "searchAndReplaceRegexPrecompiled()");

    std::string str_mod = str;
    bool did_replace = re2::RE2::Replace(&str_mod, search_value->second, replace_value);
    if (!did_replace) {
      // TODO: error handling if needed at some point ?
    }
    return str_mod;
  });
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
