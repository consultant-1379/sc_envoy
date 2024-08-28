#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>
#include <regex>
#include <sstream>
#include <string>

#include "source/extensions/filters/http/eric_proxy/json_utils.h"

using namespace nlohmann;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

/*!
Convert all elements found by the extended JSON-pointer with the supplied map_function(s)
to a new value. An extended JSON pointer understands "*" as "all elements in an array".
@throw parse_error.106   if an array index begins with '0'
@throw parse_error.109   if an array index was not a number
@throw out_of_range.402  if the array index '-' is used
@throw out_of_range.403  if the array index is not found
*/
void EricProxyJsonUtils::map_at(json* ptr, const std::string& reference_string,
                                const std::function<std::string(const std::string&)>* map_functions,
                                const std::size_t& map_functions_len,
                                int error_handling_flags) {
  auto reference_tokens = split<json>(reference_string);
  auto&& __range = reference_tokens;
  map_at_tokens(ptr, map_functions, map_functions_len, __range.begin(), __range.end(), error_handling_flags);
}

void EricProxyJsonUtils::map_at(json* ptr, const std::string& reference_string,
                                std::function<std::string(const std::string&)> map_function, 
                                int error_handling_flags) {
  auto reference_tokens = split<json>(reference_string);
  auto&& __range = reference_tokens;
  map_at_tokens(ptr, &map_function, 1 , __range.begin(), __range.end(), error_handling_flags);
}

void EricProxyJsonUtils::map_at(json* ptr, const std::string& reference_string,
                                const std::vector<std::function<std::string(const std::string&)>>& map_functions, 
                                int error_handling_flags) {
  auto reference_tokens = split<json>(reference_string);
  auto&& __range = reference_tokens;
  map_at_tokens(ptr, &map_functions[0], map_functions.size() , __range.begin(), __range.end(), error_handling_flags );
}

void EricProxyJsonUtils::map_at_tokens(json* ptr,
                                       const std::function<std::string(const std::string&)>* map_functions, 
                                       const std::size_t& map_functions_len,
                                       std::vector<std::string>::const_iterator begin,
                                       std::vector<std::string>::const_iterator end,
                                       const int& error_handling_flags
                                       ) {
  ENVOY_LOG(trace, "map_at_tokens(), error_handling_flags='{}'", error_handling_flags);
  for (auto __begin = begin, __end = end; __begin != __end; ++__begin) {
    const auto& reference_token = *__begin;
    // ENVOY_LOG(trace, "processing ref token: '{}'", reference_token);
    switch (ptr->type()) {
    case detail::value_t::array: {
      if (JSON_HEDLEY_UNLIKELY(reference_token == "-")) // one after last index, not valid here
      {
        // "-" always fails the range check
        JSON_THROW(detail::out_of_range::create(
            402, "array index '-' (std::to_string(ptr->m_value.array->size())) is out of range",
            nullptr));
      }
      if (reference_token == "*") // wildcard to indicate "apply to all"
      {
        __begin++;
        for (auto& i : *ptr) {
          json* next_ptr;
          bool ok;
          JSON_TRY {
            next_ptr = &i;
            ok = true;
          }
          JSON_CATCH(...) { ok = false; }
          if (ok) {
            if (__begin != __end) // more levels below this one?
            {
              map_at_tokens(next_ptr, map_functions, map_functions_len, __begin, __end,error_handling_flags);
            } else // we are at the deepest level
            {
              apply_map_functions(next_ptr, map_functions, map_functions_len, error_handling_flags);
            }
          }
        }
        return;
      } else // normal index
      {
        if (error_handling_flags & ThrowExceptionOnInvalid::INDEX) {
          // note: at performs range check
          ptr = &ptr->at(array_index<json>(reference_token));
        } else {
          JSON_TRY {
            // note: at performs range check
            ptr = &ptr->at(array_index<json>(reference_token));
          }
          JSON_CATCH(...) { continue; }
        }
      }
      break;
    }
    // start dictionary support (eedrak)
    case detail::value_t::object: {
      if (JSON_HEDLEY_UNLIKELY(reference_token == "-")) // one after last index, not valid here
      {
        // "-" always fails the range check
        JSON_THROW(detail::out_of_range::create(
            402, "array index '-' (std::to_string(ptr->m_value.array->size())) is out of range",
            nullptr));
      }
      if (reference_token == "*") // wildcard to indicate "apply to all"
      {
        ENVOY_LOG(trace,
                  "wildcard char '*' found, try to iterate over the all attribute of the object");
        __begin++;
        for (auto& [key, val] : ptr->items()) {
          ENVOY_LOG(trace, "key:'{}' ", key);
          ENVOY_LOG(trace, "value:'{}' ", val.dump());
          json* next_ptr;
          bool ok;
          JSON_TRY {
            next_ptr = &val;
            ok = true;
          }
          JSON_CATCH(...) { ok = false; }
          if (ok) {
            if (__begin != __end) // more levels below this one?
            {
              map_at_tokens(next_ptr, map_functions, map_functions_len  , __begin, __end, error_handling_flags);
            } else // we are at the deepest level
            {
              apply_map_functions(next_ptr, map_functions, map_functions_len, error_handling_flags);                             
            }
          }
        }
        return;
      } else // "normal" object
      {
        if (error_handling_flags & ThrowExceptionOnInvalid::KEY) {
          ptr = &ptr->at(reference_token);
          break;
        } else {
          JSON_TRY {
            // note: at performs range check
            ptr = &ptr->at(reference_token);
            break;
          }
          JSON_CATCH(...) { return; }
          break;
        }
      }
    }
    // end dictionary support (eedrak)
    default:
      JSON_THROW(detail::out_of_range::create(
          404, "unresolved reference token '" + reference_token + "'", nullptr));
    }
  }
  apply_map_functions(ptr, map_functions, map_functions_len, error_handling_flags);                             
}

void EricProxyJsonUtils::apply_map_function(
  json* ptr, std::function<std::string(const std::string&)> map_function,
  const int& error_handling_flags
) {
  ENVOY_LOG(trace, "apply_map_function()");
  if (error_handling_flags & ThrowExceptionOnInvalid::TYPE) {
    *ptr = map_function(*ptr);
  } else {
    JSON_TRY {
      *ptr = map_function(*ptr);
    }
    JSON_CATCH(...) { return; }  
  }
}

void EricProxyJsonUtils::apply_map_functions(
  json* ptr, const std::vector<std::function<std::string(const std::string&)>>& map_functions,
  const int& error_handling_flags
) {
  ENVOY_LOG(trace, "apply_map_functions()");
  for(const auto &map_function: map_functions){
    apply_map_function(ptr, map_function, error_handling_flags);
  }
}

void EricProxyJsonUtils::apply_map_functions(
  json* ptr, const std::function<std::string(const std::string&)>* map_functions,
  const std::size_t& map_functions_len, const int& error_handling_flags
) {
  ENVOY_LOG(trace, "apply_map_functions()");
  for(size_t i = 0; i < map_functions_len; i++ ){
    apply_map_function(ptr, *(map_functions + i), error_handling_flags);
  }
}

/*!
@brief split the string input to reference tokens

@note This function is only called by the json_pointer constructor.
      All exceptions below are documented there.

@throw parse_error.107  if the pointer is not empty or begins with '/'
@throw parse_error.108  if character '~' is not followed by '0' or '1'
*/
template <typename BasicJsonType>
std::vector<std::string> EricProxyJsonUtils::split(const std::string& reference_string) {
  std::vector<std::string> result;

  // special case: empty reference string -> no reference tokens
  if (reference_string.empty()) {
    return result;
  }

  // check if nonempty reference string begins with slash
  if (JSON_HEDLEY_UNLIKELY(reference_string[0] != '/')) {
    JSON_THROW(detail::parse_error::create(
        107, 1, "JSON pointer must be empty or begin with '/' - was: '" + reference_string + "'",
        nullptr));
  }

  // extract the reference tokens:
  // - slash: position of the last read slash (or end of string)
  // - start: position after the previous slash
  for (
      // search for the first slash after the first character
      std::size_t slash = reference_string.find_first_of('/', 1),
                  // set the beginning of the first reference token
      start = 1;
      // we can stop if start == 0 (if slash == std::string::npos)
      start != 0;
      // set the beginning of the next reference token
      // (will eventually be 0 if slash == std::string::npos)
      start = (slash == std::string::npos) ? 0 : slash + 1,
                  // find next slash
      slash = reference_string.find_first_of('/', start)) {
    // use the text between the beginning of the reference token
    // (start) and the last slash (slash).
    auto reference_token = reference_string.substr(start, slash - start);

    // check reference tokens are properly escaped
    for (std::size_t pos = reference_token.find_first_of('~'); pos != std::string::npos;
         pos = reference_token.find_first_of('~', pos + 1)) {
      JSON_ASSERT(reference_token[pos] == '~');

      // ~ must be followed by 0 or 1
      if (JSON_HEDLEY_UNLIKELY(
              pos == reference_token.size() - 1 ||
              (reference_token[pos + 1] != '0' && reference_token[pos + 1] != '1'))) {
        JSON_THROW(detail::parse_error::create(
            108, 0, "escape character '~' must be followed with '0' or '1'", nullptr));
      }
    }

    // finally, store the reference token
    unescape(reference_token);
    result.push_back(reference_token);
  }

  return result;
}

/*!
@param[in] s  reference token to be converted into an array index

@return integer representation of @a s

@throw parse_error.106  if an array index begins with '0'
@throw parse_error.109  if an array index begins not with a digit
@throw out_of_range.404 if string @a s could not be converted to an integer
@throw out_of_range.410 if an array index exceeds size_type
*/
template <typename BasicJsonType>
typename BasicJsonType::size_type EricProxyJsonUtils::array_index(const std::string& s) {
  using size_type = typename BasicJsonType::size_type;

  // error condition (cf. RFC 6901, Sect. 4)
  if (JSON_HEDLEY_UNLIKELY(s.size() > 1 && s[0] == '0')) {
    JSON_THROW(detail::parse_error::create(
        106, 0, "array index '" + s + "' must not begin with '0'", nullptr));
  }

  // error condition (cf. RFC 6901, Sect. 4)
  if (JSON_HEDLEY_UNLIKELY(s.size() > 1 && !(s[0] >= '1' && s[0] <= '9'))) {
    JSON_THROW(detail::parse_error::create(109, 0, "array index '" + s + "' is not a number",
                                           nullptr));
  }

  std::size_t processed_chars = 0;
  unsigned long long res = 0; // NOLINT(runtime/int)
  JSON_TRY { res = std::stoull(s, &processed_chars); }
  JSON_CATCH(std::out_of_range&) {
    JSON_THROW(detail::out_of_range::create(404, "unresolved reference token '" + s + "'",
                                            nullptr));
  }

  // check if the string was completely read
  if (JSON_HEDLEY_UNLIKELY(processed_chars != s.size())) {
    JSON_THROW(detail::out_of_range::create(404, "unresolved reference token '" + s + "'",
                                            nullptr));
  }

  // only triggered on special platforms (like 32bit), see also
  // https://github.com/nlohmann/json/pull/2203
  if (res >= static_cast<unsigned long long>(
                 (std::numeric_limits<size_type>::max)())) // NOLINT(runtime/int)
  {
    JSON_THROW(detail::out_of_range::create(410, "array index " + s + " exceeds size_type",
                                            nullptr)); // LCOV_EXCL_LINE
  }

  return static_cast<size_type>(res);
}

inline void EricProxyJsonUtils::replace_substring(std::string& s, const std::string& f,
                                                  const std::string& t) {
  JSON_ASSERT(!f.empty());
  for (auto pos = s.find(f);            // find first occurrence of f
       pos != std::string::npos;        // make sure f was found
       s.replace(pos, f.size(), t),     // replace with t, and
       pos = s.find(f, pos + t.size())) // find next occurrence of f
  {
  }
}

void EricProxyJsonUtils::unescape(std::string& s) {
  replace_substring(s, "~1", "/");
  replace_substring(s, "~0", "~");
}

/**
 * Parse the string body into JSON with configured format checks
 *
 * @param[in] body  string body to be parsed into JSON
 * @param[in] max_leaves_limit  optional configured maximum number of leaves limit
 * @param[in] max_depth_limit  optional configured maximum nesting depth limit
 *
 * @return Status or shared pointer JSON representation of @a body
 */
absl::StatusOr<std::shared_ptr<json>>
EricProxyJsonUtils::parseWithFormatCheck(const std::string& body,
                                         const absl::optional<int>& max_leaves_limit,
                                         const absl::optional<int>& max_depth_limit) {
  int leaves = 0;
  int max_depth = 0;
  int in_array_level = 0;
  bool is_simple_array = true;

  // define parser callback
  json::parser_callback_t cb = [&leaves, &in_array_level, &is_simple_array, &max_depth,
                                &max_leaves_limit, &max_depth_limit](
                                   int depth, json::parse_event_t event, json& parsed) {
    switch (event) {
    case json::parse_event_t::object_start:
      // ENVOY_LOG(trace, "event:parse_event_t::object_start");
      if (in_array_level > 0) {
        is_simple_array = false;
      }
      break;

    case json::parse_event_t::key:
      // ENVOY_LOG(trace, "event:parse_event_t::key"); 
      break;

    case json::parse_event_t::object_end:
      // an empty array should be counted as leaf
      if (parsed.empty()){
        leaves++;
      }
      // ENVOY_LOG(trace, "event:parse_event_t::object_end");
      break;

    case json::parse_event_t::array_start:
      // ENVOY_LOG(trace, "event:parse_event_t::array_start");
      if (in_array_level > 0) {
        is_simple_array = false;
      }
      in_array_level++;
      break;

    case json::parse_event_t::array_end:
      // ENVOY_LOG(trace, "event:parse_event_t::array_end");
      // If a leaf IE is an array of a simple data type, 
      // then the whole array shall count as one leaf.
      //
      // ... correct the leaves counter (stepped on "value" event) 
      if (is_simple_array){
        leaves = leaves - parsed.size() + 1;
      }      
      in_array_level--;
      if (in_array_level == 0){
        is_simple_array = true; // reset flag
      }
      break;

    case json::parse_event_t::value:
      // ENVOY_LOG(trace, "event:parse_event_t::value");
      leaves++;
      break; 
    }

    max_depth = (depth > max_depth) ? depth : max_depth;

    if (max_leaves_limit.has_value()) {
      if (leaves > max_leaves_limit.value()) {
        ENVOY_LOG(trace, "Maximum JSON leaves limit crossed, limit: '{}', found: '{}'",
                  max_leaves_limit.value(), leaves);
        throw std::string("Maximum JSON leaves limit crossed");
      }
    }

    if (max_depth_limit.has_value()) {
      if (max_depth > max_depth_limit.value()) {
        ENVOY_LOG(trace, "Maximum JSON nested depth limit crossed, limit: '{}', found: '{}'",
                  max_depth_limit.value(), max_depth);
        throw std::string("Maximum JSON nested depth limit crossed");
      }
    }

    // ENVOY_LOG(trace, "in_array_level:'{}'", in_array_level);
    // ENVOY_LOG(trace, "is_simple_array:'{}'", is_simple_array);
    // ENVOY_LOG(trace, "parsed:'{}'", parsed.dump());
    // ENVOY_LOG(trace, "depth:'{}'", depth);
    // ENVOY_LOG(trace, "max_depth:'{}'", max_depth);
    // ENVOY_LOG(trace, "leaves:'{}'", leaves);

    return true;
  };

  try {
    json json_parsed = json::parse(body, cb);
    // TODO: convert to unique pointer
    std::shared_ptr<json> json_body = std::make_shared<json>(json_parsed);
    ENVOY_LOG(trace, "json_body:'{}', leaves:'{}', max_depth:'{}'", json_body->dump(), leaves, max_depth);

    return json_body;
  } catch (std::string& e) {
    ENVOY_LOG(debug, "Invalid JSON body format ({})", e);

    return absl::OutOfRangeError(e);
  } catch (json::parse_error& e) {
    // TODO(eedala): step counter for malformed body
    ENVOY_LOG(debug, "Malformed JSON body ({})", e.what());

    return absl::InvalidArgumentError(e.what());
  }
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
