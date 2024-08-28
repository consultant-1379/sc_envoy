#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <sys/types.h>

#include "include/nlohmann/json.hpp"
#include "source/common/common/logger.h"
#include "source/common/common/statusor.h"

using namespace nlohmann;

#define JSON_HEDLEY_UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#if (defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)) &&                 \
    !defined(JSON_NOEXCEPTION)
#define JSON_THROW(exception) throw exception
#define JSON_TRY try
#define JSON_CATCH(exception) catch (exception)
#endif

#if !defined(JSON_ASSERT)
#include <cassert> // assert
#define JSON_ASSERT(x) assert(x)
#endif

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// enum IgnoreErrorOn{
//     TYPE = 1 << 0, // same as 1
//     KEY = 1  << 1, // same as 2, binary 10
//     INDEX = 1 << 2, // same as 4, binary 100
//     OTHER = 1 << 3 // same as 8, binary 1000
// };

class EricProxyJsonUtils : public Logger::Loggable<Logger::Id::eric_proxy>{
public:
  static void map_at(nlohmann::json* ptr, const std::string& reference_string,
                     std::function<std::string(const std::string&)> map_function,
                     int throw_exeption_flags = 0);
  
  static void map_at(nlohmann::json* ptr, const std::string& reference_string,
                     const std::vector<std::function<std::string(const std::string&)>>& map_functions,
                     int throw_exeption_flags = 0);

/*!
Convert all elements found by the extended JSON-pointer with the supplied map_function
to a new value. An extended JSON pointer understands "*" as "all elements in an array".
@throw parse_error.106   if an array index begins with '0'
@throw parse_error.109   if an array index was not a number
@throw out_of_range.402  if the array index '-' is used
@throw out_of_range.403  if the array index is not found
*/
  static void map_at(nlohmann::json* ptr, const std::string& reference_string,
                     const std::function<std::string(const std::string&)>* map_functions, 
                     const std::size_t& map_functions_len,
                     int throw_exeption_flags = 0);

  static absl::StatusOr<std::shared_ptr<nlohmann::json>> parseWithFormatCheck(
    const std::string& json_source,
    const absl::optional<int>& expected_leaves,
    const absl::optional<int>& expected_depth
  );

  enum ThrowExceptionOnInvalid{
    TYPE = 1 << 0, // same as 1
    KEY = 1  << 1, // same as 2, binary 10
    INDEX = 1 << 2, // same as 4, binary 100
    OTHER = 1 << 3 // same as 8, binary 1000
  };

private:

  static void map_at_tokens(nlohmann::json* ptr, 
                            const std::function<std::string(const std::string&)>* map_functions,
                            const std::size_t& map_functions_len,
                            std::vector<std::string>::const_iterator begin,
                            std::vector<std::string>::const_iterator end,
                            const int& error_handling_flags);

  static void apply_map_function(
    nlohmann::json* ptr, std::function<std::string(const std::string&)> map_function,
    const int& error_handling_flags
  );
  
  static void apply_map_functions(
    nlohmann::json* ptr, const std::vector<std::function<std::string(const std::string&)>>& map_functions,
    const int& error_handling_flags
  );

  static void apply_map_functions(
    nlohmann::json* ptr, const std::function<std::string(const std::string&)>* map_function,
    const std::size_t& map_functions_len, const int& error_handling_flags
  );

  template <typename BasicJsonType>
  static std::vector<std::string> split(const std::string& reference_string);

  template <typename BasicJsonType>
  static typename BasicJsonType::size_type array_index(const std::string& s);

  static inline void replace_substring(std::string& s, const std::string& f, const std::string& t);
  static void unescape(std::string& s);

};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
