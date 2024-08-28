
#include "source/extensions/filters/http/eric_proxy/json_utils.h"
//#include "include/nlohmann/json.hpp"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <functional>
#include <string_view>
#include <vector>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using json = nlohmann::json;

json json_dict = json::parse(R"(
      {
        "k1": {
          "a1": "v11",
          "a2": "v12"
        },
        "k2": {
          "a1": "v21",
          "a2": "v22"
        },
        "k3": {
          "a1": "v31",
          "a2": "v32"
        },
        "k4": {
          "a1": "v41",
          "a2": "v42"
        }               
      }
  )");

auto modifier = [](auto& str) { return str + "-suffix"; };

/*
Test all offered variants of map_at()

- with a single std::function<...>
- with vector<std::function<...>>

- with vector<std::function<...>> or std::function<...> 
    using std::function<...>* and map_functions_len
    (this was implemented to avoid unnecessary vector creation, when using a single function)  
*/

/*
TestMapAt_with_single_function
- test the map_at() variant providing just a std::function<...>
- tests that "map_at()" is successfully executed with a single modifier function
  on a single element of a dictionary
*/
TEST(EricProxyJsonUtilsTest, TestMapAt_with_single_function) {
  json json_src = json_dict;
  EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/k2/a2"), modifier);
  EXPECT_EQ(json_src["/k2/a2"_json_pointer], "v22-suffix");
}

/*
TestMapAt_with_single_function_with_ptr_and_length) {
- test the map_at() variant providing a std::function<...> and 
- tests that "map_at()" is successfully executed with 
    a single modifier function 
    and modifier_functions_len = 1
  on a single element of a dictionary
*/
TEST(EricProxyJsonUtilsTest,
     TestMapAt_with_single_function_with_ptr_and_length) {
  json json_src = json_dict;
  EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/k2/a2"), modifier, 1);
  EXPECT_EQ(json_src["/k2/a2"_json_pointer], "v22-suffix");
}

/*
TestMapAt_with_single_function_as_vector) {
- test the map_at() variant providing a vector::std::function<...>  
- tests that "map_at()" is successfully executed with 
    a single modifier function in an vector
  on a single element of a dictionary
*/
TEST(EricProxyJsonUtilsTest, TestMapAt_with_single_function_as_vector) {
  json json_src = json_dict;
  const std::vector<std::function<std::string(const std::string&)>> modifiers = {modifier};
  EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/k2/a2"), modifiers);
  EXPECT_EQ(json_src["/k2/a2"_json_pointer], "v22-suffix");
}

/*
TestMapAt_with_2_functions_with_ptr_and_length) {
- test the map_at() variant providing a the address of a vector<std::function<...>>  
- tests that "map_at()" is successfully executed with 
    2 modifier functions in an vector
    and modifier_functions_len = 2
  on a single element of a dictionary
*/
TEST(EricProxyJsonUtilsTest,
     TestMapAt_with_2_functions_with_ptr_and_length) {
  json json_src = json_dict;
  const std::vector<std::function<std::string(const std::string&)>> modifiers = {modifier,
                                                                                 modifier};
  EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/k2/a2"), modifiers, 2);
  EXPECT_EQ(json_src["/k2/a2"_json_pointer], "v22-suffix-suffix");
}

/*
TestMapAt_with_2_function_as_vector) {
- test the map_at() variant providing a vector::std::function<...>  
- tests that "map_at()" is successfully executed with 
    2 modifier functions in an vector
  on a single element of a dictionary
*/
TEST(EricProxyJsonUtilsTest, TestMapAt_with_2_function_as_vector) {
  json json_src = json_dict;
  const std::vector<std::function<std::string(const std::string&)>> modifiers = {modifier,
                                                                                 modifier};
  EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/k2/a2"), modifiers);
  EXPECT_EQ(json_src["/k2/a2"_json_pointer], "v22-suffix-suffix");
}


/*
  Test Variations of dictionary iteration support for map_at()
*/

/*
TestMapAt_with_single_function_dict_iter_wildcard_at_root

- test the map_at() variant providing just a std::function<...>
- tests that "map_at()" is successfully executed with a single modifier function on a dictionary
- the wildcard ("*")  is set at the root of the dictionary

*/
TEST(EricProxyJsonUtilsTest, TestMapAt_with_single_function_dict_iter_wildcard_at_root) {
  json json_src = json_dict;
  EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/*/a2"), modifier);

  EXPECT_EQ(json_src["/k1/a2"_json_pointer], "v12-suffix");
  EXPECT_EQ(json_src["/k2/a2"_json_pointer], "v22-suffix");
  EXPECT_EQ(json_src["/k3/a2"_json_pointer], "v32-suffix");
  EXPECT_EQ(json_src["/k4/a2"_json_pointer], "v42-suffix");
}

/*
TestMapAt_with_single_function_dict_iter_wildcard_at_root

- test the map_at() variant providing just a std::function<...>
- tests that "map_at()" is successfully executed with a single modifier function on a dictionary
- the wildcard ("*")  is set at the root of the dictionary

*/
TEST(EricProxyJsonUtilsTest, TestMapAt_dict_iter) {
  json json_src = json_dict;
  EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/*/a2"), modifier);

  EXPECT_EQ(json_src["/k1/a2"_json_pointer], "v12-suffix");
  EXPECT_EQ(json_src["/k2/a2"_json_pointer], "v22-suffix");
  EXPECT_EQ(json_src["/k3/a2"_json_pointer], "v32-suffix");
  EXPECT_EQ(json_src["/k4/a2"_json_pointer], "v42-suffix");
}

/*
TestMapAt_dict_iter_type_error

- test the map_at() variant providing just a std::function<...>
- tests that "map_at()" is successfully executed with a single modifier function on a dictionary
- the wildcard ("*")  is set at the root of the dictionary, -> any key should match
- one of the keys points to an integer instead od a string
   - the element will be left untouched and all other elements will be modified (default behavior)

*/
TEST(EricProxyJsonUtilsTest, TestMapAt_dict_iter_type_error_ignore) {

  json json_src = json::parse(R"(
      {
        "k1": {
          "a1": "v11",
          "a2": "v12"
        },
        "k2": {
          "a1": "v21",
          "a2": "v22"
        },
        "k3": {
          "a1": "v31",
          "a2": 32
        },
        "k4": {
          "a1": "v41",
          "a2": "v42"
        }               
      }
  )");

  EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/*/a2"), modifier);

  EXPECT_EQ(json_src["/k1/a2"_json_pointer], "v12-suffix");
  EXPECT_EQ(json_src["/k2/a2"_json_pointer], "v22-suffix");
  EXPECT_EQ(json_src["/k3/a2"_json_pointer], 32);
  EXPECT_EQ(json_src["/k4/a2"_json_pointer], "v42-suffix");
}


/*
TestMapAt_dict_iter_type_error_throw_exception

- test the map_at() variant providing just a std::function<...>
- tests that "map_at()" is successfully executed with a single modifier function on a dictionary
  - the "ignore_mapping_exception" is set to false
- the wildcard ("*")  is set at the root of the dictionary, -> any key should match
- one of the keys points to an integer instead of a string
   - the element will be left untouched and all other elements will be modified (default behavior)
   - the modification/iteration will be interrupted, by throwing an exception 

*/
TEST(EricProxyJsonUtilsTest, TestMapAt_dict_iter_type_error_throw_exception) {

  json json_src = json::parse(R"(
      {
        "k1": {
          "a1": "v11",
          "a2": "v12"
        },
        "k2": {
          "a1": "v21",
          "a2": "v22"
        },
        "k3": {
          "a1": "v31",
          "a2": 32
        },
        "k4": {
          "a1": "v41",
          "a2": "v42"
        }               
      }
  )");

  //EXPECT_THROW(
  //  EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/*/a2"), modifier, false), 
  //  nlohmann::json_abi_v3_11_2::detail::exception
  //);

  try {
    EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/*/a2"), modifier, EricProxyJsonUtils::ThrowExceptionOnInvalid::TYPE);
    FAIL();  // exception not thrown as expected
  } catch (const json::exception& ex) {
    EXPECT_STREQ("[json.exception.type_error.302] type must be string, but is number", ex.what());
  }

}

/*
Tests for combined List and dictionary iteration
*/

/*
TestMapAt_dictionary_inside_a_list

- test the map_at() variant providing just a std::function<...>
- tests that "map_at()" is successfully executed with a single modifier function on a dictionary
  - the "ignore_mapping_exception" is set to false
- the wildcard ("*")  is set at the root of the dictionary, -> any key should match
- one of the keys points to an integer instead of a string
   - the element will be left untouched and all other elements will be modified (default behavior)
   - the modification/iteration will be interrupted, by throwing an exception 
*/
TEST(EricProxyJsonUtilsTest, TestMapAt_dictionary_inside_a_list) {

  json json_dict_tmp = json::parse(R"(
      {
        "k1": {
          "a1": "v11",
          "a2": "v2"
        },
        "k2": {
          "a1": "v21",
          "a2": "v2"
        },
        "k3": {
          "a1": "v31",
          "a2": "v2"
        },
        "k4": {
          "a1": "v41",
          "a2": "v2"
        }               
      }
  )");

  json json_src;

  json_src["list"] = {json_dict_tmp, json_dict_tmp , json_dict_tmp};

  EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/list/*/*/a2"), modifier);
  for (int i = 0; i < 3; i++) {
    EXPECT_EQ(json_src[json::json_pointer("/list/"+std::to_string(i)+"/k1/a2")], "v2-suffix");
    EXPECT_EQ(json_src[json::json_pointer("/list/"+std::to_string(i)+"/k2/a2")], "v2-suffix");
    EXPECT_EQ(json_src[json::json_pointer("/list/"+std::to_string(i)+"/k3/a2")], "v2-suffix");
    EXPECT_EQ(json_src[json::json_pointer("/list/"+std::to_string(i)+"/k4/a2")], "v2-suffix");
  }
}

/*
TestMapAt_list_inside_a_dictionary
  - a list is placed in a  dictionary, map_at() is call with wildcards "*" 
    for both dict. key and list index
  - all relevant elements are modified 
*/
TEST(EricProxyJsonUtilsTest, TestMapAt_list_inside_a_dictionary) {  
  json json_src = json::parse(R"(
      {
        "k1": {
          "a1": "v11",
          "a2": ["v2", "v2", "v2"]
        },
        "k2": {
          "a1": "v21",
          "a2": ["v2", "v2", "v2"]
        },
        "k3": {
          "a1": "v31",
          "a2": ["v2", "v2", "v2"]
        },
        "k4": {
          "a1": "v41",
          "a2": ["v2", "v2", "v2"]
        }               
      }
  )");


  EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/*/a2/*"), modifier);
  for (int i = 0; i < 3; i++) {
    EXPECT_EQ(json_src[json::json_pointer("/k1/a2/"+std::to_string(i))], "v2-suffix");     
    EXPECT_EQ(json_src[json::json_pointer("/k2/a2/"+std::to_string(i))], "v2-suffix"); 
    EXPECT_EQ(json_src[json::json_pointer("/k3/a2/"+std::to_string(i))], "v2-suffix");     
    EXPECT_EQ(json_src[json::json_pointer("/k4/a2/"+std::to_string(i))], "v2-suffix"); 
  }
}

/*
TestMapAt_invalid__dict_key_throws  
  - a dictionary is placed in a list, map_at() is called with invalid keys
    i.e. "_*_" , "*.*"
  - the "error_handling_flag" is set to throw an exception on 
    invalid index : EricProxyJsonUtils::ThrowExceptionOnInvalid::INDEX
  - exceptions are thrown
*/
TEST(EricProxyJsonUtilsTest, TestMapAt_invalid_dict_key_throws) {
  json json_src = json::parse(R"(
      {
        "k1": {
          "a1": "v11",
          "a2": "v2"
        },
        "k2": {
          "a1": "v21",
          "a2": "v2"
        },
        "k3": {
          "a1": "v31",
          "a2": "v2"
        },
        "k4": {
          "a1": "v41",
          "a2": "v2"
        }               
      }
  )");
    
  try{
    EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/k40/a2"), modifier, EricProxyJsonUtils::ThrowExceptionOnInvalid::KEY);
    FAIL();  // exception not thrown as expected
  } catch (json::exception& ex) {
      EXPECT_STREQ("[json.exception.out_of_range.403] key 'k40' not found", ex.what());
  }

  try{
    EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/_*_/a2"), modifier, EricProxyJsonUtils::ThrowExceptionOnInvalid::KEY);
    FAIL();  // exception not thrown as expected
  } catch (json::exception& ex) {
      EXPECT_STREQ("[json.exception.out_of_range.403] key '_*_' not found", ex.what());
  }
}

/*

Test list iterations

*/
/*test - as index*/
/*
TestMapAt_list_invalid_idx  
  - map_at() is called with an invalid indices for a list, the "error_handling_flag" is set to throw
    an exception on invalid index : EricProxyJsonUtils::ThrowExceptionOnInvalid::INDEX
    i.e. "-" , 5 (too high)
    for both  list index and dict. key
  - no elements are modified 
*/
TEST(EricProxyJsonUtilsTest, TestMapAt_list_invalid_idx_throws_exception) {
  json json_src = json::parse(R"(
        ["v2", "v2", "v2"]
  )");

  try {
    EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/-"), modifier, EricProxyJsonUtils::ThrowExceptionOnInvalid::INDEX);
    // EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/*/a2"), modifier, false);
    FAIL(); // exception not thrown as expected
  } catch (json::exception& ex) {
    EXPECT_STREQ("[json.exception.out_of_range.402] array index '-' "
                 "(std::to_string(ptr->m_value.array->size())) is out of range",
                 ex.what());
  }
  try {
    EricProxyJsonUtils::map_at(&json_src, json::json_pointer("/3"), modifier, EricProxyJsonUtils::ThrowExceptionOnInvalid::INDEX);
    FAIL(); // exception not thrown as expected
  } catch (json::exception& ex) {
    EXPECT_STREQ("[json.exception.out_of_range.401] array index 3 is out of range", ex.what());
  }

}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
