#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.validate.h"
#include "source/extensions/filters/http/eric_proxy/config.h"

#include "source/extensions/filters/http/eric_proxy/json_operations.h"

#include "source/extensions/filters/http/eric_proxy/proxy_filter_config.h"
#include "source/common/protobuf/protobuf.h"

#include "test/mocks/server/factory_context.h"
#include "test/mocks/server/instance.h"
#include "test/mocks/upstream/cluster_manager.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using json = nlohmann::basic_json<>;

using JsonOperationProtoConfig = envoy::extensions::filters::http::eric_proxy::v3::JsonOperation;

class EricProxyJsonOperationsTest : public ::testing::Test {
protected:
  RootContext root_ctx_;
  RunContext run_ctx_ = RunContext(&root_ctx_);
  Http::MockStreamDecoderFilterCallbacks decoder_callbacks_;

  void SetUp() override {
    EXPECT_CALL(decoder_callbacks_, connection()).Times(testing::AtLeast(0));
    EXPECT_CALL(decoder_callbacks_, streamId()).Times(testing::AtLeast(0));
  }
};

json orig_json_doc = json::parse(R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
            "nFName": "123e-e8b-1d3-a46-421",
            "nFIPv4Address": "192.168.0.1",
            "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
            "nFPLMNID": {
                "mcc": "311",
                "mnc": 280
            },
            "nodeFunctionality": "SMF"
        }
      }
  )");

/**
 * ADD TESTS
 *
 */


/**
 * not standard JSON Patch behaviour
 */
TEST_F(EricProxyJsonOperationsTest, AddToJson_string_value_element_exists_no_action) {

  auto json_pointer = "/subscriberIdentifier"_json_pointer;
  std::string expected_value = "imsi-460001357924610";

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'supi_added'
  json_pointer:
    term_string: "/subscriberIdentifier"
  if_path_not_exists:  DO_NOTHING
  if_element_exists:  NO_ACTION
  )EOF";

  json orig_json = orig_json_doc;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
  auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  json mod_json = *op_result.value();
  string actual_value = mod_json[json_pointer];
  EXPECT_EQ(actual_value, expected_value);
}

/**
 * standard JSON Patch behaviour
 */
TEST_F(EricProxyJsonOperationsTest, AddToJson_string_value_element_exists_replace) {

  auto json_pointer = "/subscriberIdentifier"_json_pointer;
  std::string expected_value = "supi_added";

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'supi_added'
  json_pointer:
    term_string: "/subscriberIdentifier"
  if_path_not_exists:  DO_NOTHING
  if_element_exists:  REPLACE
  )EOF";

  json orig_json = orig_json_doc;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

  auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  json mod_json = *op_result.value();
  string actual_value = mod_json[json_pointer];
  EXPECT_EQ(actual_value, expected_value);
}

/**
 * PATH: exists
 * ELEMENT: does not exists
 * 
 * EXP. RESULT:  value is added
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_string_value_path_exists_element_does_not_exist) {

  auto json_pointer = "/subscriberIdentifier_added"_json_pointer;
  std::string expected_value = "supi_added";

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'supi_added'
  json_pointer:
    term_string: "/subscriberIdentifier_added"
  if_path_not_exists:  DO_NOTHING
  if_element_exists:  NO_ACTION
  )EOF";

  json orig_json = orig_json_doc;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

  auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  json mod_json = *op_result.value();
  string actual_value = mod_json[json_pointer];
  EXPECT_EQ(actual_value, expected_value);
}

/**
 * PATH:  exists 
 * ELEMENT: is array existing index 
 * 
 * if_path_not_exists:  CREATE
 * if_element_exists:  REPLACE
 * 
 * EXP. RESULT:  path to element is created (root) and the value is added
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_string_value_inserted_into__existing_array) {

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'v23_2_inserted'
  json_pointer:
    term_string: "/k2/k23/2"
  if_path_not_exists:  CREATE
  if_element_exists:  REPLACE
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1","v23_2_inserted", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();
  ASSERT_TRUE(op_result.ok());
  auto actual_value = *op_result.value();
  EXPECT_EQ(actual_value, exp_json);
}


/**
 * PATH:  exists 
 * ELEMENT: is array index "-"
 * 
 * if_path_not_exists:  CREATE
 * 
 * EXP. RESULT:  path to element is created (root) and the value is added
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_string_value_added_to_end_of_existing_array) {

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'v23_4_added'
  json_pointer:
    term_string: "/k2/k23/-"
  if_path_not_exists:  CREATE
  if_element_exists:  NO_ACTION
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3", "v23_4_added"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  auto actual_value = *op_result.value();
  EXPECT_EQ(actual_value, exp_json);
}

/**
 * PATH: does not exists (empty JSON doc.)
 * ELEMENT: does not exists
 * 
 * if_path_not_exists:  DO_NOTHING
 * 
 * EXP. RESULT:  path value is added
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_string_value_path_not_exists_do_nothing) {

  auto json_pointer = "/subscriberIdentifier_added"_json_pointer;
  json expected_value = "\"\""_json;

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'supi_added'
  json_pointer:
    term_string: "/subscriberIdentifier_added"
  if_path_not_exists:  DO_NOTHING
  if_element_exists:  NO_ACTION
  )EOF";

  json orig_json = "\"\""_json;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  auto actual_value = *op_result.value();
  EXPECT_EQ(actual_value, expected_value);
}

/**
 * PATH: does not exists (empty JSON doc.)
 * ELEMENT: does not exists
 * 
 * if_path_not_exists:  CREATE
 * 
 * EXP. RESULT:  path to element is created (root) and the value is added
 * 
 * non standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_string_value_path_not_exists_create_root) {

  auto json_pointer = "/subscriberIdentifier_added"_json_pointer;
  std::string expected_value = "supi_added";

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'supi_added'
  json_pointer:
    term_string: "/subscriberIdentifier_added"
  if_path_not_exists:  CREATE
  if_element_exists:  NO_ACTION
  )EOF";

  json orig_json = "\"\""_json;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  json mod_json = *op_result.value();
  string actual_value = mod_json[json_pointer];
  EXPECT_EQ(actual_value, expected_value);
}


/**
 * PATH: does not exists (path to nested object does not exist)
 * ELEMENT: does not exists
 * 
 * if_path_not_exists:  CREATE
 * 
 * EXP. RESULT:  path to element is created (root) and the value is added
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_string_value_path_not_exists_create_nested_path) {

  auto json_pointer = "/k2/k24/k243/k243/1/k2431"_json_pointer;
  std::string expected_value = "v2431_added";

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'v2431_added'
  json_pointer:
    term_string: "/k2/k24/k243/k243/1/k2431"
  if_path_not_exists:  CREATE
  if_element_exists:  NO_ACTION
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  json mod_json = *op_result.value();
  string actual_value = mod_json[json_pointer];
  EXPECT_EQ(actual_value, expected_value);
}


/**
 * ADD
 * 
 * REQ.: in case the specified element by the json-pointer attribute is either an array 
 *       or an object and the “if-element-exists” value is “replace”, then the whole array
 *       or object value is replaced by the new value specified in the “value” attribute
 * 
 * PATH: exists 
 * ELEMENT: is an existing array
 * 
 *  if_path_not_exists:  DO_NOTHING
 *  if_element_exists:  REPLACE
 * 
 * EXP. RESULT:  the whole array is replaced
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_replace_existing_array) {

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: '{"k23_1":"v23_1"}'
  json_pointer:
    term_string: "/k2/k23"
  if_path_not_exists:  DO_NOTHING
  if_element_exists:  REPLACE
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": {"k23_1":"v23_1"},
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}

/**
 * ADD
 * 
 * REQ.: in case the specified element by the json-pointer attribute is either an array 
 *       or an object and the “if-element-exists” value is “replace”, then the whole array
 *       or object value is replaced by the new value specified in the “value” attribute
 * 
 * PATH: exists 
 * ELEMENT: is an existing object
 * 
 *  if_path_not_exists:  DO_NOTHING
 *  if_element_exists:  REPLACE
 * 
 * EXP. RESULT:  the whole object is replaced
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_replace_existing_object) {

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: '["1","2","3"]'
  json_pointer:
    term_string: "/k2/k24"
  if_path_not_exists:  DO_NOTHING
  if_element_exists:  REPLACE
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": ["1","2","3"],
            "25": "v25"
        }
      }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}

/**
 * ADD
 * 
 * REQ.: If the json-pointer specifies an array index, and the index value is greater
 *       than the number of existing elements in the array, then nothing will be added.​  
 * 
 * PATH: exists 
 * ELEMENT: is an existing array element at index = 0 
 * 
 *  if_path_not_exists:  DO_NOTHING
 *  if_element_exists:  REPLACE
 * 
 * EXP. RESULT:  the element is added to the begginn of the the array existing elements
 * are shifted right
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_add_array_element_at_idx_0) {

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'new_val'
  json_pointer:
    term_string: "/k2/k23/0"
  if_path_not_exists:  DO_NOTHING
  if_element_exists:  REPLACE
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": [ "new_val", "v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}



/**
 * ADD
 * 
 * REQ.: If the json-pointer specifies an array index, and the index value is greater
 *       than the number of existing elements in the array, then nothing will be added.​  
 * 
 * PATH: exists 
 * ELEMENT: is an array element index == the current number of elements
 * 
 *  if_path_not_exists:  DO_NOTHING
 *  if_element_exists:  REPLACE
 * 
 * EXP. RESULT:  the element is added to the end of the array
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_add_array_element_idx_eq_number_of_elements) {

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'new_val'
  json_pointer:
    term_string: "/k2/k23/3"
  if_path_not_exists:  DO_NOTHING
  if_element_exists:  REPLACE
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3", "new_val"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}


/**
 * ADD
 * 
 * REQ.: If the json-pointer specifies an array index, and the index value is greater
 *       than the number of existing elements in the array, then nothing will be added.​  
 * 
 * PATH: exists 
 * ELEMENT: is an array element index higher than the current number of elements
 * 
 *  if_path_not_exists:  DO_NOTHING
 *  if_element_exists:  REPLACE
 * 
 * EXP. RESULT:  original json document is not change
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_do_not_replace_array_element_out_of_range) {

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'new_val'
  json_pointer:
    term_string: "/k2/k23/4"
  if_path_not_exists:  DO_NOTHING
  if_element_exists:  REPLACE
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  json exp_json = orig_json;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}

/**
 * ADD
 * 
 * REQ.: If the json-pointer specifies the JSON body (json-pointer = ""),
 *       then the body content is replaced with the new value.  
 * 
 * PATH:  
 * ELEMENT: 
 * 
 *  if_path_not_exists:  DO_NOTHING
 *  if_element_exists:  REPLACE
 * 
 * EXP. RESULT:  the whole json document is replaced
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_replace_whole_json_if_json_pointer_is_empty) {

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'new json doc'
  json_pointer:
    term_string: ""
  if_path_not_exists:  DO_NOTHING
  if_element_exists:  REPLACE
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  json exp_json = "\"new json doc\""_json;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}

/**
 * ADD
 *
 * REQ.: If the json-pointer value ends with a '/', the element with empty key ("": )
 *       is defined aspath. For example, if the json-pointer = "/object1/object2/", 
 *       then the element with key "" inside the /object1/object2 is searched. 
 *       The same applies when the json-pointer specifies the root of the JSON body 
 *       (json-pointer = "/"). 
 *       If the json-pointer = "/", then the element with key "" inside the root of
 *       the JSON body is searched for.
 *
 * PATH:  exists 
 * ELEMENT: exists
 *
 *  if_path_not_exists:  DO_NOTHING
 *  if_element_exists:  REPLACE
 *
 * EXP. RESULT:  the value identified by and empty key ("") is replaced
 *
 * standard JSON Patch behaviour
 *
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_replace_element_with_empty_key_if_json_pointer_ends_with_slash) {

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'v_replaced'
  json_pointer:
    term_string: "/k2/"
  if_path_not_exists:  DO_NOTHING
  if_element_exists:  REPLACE
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "": "v25"
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "": "v_replaced"
        }
      }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}

/**
 * ADD
 *
 * REQ.: If the json-pointer value ends with a '/', the element with empty key ("": )
 *       is defined aspath. For example, if the json-pointer = "/object1/object2/", 
 *       then the element with key "" inside the /object1/object2 is searched. 
 *       The same applies when the json-pointer specifies the root of the JSON body 
 *       (json-pointer = "/"). 
 *       If the json-pointer = "/", then the element with key "" inside the root of
 *       the JSON body is searched for.
 *
 * PATH:  exists == "/"
 * ELEMENT: does not exist
 *
 *  if_path_not_exists:  DO_NOTHING
 *  if_element_exists:  NO_ACTION
 *
 * EXP. RESULT:  the value identified by and empty key ("") is replaced
 *
 * standard JSON Patch behaviour
 *
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_add_element_with_empty_key_in_root_if_json_pointer_is_slash) {

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'v_added'
  json_pointer:
    term_string: "/"
  if_path_not_exists:  DO_NOTHING
  if_element_exists:  NO_ACTION
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"       
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"       
        },
        "": "v_added"
      }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}

/**
 * PATH: does not exists (path to nested object does not exist , create whole object tree)
 * ELEMENT: does not exists
 * 
 * if_path_not_exists:  CREATE
 * 
 * EXP. RESULT:  path to element is created (root) and the value is added
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_object_value_path_not_exists_create_object_tree) {

  auto json_pointer = "/k1/k24/k243/1/k2431"_json_pointer;
  std::string expected_value = "{\"object_added\": \"flag1\": true}";

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: '{"object_added": "flag1": true}'
  json_pointer:
    term_string: "/k1/k24/k243/1/k2431"
  if_path_not_exists:  CREATE
  if_element_exists:  NO_ACTION
  )EOF";

  json orig_json = "{\"k2\": {}}"_json;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  json mod_json = *op_result.value();
  string actual_value = mod_json[json_pointer];
  EXPECT_EQ(actual_value, expected_value);
}

/**
 * PATH: does not exists (path to nested object does not exist , create whole object tree)
 *       the path contains a "-" instead of an index
 * 
 * OPEN Q, the created structure is actually no array, how wouldwe know that it should be one?
 * 
 * ELEMENT: does not exists
 * 
 * if_path_not_exists:  CREATE
 * 
 * EXP. RESULT:  path to element is created (root) and the value is added
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_object_value_path_not_exists_create_object_tree_insert_at_end_of_array) {

  auto json_pointer = "/k1/k24/k243/-/k2431"_json_pointer;

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: '{"object_added": "flag1": true}'
  json_pointer:
    term_string: "/k1/k24/k243/-/k2431"
  if_path_not_exists:  CREATE
  if_element_exists:  NO_ACTION
  )EOF";

  json orig_json = "{\"k2\": {}}"_json;

  json exp_json = json::parse(R"(
  {
  "k1":{
    "k24":{
      "k243":[
          {
            "k2431":"{\"object_added\": \"flag1\": true}"
          }
        ]
      }
    },
    "k2":{}
  }
  )");
  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}

/**
 * PATH: does not exists (path to grandparent of the element exists )
 * 
 * OPEN Q, the created structure is actually no array, how wouldwe know that it should be one?
 * 
 * ELEMENT: does not exists
 * 
 * if_path_not_exists:  CREATE
 * 
 * EXP. RESULT:  path to element is created and the value is added
 * 
 * standard JSON Patch behaviour ?
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_object_value_path_not_exists_grandparent_object) {

  const std::string yaml = R"EOF(
add_to_json:
  value:
    term_string: '{"object_added": {"flag1": true}}'
  json_pointer:
    term_string: "/k2/k21/k211"
  if_path_not_exists:  CREATE
  if_element_exists:  NO_ACTION
  )EOF";

  json orig_json = json::parse(R"(
    {
    "k2": {} 
   }
  )");

  json exp_json = json::parse(R"(
  {
    "k2": {
      "k21": {
        "k211": {
          "object_added": {
            "flag1": true
            }
        }
      }
    }
  }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}

/**
 * PATH: does not exists (path to grandparent of the element exists )
 * 
 * the element is to be added to and array, the index (3), does not exist, null values will be inserted
 * 
 * ELEMENT: does not exists
 * 
 * if_path_not_exists:  CREATE
 * 
 * EXP. RESULT:  path to element is created (by adding ) and the value is added
 * 
 * standard JSON Patch behaviour ?
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_object_value_path_not_exists_parent_is_existing_array) {

  const std::string yaml = R"EOF(
add_to_json:
  value:
    term_string: '{"object_added": {"flag1": true}}'
  json_pointer:
    term_string: "/k2/3/k211"
  if_path_not_exists:  CREATE
  if_element_exists:  NO_ACTION
  )EOF";

  json orig_json = json::parse(R"(
    {
    "k2": [] 
   }
  )");

  json exp_json = json::parse(R"(
  {
    "k2": [
        null, 
        null,
        null,
        {"k211": {
          "object_added": {
            "flag1": true
          }
        }
      }
    ]
  }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}


/**
 * PATH: does not exists (path to grandparent of the element exists )
 * 
 * the element is to be added to and array, the index (3), does not exist, null values will be inserted
 * 
 * ELEMENT: does not exists
 * 
 * if_path_not_exists:  CREATE
 * 
 * EXP. RESULT:  path to element is created (by adding ) and the value is added
 * 
 * standard JSON Patch behaviour ?
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_object_value_path_not_exists_parent_does_not_exist) {

  const std::string yaml = R"EOF(
add_to_json:
  value:
    term_string: '{"object_added": {"flag1": true}}'
  json_pointer:
    term_string: "/k2/3/k211"
  if_path_not_exists:  CREATE
  if_element_exists:  NO_ACTION
  )EOF";

  json orig_json = json::parse(R"(
    {
   }
  )");

  // json exp_json = json::parse(R"(
  // {
  //   "k2": {
  //     "3": {
  //           "k211": {
  //           "object_added": {
  //           "flag1": true
  //          }
  //       }
  //     }
  //   }
  // }
  // )");

  json exp_json = json::parse(R"(
{
  "k2":[
    null,
    null,
    null,
    {
      "k211":{
        "object_added":{
          "flag1":true
        }
      }
    }
  ]
}
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}

/**
 * PATH: does not exists (path to grandparent of the element exists, grandparent is root)
 * 
 * OPEN Q, the created structure is actually no array, how wouldwe know that it should be one?
 * 
 * ELEMENT: does not exists
 * 
 * if_path_not_exists:  CREATE
 * 
 * EXP. RESULT:  path to element is created and the value is added
 * 
 * standard JSON Patch behaviour ?
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, AddToJson_object_value_path_not_exists_grandparent_is_root) {

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: '{"object_added": {"flag1": true}}'
  json_pointer:
    term_string: "/k1/k11"
  if_path_not_exists:  CREATE
  if_element_exists:  NO_ACTION
  )EOF";

  json orig_json = json::parse(R"(
    {
    "k2": "v2" 
   }
  )");

  json exp_json = json::parse(R"(
  {
    "k1": {
      "k11": {"object_added": {"flag1": true}}
    },
    "k2": "v2"
  }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}


/**
 * REPLACE  TESTS
 *
 */

/**
 * REPLACE
 * 
 * REQ.: If the json-pointer specifies an object,
 *       then the object’s whole content is replaced by the value.​
 *  
 * PATH: exists 
 * ELEMENT: exists
 *  
 * EXP. RESULT:  the JSON element is replaced
 **/
TEST_F(EricProxyJsonOperationsTest, ReplaceInJson_replace_object) {

  auto json_pointer = "/nfConsumerIdentification/nFPLMNID"_json_pointer;
  json expected_value = R"({"k1": 1, "k2": "2"})"_json;

  const std::string yaml = R"EOF(
replace_in_json:
  value:
    term_string: '{"k1": 1, "k2": "2"}'
  json_pointer:
    term_string: "/nfConsumerIdentification/nFPLMNID"
  )EOF";

  json orig_json = orig_json_doc;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();
  json mod_json = *op_result.value();
  auto actual_value = mod_json[json_pointer];

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(actual_value, expected_value);
}

/**
 * REPLACE 
 * PATH: does not exists 
 * ELEMENT: does not exists
 *  
 * EXP. RESULT:  the JSON document is not modified
 **/
TEST_F(EricProxyJsonOperationsTest, ReplaceInJson_replace_element_does_not_exist) {

  auto json_pointer = "/nfConsumerIdentification/nFPLMNID"_json_pointer;
  auto expected_value = orig_json_doc[json_pointer];

  const std::string yaml = R"EOF(
replace_in_json:
  value:
    term_string: '{"k1": 1, "k2": "2"}'
  json_pointer:
    term_string: "/nonExistingPath/nFPLMNID"
  )EOF";

  json orig_json = orig_json_doc;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value() ,orig_json );
}

TEST_F(EricProxyJsonOperationsTest, ReplaceInJson_bool_dnd_407786) {

  auto json_pointer =
      "/pDUSessionChargingInformation/userInformation/unauthenticatedFlag"_json_pointer;
  json original_body = json::parse(
      R"({"invocationSequenceNumber":0,"invocationTimeStamp":"2019-03-28T14:30:50Z","multipleUnitUsage":[{"ratingGroup":100,"requestedUnit":{"downlinkVolume":1234,"serviceSpecificUnits":6543,"time":123,"totalVolume":211,"uplinkVolume":123},"uPFID":"123e-e8b-1d3-a46-421"}],"nfConsumerIdentification":{"nFIPv4Address":"192.168.0.1","nFIPv6Address":"2001:db8:85a3:8d3:1319:8a2e:370:7348","nFName":"123e-e8b-1d3-a46-421","nFPLMNID":{"mcc":"311","mnc":"280"},"nodeFunctionality":"SMF"},"pDUSessionChargingInformation":{"chargingId":123,"pduSessionInformation":{"3gppPSDataOffStatus":"ACTIVE","chargingCharacteristics":"AB","chargingCharacteristicsSelectionMode":"HOME_DEFAULT","dnnId":"DN-AAA","hPlmnId":{"mcc":"374","mnc":"645"},"networkSlicingInfo":{"sNSSAI":{"sd":"Aaa123","sst":0}},"pduAddress":{"IPv4dynamicAddressFlag":true,"IPv6dynamicAddressFlag":false,"pduAddressprefixlength":0,"pduIPv4Address":"192.168.0.1","pduIPv6Address":"2001:db8:85a3:8d3:1319:8a2e:370:7348"},"pduSessionID":1,"pduType":"IPV4","qoSInformation":"test127","ratType":"EUTRA","servingCNPlmnId":{"mcc":"311","mnc":"280"},"servingNetworkFunctionID":{"gUAMI":{"amfId":"ABab09","plmnId":{"mcc":"311","mnc":"280"}},"servingNetworkFunctionInstanceid":"SMF_Instanceid_1","servingNetworkFunctionName":"SMF"},"servingNodeID":[{"amfId":"ABab09","plmnId":{"mcc":"311","mnc":"280"}}],"sscMode":"SSC_MODE_1","startTime":"2019-03-28T14:30:50Z"},"uetimeZone":"+05:30","unitCountInactivityTimer":125,"userInformation":{"roamerInOut":"OUT_BOUND","servedGPSI":"msisdn-77117777","servedPEI":"imei-234567891098765","unauthenticatedFlag":true},"userLocationTime":"2019-03-28T14:30:50Z","userLocationinfo":{"eutraLocation":{"ageOfLocationInformation":32766,"ecgi":{"eutraCellId":"abcAB12","plmnId":{"mcc":"374","mnc":"645"}},"geodeticInformation":"ABCDEFAB123456789023","geographicalInformation":"234556ABCDEF2345","globalNgenbId":{"n3IwfId":"ABCD123","ngRanNodeId":"MacroNGeNB-abc92","plmnId":{"mcc":"374","mnc":"645"}},"tai":{"plmnId":{"mcc":"374","mnc":"645"},"tac":"ab01"},"ueLocationTimestamp":"2019-03-28T14:30:50Z"},"n3gaLocation":{"n3IwfId":"ABCD123","n3gppTai":{"plmnId":{"mcc":"374","mnc":"645"},"tac":"ab01"},"portNumber":1,"ueIpv4Addr":"192.168.0.1","ueIpv6Addr":"2001:db8:85a3:8d3:1319:8a2e:370:7348"},"nrLocation":{"ageOfLocationInformation":1,"geodeticInformation":"AB12334765498F12ACBF","geographicalInformation":"AB12334765498F12","globalGnbId":{"n3IwfId":"ABCD123","ngRanNodeId":"MacroNGeNB-abc92","plmnId":{"mcc":"374","mnc":"645"}},"ncgi":{"nrCellId":"ABCabc123","plmnId":{"mcc":"374","mnc":"645"}},"tai":{"plmnId":{"mcc":"374","mnc":"645"},"tac":"ab01"},"ueLocationTimestamp":"2019-03-28T14:30:50Z"}}},"subscriberIdentifier":"imsi-460030700000001"})");

  const std::string yaml = R"EOF(
replace_in_json:
  value:
    term_string: 'false'
  json_pointer:
    term_string: "/pDUSessionChargingInformation/userInformation/unauthenticatedFlag"
  )EOF";

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, original_body, &decoder_callbacks_, run_ctx_);

  EXPECT_TRUE(original_body.at(json_pointer));

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_FALSE(op_result.value()->at(json_pointer));
}


/**
 * REPLACE 
 * 
 * REQ.:
 *     If the json-pointer specifies an array index, 
 *     the value of the array element at the specified index is replaced.​ 
 * 
 * PATH: exists 
 * ELEMENT: exists
 *  
 * EXP. RESULT:  the element is replaced
 **/
TEST_F(EricProxyJsonOperationsTest, ReplaceInJson_replace_array_element) {

  const std::string yaml = R"EOF(
replace_in_json:
  value:
    term_string: 'value_replaced'
  json_pointer:
    term_string: "/k2/k23/0"
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_2"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"       
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["value_replaced", "v23_1", "v23_2"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"       
        }
      }
  )");


  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json );
}

/**
 * REPLACE 
 * 
 * REQ.:
 *     If the json-pointer specifies the array index “-” of an existing array,
 *     then the value of the last array element is replaced. 
 * 
 * PATH: exists 
 * ELEMENT: (exists)
 *  
 * EXP. RESULT:  the last array element is replaced
 **/
TEST_F(EricProxyJsonOperationsTest, ReplaceInJson_replace_last_array_element) {

  const std::string yaml = R"EOF(
replace_in_json:
  value:
    term_string: 'value_replaced'
  json_pointer:
    term_string: "/k2/k23/-"
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_2"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"       
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "value_replaced"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"       
        }
      }
  )");


  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json );
}


/**
 * REPLACE 
 * 
 * REQ.:
 *     If the json-pointer specifies the array index “-” of an existing array,
 *     then the value of the last array element is replaced. 
 * 
 * PATH: exists 
 * ELEMENT: (exists) is an empty array
 *  
 * EXP. RESULT:  the original json doc. is not modified
 **/
TEST_F(EricProxyJsonOperationsTest, ReplaceInJson_do_not_replace_last_array_element_of_empty_array) {

  const std::string yaml = R"EOF(
replace_in_json:
  value:
    term_string: 'value_replaced'
  json_pointer:
    term_string: "/k2/k23/-"
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": [],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"       
        }
      }
  )");

  json exp_json = orig_json;


  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json );
}
/**
 * REPLACE 
 * 
 * REQ.:
 *     If the json-pointer specifies an array, then the array’s whole content is replaced by the value.
 * 
 * PATH: exists 
 * ELEMENT: exists
 *  
 * EXP. RESULT:  the whole array is replaced
 **/
TEST_F(EricProxyJsonOperationsTest, ReplaceInJson_replace_whole_array_by_a_string) {

  const std::string yaml = R"EOF(
replace_in_json:
  value:
    term_string: 'this was an array'
  json_pointer:
    term_string: "/k2/k23"
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_2"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"       
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": "this was an array",
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"       
        }
      }
  )");


  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json );
}
/**
 * REPLACE 
 * 
 * REQ.:
 *     If the json-pointer specifies a non-existing element inside the JSON body, then no value is replaced.
 * 
 * PATH: exists 
 * ELEMENT: does not exists
 *  
 * EXP. RESULT:  the original json doc. is not modified
 **/
TEST_F(EricProxyJsonOperationsTest, ReplaceInJson_do_not_replace_non_existing_element) {

  const std::string yaml = R"EOF(
replace_in_json:
  value:
    term_string: 'value_replaced'
  json_pointer:
    term_string: "/k2/k24/k243"
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": [],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"       
        }
      }
  )");

  json exp_json = orig_json;


  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json );
}
/**
 * REPLACE 
 * 
 * REQ.:
 *     If the json-pointer specifies the content of the JSON document (json-pointer = ""), 
 *     then the specified value becomes the entire content of the JSON body.
 * 
 * PATH: exists 
 * ELEMENT: is the whole body
 *  
 * EXP. RESULT:  the whole json doc. is replaced by the configured value
 **/
TEST_F(EricProxyJsonOperationsTest, ReplaceInJson_replace_the_whole_json_doc) {

  const std::string yaml = R"EOF(
replace_in_json:
  value:
    term_string: 'json_replaced'
  json_pointer:
    term_string: ""
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": [],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"       
        }
      }
  )");

  json exp_json = "\"json_replaced\""_json;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json );
}

/**
 * REPLACE 
 * 
 * REQ.:
 *     If the json-pointer specifies the content of the JSON document (json-pointer = ""), 
 *     then the specified value becomes the entire content of the JSON body.
 * 
 * PATH: exists 
 * ELEMENT: exists under root , json pointer is "/"
 *  
 * EXP. RESULT:  the element under root with an empty key is replaced
 **/
TEST_F(EricProxyJsonOperationsTest, ReplaceInJson_replace_element_identified_by_empty_key) {

  const std::string yaml = R"EOF(
replace_in_json:
  value:
    term_string: 'value_replaced'
  json_pointer:
    term_string: "/"
  )EOF";

  json orig_json = json::parse(R"(
      {
        "" : "v_0",
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": [],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "" : "value_replaced",
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": [],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"
        }
      }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json );
}

/**
 * REMOVE TESTS
 *
 */



/**
 * REMOVE
 * 
 * REQ.: ​If the json-pointer specifies an object member, then the object member is removed.​
 * 
 * PATH:  exists 
 * ELEMENT: exists  
 *  * 
 * EXP. RESULT:  the object member is removed
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, RemoveFromJson_remove_object_member) {

  const std::string yaml = R"EOF(
remove_from_json:    
  json_pointer:
    term_string: "/k2/k22"
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": [],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k23": [],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"
        }
      }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json );
}

/**
 * REMOVE
 * 
 * REQ.: If the json-pointer specifies an object, then the object is removed (and existing sub-objects).​
 * 
 * PATH:  exists 
 * ELEMENT: non existing array  
 *  * 
 * EXP. RESULT:  exists
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, RemoveFromJson_remove_object) {

  const std::string yaml = R"EOF(
remove_from_json:    
  json_pointer:
    term_string: "/k2"
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": [],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "k1": "v1"
      }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json );
}

/**
 * REMOVE
 * 
 * REQ.: If the json-pointer specifies an element from an array,
 *       then the element is removed and any elements above the specified index are shifted.​​
 * 
 * PATH:  exists 
 * ELEMENT:  existing array element
 *  * 
 * EXP. RESULT:  the element is removed and any elements above the specified index are shifted.​​
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, RemoveFromJson_remove_array_element) {

  const std::string yaml = R"EOF(
remove_from_json:    
  json_pointer:
    term_string: "/k2/k23/1"
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0","v23_1","v23_2"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0","v23_2"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"
        }
      }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json );
}
/**
 * REMOVE
 * 
 * REQ.: If the json-pointer specifies an array, then the array with its elements are removed.
 * 
 * PATH:  exists 
 * ELEMENT:  existing array element
 *  * 
 * EXP. RESULT:  the whole array is removed
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, RemoveFromJson_remove_whole_array) {

  const std::string yaml = R"EOF(
remove_from_json:    
  json_pointer:
    term_string: "/k2/k23"
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0","v23_1","v23_2"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"
        }
      }
  )");

  json exp_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"
        }
      }
  )");

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json );
}



/**
 * REMOVE
 * PATH:  exists 
 * ELEMENT: non existing array  
 *  * 
 * EXP. RESULT:  json document is not modified
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, RemoveFromJson_element_does_not_exist) {

  const std::string yaml = R"EOF(
remove_from_json:    
  json_pointer:
    term_string: "/k2/k22/1"
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  json exp_json = orig_json;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}

/**
 * REMOVE
 * 
 * REQ.: If the json-pointer specifies a non-existing target
 *       (object, object member, array), then nothing will be removed.​​
 * 
 * PATH:  exists 
 * ELEMENT: non existing object member  
 *  * 
 * EXP. RESULT:  json document is not modified
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, RemoveFromJson_object_member_does_not_exist) {

  const std::string yaml = R"EOF(
remove_from_json:    
  json_pointer:
    term_string: "/k2/k24/k243"
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  json exp_json = orig_json;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}

/**
 * REMOVE
 * 
 * REQ.: If the json-pointer specifies an index on an existing array, but the specified index is out of bounds
 *       (e.g index is 5 while array has 3 elements) then nothing will be removed.
 * 
 * PATH:  exists 
 * ELEMENT: non existing object member  
 *  * 
 * EXP. RESULT:  json document is not modified
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, RemoveFromJson_array_index_does_not_exist) {

  const std::string yaml = R"EOF(
remove_from_json:    
  json_pointer:
    term_string: "/k2/k24/k243/3"
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  json exp_json = orig_json;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}


/**
 * REMOVE
 * 
 * REQ.: If the json-pointer specifies an index on an existing array, but the specified index is out of bounds
 *       (e.g index is 5 while array has 3 elements) then nothing will be removed.
 * 
 *       For remove "-" shall not identify the last index (?)
 * 
 * PATH:  exists 
 * ELEMENT: non existing object member  
 *  * 
 * EXP. RESULT:  json document is not modified
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, RemoveFromJson_array_last_index_not_removed_by_dash) {

  const std::string yaml = R"EOF(
remove_from_json:    
  json_pointer:
    term_string: "/k2/k24/k243/-"
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  json exp_json = orig_json;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}


/**
 * REMOVE
 * 
 * REQ.: If the json-pointer specifies the JSON body content (json-pointer = ""),
 *       then all the JSON body content is removed, and the body is left with null value.
 * 
 * 
 * PATH:  exists 
 * ELEMENT: non existing object member  
 *  * 
 * EXP. RESULT:  json document is replaced by null
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, RemoveFromJson_whole_document_removed) {

  const std::string yaml = R"EOF(
remove_from_json:    
  json_pointer:
    term_string: ""
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "25": "v25"
        }
      }
  )");

  json exp_json = "null"_json;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}



/**
 * REMOVE
 * PATH:  does not exists 
 * ELEMENT: does not exists
 *  * 
 * EXP. RESULT:  json document is not modified
 * 
 * standard JSON Patch behaviour
 * 
 **/
TEST_F(EricProxyJsonOperationsTest, RemoveFromJson_path_does_not_exist) {

  const std::string yaml = R"EOF(
remove_from_json:    
  json_pointer:
    term_string: "/k2/k26/1"
  )EOF";

  json orig_json = json::parse(R"(
      {
        "k1": "v1",
        "k2": {
            "k21": "v21",
            "k22": "v22",
            "k23": ["v23_0", "v23_1", "v23_3"],
            "k24": {
                "k241": "v241",
                "k242": "v241"
            },
            "k25": "v25"
        }
      }
  )");

  json exp_json = orig_json;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  EXPECT_EQ(*op_result.value(), exp_json);
}
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
