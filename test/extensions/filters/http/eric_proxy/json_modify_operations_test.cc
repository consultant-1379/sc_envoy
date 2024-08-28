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
 * not standard JSON Patch behaviour
 */
TEST_F(EricProxyJsonOperationsTest, ModifyJsonValue_prepend_append_toupper_term_string_basic) {

  auto json_pointer = "/subscriberIdentifier"_json_pointer;
  std::string expected_value = "PREFIX-IMSI-460001357924610-SUFFIX";

  const std::string yaml = R"EOF(
modify_json_value:    
  string_modifiers:
    - append: 
        term_string: "-suffix"
    - prepend: 
        term_string: "prefix-"
    - to_upper: true
  json_pointer:
    term_string: "/subscriberIdentifier"
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
* test that a single modifier (append) works as expected
* (this is a design base test to check that the modificatin also works if no vector
*  is generated in json_operations.cc when calling modifyJson()
*/
TEST_F(EricProxyJsonOperationsTest, ModifyJsonValue_append_term_string_basic) {

  auto json_pointer = "/subscriberIdentifier"_json_pointer;
  std::string expected_value = "imsi-460001357924610-suffix";

  const std::string yaml = R"EOF(
modify_json_value:    
  string_modifiers:
    - append: 
        term_string: "-suffix"
  json_pointer:
    term_string: "/subscriberIdentifier"
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
* test that a single modifier (tolower) works as expected
* (this is a design base test to check that the modificatin also works if no vector
*  is generated in json_operations.cc when calling modifyJson()
*/
TEST_F(EricProxyJsonOperationsTest, ModifyJsonValue_tolower_term_string_basic) {

  auto json_pointer = "/nfConsumerIdentification/nodeFunctionality"_json_pointer;
  std::string expected_value = "smf";

  const std::string yaml = R"EOF(
modify_json_value:    
  string_modifiers:
    - to_lower: true
  json_pointer:
    term_string: "/nfConsumerIdentification/nodeFunctionality"
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
 * not standard JSON Patch behaviour
 */
TEST_F(EricProxyJsonOperationsTest, ModifyJsonValue_prepend_append_term_string_basic_dict) {

orig_json_doc = json::parse(R"(
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

  const std::string yaml = R"EOF(
modify_json_value:    
  string_modifiers:
    - append: 
        term_string: "-suffix"
    - prepend: 
        term_string: "prefix-"
  json_pointer:
    term_string: "/*/a2"
  )EOF";

  json orig_json = orig_json_doc;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  json mod_json = *op_result.value();
  //string actual_value = mod_json[json_pointer];
  //EXPECT_EQ(actual_value, expected_value);
  EXPECT_EQ(mod_json["/k1/a2"_json_pointer], "prefix-v12-suffix");
  EXPECT_EQ(mod_json["/k2/a2"_json_pointer], "prefix-v22-suffix");
  EXPECT_EQ(mod_json["/k3/a2"_json_pointer], "prefix-v32-suffix");
  EXPECT_EQ(mod_json["/k4/a2"_json_pointer], "prefix-v42-suffix");
}

TEST_F(EricProxyJsonOperationsTest, Scds1717) {

  orig_json_doc = json::parse(R"({"monitoredResourceUris": ["v1","v2","v3"]})");

  const std::string yaml = R"EOF(
modify_json_value:
  string_modifiers:
  - append: 
      term_string: "-suffix"
  json_pointer:
    term_string: "/monitoredResourceUris/*"
  )EOF";

  json orig_json = orig_json_doc;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
  auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  json mod_json = *op_result.value();
  // string actual_value = mod_json[json_pointer];
  // EXPECT_EQ(actual_value, expected_value);
  EXPECT_EQ(mod_json["/monitoredResourceUris/0"_json_pointer], "v1-suffix");
  EXPECT_EQ(mod_json["/monitoredResourceUris/1"_json_pointer], "v2-suffix");
  EXPECT_EQ(mod_json["/monitoredResourceUris/2"_json_pointer], "v3-suffix");
}

/**
 * not standard JSON Patch behaviour
 */
TEST_F(EricProxyJsonOperationsTest, ModifyJsonValue_prepend_append_term_string_basic_dict_in_list) {

orig_json_doc = json::parse(R"(
{
  "aList": [
    {
      "k1": {
        "a1": "v11",
        "a2": "v12"
      }
    },
    {
      "k2": {
        "a1": "v21",
        "a2": "v22"
      }
    },
    {
      "k3": {
        "a1": "v31",
        "a2": "v32"
      }
    },
    {
      "k4": {
        "a1": "v41",
        "a2": "v42"
      }
    }
  ]
}
  )");

  const std::string yaml = R"EOF(
modify_json_value:    
  string_modifiers:
    - append: 
        term_string: "-suffix"
    - prepend: 
        term_string: "prefix-"
  json_pointer:
    term_string: "/aList/*/*/a2"
  )EOF";

  json orig_json = orig_json_doc;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  json mod_json = *op_result.value();

  EXPECT_EQ(mod_json["/aList/0/k1/a1"_json_pointer], "v11");
  EXPECT_EQ(mod_json["/aList/1/k2/a1"_json_pointer], "v21");
  EXPECT_EQ(mod_json["/aList/2/k3/a1"_json_pointer], "v31");
  EXPECT_EQ(mod_json["/aList/3/k4/a1"_json_pointer], "v41");

  EXPECT_EQ(mod_json["/aList/0/k1/a2"_json_pointer], "prefix-v12-suffix");
  EXPECT_EQ(mod_json["/aList/1/k2/a2"_json_pointer], "prefix-v22-suffix");
  EXPECT_EQ(mod_json["/aList/2/k3/a2"_json_pointer], "prefix-v32-suffix");
  EXPECT_EQ(mod_json["/aList/3/k4/a2"_json_pointer], "prefix-v42-suffix");

}



TEST_F(EricProxyJsonOperationsTest, ModifyJsonValue_prepend_append_term_string_basic_dict_in_list_any) {

orig_json_doc = json::parse(R"(
{
  "aList": [
    {
      "k1": {
        "a1": "v11",
        "a2": "v12"
      }
    },
    {
      "k2": {
        "a1": "v21",
        "a2": "v22"
      }
    },
    {
      "k3": {
        "a1": "v31",
        "a2": "v32"
      }
    },
    {
      "k4": {
        "a1": "v41",
        "a2": "v42"
      }
    }
  ]
}
  )");

  const std::string yaml = R"EOF(
modify_json_value:    
  string_modifiers:
    - append: 
        term_string: "-suffix"
    - prepend: 
        term_string: "prefix-"
  json_pointer:
    term_string: "/aList/*/*/*"
  )EOF";

  json orig_json = orig_json_doc;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  json mod_json = *op_result.value();

  EXPECT_EQ(mod_json["/aList/0/k1/a1"_json_pointer], "prefix-v11-suffix");
  EXPECT_EQ(mod_json["/aList/1/k2/a1"_json_pointer], "prefix-v21-suffix");
  EXPECT_EQ(mod_json["/aList/2/k3/a1"_json_pointer], "prefix-v31-suffix");
  EXPECT_EQ(mod_json["/aList/3/k4/a1"_json_pointer], "prefix-v41-suffix");

  EXPECT_EQ(mod_json["/aList/0/k1/a2"_json_pointer], "prefix-v12-suffix");
  EXPECT_EQ(mod_json["/aList/1/k2/a2"_json_pointer], "prefix-v22-suffix");
  EXPECT_EQ(mod_json["/aList/2/k3/a2"_json_pointer], "prefix-v32-suffix");
  EXPECT_EQ(mod_json["/aList/3/k4/a2"_json_pointer], "prefix-v42-suffix");

}

/*
*  TEST:
*  scenario: the modifier function can not be applied if one dictionary item indicated by the 
*            json pointer is not of string type
*  expected result: modification of this item (only) is skipped, counter needed ?                  
* 
*/
TEST_F(EricProxyJsonOperationsTest, ModifyJsonValue_prepend_append_term_string_basic_dict_type_error) {

orig_json_doc = json::parse(R"(
      {
        "k1": {
          "a1": "v11",
          "a2": "v12"
        },
        "k2": {
          "a1": "v21",
          "a2": 100
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

  const std::string yaml = R"EOF(
modify_json_value:    
  string_modifiers:
    - append: 
        term_string: "-suffix"
    - prepend: 
        term_string: "prefix-"
  json_pointer:
    term_string: "/*/a2"
  )EOF";

  json orig_json = orig_json_doc;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
 auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  json mod_json = *op_result.value();
  //string actual_value = mod_json[json_pointer];
  //EXPECT_EQ(actual_value, expected_value);
  EXPECT_EQ(mod_json["/k1/a1"_json_pointer], "v11");
  EXPECT_EQ(mod_json["/k2/a1"_json_pointer], "v21");
  EXPECT_EQ(mod_json["/k3/a1"_json_pointer], "v31");
  EXPECT_EQ(mod_json["/k4/a1"_json_pointer], "v41");

  EXPECT_EQ(mod_json["/k1/a2"_json_pointer], "prefix-v12-suffix");
  EXPECT_EQ(mod_json["/k2/a2"_json_pointer], 100);
  EXPECT_EQ(mod_json["/k3/a2"_json_pointer], "prefix-v32-suffix");
  EXPECT_EQ(mod_json["/k4/a2"_json_pointer], "prefix-v42-suffix");
}

/*
*  TEST:
*  scenario: the modifier function can not be applied if one dictionary item indicated by the 
*            json pointer * is not of string type
*  expected result: modification of this item (only) is skipped, counter needed ?                  
* 
*/
TEST_F(EricProxyJsonOperationsTest, ModifyJsonValue_prepend_append_term_string_basic_dict_type_error_on_wildcarded_value) {

orig_json_doc = json::parse(R"(
      {
        "k1": {
          "a1": "v11",
          "a2": "v12"
        },
        "k2": {
          "a1": "v21",
          "a2": 100
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

  const std::string yaml = R"EOF(
modify_json_value:    
  string_modifiers:
    - append: 
        term_string: "-suffix"
    - prepend: 
        term_string: "prefix-"
  json_pointer:
    term_string: "/*/*"
  )EOF";

  json orig_json = orig_json_doc;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);
  auto op_result = json_operation.execute();

  ASSERT_TRUE(op_result.ok());
  json mod_json = *op_result.value();
  //string actual_value = mod_json[json_pointer];
  //EXPECT_EQ(actual_value, expected_value);
  EXPECT_EQ(mod_json["/k1/a1"_json_pointer], "prefix-v11-suffix");
  EXPECT_EQ(mod_json["/k2/a1"_json_pointer], "prefix-v21-suffix");
  EXPECT_EQ(mod_json["/k3/a1"_json_pointer], "prefix-v31-suffix");
  EXPECT_EQ(mod_json["/k4/a1"_json_pointer], "prefix-v41-suffix");

  EXPECT_EQ(mod_json["/k1/a2"_json_pointer], "prefix-v12-suffix");
  EXPECT_EQ(mod_json["/k2/a2"_json_pointer], 100);
  EXPECT_EQ(mod_json["/k3/a2"_json_pointer], "prefix-v32-suffix");
  EXPECT_EQ(mod_json["/k4/a2"_json_pointer], "prefix-v42-suffix");
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
