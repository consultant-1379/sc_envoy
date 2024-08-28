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


TEST_F(EricProxyJsonOperationsTest, ModifyJsonValue_search_replace_term_string_basic) {

  auto json_pointer = "/subscriberIdentifier"_json_pointer;
  std::string expected_value = "PREFIX-IMSI-460001357924610";

  const std::string yaml = R"EOF(
modify_json_value:    
  string_modifiers:
    - search_and_replace:
        search_value:
          term_string: "imsi-"
        search_options:
          full_match: false
          regex_search: false
          case_sensitive: true
        replace_value:   
          term_string: "PREFIX-IMSI-"
        replace_options:
          replace_all_occurances: true                         
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

/*
ModifyJsonValue_search_replace_empty_search_string

verify: if the search string is empty, no modification should take place

*/
TEST_F(EricProxyJsonOperationsTest, ModifyJsonValue_search_replace_empty_search_string) {

  auto json_pointer = "/subscriberIdentifier"_json_pointer;
  std::string expected_value = "imsi-460001357924610";

  const std::string yaml = R"EOF(
modify_json_value:    
  string_modifiers:
    - search_and_replace:
        search_value:
          term_string: ""
        search_options:
          full_match: false
          regex_search: false
          case_sensitive: true
        replace_value:   
          term_string: "PREFIX-IMSI-"
        replace_options:
          replace_all_occurances: true                         
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

TEST_F(EricProxyJsonOperationsTest, ModifyJsonValue_search_replace_term_string_basic_without_options) {

  auto json_pointer = "/subscriberIdentifier"_json_pointer;
  std::string expected_value = "PREFIX-IMSI-460001357924610";

  const std::string yaml = R"EOF(
modify_json_value:    
  string_modifiers:
    - search_and_replace:
        search_value:
          term_string: "imsi-"
        replace_value:   
          term_string: "PREFIX-IMSI-"                        
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

TEST_F(EricProxyJsonOperationsTest, ModifyJsonValue_search_replace_twice_term_string_basic) {

  auto json_pointer = "/subscriberIdentifier"_json_pointer;
  std::string expected_value = "PREFIX-IMSI-460001357924610-SUFFIX";

  const std::string yaml = R"EOF(
modify_json_value:    
  string_modifiers:
    - search_and_replace:
        search_value:
          term_string: "imsi-4600"
        search_options:
          regex_search: false
          case_sensitive: true
          search_from_end: true
        replace_value:   
          term_string: "PREFIX-IMSI-4600"
        replace_options:
          replace_all_occurances: true
    - search_and_replace:
        search_value:
          term_string: "4610"
        search_options:
          regex_search: false
          case_sensitive: true
          search_from_end: false
        replace_value:   
          term_string: "4610-SUFFIX"
        replace_options:
          replace_all_occurances: true                       
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


TEST_F(EricProxyJsonOperationsTest, ModifyJsonValue_search_replace_term_string_full_match_case_sensitive) {
  const std::string yaml = R"EOF(
modify_json_value:    
  string_modifiers:
    - search_and_replace:
        search_value:
          term_string: "imsi-460001357924610"
        search_options:
          full_match: true
          regex_search: false
          case_sensitive: true
        replace_value:   
          term_string: "PREFIX-IMSI-460001357924610-SUFFIX"
        replace_options:
          replace_all_occurances: true                         
  json_pointer:
    term_string: "/subscriberIdentifier"
  )EOF";

  json orig_json = orig_json_doc;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

  auto op_result = json_operation.execute();

  auto json_pointer = "/subscriberIdentifier"_json_pointer;
  std::string expected_value = "PREFIX-IMSI-460001357924610-SUFFIX";

  ASSERT_TRUE(op_result.ok());
  json mod_json = *op_result.value();
  string actual_value = mod_json[json_pointer];
  EXPECT_EQ(actual_value, expected_value);
}

//ModifyJsonValue_search_replace_term_string_full_match_case_sensitive
TEST_F(EricProxyJsonOperationsTest, ModifyJsonValue_search_replace_term_string_full_match_case_insensitive) {
  const std::string yaml = R"EOF(
modify_json_value:    
  string_modifiers:
    - search_and_replace:
        search_value:
          term_string: "IMSI-460001357924610"
        search_options:
          full_match: true
          regex_search: false
          case_sensitive: false
        replace_value:   
          term_string: "PREFIX-IMSI-460001357924610-SUFFIX"
        replace_options:
          replace_all_occurances: true                         
  json_pointer:
    term_string: "/subscriberIdentifier"
  )EOF";

  json orig_json = orig_json_doc;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

  auto op_result = json_operation.execute();

  auto json_pointer = "/subscriberIdentifier"_json_pointer;
  std::string expected_value = "PREFIX-IMSI-460001357924610-SUFFIX";

  ASSERT_TRUE(op_result.ok());
  json mod_json = *op_result.value();
  string actual_value = mod_json[json_pointer];
  EXPECT_EQ(actual_value, expected_value);
}

TEST_F(EricProxyJsonOperationsTest, ModifyJsonValue_search_replace_term_string_regex) {
  auto json_pointer = "/subscriberIdentifier"_json_pointer;
  std::string expected_value = "PREFIX-IMSI-460001357924610";

  const std::string yaml = R"EOF(
modify_json_value:
  string_modifiers:
    - search_and_replace:
        search_value:
          term_string: "imsi-"
        search_options:
          regex_search: true
        replace_value:   
          term_string: "PREFIX-IMSI-"
        replace_options:
          replace_all_occurances: true
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


} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
