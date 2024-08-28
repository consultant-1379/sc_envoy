#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.validate.h"
#include "source/extensions/filters/http/eric_proxy/contexts.h"
#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/extensions/filters/http/eric_proxy/condition_config.h"
#include "source/common/protobuf/protobuf.h"
#include "source/extensions/filters/http/eric_proxy/wrappers.h"
#include "test/test_common/utility.h"
#include "test/mocks/upstream/cluster_manager.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using ConditionProtoConfig =
    envoy::extensions::filters::http::eric_proxy::v3::Condition; // temporary for
                                                                          // developing EEDALA
using EricProxyFilterProtoConfig = envoy::extensions::filters::http::eric_proxy::v3::EricProxyConfig;

//--------------------------------------------------------------------------------
// Check if a filter-rule inside a filter-case contains all expected filter-data names.
bool filterdataRequiredContains(std::shared_ptr<EricProxyFilterConfig> config, std::string fc_name,
    std::string fr_name, std::set<std::string> expected_fd_names) {
  auto fc_wrapper = config->filterCaseByName(fc_name);
  auto fr_wrapper = fc_wrapper->filterRuleByName(fr_name);
  auto fd_required_wp = (*fr_wrapper)->filterdataRequired();
  // We have a list of filterdata-required, which are weak_ptr to
  // FilterDataWrapper objects. Go through the list and extract the name
  // from each FilterDataWrapper object (in the lambda). With the "inserter",
  // the name is added to the "existing_fd_names" list.
  std::set<std::string> existing_fd_names;
  std::transform(std::begin(fd_required_wp), std::end(fd_required_wp),
      std::inserter(existing_fd_names, std::begin(existing_fd_names)),
      [](auto& fd_wp) -> std::string {
        if(std::shared_ptr<FilterDataWrapper> fd_sp = fd_wp.lock()) {
          return fd_sp->name();
        } else {
          return ""; // Should never happen
        }
      });

  return expected_fd_names == existing_fd_names;
}

// Check if a filter-rule inside a filter-case contains all expected header-value-indices ("hvi")
bool headerValIdxRequiredContains(std::shared_ptr<EricProxyFilterConfig> config, std::string fc_name,
                                  std::string fr_name, std::set<std::string> expected_hvi_names) {
  auto fc_wrapper = config->filterCaseByName(fc_name);
  auto fr_wrapper = fc_wrapper->filterRuleByName(fr_name);
  auto hvi_required_sp = (*fr_wrapper)->headerValueIndicesRequired();
  // FIXME (eedala): add comment to explain
  std::set<std::string> existing_hvi_names;
  std::transform(std::begin(hvi_required_sp), std::end(hvi_required_sp),
                 std::inserter(existing_hvi_names, std::begin(existing_hvi_names)),
                 [config](auto header_idx) -> std::string {
                   return std::string(config->rootContext().headerName(header_idx));
                 });
  return expected_hvi_names == existing_hvi_names;
}

//--------------------------------------------------------------------------------
// Construct a configuration with a given condition:
std::string makeConfig(const std::string& condition) {
  std::string yaml = R"EOF(
own_internal_port: 80
filter_cases:
  - name: default_routing
    filter_data:
    - name: rd1_mcc_mnc
      header: 3gpp-Sbi-target-apiRoot
      extractor_regex: "country=(?P<mcc>\\d+),nw=(?P<mnc>\\d+).*"
    - name: rd2_networkcode
      header: nwc
      extractor_regex: "nwc=(?P<countrycodecode>\\d+),nw=(?P<networkcode>\\d+).*"
    - name: rd3_supi
      header: IShoudBeInABody
      extractor_regex: "id=(?P<supi>imsi-\\d+).*"
    filter_rules:
    - name: csepp_to_rp_A
      condition: 
  )EOF";
  yaml += "        " + condition;
  return yaml;
}

//-------------------------------------------------------------------------------
// Tests for parsing conditions
//-------------------------------------------------------------------------------

// true
TEST(EricProxyFilterConfigTest, TestValidPredExp) {
  const std::vector<std::string> test_condition = {
      // clang-format off
      //// term_boolean ////
      // true    // if the user leaves the condition empty, the compiler shall set it to "true"
      "term_boolean: true",
      //// op_equals ////
      // "Ericsson" == "Ericsson"
      "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'Ericsson'}, "
                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'Ericsson'}}",
      // var.nonexisting == ""
      "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'nonexisting'}, "
                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: ''}}",
      // var.mnc == "262"
      "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mnc'}, "
                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}",
      // var.prio == 1
      "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'prio'}, "
                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 1}}",
      // 1 == 1
      "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 1}, "
                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 1}}",
      // var.mnc == var.mcc
      "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mnc'}, "
                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mcc'}}",
      // req.header["abc"] == "def"
      "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'abc'}, "
                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'def'}}",
      // req.header["3gpp-country-code"] == var.mcc
      "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-country-code'}, "
                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mcc'}}",
      // req.header["abc"] == req.header["def"]
      "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-country-code'}, "
                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'def'}}",
      // req.method == "POST"
      "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':method'}, "
                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'POST'}}",
      // req.path == "/nchf-convergedcharging"
      "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':path'}, "
                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '/nchf-convergedcharging'}}",
      // true == true
      "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_boolean: true}, "
                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_boolean: true}}",
      // apicontext.apiName == "nnrf-disc"   (depends on the manager)
      "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_apicontext: API_NAME}, "
                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'nnrf-disc'}}",
      //----------op_equals_case_insensitive ---------------------------------------------------
      "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'Ericsson'}, "
                                   "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'ericsson'}}",
      // var.nonexisting == ""
      "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'nonexisting'}, "
                                   "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: ''}}",
      // var.mnc == "262"
      "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mnc'}, "
                                   "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}",
      // var.prio == 1
      "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'prio'}, "
                                   "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 1}}",
      // 1 == 1
      "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 1}, "
                                   "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 1}}",
      // var.mnc == var.mcc
      "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mnc'}, "
                                   "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mcc'}}",
      // req.header["abc"] == "def"
      "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'abc'}, "
                                   "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'def'}}",
      // req.header["3gpp-country-code"] == var.mcc
      "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-country-code'}, "
                                   "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mcc'}}",
      // req.header["abc"] == req.header["def"]
      "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: '3gpp-country-code'}, "
                                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'def'}}",
      // req.method == "POST"
      "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':method'}, "
                                    "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'POST'}}",
      // req.path == "/nchf-convergedcharging"
      "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':path'}, "
                                   "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '/nchf-convergedcharging'}}",
      // true == true
      "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_boolean: true}, "
                                   "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_boolean: true}}",
      //----------------------------------------------------------------------------------------
      //// op_exists ////
      // var.mnc exists
      "op_exists: {arg1: {term_var: 'mnc'}}",
      // req.header["3gpp-Sbi-target-apiRoot"] exists
      "op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}",
      // req.method exists   // always true
      "op_exists: {arg1: {term_reqheader: ':method'}}",
      // req.path exists    // always true
      "op_exists: {arg1: {term_reqheader: ':path'}}",
      // "abc" exists      // always true
      "op_exists: {arg1: {term_string: 'abc'}}",
      // 123 exists       // always true
      "op_exists: {arg1: {term_number: 123}}",
      // -123.456E78 exists       // always true
      "op_exists: {arg1: {term_number: -123.456E78}}",
      // true exists     // always true
      "op_exists: {arg1: {term_boolean: true}}",
      // false exists  // always true(!)
      "op_exists: {arg1: {term_boolean: false}}",

      "op_exists: { arg1: { term_apicontext: API_NAME } }",

      //// op_isempty ////
      // var.mnc isEmpty
      "op_isempty: {arg1: {term_var: 'mnc'}}",
      // req.header["3gpp-Sbi-target-apiRoot"] isEmpty
      "op_isempty: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}",
      // req.path isEmpty     // always false
      "op_isempty: {arg1: {term_reqheader: ':path'}}",
      // req.method isEmpty  // always false
      "op_isempty: {arg1: {term_reqheader: ':method'}}",
      // false isEmpty      // always false
      "op_isempty: {arg1: {term_boolean: false}}",
      // true isEmpty      // always false
      "op_isempty: {arg1: {term_boolean: true}}",
      // -123.456E78 isEmpty      // always false
      "op_isempty: {arg1: {term_number: -123.456E78}}",
      // "abc" isEmpty   // always false
      "op_isempty: {arg1: {term_string: 'abc'}}",

      "op_isempty: { arg1: { term_apicontext: API_NAME } }",

      // "abc" isEmpty == true   // always false
     "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', op_isempty: {arg1: {term_string: 'abc'}}}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', term_boolean: true}}",

      //// op_and ////
      // true and true
      "op_and: {arg1: {term_boolean: true}, arg2: {term_boolean: false}}",
      // var.mcc == "262" and true
      "op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mcc}, "
                                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}}, "
               "arg2: {term_boolean: true}}",
      // var.mcc == "262" and var.mnc == "02"
      "op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mcc}, "
                                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}}, "
               "arg2: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mnc}, "
                                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '02'}}}}",
      // var.mcc == "262" and var.mnc isEmpty
      "op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mcc}, "
                                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}}, "
               "arg2: {op_isempty: {arg1: {term_var: mnc}}}}",
      // var.mcc == "262" and var.mnc == "02" and var.supi exists
      "op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mcc}, "
                                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}}, "
               "arg2: {op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mnc}, "
                                                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '02'}}}, "
                               "arg2: {op_exists: {arg1: {term_var: supi}}}}}}",

      //// op_or ////
      // true or false
      "op_or: {arg1: {term_boolean: true}, "
              "arg2: {term_boolean: false}}",
      // req.header["3gpp-Sbi-target-apiRoot"] exists or req.method == "POST"
      "op_or: {arg1: {op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}}, "
              "arg2: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':method'}, "
                                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'POST'}}}}",
      // var.mcc == "262" or req.method == "POST" and req.path == "/nchf-convergedcharging"
      "op_or: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mcc}, "
                                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}}, "
              "arg2: {op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':method'}, "
                                                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'POST'}}}, "
                              "arg2: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':path'}, "
                                                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '/nchf-convergedcharging'}}}}}}",

      //// op_not ////
      // not true
      "op_not: {arg1: {term_boolean: true}}",
      // req.method == "POST" and not req.header["x-trace"] exists
      "op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':method'}, "
                                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'POST'}}}, "
               "arg2: {op_not: {arg1: {op_exists: {arg1: {term_reqheader: 'x-trace'}}}}}}",
      // req.method == "GET" and not var.mcc == "262"
      "op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':method'}, "
                                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'GET'}}}, "
               "arg2: {op_not: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mcc'}, "
                                                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}}}}}",

      //// op_isinsubnet ////
      // '10.0.0.1' isInSubnet '10.0.0.0/8'
      "op_isinsubnet: {arg1: {term_string: '10.0.0.1'}, arg2: '10.0.0.0/8'}",
      // 'fa:16:3e:6a:fe:34' isInSubnet 'fa:16:3e:6a/64'
      "op_isinsubnet: {arg1: {term_string: 'fe80::c88d:edff:fee8:acd8'}, arg2: 'fe80::c88d:edff:fee8:acd8/64'}",
      // var.addr isInSubnet '164.48.132.0/24'
      "op_isinsubnet: {arg1: {term_var: 'addr'}, arg2: '164.48.132.0/24'}",
      // req.header["address"] isInSubnet 'fa:16:3e:6a/64'
      "op_isinsubnet: {arg1: {term_reqheader: 'address'}, arg2: 'fa:16:3e:6a/64'}",
  
      //// op_isvalidjson ////
      // req.body isvalidjson
      "op_isvalidjson: {request_body: true}",
      // not req.body isvalidjson
      "op_not: {arg1: {op_isvalidjson: {request_body: true}}}",
      // resp.body isvalidjson
      "op_isvalidjson: {response_body: true}",
      // not resp.body isvalidjson
      "op_not: {arg1: {op_isvalidjson: {response_body: true}}}",
      // clang-format on
  };
  std::string yaml;
  EricProxyFilterProtoConfig proto_config;
  for (auto& pe : test_condition) {
    yaml = makeConfig(pe);
    EXPECT_NO_THROW(TestUtility::loadFromYamlAndValidate(yaml, proto_config));
  }
}

//----------------------------------------------------------------------------
// Tests that use the configuration
//----------------------------------------------------------------------------
// Macro common to many/most/all tests
#define SETUP_EQUAL \
  EricProxyFilterProtoConfig proto_config; \
  TestUtility::loadFromYamlAndValidate(yaml, proto_config); \
  Upstream::MockClusterManager cluster_manager_; \
  auto config = std::make_shared<EricProxyFilterConfig>(proto_config, cluster_manager_); \
  auto rule = config->filterCases().at(0).filter_rules().at(0); \
  std::set<ValueIndex> strvar_req; \
  std::set<ValueIndex> hdr_req; \
  std::set<ValueIndex> query_param_req; \
  auto op = setUpCondition(config->rootContext(), rule.condition(), strvar_req, hdr_req, query_param_req); \
  EXPECT_NE(op, nullptr); \
  RunContext run_ctx(&config->rootContext());
 
//----- term_boolean ----------------------------------------------------------
// Tests the most simple condition:
// condition:  true
TEST(EricProxyFilterConfigTest, TestTrue) {
  auto yaml = makeConfig(
    "term_boolean: true"
  );
  SETUP_EQUAL
  EXPECT_TRUE(op->eval(run_ctx));
  EXPECT_TRUE(op->eval(run_ctx));
}

// Tests the most simple condition:
// condition:  false
TEST(EricProxyFilterConfigTest, TestFalse) {
  auto yaml = makeConfig(
    "term_boolean: false"
  );
  SETUP_EQUAL
  EXPECT_FALSE(op->eval(run_ctx));
  EXPECT_FALSE(op->eval(run_ctx));
}

//------- op_equals-------------------------------------------------------------
// In general, we don't have/need tests for:
// - term_boolean with other types
// - term_string with term_number
// because the validator in the manager does type checking and rejects such
// combinations.
//-----------------------------------------------------------------------------
#pragma region op_equals
// Tests that a condition (two string literals) is configured
// correctly and op_equals works, result "equal"
// condition:  "abc" == "abc"
TEST(EricProxyFilterConfigTest, TestOpEqualsCCIsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'abc'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'abc'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_EQ(run_ctx.rootContext()->constValue(0), "abc");
  EXPECT_TRUE(op->eval(run_ctx));
}

TEST(EricProxyFilterConfigTest, TestOpEqualsBoolsTrue) {
  GTEST_SKIP_("true == true not working currently as equals between term_boolean is not supported");
  auto yaml = makeConfig("op_equals: { typed_config1: {'@type': "
                         "'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', "
                         "term_boolean: true}, "
                         "typed_config2: {'@type': "
                         "'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', "
                         "term_boolean: true}}");
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_TRUE(op->eval(run_ctx));
}

// Tests that a condition (two string literals) is configured
// correctly and op_equals works, result "not equal"
// condition:  "abc" == "defg"
TEST(EricProxyFilterConfigTest, TestOpEqualsCCIsFalse) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'abc'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'defg'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_EQ(config->rootContext().constValue(0), "abc");
  EXPECT_EQ(config->rootContext().constValue(1), "defg");
  EXPECT_FALSE(op->eval(run_ctx));
}

// Tests that a condition (two number literals) is configured
// correctly and op_equals works, result "equal"
// condition:  1 == 1
TEST(EricProxyFilterConfigTest, TestOpEqualsCN1IsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 1}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 1}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_EQ(run_ctx.rootContext()->constValue(0), 1);
  EXPECT_TRUE(op->eval(run_ctx));
}

// Tests that a condition (two number literals) is configured
// correctly and op_equals works, result "equal"
// condition:  1.0 == 1
TEST(EricProxyFilterConfigTest, TestOpEqualsCN2IsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 1.0}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 1}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_EQ(run_ctx.rootContext()->constValue(0), 1.0); // 1.0 and 1 are the same in JSON
  EXPECT_TRUE(op->eval(run_ctx));
}

// Tests that a condition (two number literals) is configured
// correctly and op_equals works, result "equal"
// condition:  +1.0E-2 == 0.01
TEST(EricProxyFilterConfigTest, TestOpEqualsCN3IsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: +1.0E-2}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 0.01}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_EQ(run_ctx.rootContext()->constValue(0), 1.0e-2);
  EXPECT_TRUE(op->eval(run_ctx));
}

// Tests that a condition (two number literals) is configured
// correctly and op_equals works, result "not equal"
// condition:  0.01 == 0.011
TEST(EricProxyFilterConfigTest, TestOpEqualsCN4IsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 0.01}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 0.011}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_EQ(run_ctx.rootContext()->constValue(0), 1.0e-2);
  EXPECT_EQ(run_ctx.rootContext()->constValue(1), 1.1e-2);
  EXPECT_FALSE(op->eval(run_ctx));
}


// Tests that a condition (string literal and variable) is configured
// correctly and op_equals works
// condition:  var.mnc == "262"
TEST(EricProxyFilterConfigTest, TestOpEqualsVCIsTrue) {
  auto yaml = makeConfig(
        "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mnc'}, "
                     "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc"}));
  run_ctx.setVarValueForTest("mnc", "262", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
}
// condition:  "262" == var.mnc
TEST(EricProxyFilterConfigTest, TestOpEqualsCVIsTrue) {
  auto yaml = makeConfig(
        "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}, "
                     "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mnc'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc"}));
  run_ctx.setVarValueForTest("mnc", "262", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
}

// test term_apiname. Expect false as it's retrieved from the request
TEST(EricProxyFilterConfigTest, TestOpEqualsApiContextName) {
  auto yaml = makeConfig(
      // clang-format off
        "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_apicontext: API_NAME}, "
                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'nnrf-disc'}}"
      // clang-format on
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_FALSE(op->eval(run_ctx));
}

TEST(EricProxyFilterConfigTest, TestIsEmptyApiContextName) {
  auto yaml = makeConfig(
      // clang-format off
        "op_isempty: { arg1: { term_apicontext: API_NAME } }"
      // clang-format on
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isempty());
  EXPECT_TRUE(op->eval(run_ctx));
}

TEST(EricProxyFilterConfigTest, TestExistsApiContextName) {
  auto yaml = makeConfig(
      // clang-format off
        "op_exists: { arg1: { term_apicontext: API_NAME } }"
      // clang-format on
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_exists());
  EXPECT_FALSE(op->eval(run_ctx));
}

// Tests that a condition (number literal and variable) is configured
// correctly and op_equals works
// condition:  var.prio == 2
TEST(EricProxyFilterConfigTest, TestOpEqualsVNIsTrue) {
  auto yaml = makeConfig(
        "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'prio'}, "
                     "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 2}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  run_ctx.setVarValueForTest("prio", 2, nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
}

// Tests that a condition (string literal and header) is configured
// correctly and op_equals works
// condition:  req.header["mnc"] == "262"
TEST(EricProxyFilterConfigTest, TestOpEqualsHCIsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'mnc'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"mnc"}));
  EXPECT_EQ(config->rootContext().constValue(0), "262");
  run_ctx.setHeaderValueForTest("mnc", "262", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("mnc", "262", ReqOrResp::Response);
  EXPECT_TRUE(op->eval(run_ctx));
}

// condition:  "262" == req.header["mcc"]
TEST(EricProxyFilterConfigTest, TestOpEqualsCReqHIsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'mnc'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"mnc"}));
  EXPECT_EQ(config->rootContext().constValue(0), "262");
  run_ctx.setHeaderValueForTest("mnc", "262", ReqOrResp::Response);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("mnc", "262", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
}

// condition:  "262" == resp.header["mcc"]
TEST(EricProxyFilterConfigTest, TestOpEqualsCRespHIsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_respheader: 'mnc'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"mnc"}));
  EXPECT_EQ(config->rootContext().constValue(0), "262");
  run_ctx.setHeaderValueForTest("mnc", "262", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("mnc", "262", ReqOrResp::Response);
  EXPECT_TRUE(op->eval(run_ctx));
}

// Tests that a condition (number literal and header) is configured
// correctly and op_equals works = returns false because a header is
// always a string and comparing different types always results in false.
// No automatic conversion is done when comparing/reading from headers.
// condition:  req.header["prio"] == 3 and the header "prio" contains
// the string "3"
TEST(EricProxyFilterConfigTest, TestOpEqualsReqHNIsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'prio'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 3}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_EQ(config->rootContext().constValue(0), 3);
  run_ctx.setHeaderValueForTest("prio", "3", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
}
// Same as before, but with resp.header
// condition:  resp.header["prio"] == 3 and the header "prio" contains
// the string "3"
TEST(EricProxyFilterConfigTest, TestOpEqualsRespHNIsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_respheader: 'prio'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 3}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_EQ(config->rootContext().constValue(0), 3);
  run_ctx.setHeaderValueForTest("prio", "3", ReqOrResp::Response);
  EXPECT_FALSE(op->eval(run_ctx));
}

// Tests that a condition (string-variable and string-variable) is configured
// correctly and op_equals works
// condition:  var.mnc == var.networkcode
TEST(EricProxyFilterConfigTest, TestOpEqualsVV1IsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mnc'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'networkcode'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc", "rd2_networkcode"}));
  run_ctx.setVarValueForTest("mnc", "262", nullptr);
  run_ctx.setVarValueForTest("networkcode", "262", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("networkcode", "678", nullptr);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("networkcode", "262", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
}

// Tests that a condition (number-variable and number-variable) is configured
// correctly and op_equals works
// condition:  var.prio == var.priority
TEST(EricProxyFilterConfigTest, TestOpEqualsVV2IsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'prio'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'priority'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  run_ctx.setVarValueForTest("prio", 1, nullptr);
  run_ctx.setVarValueForTest("priority", 1, nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("priority", 2, nullptr);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("priority", 1.0, nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
}

// Tests that a condition (number-variable and string-variable) is configured
// correctly and op_equals works
// condition:  var.prio == var.mcc -> false b/c type mismatch
TEST(EricProxyFilterConfigTest, TestOpEqualsVV3IsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'prio'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mcc'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  run_ctx.setVarValueForTest("prio", 1, nullptr);
  run_ctx.setVarValueForTest("mcc", "262", nullptr);
  EXPECT_FALSE(op->eval(run_ctx));
}

// Tests that a condition (string-variable and number-variable) is configured
// correctly and op_equals works
// condition:  var.mcc == var.prio -> false b/c type mismatch
TEST(EricProxyFilterConfigTest, TestOpEqualsVV4IsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mcc'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'prio'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  run_ctx.setVarValueForTest("mcc", "262", nullptr);
  run_ctx.setVarValueForTest("prio", 1, nullptr);
  EXPECT_FALSE(op->eval(run_ctx));
}

// Tests that a condition (variable and header) is configured
// correctly and op_equals works
// condition:  req.header["mcc"] == var.networkcode
TEST(EricProxyFilterConfigTest, TestOpEqualsVHIsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'networkcode'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'mnc'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd2_networkcode"}));
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"mnc"}));
  run_ctx.setVarValueForTest("networkcode", "262", nullptr);
  run_ctx.setHeaderValueForTest("mnc", "262", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("networkcode", "678", nullptr);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("networkcode", "262", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
}
// Tests that a condition (variable and header) is configured
// correctly and op_equals works
// condition:  var.networkcode == req.header["mcc"]
TEST(EricProxyFilterConfigTest, TestOpEqualsHVIsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'mnc'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'networkcode'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"mnc"}));
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd2_networkcode"}));
  run_ctx.setVarValueForTest("networkcode", "262", nullptr);
  run_ctx.setHeaderValueForTest("mnc", "262", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("networkcode", "678", nullptr);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("networkcode", "262", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
}

// Tests that a condition (header and header) is configured
// correctly and op_equals works
// condition:  req.header["mcc1"] == req.header["mcc2"]
TEST(EricProxyFilterConfigTest, TestOpEqualsHHIsTrue) {
  auto yaml = makeConfig(
    "op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'mnc1'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'mnc2'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"mnc1", "mnc2"}));
  run_ctx.setHeaderValueForTest("mnc1", "262", ReqOrResp::Request);
  run_ctx.setHeaderValueForTest("mnc2", "262", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("mnc1", "678", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("mnc1", "262", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
}

// Test that a condition with parameters that are conditions
// and not values works.
// condition:  true == true
TEST(EricProxyFilterConfigTest, TestOpEqualsPPIsTrue1) {
  auto yaml = makeConfig(
    "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', term_boolean: true}, "
                "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', term_boolean: true}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_TRUE(op->eval(run_ctx));
}

// Test that a condition with parameters that are conditions
// and not values works.
// condition:  true == true
TEST(EricProxyFilterConfigTest, TestOpEqualsPPIsFalse1) {
  auto yaml = makeConfig(
    "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', term_boolean: true}, "
                "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', term_boolean: false}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_FALSE(op->eval(run_ctx));
}

// Test that a condition with parameters that are conditions
// and not values works.
// condition:  "abc" isEmpty == true
TEST(EricProxyFilterConfigTest, TestOpEqualsPPIsTrue) {
  auto yaml = makeConfig(
    "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', op_isempty: {arg1: {term_string: 'abc'}}}, "
                "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', term_boolean: true}}"
  );
  SETUP_EQUAL
  EXPECT_FALSE(op->eval(run_ctx));
}
#pragma endregion op_equals

//------- op_equals_case_insensitive-------------------------------------------------------------
#pragma region op_equals_case_insensitive
// Tests that a condition (two string literals) is configured
// correctly and op_equals works, result "equal"
// condition:  "aBc" == "abC"
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseCCIsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'aBc'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'abC'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_EQ(run_ctx.rootContext()->constValue(0), "aBc");
  EXPECT_TRUE(op->eval(run_ctx));
}
// Tests that a condition (two string literals) is configured
// correctly and op_equals works, result "equal"
// condition:  "abc" == "abc"
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseCCIsTrue2) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'abc'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'abc'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_EQ(run_ctx.rootContext()->constValue(0), "abc");
  EXPECT_TRUE(op->eval(run_ctx));
}
// Tests that a condition (two string literals) is configured
// correctly and op_equals works, result "not equal"
// condition:  "abc" == "defg"
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseCCIsFalse) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'abc'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'defg'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_EQ(config->rootContext().constValue(0), "abc");
  EXPECT_EQ(config->rootContext().constValue(1), "defg");
  EXPECT_FALSE(op->eval(run_ctx));
}
// Tests that a condition (two number literals) is configured
// correctly and op_equals works, result "equal"
// condition:  1 == 1
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseCN1IsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 1}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 1}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_EQ(run_ctx.rootContext()->constValue(0), 1);
  EXPECT_TRUE(op->eval(run_ctx));
}
// Tests that a condition (two number literals) is configured
// correctly and op_equals works, result "equal"
// condition:  1.0 == 1
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseCN2IsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 1.0}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 1}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_EQ(run_ctx.rootContext()->constValue(0), 1.0); // 1.0 and 1 are the same in JSON
  EXPECT_TRUE(op->eval(run_ctx));
}
// Tests that a condition (two number literals) is configured
// correctly and op_equals works, result "equal"
// condition:  +1.0E-2 == 0.01
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseCN3IsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: +1.0E-2}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 0.01}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_EQ(run_ctx.rootContext()->constValue(0), 1.0e-2);
  EXPECT_TRUE(op->eval(run_ctx));
}
// Tests that a condition (two number literals) is configured
// correctly and op_equals works, result "not equal"
// condition:  0.01 == 0.011
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseCN4IsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 0.01}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 0.011}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_EQ(run_ctx.rootContext()->constValue(0), 1.0e-2);
  EXPECT_EQ(run_ctx.rootContext()->constValue(1), 1.1e-2);
  EXPECT_FALSE(op->eval(run_ctx));
}
// Tests that a condition (string literal and variable) is configured
// correctly and op_equals works
// condition:  var.mnc == "262"
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseVCIsTrue) {
  auto yaml = makeConfig(
        "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mnc'}, "
                     "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc"}));
  run_ctx.setVarValueForTest("mnc", "262", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
}
// condition:  "262" == var.mnc
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseCVIsTrue) {
  auto yaml = makeConfig(
        "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}, "
                     "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mnc'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc"}));
  run_ctx.setVarValueForTest("mnc", "262", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
}
// Tests that a condition (number literal and variable) is configured
// correctly and op_equals_case_insensitive works
// condition:  var.prio == 2
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseVNIsTrue) {
  auto yaml = makeConfig(
        "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'prio'}, "
                     "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 2}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  run_ctx.setVarValueForTest("prio", 2, nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
}
// Tests that a condition (string literal and header) is configured
// correctly and op_equals_case_insensitive works
// condition:  req.header["mnc"] == "262"
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseHCIsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'mnc'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A", {"mnc"}));
  EXPECT_EQ(config->rootContext().constValue(0), "262");
  run_ctx.setHeaderValueForTest("mnc", "262", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("mnc", "262", ReqOrResp::Response);
  EXPECT_TRUE(op->eval(run_ctx));
}
// condition:  "262" == req.header["mcc"]
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseCReqHIsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'mnc'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A", {"mnc"}));
  EXPECT_EQ(config->rootContext().constValue(0), "262");
  run_ctx.setHeaderValueForTest("mnc", "262", ReqOrResp::Response);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("mnc", "262", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
}
// Tests that a condition (number literal and header) is configured
// correctly and op_equals_case_insensitive works = returns false because a header is
// always a string and comparing different types always results in false.
// No automatic conversion is done when comparing/reading from headers.
// condition:  req.header["prio"] == 3 and the header "prio" contains
// the string "3"
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseReqHNIsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'prio'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 3}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_EQ(config->rootContext().constValue(0), 3);
  run_ctx.setHeaderValueForTest("prio", "3", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
}
// Same as before, but with resp.header
// condition:  resp.header["prio"] == 3 and the header "prio" contains
// the string "3"
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseRespHNIsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_respheader: 'prio'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_number: 3}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_EQ(config->rootContext().constValue(0), 3);
  run_ctx.setHeaderValueForTest("prio", "3", ReqOrResp::Response);
  EXPECT_FALSE(op->eval(run_ctx));
}
// Tests that a condition (string-variable and string-variable) is configured
// correctly and op_equals_case_insensitive works
// condition:  var.mnc == var.networkcode
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseVV1IsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mnc'}, "
                                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'networkcode'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc", "rd2_networkcode"}));
  run_ctx.setVarValueForTest("mnc", "262", nullptr);
  run_ctx.setVarValueForTest("networkcode", "262", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("networkcode", "678", nullptr);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("networkcode", "262", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
}
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseVV1IsTrue2) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mnc'}, "
                                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'networkcode'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc", "rd2_networkcode"}));
  run_ctx.setVarValueForTest("mnc", "abc", nullptr);
  run_ctx.setVarValueForTest("networkcode", "ABC", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("networkcode", "678", nullptr);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("networkcode", "AbC", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
}
// Tests that a condition (number-variable and number-variable) is configured
// correctly and op_equals_case_insensitive works
// condition:  var.prio == var.priority
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseVV2IsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'prio'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'priority'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  run_ctx.setVarValueForTest("prio", 1, nullptr);
  run_ctx.setVarValueForTest("priority", 1, nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("priority", 2, nullptr);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("priority", 1.0, nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
}

// test term_apiname. Expect false as it's retrieved from the request
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseApiContextName) {
  auto yaml = makeConfig(
      // clang-format off
        "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_apicontext: API_NAME}, "
                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'nnrf-disc'}}"
      // clang-format on
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_FALSE(op->eval(run_ctx));
}
// Tests that a condition (number-variable and string-variable) is configured
// correctly and op_equals_case_insensitive works
// condition:  var.prio == var.mcc -> false b/c type mismatch
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseVV3IsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'prio'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mcc'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  run_ctx.setVarValueForTest("prio", 1, nullptr);
  run_ctx.setVarValueForTest("mcc", "262", nullptr);
  EXPECT_FALSE(op->eval(run_ctx));
}
// Tests that a condition (string-variable and number-variable) is configured
// correctly and op_equals_case_insensitive works
// condition:  var.mcc == var.prio -> false b/c type mismatch
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseVV4IsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mcc'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'prio'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  run_ctx.setVarValueForTest("mcc", "262", nullptr);
  run_ctx.setVarValueForTest("prio", 1, nullptr);
  EXPECT_FALSE(op->eval(run_ctx));
}
// Tests that a condition (variable and header) is configured
// correctly and op_equals_case_insensitive works
// condition:  req.header["mcc"] == var.networkcode
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseVHIsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'networkcode'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'mnc'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd2_networkcode"}));
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"mnc"}));
  run_ctx.setVarValueForTest("networkcode", "262", nullptr);
  run_ctx.setHeaderValueForTest("mnc", "262", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("networkcode", "678", nullptr);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("networkcode", "262", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
}
// Tests that a condition (header and header) is configured
// correctly and op_equals_case_insensitive works
// condition:  req.header["mcc1"] == req.header["mcc2"]
TEST(EricProxyFilterConfigTest, TestOpEqualsCaseHHIsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'mnc1'}, "
                 "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'mnc2'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"mnc1", "mnc2"}));
  run_ctx.setHeaderValueForTest("mnc1", "abc", ReqOrResp::Request);
  run_ctx.setHeaderValueForTest("mnc2", "ABC", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("mnc1", "678", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("mnc1", "AbC", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
}
// Test that a condition with parameters that are conditions
// and not values works.
// condition:  true == true
TEST(EricProxyFilterConfigTest, TestOpEqualsCasePPIsTrue1) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', term_boolean: true}, "
                "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', term_boolean: true}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_TRUE(op->eval(run_ctx));
}
// Test that a condition with parameters that are conditions
// and not values works.
// condition:  true == TRUE
TEST(EricProxyFilterConfigTest, TestOpEqualsCasePPIsTrue2) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', term_boolean: true}, "
                "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', term_boolean: TRUE}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals_case_insensitive());
  EXPECT_TRUE(op->eval(run_ctx));
}
// Test that a condition with parameters that are conditions
// and not values works.
// condition:  "abc" isEmpty == true
TEST(EricProxyFilterConfigTest, TestOpEqualsCasePPIsTrue) {
  auto yaml = makeConfig(
    "op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', op_isempty: {arg1: {term_string: 'abc'}}}, "
                "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', term_boolean: true}}"
  );
  SETUP_EQUAL
  EXPECT_FALSE(op->eval(run_ctx));
}
#pragma endregion op_equals_case_insensitive

//----------- op_and ----------------------------------------------------------
// Test that an "and" condition with parameters that are booleans works.
// condition:  true and true
TEST(EricProxyFilterConfigTest, TestOpAndBBIsTrue) {
  auto yaml = makeConfig(
    "op_and: {arg1: {term_boolean: true}, "
             "arg2: {term_boolean: true}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_and());
  EXPECT_TRUE(op->eval(run_ctx));
}

// Test that an "and" condition with boolean parameters works
// condition:  true and false
TEST(EricProxyFilterConfigTest, TestOpAndBBIsFalse) {
  auto yaml = makeConfig(
    "op_and: {arg1: {term_boolean: true}, "
             "arg2: {term_boolean: false}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_and());
  EXPECT_FALSE(op->eval(run_ctx));
}

// Test a mix of op_and and op_equals
// condition:  var.mcc == "262" and true
TEST(EricProxyFilterConfigTest, TestOpAndOpEquals1) {
  auto yaml = makeConfig(
    "op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mcc}, "
                                "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}}, "
             "arg2: {term_boolean: true}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_and()); 
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc"}));
  run_ctx.setVarValueForTest("mcc", "262", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("mcc", "345", nullptr);
  EXPECT_FALSE(op->eval(run_ctx));
}

// Test a mix of op_and and op_equals
// condition:  var.mcc == "262" and var.mnc == "02"
TEST(EricProxyFilterConfigTest, TestOpAndOpEquals2) {
  auto yaml = makeConfig(
    "op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mcc}, "
                                "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}}, "
             "arg2: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mnc}, "
                                "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '02'}}}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_and());
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc"}));
  run_ctx.setVarValueForTest("mcc", "262", nullptr);
  run_ctx.setVarValueForTest("mnc", "02", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("mnc", "89", nullptr);
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:  var.mcc == "262" and var.mnc isEmpty
TEST(EricProxyFilterConfigTest, TestOpAndOpEquals3) {
  auto yaml = makeConfig(
    "op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mcc}, "
                                "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}}, "
             "arg2: {op_isempty: {arg1: {term_var: mnc}}}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_and());
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc"}));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("mcc", "262", nullptr);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("mnc", "02", reinterpret_cast<FilterCaseWrapper*>(1));
  EXPECT_FALSE(op->eval(run_ctx));
}

TEST(EricProxyFilterConfigTest, TestOpAndOpEquals4) {
  auto yaml = makeConfig(
// condition:  var.mcc == "262" and var.supi exists
    "op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mcc}, "
                                "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}}, "
             "arg2: {op_exists: {arg1: {term_var: 'supi'}}}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_and());
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc", "rd3_supi"}));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("mcc", "262", reinterpret_cast<FilterCaseWrapper*>(1)); // this indicates the variable was set
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("supi", "imsi-0123456789", reinterpret_cast<FilterCaseWrapper*>(1)); // this indicates the variable was set
  EXPECT_TRUE(op->eval(run_ctx));
}

//--------- op_exists -------------------------------------------------------------
// condition: var.mnc exists
 TEST(EricProxyFilterConfigTest, TestOpExistsStringVar) {
  auto yaml = makeConfig(
    "op_exists: {arg1: {term_var: 'mnc'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_exists());
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc"}));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("mnc", "89", reinterpret_cast<FilterCaseWrapper*>(1)); // this indicates the variable was set
  EXPECT_TRUE(op->eval(run_ctx));
}

// condition:  req.header["3gpp-Sbi-target-apiRoot"] exists
TEST(EricProxyFilterConfigTest, TestOpExistsReqHeader) {
  auto yaml = makeConfig(
    "op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_exists());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"3gpp-Sbi-target-apiRoot"}));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("3gpp-Sbi-target-apiRoot", "", ReqOrResp::Request);  // even if empty, the header exists
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("3gpp-Sbi-target-apiRoot", "asdf", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
}

// condition:  req.method exists   // always true
TEST(EricProxyFilterConfigTest, TestOpExistsReqMethod) {
  auto yaml = makeConfig(
    "op_exists: {arg1: {term_reqheader: ':method'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_exists());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {":method"}));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest(":method", "POST", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
}
// condition:  req.path exists    // always true
TEST(EricProxyFilterConfigTest, TestOpExistsReqPath) {
  auto yaml = makeConfig(
    "op_exists: {arg1: {term_reqheader: ':path'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_exists());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {":path"}));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest(":path", "/", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
}

// condition:  "abc" exists      // always true
TEST(EricProxyFilterConfigTest, TestOpExistsStringConst) {
  auto yaml = makeConfig(
    "op_exists: {arg1: {term_string: 'abc'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_exists());
  EXPECT_TRUE(op->eval(run_ctx));
}

// condition:  123 exists       // always true
TEST(EricProxyFilterConfigTest, TestOpExistsIntegerConst) {
  auto yaml = makeConfig(
    "op_exists: {arg1: {term_number: 123}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_exists());
  EXPECT_TRUE(op->eval(run_ctx));
}

// condition:  -123.45E67 exists       // always true
TEST(EricProxyFilterConfigTest, TestOpExistsFloatConst) {
  auto yaml = makeConfig(
    "op_exists: {arg1: {term_number: -123.45E67}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_exists());
  EXPECT_TRUE(op->eval(run_ctx));
}

// condition:  true exists     // always true
TEST(EricProxyFilterConfigTest, TestOpExistsBooleanTrue) {
  auto yaml = makeConfig(
    "op_exists: {arg1: {term_boolean: true}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_exists());
  EXPECT_TRUE(op->eval(run_ctx));
}

// condition:  false exists  // always true(!)
TEST(EricProxyFilterConfigTest, TestOpExistsBooleanFalse) {
  auto yaml = makeConfig(
    "op_exists: {arg1: {term_boolean: false}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_exists());
  EXPECT_TRUE(op->eval(run_ctx));
}

//----------- op_isinsubnet -------------------------------------------------------
// condition:   '10.0.0.1' isInSubnet '10.0.0.0/8'  // true
TEST(EricProxyFilterConfigTest, TestOpIsinsubnetStringConstv4True) {
  auto yaml = makeConfig(
      "op_isinsubnet: {arg1: {term_string: '10.0.0.1'}, arg2: '10.0.0.0/8'}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isinsubnet());
  EXPECT_TRUE(op->eval(run_ctx));
}

// condition:   '33.0.0.1' isInSubnet '10.0.0.0/8'  // false
TEST(EricProxyFilterConfigTest, TestOpIsinsubnetStringConstv4False) {
  auto yaml = makeConfig(
      "op_isinsubnet: {arg1: {term_string: '33.0.0.1'}, arg2: '10.0.0.0/8'}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isinsubnet());
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:   'fe80::c88d:edff:fee8:acd8' isInSubnet 'fe80::c88d:edff:fee8:acd8/64'  // true
TEST(EricProxyFilterConfigTest, TestOpIsinsubnetStringConstv6True) {
  auto yaml = makeConfig(
      "op_isinsubnet: {arg1: {term_string: 'fe80::c88d:edff:fee8:acd8'}, arg2: 'fe80::c88d:edff:fee8:acd8/64'}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isinsubnet());
  EXPECT_TRUE(op->eval(run_ctx));
}

// condition:   'fe80::c88d:edff:fee8:acd8' isInSubnet '1234::c88d:edff:fee8:acd8/64'  // false
TEST(EricProxyFilterConfigTest, TestOpIsinsubnetStringConstv6False) {
  auto yaml = makeConfig(
      "op_isinsubnet: {arg1: {term_string: 'fe80::c88d:edff:fee8:acd8'}, arg2: '1234::c88d:edff:fee8:acd8/64'}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isinsubnet());
  EXPECT_FALSE(op->eval(run_ctx));
}

// Crazy cases:
// Mix IPv4 and IPv6:
// condition:   '10.0.0.1' isInSubnet '1234::c88d:edff:fee8:acd8/64'  // false
TEST(EricProxyFilterConfigTest, TestOpIsinsubnetStringConstv4v6False) {
  auto yaml = makeConfig(
      "op_isinsubnet: {arg1: {term_string: '10.0.0.1'}, arg2: '1234::c88d:edff:fee8:acd8/64'}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isinsubnet());
  EXPECT_FALSE(op->eval(run_ctx));
}

// Illegal subnet
// condition:   'fe80::c88d:edff:fee8:acd8' isInSubnet 'alex::c88d:edff:fee8:acd8/64'  // always false
TEST(EricProxyFilterConfigTest, TestOpIsinsubnetStringConstIllegalSubnet1) {
  auto yaml = makeConfig(
      "op_isinsubnet: {arg1: {term_string: 'fe80::c88d:edff:fee8:acd8'}, arg2: 'alex::c88d:edff:fee8:acd8/64'}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isinsubnet());
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:   'fe80::c88d:edff:fee8:acd8' isInSubnet 'ericsson'  // always false
TEST(EricProxyFilterConfigTest, TestOpIsinsubnetStringConstIllegalSubnet2) {
  auto yaml = makeConfig(
      "op_isinsubnet: {arg1: {term_string: 'fe80::c88d:edff:fee8:acd8'}, arg2: 'ericsson'}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isinsubnet());
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:   var.addr isInSubnet '10.0.0.0/24'
TEST(EricProxyFilterConfigTest, TestOpIsinsubnetStringVarv4) {
  auto yaml = makeConfig(
      "op_isinsubnet: {arg1: {term_var: 'addr'}, arg2: '10.0.0.0/24'}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isinsubnet());
  // Unset variable -> false
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("addr", "10.0.0.12", reinterpret_cast<FilterCaseWrapper*>(1)); // this indicates the variable was set
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("addr", "33.33.22.22", reinterpret_cast<FilterCaseWrapper*>(1));
  EXPECT_FALSE(op->eval(run_ctx));
  // Port is not allowed -> false
  run_ctx.setVarValueForTest("addr", "10.0.0.12:80", reinterpret_cast<FilterCaseWrapper*>(1));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("addr", "fe80::c88d:edff:fee8:acd8", reinterpret_cast<FilterCaseWrapper*>(1));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("addr", "ericsson", reinterpret_cast<FilterCaseWrapper*>(1));
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:   var.addr isInSubnet 'fe80::c88d:edff:fee8:acd8/64'
TEST(EricProxyFilterConfigTest, TestOpIsinsubnetStringVarv6) {
  auto yaml = makeConfig(
      "op_isinsubnet: {arg1: {term_var: 'addr'}, arg2: 'fe80::c88d:edff:fee8:acd8/64'}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isinsubnet());
  // Unset variable -> false
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("addr", "fe80::c88d:edff:fee8:acd8", reinterpret_cast<FilterCaseWrapper*>(1)); // this indicates the variable was set
  EXPECT_TRUE(op->eval(run_ctx));
  // An IPv6 address does not have [ ] around it:
  run_ctx.setVarValueForTest("addr", "[fe80::c88d:edff:fee8:acd8]", reinterpret_cast<FilterCaseWrapper*>(1));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("addr", "1234::c88d:edff:fee8:acd8", reinterpret_cast<FilterCaseWrapper*>(1));
  EXPECT_FALSE(op->eval(run_ctx));
  // Port is not allowed -> false
  run_ctx.setVarValueForTest("addr", "[fe80::c88d:edff:fee8:acd8]:80", reinterpret_cast<FilterCaseWrapper*>(1));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("addr", "10.0.0.1", reinterpret_cast<FilterCaseWrapper*>(1));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("addr", "alex::c88d:edff:fee8:acd8", reinterpret_cast<FilterCaseWrapper*>(1));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("addr", "ericsson", reinterpret_cast<FilterCaseWrapper*>(1));
  EXPECT_FALSE(op->eval(run_ctx));
}


// condition:   req.header['addr'] isInSubnet '10.0.0.0/24'
TEST(EricProxyFilterConfigTest, TestOpIsinsubnetStringReqHeaderv4) {
  auto yaml = makeConfig(
      "op_isinsubnet: {arg1: {term_reqheader: 'addr'}, arg2: '10.0.0.0/24'}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isinsubnet());
  // Unset variable -> false
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("addr", "10.0.0.12", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("addr", "33.33.22.22", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
  // Port is not allowed -> false
  run_ctx.setHeaderValueForTest("addr", "10.0.0.12:80", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("addr", "fe80::c88d:edff:fee8:acd8", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("addr", "ericsson", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:   var.addr isInSubnet 'fe80::c88d:edff:fee8:acd8/64'
TEST(EricProxyFilterConfigTest, TestOpIsinsubnetStringRespHeaderv6) {
  auto yaml = makeConfig(
      "op_isinsubnet: {arg1: {term_respheader: 'addr'}, arg2: 'fe80::c88d:edff:fee8:acd8/64'}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isinsubnet());
  // Unset variable -> false
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("addr", "fe80::c88d:edff:fee8:acd8", ReqOrResp::Response);
  EXPECT_TRUE(op->eval(run_ctx));
  // An IPv6 address does not have [ ] around it:
  run_ctx.setHeaderValueForTest("addr", "[fe80::c88d:edff:fee8:acd8]", ReqOrResp::Response);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("addr", "1234::c88d:edff:fee8:acd8", ReqOrResp::Response);
  EXPECT_FALSE(op->eval(run_ctx));
  // Port is not allowed -> false
  run_ctx.setHeaderValueForTest("addr", "[fe80::c88d:edff:fee8:acd8]:80", ReqOrResp::Response);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("addr", "10.0.0.1", ReqOrResp::Response);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("addr", "alex::c88d:edff:fee8:acd8", ReqOrResp::Response);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("addr", "ericsson", ReqOrResp::Response);
  EXPECT_FALSE(op->eval(run_ctx));
}


//----------- op_isempty ----------------------------------------------------------
// condition:   var.mnc isEmpty
TEST(EricProxyFilterConfigTest, TestOpIsemptyStringVar) {
  auto yaml = makeConfig(
      "op_isempty: {arg1: {term_var: 'mnc'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isempty());
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc"}));
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("mnc", "", reinterpret_cast<FilterCaseWrapper*>(1)); // this indicates the variable was set
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("mnc", "262", reinterpret_cast<FilterCaseWrapper*>(2)); // this indicates the variable was set
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:   req.header["3gpp-Sbi-target-apiRoot"] isEmpty
TEST(EricProxyFilterConfigTest, TestOpIsemptyReqHeader) {
  auto yaml = makeConfig(
    "op_isempty: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isempty());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"3gpp-Sbi-target-apiRoot"}));
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("3gpp-Sbi-target-apiRoot", "", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("3gpp-Sbi-target-apiRoot", "asdf", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:   req.path isEmpty     // always false
TEST(EricProxyFilterConfigTest, TestOpIsemptyReqPath) {
  auto yaml = makeConfig(
    "op_isempty: {arg1: {term_reqheader: ':path'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isempty());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {":path"}));
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest(":path", "/", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:   req.method isEmpty  // always false
TEST(EricProxyFilterConfigTest, TestOpIsemptyReqMethod) {
  auto yaml = makeConfig(
    "op_isempty: {arg1: {term_reqheader: ':method'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isempty());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {":method"}));
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest(":method", "GET", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:   false isEmpty      // always false
TEST(EricProxyFilterConfigTest, TestOpIsemptyBooleanFalse) {
  auto yaml = makeConfig(
    "op_isempty: {arg1: {term_boolean: false}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isempty());
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:   true isEmpty      // always false
TEST(EricProxyFilterConfigTest, TestOpIsemptyBooleanTrue) {
  auto yaml = makeConfig(
    "op_isempty: {arg1: {term_boolean: true}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isempty());
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:   123 isEmpty      // always false
TEST(EricProxyFilterConfigTest, TestOpIsemptyIntegerConst) {
  auto yaml = makeConfig(
    "op_isempty: {arg1: {term_number: 123}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isempty());
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:   -123.45E-3 isEmpty      // always false
TEST(EricProxyFilterConfigTest, TestOpIsemptyFloatConst) {
  auto yaml = makeConfig(
    "op_isempty: {arg1: {term_number: -123.45E-3}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isempty());
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:   "abc" isEmpty   // always false
TEST(EricProxyFilterConfigTest, TestOpIsemptyStringConst) {
  auto yaml = makeConfig(
    "op_isempty: {arg1: {term_string: 'abc'}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_isempty());
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:   "abc" isEmpty == true   // always false
TEST(EricProxyFilterConfigTest, TestOpIsemptyStringConstEqualsBoolean) {
  auto yaml = makeConfig(
    "op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', op_isempty: {arg1: {term_string: 'abc'}}}, "
                "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Condition', term_boolean: true}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_equals());
  EXPECT_FALSE(op->eval(run_ctx));
}

//-------- op_or -------------------------------------------------------------
// condition: false or false
TEST(EricProxyFilterConfigTest, TestOpOrBoolean1) {
  auto yaml = makeConfig(
      "op_or: {arg1: {term_boolean: false}, "
              "arg2: {term_boolean: false}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_or());
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition: true or false
TEST(EricProxyFilterConfigTest, TestOpOrBoolean2) {
  auto yaml = makeConfig(
      "op_or: {arg1: {term_boolean: true}, "
              "arg2: {term_boolean: false}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_or());
  EXPECT_TRUE(op->eval(run_ctx));
}

// condition:   req.header["3gpp-Sbi-target-apiRoot"] exists or req.method == "POST"
TEST(EricProxyFilterConfigTest, TestOpOrExistsEqual) {
  auto yaml = makeConfig(
    "op_or: {arg1: {op_exists: {arg1: {term_reqheader: '3gpp-Sbi-target-apiRoot'}}}, "
            "arg2: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':method'}, "
                               "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'POST'}}}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_or());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"3gpp-Sbi-target-apiRoot", ":method"}));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest(":method", "GET", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest(":method", "POST", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("3gpp-Sbi-target-apiRoot", "asdf", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
}

// condition:   var.mcc == "262" or req.method == "POST" and req.path == "/nchf-convergedcharging"
TEST(EricProxyFilterConfigTest, TestOpOrPrecedence1) {
  auto yaml = makeConfig(
    "op_or: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mcc}, "
                               "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}}, "
            "arg2: {op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':method'}, "
                                               "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'POST'}}}, "
                            "arg2: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':path'}, "
                                               "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '/nchf-convergedcharging'}}}}}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_or());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {":path", ":method"}));
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc"}));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest(":method", "GET", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest(":method", "POST", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest(":path", "/nchf-convergedcharging", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("mcc", "262", reinterpret_cast<FilterCaseWrapper*>(1)); // this indicates the variable was set
  EXPECT_TRUE(op->eval(run_ctx));
  
}

// Same as before, but set var.mcc first
// condition:   var.mcc == "262" or req.method == "POST" and req.path == "/nchf-convergedcharging"
TEST(EricProxyFilterConfigTest, TestOpOrPrecedence2) {
  auto yaml = makeConfig(
    "op_or: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: mcc}, "
                               "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}}, "
            "arg2: {op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':method'}, "
                                               "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'POST'}}}, "
                            "arg2: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':path'}, "
                                               "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '/nchf-convergedcharging'}}}}}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_or());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {":path", ":method"}));
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc"}));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("mcc", "262", reinterpret_cast<FilterCaseWrapper*>(1)); // this indicates the variable was set
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest(":method", "POST", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest(":path", "/nchf-convergedcharging", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
}
   
//-------- op_not ------------------------------------------------------------------------
// condition:  not true
TEST(EricProxyFilterConfigTest, TestOpNotTrue) {
  auto yaml = makeConfig(
    "op_not: {arg1: {term_boolean: true}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_not());
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:  req.method == "POST" and not exists req.header["x-trace"]
TEST(EricProxyFilterConfigTest, TestOpNotExists) {
  auto yaml = makeConfig(
      "op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':method'}, "
                                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'POST'}}}, "
               "arg2: {op_not: {arg1: {op_exists: {arg1: {term_reqheader: 'x-trace'}}}}}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_and());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"x-trace", ":method"}));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest(":method", "POST", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest("x-trace", "", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
}

// condition:   req.method == "GET" and not var.mcc == "262"
TEST(EricProxyFilterConfigTest, TestOpNotAnd) {
  auto yaml = makeConfig(
      "op_and: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: ':method'}, "
                                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'GET'}}}, "
               "arg2: {op_not: {arg1: {op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_var: 'mcc'}, "
                                                  "typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: '262'}}}}}}"
  );
  SETUP_EQUAL
  EXPECT_TRUE(rule.condition().has_op_and());
  EXPECT_TRUE(headerValIdxRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {":method"}));
  EXPECT_TRUE(filterdataRequiredContains(config, "default_routing", "csepp_to_rp_A",
                              {"rd1_mcc_mnc"}));
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest(":method", "POST", ReqOrResp::Request);
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("mcc", "595", reinterpret_cast<FilterCaseWrapper*>(1)); // this indicates the variable was set
  EXPECT_FALSE(op->eval(run_ctx));
  run_ctx.setHeaderValueForTest(":method", "GET", ReqOrResp::Request);
  EXPECT_TRUE(op->eval(run_ctx));
  run_ctx.setVarValueForTest("mcc", "262", reinterpret_cast<FilterCaseWrapper*>(1)); // this indicates the variable was set
  EXPECT_FALSE(op->eval(run_ctx));
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
