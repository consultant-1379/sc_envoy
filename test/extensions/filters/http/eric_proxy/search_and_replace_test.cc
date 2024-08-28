#include "source/extensions/filters/http/eric_proxy/search_and_replace.h"

#include "test/mocks/server/factory_context.h"
#include "test/mocks/server/instance.h"
#include "test/mocks/upstream/cluster_manager.h"
#include "test/test_common/utility.h"
#include "re2/re2.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {


class EricProxySearchAndReplaceTest : public ::testing::Test {
protected:

  
  void SetUp() override {
  }
};

TEST_F(EricProxySearchAndReplaceTest, searchAndReplace_search_from_beginning_replace_first) {

auto search_value = "imsi-";
auto replace_value = "PREFIX-IMSI-";
auto search_from_end = false;

auto search_and_replace_func = EricProxySearchAndReplace::searchAndReplace(search_value, replace_value, search_from_end);

auto actual_value = search_and_replace_func("imsi-460001357924610-imsi-");
auto expected_value = "PREFIX-IMSI-460001357924610-imsi-";
EXPECT_EQ(actual_value, expected_value);

}

TEST_F(EricProxySearchAndReplaceTest, searchAndReplace_search_from_end_replace_first) {

auto search_value = "imsi-";
auto replace_value = "PREFIX-IMSI-";
auto search_from_end = true;

auto search_and_replace_func = EricProxySearchAndReplace::searchAndReplace(search_value, replace_value, search_from_end);

auto actual_value = search_and_replace_func("imsi-460001357924610-imsi-");
auto expected_value = "imsi-460001357924610-PREFIX-IMSI-";
EXPECT_EQ(actual_value, expected_value);

}

TEST_F(EricProxySearchAndReplaceTest, searchAndReplace_search_from_end_replace_all) {

auto search_value = "imsi";
auto replace_value = "IMSI";

auto search_from_end = true;
auto replace_all = true;

auto search_and_replace_func = EricProxySearchAndReplace::searchAndReplace(search_value, replace_value, search_from_end, replace_all);

auto actual_value = search_and_replace_func("imsi-460001357924610-imsi");
auto expected_value = "IMSI-460001357924610-IMSI";
EXPECT_EQ(actual_value, expected_value);

}

TEST_F(EricProxySearchAndReplaceTest, searchAndReplaceCaseInsensitive_search_from_beginning_replace_first) {

auto search_value = "IMSI-";
auto replace_value = "PREFIX-IMSI-";
auto search_from_end = false;
auto replace_all = false;

auto search_and_replace_func = EricProxySearchAndReplace::searchAndReplaceCaseInsensitive(search_value, replace_value, search_from_end, replace_all);

auto actual_value = search_and_replace_func("imsi-460001357924610-imsi-");
auto expected_value = "PREFIX-IMSI-460001357924610-imsi-";
EXPECT_EQ(actual_value, expected_value);

}

TEST_F(EricProxySearchAndReplaceTest, searchAndReplaceCaseInsensitive_search_from_end_replace_first) {

auto search_value = "IMSI-";
auto replace_value = "PREFIX-IMSI-";
auto search_from_end = true;
auto replace_all = false;

auto search_and_replace_func = EricProxySearchAndReplace::searchAndReplaceCaseInsensitive(search_value, replace_value, search_from_end, replace_all);

auto actual_value = search_and_replace_func("imsi-460001357924610-imsi-");
auto expected_value = "imsi-460001357924610-PREFIX-IMSI-";
EXPECT_EQ(actual_value, expected_value);

}

TEST_F(EricProxySearchAndReplaceTest, searchAndReplaceCaseInsensitive_search_from_beginning_replace_all) {

auto search_value = "imsi";
auto replace_value = "SUPI";

auto search_from_end = false;
auto replace_all = true;

auto search_and_replace_func = EricProxySearchAndReplace::searchAndReplaceCaseInsensitive(search_value, replace_value, search_from_end, replace_all);

auto actual_value = search_and_replace_func("imsi-12345-imsi-6789-imsi");
auto expected_value = "SUPI-12345-SUPI-6789-SUPI";
EXPECT_EQ(actual_value, expected_value);

}

TEST_F(EricProxySearchAndReplaceTest, searchAndReplaceCaseInsensitive_search_from_beginning_replace_all_to_upper) {

auto search_value = "imsi";
auto replace_value = "IMSI";

auto search_from_end = false;
auto replace_all = true;

auto search_and_replace_func = EricProxySearchAndReplace::searchAndReplaceCaseInsensitive(search_value, replace_value, search_from_end, replace_all);

auto actual_value = search_and_replace_func("imsi-460001357924610-imsi");
auto expected_value = "IMSI-460001357924610-IMSI";
EXPECT_EQ(actual_value, expected_value);

}



TEST_F(EricProxySearchAndReplaceTest, searchAndReplaceCaseInsensitive_search_from_end_replace_all) {

auto search_value = "imsi";
auto replace_value = "IMSI";

auto search_from_end = true;
auto replace_all = true;

auto search_and_replace_func = EricProxySearchAndReplace::searchAndReplaceCaseInsensitive(search_value, replace_value, search_from_end, replace_all);

auto actual_value = search_and_replace_func("imsi-460001357924610-imsi");
auto expected_value = "IMSI-460001357924610-IMSI";
EXPECT_EQ(actual_value, expected_value);

}

TEST_F(EricProxySearchAndReplaceTest, searchAndReplaceCaseRegex_basic) {

auto search_value = "10\\.1\\.2\\.3:30060";
auto replace_value = "192.168.10.20:80";

auto search_and_replace_func = EricProxySearchAndReplace::searchAndReplaceRegex(search_value, replace_value);

auto actual_value = search_and_replace_func("http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x");
auto expected_value = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
EXPECT_EQ(actual_value, expected_value);

}

TEST_F(EricProxySearchAndReplaceTest, searchAndReplaceCaseRegexPrecompiled_basic) {
  auto search_value = "10\\.1\\.2\\.3:30060";
  auto replace_value = "192.168.10.20:80";

  std::map<std::string, re2::RE2> precompiled_regexs;
  precompiled_regexs.emplace(search_value, search_value);
  const auto& precompiled_regex = precompiled_regexs.find(search_value);

  auto search_and_replace_func = EricProxySearchAndReplace::searchAndReplaceRegexPrecompiled(precompiled_regex, replace_value);

  auto actual_value = search_and_replace_func("http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x");
  auto expected_value = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  EXPECT_EQ(actual_value, expected_value);
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
