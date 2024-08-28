#include "envoy/http/codes.h"
#include "envoy/http/filter.h"
#include "source/extensions/filters/http/eric_ingress_ratelimit/ratelimit.h"

#include "envoy/common/time.h"

#include "source/common/common/macros.h"
#include "source/common/common/utility.h"
#include "test/test_common/simulated_time_system.h"


#include "gtest/gtest.h"
#include <cstdlib>
#include <iostream>
#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IngressRateLimitFilter {


struct CalculateDateTestCase {
  std::string test_name;
  int  delay_seconds;
  Json rlf_response;
};

class CalculateDateTest : public testing::TestWithParam<CalculateDateTestCase> {
public: 
  static std::string durationToString(const SystemTime::duration& duration) {
    return std::to_string(duration.count());
  }

  static std::string formatTime(const SystemTime& time) { return CalculateDateTest::formatter().fromTime(time); }
  static const DateFormatter& formatter() {
    CONSTRUCT_ON_FIRST_USE(DateFormatter, {"Date: %a, %d %b %Y %H:%M:%S GMT"});
  }
  static const SystemTime& currentTime() {
    CONSTRUCT_ON_FIRST_USE(SystemTime, Event::SimulatedTimeSystem().systemTime());
  }

    static const std::vector<CalculateDateTestCase>& getTestCases() {
    // clang-format off
    CONSTRUCT_ON_FIRST_USE(std::vector<CalculateDateTestCase>,
        {
          "one_second_roundup",
          /*delay_seconds=*/1,
          /*rlf_response=*/R"([{ "rc" : 429, "ra" : 200}])"_json
        },
        {
          "one_minute",
          /*delay_seconds=*/60,
          /*rlf_response=*/R"([{ "rc" : 429, "ra" : 60000}])"_json
        },
        {
          "big_number",
          /*delay_seconds=*/123457,
          /*rlf_response=*/R"([{ "rc" : 429, "ra" : 123456789}])"_json
        },
        {
          "exactly_one_second",
          /*delay_seconds=*/1,
          /*rlf_response=*/R"([{ "rc" : 429, "ra" : 1000}])"_json
        },
        {
          "thousand_one_millis",
          /*delay_seconds=*/2,
          /*rlf_response=*/R"([{ "rc" : 429, "ra" : 1001}])"_json
        },
        {
          "fourty_millis",
          /*delay_seconds=*/1,
          /*rlf_response=*/R"([{ "rc" : 429, "ra" : 40}])"_json
        },
        {
          "one_half_hour",
          /*delay_seconds=*/5400,
          /*rlf_response=*/R"([{ "rc" : 429, "ra" : 5400000}])"_json
        },
        {
          "one_year",
          /*delay_seconds=*/31536000,
          /*rlf_response=*/R"([{ "rc" : 429, "ra" : 31536000000}])"_json
        },
    );
    // clang-format on
  }

};

INSTANTIATE_TEST_SUITE_P(CalculateDateTest, CalculateDateTest,
                         testing::ValuesIn(CalculateDateTest::getTestCases()),
                         [](const auto& info) { return info.param.test_name; });
TEST_P(CalculateDateTest, CalculateDateTest) {
  
    Json response = CalculateDateTest::GetParam().rlf_response;

    for ( Json::iterator it = response.begin(); it != response.end(); ++it) {
      EXPECT_EQ(std::to_string(CalculateDateTest::GetParam().delay_seconds), RetryAfterHeaderFormat::getSecondsJsonBody(it));
      EXPECT_EQ(CalculateDateTest::formatTime(CalculateDateTest::currentTime()+Seconds(CalculateDateTest::GetParam().delay_seconds)), RetryAfterHeaderFormat::getHttpDateFromJsonBody(it));
    }
  
}



} // namespace IngressRateLimitFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy