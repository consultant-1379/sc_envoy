#include "envoy/common/exception.h"
#include "envoy/type/matcher/v3/regex.pb.h"

#include "source/common/common/regex.h"

#include "test/test_common/logging.h"
#include "test/test_common/test_runtime.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Regex {
namespace {

TEST(Utility, ProgramSize) {

  // re2::RE2
  // regex_opt{"^(?:(?:selipcnsgsnmme263\\.interplmnfqdn|selipcnsgsnmme263)\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org|10\\.43\\.192\\.26):8080$"};

  re2::RE2 regex_cur{"^((selipcnsgsnmme280\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org)|("
                     "10\\.43\\.192\\.2)|(selipcnsgsnmme280\\.interplmnfqdn\\.amf\\.5gc\\.mnc008\\."
                     "mcc460\\.3gppnetwork\\.org)):8080$"};
  re2::RE2 regex_opt{
      "^(?:selipcnsgsnmme280\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org|10\\.43\\.192\\.2|"
      "selipcnsgsnmme280\\.interplmnfqdn\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org):8080$"};

  re2::RE2 regex_opt_cg{
      "^(selipcnsgsnmme280\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org|10\\.43\\.192\\.2|"
      "selipcnsgsnmme280\\.interplmnfqdn\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org):8080$"};
  const uint32_t cur_program_size = static_cast<uint32_t>(regex_cur.ProgramSize());
  const uint32_t opt_program_size = static_cast<uint32_t>(regex_opt.ProgramSize());
  const uint32_t opt_cg_program_size = static_cast<uint32_t>(regex_opt_cg.ProgramSize());

  fmt::print(
      "Program sizes: current regex: {}, optimized regex:{}, optimized with capturing group: {}",
      cur_program_size, opt_program_size, opt_cg_program_size);

  std::vector<std::string> input{
      "selipcnsgsnmme280.amf.5gc.mnc008.mcc460.3gppnetwork.org",
      "selipcnsgsnmme280.interplmnfqdn.amf.5gc.mnc008.mcc460.3gppnetwork.org", "10.43.192.2"};

  // verify that input without port suffix fails
  for (const auto& in : input) {

    EXPECT_THAT(re2::RE2::FullMatch(in, regex_cur), false);

    EXPECT_THAT(re2::RE2::FullMatch(in, regex_opt), false);
  }
  // verify that input with port suffix matches
  for (const auto& in : input) {

    EXPECT_THAT(re2::RE2::FullMatch(in + ":8080", regex_cur), true);

    EXPECT_THAT(re2::RE2::FullMatch(in + ":8080", regex_opt), true);
  }
  EXPECT_THAT(re2::RE2::FullMatch(input[2] + "s:8080", regex_opt), false);
  EXPECT_THAT(re2::RE2::FullMatch(input[2] + input[1] + ":8080", regex_opt), false);
}

TEST(Utility, RegexMatches) {
  std::string via_header =
      "1.0 scp1.ericsson.com, 1.1 scp2.ericsson.com, HTTP/2.0 scp3.ericsson.com";
  re2::StringPiece input(via_header);
  std::set<std::string> proxies;
  // extracts hostsnames from a via header via numbered groups
  re2::RE2 via_regex{
      "(?:HTTP/)?[12]\\.[01]? ((?:(?:[\\w\\d-.]+\\.?)+|(?:\\[[A-Fa-f0-9:]+\\]))(?::[0-9]+)?),?"};

  const uint32_t program_size = static_cast<uint32_t>(via_regex.ProgramSize());

  fmt::print("Program size for regex: {}", program_size);

  int num_matches = 0;
  std::string var;
  while (re2::RE2::FindAndConsume(&input, via_regex, &var)) {
    // fmt::print("match {} : {}", num_matches, var);
    num_matches++;
    proxies.insert(var);
  }
  EXPECT_THAT(proxies.empty(), false);
  fmt::print("{}\n", proxies);
}

TEST(Utility, ParseRegex) {
  ScopedInjectableLoader<Regex::Engine> engine(std::make_unique<Regex::GoogleReEngine>());
  {
    envoy::type::matcher::v3::RegexMatcher matcher;
    matcher.mutable_google_re2();
    matcher.set_regex("(+invalid)");
    EXPECT_THROW_WITH_MESSAGE(Utility::parseRegex(matcher), EnvoyException,
                              "no argument for repetition operator: +");
  }

  // Regression test for https://github.com/envoyproxy/envoy/issues/7728
  {
    envoy::type::matcher::v3::RegexMatcher matcher;
    matcher.mutable_google_re2();
    matcher.set_regex("/asdf/.*");
    const auto compiled_matcher = Utility::parseRegex(matcher);
    const std::string long_string = "/asdf/" + std::string(50 * 1024, 'a');
    EXPECT_TRUE(compiled_matcher->match(long_string));
  }

  // Regression test for https://github.com/envoyproxy/envoy/issues/15826
  {
    envoy::type::matcher::v3::RegexMatcher matcher;
    matcher.mutable_google_re2();
    matcher.set_regex("/status/200(/.*)?$");
    const auto compiled_matcher = Utility::parseRegex(matcher);
    EXPECT_TRUE(compiled_matcher->match("/status/200"));
    EXPECT_TRUE(compiled_matcher->match("/status/200/"));
    EXPECT_TRUE(compiled_matcher->match("/status/200/foo"));
    EXPECT_FALSE(compiled_matcher->match("/status/200foo"));
  }

  // Positive case to ensure no max program size is enforced.
  {
    TestScopedRuntime scoped_runtime;
    envoy::type::matcher::v3::RegexMatcher matcher;
    matcher.set_regex("/asdf/.*");
    matcher.mutable_google_re2();
    EXPECT_NO_THROW(Utility::parseRegex(matcher));
  }

  // Positive case to ensure matcher can be created by config without google_re2 field.
  {
    TestScopedRuntime scoped_runtime;
    envoy::type::matcher::v3::RegexMatcher matcher;
    matcher.set_regex("/asdf/.*");
    EXPECT_NO_THROW(Utility::parseRegex(matcher));
  }

  // Verify max program size with the deprecated field codepath plus runtime.
  // The deprecated field codepath precedes any runtime settings.
  {
    TestScopedRuntime scoped_runtime;
    scoped_runtime.mergeValues({{"re2.max_program_size.error_level", "3"}});
    envoy::type::matcher::v3::RegexMatcher matcher;
    matcher.set_regex("/asdf/.*");
    matcher.mutable_google_re2()->mutable_max_program_size()->set_value(1);
#ifndef GTEST_USES_SIMPLE_RE
    EXPECT_THROW_WITH_REGEX(Utility::parseRegex(matcher), EnvoyException,
                            "RE2 program size of [0-9]+ > max program size of 1\\.");
#else
    EXPECT_THROW_WITH_REGEX(Utility::parseRegex(matcher), EnvoyException,
                            "RE2 program size of \\d+ > max program size of 1\\.");
#endif
  }

  // Verify that an exception is thrown for the error level max program size.
  {
    TestScopedRuntime scoped_runtime;
    scoped_runtime.mergeValues({{"re2.max_program_size.error_level", "1"}});
    envoy::type::matcher::v3::RegexMatcher matcher;
    matcher.set_regex("/asdf/.*");
    matcher.mutable_google_re2();
#ifndef GTEST_USES_SIMPLE_RE
    EXPECT_THROW_WITH_REGEX(
        Utility::parseRegex(matcher), EnvoyException,
        "RE2 program size of [0-9]+ > max program size of 1 set for the error level threshold\\.");
#else
    EXPECT_THROW_WITH_REGEX(
        Utility::parseRegex(matcher), EnvoyException,
        "RE2 program size of \\d+ > max program size of 1 set for the error level threshold\\.");
#endif
  }

  // Verify that the error level max program size defaults to 100 if not set by runtime.
  {
    TestScopedRuntime scoped_runtime;
    envoy::type::matcher::v3::RegexMatcher matcher;
    matcher.set_regex(
        "/asdf/.*/asdf/.*/asdf/.*/asdf/.*/asdf/.*/asdf/.*/asdf/.*/asdf/.*/asdf/.*/asdf/.*");
    matcher.mutable_google_re2();
#ifndef GTEST_USES_SIMPLE_RE
    EXPECT_THROW_WITH_REGEX(Utility::parseRegex(matcher), EnvoyException,
                            "RE2 program size of [0-9]+ > max program size of 100 set for the "
                            "error level threshold\\.");
#else
    EXPECT_THROW_WITH_REGEX(
        Utility::parseRegex(matcher), EnvoyException,
        "RE2 program size of \\d+ > max program size of 100 set for the error level threshold\\.");
#endif
  }

  // Verify that a warning is logged for the warn level max program size.
  {
    TestScopedRuntime scoped_runtime;
    scoped_runtime.mergeValues({{"re2.max_program_size.warn_level", "1"}});
    envoy::type::matcher::v3::RegexMatcher matcher;
    matcher.set_regex("/asdf/.*");
    matcher.mutable_google_re2();
    EXPECT_NO_THROW(Utility::parseRegex(matcher));
    EXPECT_LOG_CONTAINS("warn", "> max program size of 1 set for the warn level threshold",
                        Utility::parseRegex(matcher));
  }

  // Verify that no check is performed if the warn level max program size is not set by runtime.
  {
    TestScopedRuntime scoped_runtime;
    envoy::type::matcher::v3::RegexMatcher matcher;
    matcher.set_regex("/asdf/.*");
    matcher.mutable_google_re2();
    EXPECT_NO_THROW(Utility::parseRegex(matcher));
    EXPECT_LOG_NOT_CONTAINS("warn", "> max program size", Utility::parseRegex(matcher));
  }
}

} // namespace
} // namespace Regex
} // namespace Envoy
