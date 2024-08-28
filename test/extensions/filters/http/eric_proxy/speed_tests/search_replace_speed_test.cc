// Compare search and replace functions
#include "gtest/gtest.h"
#include <algorithm>
#include <cctype>
#include <regex>
#include <string>
#include "re2/re2.h"
#include "benchmark/benchmark.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

// Baseline: copy string and compare. This needs to be subtracted from the other results
static void bmCopyCompareString(benchmark::State& state) {
  volatile long x = 0;
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    EXPECT_EQ(url, "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x");
    x++;
  }
}

BENCHMARK(bmCopyCompareString);


//------------------------------------------------------------------------
// UC1: Replace IP-address and port in URL

// UC1 with std::string functions. Case-sensitive, start from beginning
static void bmIpAddrCaseStd(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "10.1.2.3:30060";
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto pos = url.find(search_value);
    EXPECT_TRUE(pos != std::string::npos);
    if (pos != std::string::npos) {
      url.replace(pos, search_value.length(), replace_value);
      EXPECT_EQ(url, expected_url);
    }
  }
}
BENCHMARK(bmIpAddrCaseStd);

// No match at last char
// UC1 with std::string functions. Case-sensitive, start from beginning.
static void bmIpAddrCaseStdNoMatchLast(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "10.1.2.3:30067";
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto pos = url.find(search_value);
    EXPECT_TRUE(pos == std::string::npos);
    if (pos != std::string::npos) {
      url.replace(pos, search_value.length(), replace_value);
      EXPECT_EQ(url, expected_url);
    }
  }
}
BENCHMARK(bmIpAddrCaseStdNoMatchLast);


// No match at first char already
// UC1 with std::string functions. Case-sensitive, start from beginning.
static void bmIpAddrCaseStdNoMatchFirst(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "90.1.2.3:30060";
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto pos = url.find(search_value);
    EXPECT_TRUE(pos == std::string::npos);
    if (pos != std::string::npos) {
      url.replace(pos, search_value.length(), replace_value);
      EXPECT_EQ(url, expected_url);
    }
  }
}
BENCHMARK(bmIpAddrCaseStdNoMatchFirst);


//---------------
// UC1 with std::string functions and iterators. Case-sensitive, start from beginning
static void bmIpAddrCaseStdIt(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "10.1.2.3:30060";
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto search_it = std::search(url.begin(), url.end(), search_value.begin(), search_value.end());
    EXPECT_TRUE(search_it != url.end());
    if (search_it != url.end()) {
      url.replace(search_it, search_it + search_value.length(), replace_value);
      EXPECT_EQ(url, expected_url);
    }
  }
}
BENCHMARK(bmIpAddrCaseStdIt);


// No match at first char
// UC1 with std::string functions and iterators. Case-sensitive, start from beginning
static void bmIpAddrCaseStdItNoMatchFirst(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "90.1.2.3:30060";
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto search_it = std::search(url.begin(), url.end(), search_value.begin(), search_value.end());
    EXPECT_TRUE(search_it == url.end());
    if (search_it != url.end()) {
      url.replace(search_it, search_it + search_value.length(), replace_value);
      EXPECT_EQ(url, expected_url);
    }
  }
}
BENCHMARK(bmIpAddrCaseStdItNoMatchFirst);


// No match at last char
// UC1 with std::string functions and iterators. Case-sensitive, start from beginning
static void bmIpAddrCaseStdItNoMatchLast(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "10.1.2.3:30069";
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto search_it = std::search(url.begin(), url.end(), search_value.begin(), search_value.end());
    EXPECT_TRUE(search_it == url.end());
    if (search_it != url.end()) {
      url.replace(search_it, search_it + search_value.length(), replace_value);
      EXPECT_EQ(url, expected_url);
    }
  }
}
BENCHMARK(bmIpAddrCaseStdItNoMatchLast);


//------
// UC1 with std::string functions and iterators. Case-*in*sensitive, start from beginning
static void bmIpAddrCaseInsStdIt(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "10.1.2.3:30060";
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto search_it = std::search(url.begin(), url.end(), search_value.begin(), search_value.end(),
        [](unsigned char ch1, unsigned char ch2) {return std::tolower(ch1) == std::tolower(ch2);});
    EXPECT_TRUE(search_it != url.end());
    if (search_it != url.end()) {
      url.replace(search_it, search_it + search_value.length(), replace_value);
      EXPECT_EQ(url, expected_url);
    }
  }
}
BENCHMARK(bmIpAddrCaseInsStdIt);

// No match at first char
// UC1 with std::string functions and iterators. Case-*in*sensitive, start from beginning
static void bmIpAddrCaseInsStdItNoMatchFirst(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "90.1.2.3:30060";
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto search_it = std::search(url.begin(), url.end(), search_value.begin(), search_value.end(),
        [](unsigned char ch1, unsigned char ch2) {return std::tolower(ch1) == std::tolower(ch2);});
    EXPECT_TRUE(search_it == url.end());
    if (search_it != url.end()) {
      url.replace(search_it, search_it + search_value.length(), replace_value);
      EXPECT_EQ(url, expected_url);
    }
  }
}
BENCHMARK(bmIpAddrCaseInsStdItNoMatchFirst);


// No match at last char
// UC1 with std::string functions and iterators. Case-*in*sensitive, start from beginning
static void bmIpAddrCaseInsStdItNoMatchLast(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "10.1.2.3:30069";
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto search_it = std::search(url.begin(), url.end(), search_value.begin(), search_value.end(),
        [](unsigned char ch1, unsigned char ch2) {return std::tolower(ch1) == std::tolower(ch2);});
    EXPECT_TRUE(search_it == url.end());
    if (search_it != url.end()) {
      url.replace(search_it, search_it + search_value.length(), replace_value);
      EXPECT_EQ(url, expected_url);
    }
  }
}
BENCHMARK(bmIpAddrCaseInsStdItNoMatchLast);


//------------
// UC1 with re2 functions. Case-sensitive, start from beginning. On-the-fly regex
static void bmIpAddrCaseRe2(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "10\\.1\\.2\\.3:30060";
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto did_replace = RE2::Replace(&url, search_value, replace_value);
    EXPECT_TRUE(did_replace);
    EXPECT_EQ(url, expected_url);
  }
}
BENCHMARK(bmIpAddrCaseRe2);


//-------------
// UC1 with re2 functions. Case-sensitive, start from beginning. Quote the search-string, then
// on-the-fly regex
static void bmIpAddrCaseRe2QuoteMeta(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "10.1.2.3:30060";
  auto search_quoted = RE2::QuoteMeta(search_value);
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto did_replace = RE2::Replace(&url, search_quoted, replace_value);
    EXPECT_TRUE(did_replace);
    EXPECT_EQ(url, expected_url);
  }
}
BENCHMARK(bmIpAddrCaseRe2QuoteMeta);


//-------------
// UC1 with re2 functions. Case-sensitive, start from beginning. Quote the search-string, then
// pre-compiled regex
static void bmIpAddrCaseRe2QuoteMetaPrecomp(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "10.1.2.3:30060";
  auto search_quoted = RE2::QuoteMeta(search_value);
  auto search_re = RE2(search_quoted);
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto did_replace = RE2::Replace(&url, search_re, replace_value);
    EXPECT_TRUE(did_replace);
    EXPECT_EQ(url, expected_url);
  }
}
BENCHMARK(bmIpAddrCaseRe2QuoteMetaPrecomp);


//-------------
// UC1 with re2 functions. Case-sensitive, start from beginning. Search-re given by user, then
// pre-compiled regex
static void bmIpAddrCaseRe2Precomp(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "10\\.1\\.2\\.3:30060";
  auto search_re = RE2(search_value);
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto did_replace = RE2::Replace(&url, search_re, replace_value);
    EXPECT_TRUE(did_replace);
    EXPECT_EQ(url, expected_url);
  }
}
BENCHMARK(bmIpAddrCaseRe2Precomp);


// No match at first char
// UC1 with re2 functions. Case-sensitive, start from beginning. Search-re given by user, then
// pre-compiled regex
static void bmIpAddrCaseRe2PrecompNoMatchFirst(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "90\\.1\\.2\\.3:30060";
  auto search_re = RE2(search_value);
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto did_replace = RE2::Replace(&url, search_re, replace_value);
    EXPECT_FALSE(did_replace);
    // No comparison here because the std::string-based ones skip it as well
  }
}
BENCHMARK(bmIpAddrCaseRe2PrecompNoMatchFirst);


// No match at last char
// UC1 with re2 functions. Case-sensitive, start from beginning. Search-re given by user, then
// pre-compiled regex
static void bmIpAddrCaseRe2PrecompNoMatchLast(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "10\\.1\\.2\\.3:3006A";
  auto search_re = RE2(search_value);
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto did_replace = RE2::Replace(&url, search_re, replace_value);
    EXPECT_FALSE(did_replace);
    // No comparison here because the std::string-based ones skip it as well
  }
}
BENCHMARK(bmIpAddrCaseRe2PrecompNoMatchLast);


//-------------
// UC1 with re2 functions. Case-*in*sensitive, start from beginning. Search-re given by user, then
// pre-compiled regex
static void bmIpAddrCaseInsRe2Precomp(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "10\\.1\\.2\\.3:30060";
  auto options = RE2::Options();
  options.set_case_sensitive(false);
  auto search_re = RE2(search_value);
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto did_replace = RE2::Replace(&url, search_re, replace_value);
    EXPECT_TRUE(did_replace);
    EXPECT_EQ(url, expected_url);
  }
}
BENCHMARK(bmIpAddrCaseInsRe2Precomp);

//
//-------------
// UC1 with std::regex functions. Case-sensitive, start from beginning. Search-re given by user, then
// pre-compiled regex
static void bmIpAddrCaseStdRegexPrecomp(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "10\\.1\\.2\\.3:30060";
  auto search_re = std::regex(search_value);
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    std::string modified_url = std::regex_replace(url, search_re, replace_value);
    EXPECT_EQ(modified_url, expected_url);
  }
}
BENCHMARK(bmIpAddrCaseStdRegexPrecomp);


// No match at first char
// UC1 with re2 functions. Case-sensitive, start from beginning. Search-re given by user, then
// pre-compiled regex
static void bmIpAddrCaseStdRegexPrecompNoMatchFirst(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "90\\.1\\.2\\.3:30060";
  auto search_re = std::regex(search_value);
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    std::string modified_url = std::regex_replace(url, search_re, replace_value);
  }
}
BENCHMARK(bmIpAddrCaseStdRegexPrecompNoMatchFirst);


// No match at last char
// UC1 with re2 functions. Case-sensitive, start from beginning. Search-re given by user, then
// pre-compiled regex
static void bmIpAddrCaseStdRegexPrecompNoMatchLast(benchmark::State& state) {
  std::string expected_url = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string search_value = "10\\.1\\.2\\.3:3006A";
  auto search_re = std::regex(search_value);
  std::string replace_value = "192.168.10.20:80";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    std::string modified_url = std::regex_replace(url, search_re, replace_value);
  }
}
BENCHMARK(bmIpAddrCaseStdRegexPrecompNoMatchLast);


//----------------
// UC2: delete '#' in a string, perhaps multiple times
// Use std::string functions, case-sensitve, start from beginning.
static void bmHashCaseStd(benchmark::State& state) {
  std::string expected = "crnrule1subrule2subsubrule3";
  std::string search_value = "#";
  std::string replace_value = "";
  for (auto _ : state) {
    // This code is timed
    std::string original = "crn#rule1##subrule2#subsubrule3";
    auto pos = original.find(search_value);
    while (pos != std::string::npos) {
      original.replace(pos, search_value.length(), replace_value);
      pos = original.find(search_value);
    }
    EXPECT_EQ(original, expected);
  }
}
BENCHMARK(bmHashCaseStd);


// UC2: delete all '#' in a string
// Use RE2, precompiled regex, case-sensitive, start from beginning
static void bmHashCaseRe2Precomp(benchmark::State& state) {
  std::string expected = "crnrule1subrule2subsubrule3";
  std::string search_value = "#";
  std::string replace_value = "";
  auto search_re = RE2(search_value);
  for (auto _ : state) {
    // This code is timed
    std::string original = "crn#rule1##subrule2#subsubrule3";
    while (RE2::Replace(&original, search_re, replace_value)) { };
    EXPECT_EQ(original, expected);
  }
}
BENCHMARK(bmHashCaseRe2Precomp);


//----------------------
// UC3: replace at the end
// Use std::string, case sensitive, start from beginning of string
static void bmNetmaskCaseBeginningStd(benchmark::State& state) {
  std::string expected = "2001:1b70:8230:601:f816:3eff:fed3:4887";
  std::string search_value = "/64";
  std::string replace_value = "";
  for (auto _ : state) {
    // This code is timed
    std::string original = "2001:1b70:8230:601:f816:3eff:fed3:4887/64";
    auto pos = original.find(search_value);
    EXPECT_TRUE(pos != std::string::npos);
    if (pos != std::string::npos) {
      original.replace(pos, search_value.length(), replace_value);
      EXPECT_EQ(original, expected);
    }
  }
}
BENCHMARK(bmNetmaskCaseBeginningStd);


// UC3: replace at the end
// Use std::string, case sensitive, start from end
static void bmNetmaskCaseEndStd(benchmark::State& state) {
  std::string expected = "2001:1b70:8230:601:f816:3eff:fed3:4887";
  std::string search_value = "/64";
  std::string replace_value = "";
  for (auto _ : state) {
    // This code is timed
    std::string original = "2001:1b70:8230:601:f816:3eff:fed3:4887/64";
    auto pos = original.rfind(search_value);
    EXPECT_TRUE(pos != std::string::npos);
    if (pos != std::string::npos) {
      original.replace(pos, search_value.length(), replace_value);
      EXPECT_EQ(original, expected);
    }
  }
}
BENCHMARK(bmNetmaskCaseEndStd);


// UC3: replace at the end
// pre-compiled regex with fixed string (to compare to fixed string with std::string tests)
static void bmNetmaskCaseEndRe2Precomp(benchmark::State& state) {
  std::string expected = "2001:1b70:8230:601:f816:3eff:fed3:4887";
  std::string search_value = "/64$";
  std::string replace_value = "";
  auto search_re = RE2(search_value);
  for (auto _ : state) {
    // This code is timed
    std::string original = "2001:1b70:8230:601:f816:3eff:fed3:4887/64";
    auto did_replace = RE2::Replace(&original, search_re, replace_value);
    EXPECT_TRUE(did_replace);
    EXPECT_EQ(original, expected);
  }
}
BENCHMARK(bmNetmaskCaseEndRe2Precomp);


// UC3: replace at the end
// pre-compiled regex with regex for prefix-len/netmask
static void bmNetmaskRegexCaseEndRe2Precomp(benchmark::State& state) {
  std::string search_value = "/\\d{1,2}$";
  std::string replace_value = "";
  std::string expected = "2001:1b70:8230:601:f816:3eff:fed3:4887";
  auto search_re = RE2(search_value);
  for (auto _ : state) {
    // This code is timed
    std::string original = "2001:1b70:8230:601:f816:3eff:fed3:4887/64";
    auto did_replace = RE2::Replace(&original, search_re, replace_value);
    EXPECT_TRUE(did_replace);
    EXPECT_EQ(original, expected);
  }
}
BENCHMARK(bmNetmaskRegexCaseEndRe2Precomp);


//----------------
// UC6: Full string match vs. find
// Compare two strings for equality
static void bmCompareFullString(benchmark::State& state) {
  std::string replace_value = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string expected      = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    if  (url == expected) {
      url = replace_value;
      EXPECT_EQ(url, expected);
    }
  }
}

BENCHMARK(bmCompareFullString);


// UC6: Full string match vs. find
// Find full string in other string
static void bmFindFullString(benchmark::State& state) {
  std::string search_value  = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string replace_value = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  std::string expected      = "http://192.168.10.20:80/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
  for (auto _ : state) {
    // This code is timed
    std::string url = "http://10.1.2.3:30060/smsf/v1/sdm-status/imsi-xxxx80xxx0000x";
    auto pos = url.find(search_value);
    EXPECT_TRUE(pos != std::string::npos);
    if (pos != std::string::npos) {
      url.replace(pos, search_value.length(), replace_value);
      EXPECT_EQ(url, expected);
    }
  }
}
BENCHMARK(bmFindFullString);

//------------------------------------------------------------------------
} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy

