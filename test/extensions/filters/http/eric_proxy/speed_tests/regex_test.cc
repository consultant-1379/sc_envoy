#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <algorithm>
#include <iostream>
#include <regex>
#include <string>
#include <utility>

#include "benchmark/benchmark.h"
#include "external/com_github_google_benchmark/_virtual_includes/benchmark/benchmark/benchmark.h"
#include "re2/re2.h"
#include "test/test_common/utility.h"
#include <sstream>

#include "source/extensions/filters/http/cdn_loop/parser.h"

#include "test/test_common/status_utility.h"

#include "absl/status/status.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

// static void RegexFullMatchFullCurrent(benchmark::State& state) {

//   re2::RE2
//   regex_full_cur{"^((selipcnsgsnmme280\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org)|"
//                           "(10\\.43\\.192\\.2)|(selipcnsgsnmme280\\.interplmnfqdn\\.amf\\.5gc\\."
//                           "mnc008\\.mcc460\\.3gppnetwork\\.org)):8080$"};

//   std::vector<std::string> input{
//       "selipcnsgsnmme280.amf.5gc.mnc008.mcc460.3gppnetwork.org:8080",
//       "selipcnsgsnmme280.interplmnfqdn.amf.5gc.mnc008.mcc460.3gppnetwork.org:8080",
//       "10.43.192.2:8080"};

//   srand(static_cast<unsigned>(time(nullptr)));
//   for (auto _ : state) {
//     // This code gets timed
//     int random = rand() % 3;
//     benchmark::DoNotOptimize(re2::RE2::FullMatch(input[random], regex_full_cur));
//   }
// }
// BENCHMARK(RegexFullMatchFullCurrent);

// static void RegexFullMatchFullOpt(benchmark::State& state) {

//   re2::RE2 regex_full_opt{
//       "^(?:selipcnsgsnmme280\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org|10\\.43\\.192\\.2|"
//       "selipcnsgsnmme280\\.interplmnfqdn\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org):8080$"};

//   std::vector<std::string> input{
//       "selipcnsgsnmme280.amf.5gc.mnc008.mcc460.3gppnetwork.org:8080",
//       "selipcnsgsnmme280.interplmnfqdn.amf.5gc.mnc008.mcc460.3gppnetwork.org:8080",
//       "10.43.192.2:8080"};

//   srand(static_cast<unsigned>(time(nullptr)));
//   for (auto _ : state) {
//     // This code gets timed
//     int random = rand() % 3;
//     benchmark::DoNotOptimize(re2::RE2::FullMatch(input[random], regex_full_opt));
//   }
// }

// BENCHMARK(RegexFullMatchFullOpt);

// static void RegexFullMatchSplit(benchmark::State& state) {

//   re2::RE2
//   regex_cur_1{"^((selipcnsgsnmme280\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org)|("
//                        "10\\.43\\.192\\.2)):8080$"};

//   re2::RE2 regex_interplmn{
//       "selipcnsgsnmme280\\.interplmnfqdn\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org:8080$"};

//   // re2::RE2
//   // regex_split_1{"^(?:selipcnsgsnmme280\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org|"
//   //                        "10\\.43\\.192\\.2):8080$"};

//   std::vector<std::string> input{
//       "selipcnsgsnmme280.amf.5gc.mnc008.mcc460.3gppnetwork.org:8080",
//       "selipcnsgsnmme280.interplmnfqdn.amf.5gc.mnc008.mcc460.3gppnetwork.org:8080",
//       "10.43.192.2:8080"};

//   srand(static_cast<unsigned>(time(nullptr)));
//   for (auto _ : state) {
//     // This code gets timed
//     int random = rand() % 3;
//     benchmark::DoNotOptimize(re2::RE2::FullMatch(input[random], regex_cur_1));
//     benchmark::DoNotOptimize(re2::RE2::FullMatch(input[random], regex_interplmn));
//   }
// }
// BENCHMARK(RegexFullMatchSplit);

// static void RegexFullMatchFullOptLonger(benchmark::State& state) {

//   re2::RE2 regex_full_opt{
//       "^(?:selipcnsgsnmme280\\.interplmnfqdn\\.amf\\.5gc\\.mnc666\\.mcc666\\.3gppnetwork\\.org|"
//       "selipcnsgsnmme280\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org|10\\.43\\.192\\.2|"
//       "selipcnsgsnmme280\\.interplmnfqdn\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org):8080$"};

//   std::vector<std::string> input{
//       "selipcnsgsnmme280.amf.5gc.mnc008.mcc460.3gppnetwork.org:8080",
//       "selipcnsgsnmme280.interplmnfqdn.amf.5gc.mnc008.mcc460.3gppnetwork.org:8080",
//       "selipcnsgsnmme280.interplmnfqdn.amf.5gc.mnc666.mcc666.3gppnetwork.org:8080",
//       "10.43.192.2:8080"};

//   srand(static_cast<unsigned>(time(nullptr)));
//   for (auto _ : state) {
//     // This code gets timed
//     int random = rand() % 4;
//     benchmark::DoNotOptimize(re2::RE2::FullMatch(input[random], regex_full_opt));
//   }
// }

// BENCHMARK(RegexFullMatchFullOptLonger);

// static void RegexFullMatchFullCurrentLonger(benchmark::State& state) {

//   re2::RE2 regex_full_cur{
//       "^((selipcnsgsnmme280\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org)|"
//       "(10\\.43\\.192\\.2)|(selipcnsgsnmme280\\.interplmnfqdn\\.amf\\.5gc\\."
//       "mnc008\\.mcc460\\.3gppnetwork\\.org)|(selipcnsgsnmme280\\.interplmnfqdn\\.amf\\.5gc\\."
//       "mnc666\\.mcc666\\.3gppnetwork\\.org)):8080$"};

//   std::vector<std::string> input{
//       "selipcnsgsnmme280.amf.5gc.mnc008.mcc460.3gppnetwork.org:8080",
//       "selipcnsgsnmme280.interplmnfqdn.amf.5gc.mnc008.mcc460.3gppnetwork.org:8080",
//       "selipcnsgsnmme280.interplmnfqdn.amf.5gc.mnc666.mcc666.3gppnetwork.org:8080",

//       "10.43.192.2:8080"};

//   srand(static_cast<unsigned>(time(nullptr)));
//   for (auto _ : state) {
//     // This code gets timed
//     int random = rand() % 4;
//     benchmark::DoNotOptimize(re2::RE2::FullMatch(input[random], regex_full_cur));
//   }
// }
// BENCHMARK(RegexFullMatchFullCurrentLonger);

// static void RegexStdFullMatchFullCurrentLonger(benchmark::State& state) {

//   std::regex regex_full_cur{
//       "^((selipcnsgsnmme280\\.amf\\.5gc\\.mnc008\\.mcc460\\.3gppnetwork\\.org)|"
//       "(10\\.43\\.192\\.2)|(selipcnsgsnmme280\\.interplmnfqdn\\.amf\\.5gc\\."
//       "mnc008\\.mcc460\\.3gppnetwork\\.org)|(selipcnsgsnmme280\\.interplmnfqdn\\.amf\\.5gc\\."
//       "mnc666\\.mcc666\\.3gppnetwork\\.org)):8080$"};

//   std::vector<std::string> input{
//       "selipcnsgsnmme280.amf.5gc.mnc008.mcc460.3gppnetwork.org:8080",
//       "selipcnsgsnmme280.interplmnfqdn.amf.5gc.mnc008.mcc460.3gppnetwork.org:8080",
//       "selipcnsgsnmme280.interplmnfqdn.amf.5gc.mnc666.mcc666.3gppnetwork.org:8080",

//       "10.43.192.2:8080"};

//   srand(static_cast<unsigned>(time(nullptr)));
//   for (auto _ : state) {
//     // This code gets timed
//     int random = rand() % 4;

//     benchmark::DoNotOptimize(std::regex_match(input[random], regex_full_cur));
//   }
// }
// BENCHMARK(RegexStdFullMatchFullCurrentLonger);

static void viaHeaderGenerator(int size, std::string& via_header,
                               std::vector<std::pair<std::string, bool>>& hosts);
static void tokenizeAndSetInsert(benchmark::State& state) {

  std::string via_header;

  std::vector<std::pair<std::string, bool>> hosts;
  // srand(static_cast<unsigned>(time(nullptr)));
  viaHeaderGenerator(state.range(), via_header, hosts);

  // extracts hostsnames from a via header via numbered groups
  // re2::RE2 via_regex{"(?:HTTP/)?[12]\\.[01]? ((?:[a-zA-z0-9]+\\.?)+),?"};
  re2::RE2 via_regex{
      "(?:HTTP/)?[12]\\.[01]? ((?:(?:[\\w\\d-.]+\\.?)+|(?:\\[[A-Fa-f0-9:]+\\]))(?::[0-9]+)?),?"};
  re2::StringPiece input(via_header);
  std::string var;

  std::set<std::string> proxies;
  for (auto _ : state) {

    //  int num_matches = 0;
    while (re2::RE2::FindAndConsume(&input, via_regex, &var)) {
      //  fmt::print("match {} : {}", num_matches, var);
      // num_matches++;
      proxies.insert(var);
      // EXPECT_THAT(res.second, true);
      EXPECT_THAT(proxies.empty(), false);
    }
    // proxies.
    // proxies.erase(proxies.begin(), proxies.end());
  }
}

BENCHMARK(tokenizeAndSetInsert)->Arg(10);
BENCHMARK(tokenizeAndSetInsert)->Arg(100);
BENCHMARK(tokenizeAndSetInsert)->Arg(1000);

static void splitAndSetInsert(benchmark::State& state) {

  std::string via_header;
  std::vector<std::pair<std::string, bool>> hosts;
  srand(static_cast<unsigned>(time(nullptr)));
  viaHeaderGenerator(state.range_x(), via_header, hosts);
  std::set<absl::string_view> unwanted = {"HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "1.0", "1.1", "1.0"};

  for (auto _ : state) {

    std::set<std::string> s =
        absl::StrSplit(via_header, absl::ByAnyChar(", "), [&unwanted](absl::string_view l) {
          // l = absl::StripAsciiWhitespace(l);
          return !l.empty() && unwanted.find(l) == unwanted.end();
        });
    EXPECT_THAT(s.empty(), false);
  }
}

BENCHMARK(splitAndSetInsert)->Arg(10);
BENCHMARK(splitAndSetInsert)->Arg(100);
BENCHMARK(splitAndSetInsert)->Arg(1000);

static void strContains(benchmark::State& state) {

  std::string via_header;
  std::vector<std::pair<std::string, bool>> hosts;
  srand(static_cast<unsigned>(time(nullptr)));
  viaHeaderGenerator(state.range(), via_header, hosts);

  for (auto _ : state) {
    // This code gets timed
    const auto& h = hosts[rand() % (state.range() / 2)];

    EXPECT_EQ(absl::StrContains(via_header, h.first), h.second);
  }
}

BENCHMARK(strContains)->Arg(10);
BENCHMARK(strContains)->Arg(100);
BENCHMARK(strContains)->Arg(1000);

// static void strFind(benchmark::State& state) {

//   std::string via_header;
//   std::vector<std::pair<std::string, bool>> hosts;
//   srand(static_cast<unsigned>(time(nullptr)));
//   viaHeaderGenerator(state.range(), via_header, hosts);

//   srand(static_cast<unsigned>(time(nullptr)));

//   for (auto _ : state) {
//     // This code gets timed
//     const auto& h = hosts[rand() % (state.range() / 2)];

//     EXPECT_EQ(via_header.find(h.first) != std::string::npos, h.second);
//   }
// }

// BENCHMARK(strFind)->Arg(100);

static void setLookup(benchmark::State& state) {

  std::string via_header;
  std::vector<std::pair<std::string, bool>> hosts;
  srand(static_cast<unsigned>(time(nullptr)));
  viaHeaderGenerator(state.range(), via_header, hosts);
  std::set<std::string> proxies;

  for (auto& h : hosts) {
    if (h.second) {
      proxies.insert(h.first);
    }
  }

  for (auto _ : state) {

    // This code gets timed
    const auto& h = hosts[rand() % (state.range() / 2)];

    EXPECT_EQ(proxies.find(h.first) != proxies.end(), h.second);
  }
}

BENCHMARK(setLookup)->Arg(10);
BENCHMARK(setLookup)->Arg(100);
BENCHMARK(setLookup)->Arg(1000);

static void parserLookup(benchmark::State& state) {

  std::string via_header;
  std::vector<std::pair<std::string, bool>> hosts;
  srand(static_cast<unsigned>(time(nullptr)));
  viaHeaderGenerator(state.range(), via_header, hosts);
  CdnLoop::Parser::ParseContext input(via_header);
  auto parsed = parseCdnInfoList(input);

  for (auto _ : state) {

    // This code gets timed
    const auto& h = hosts[rand() % (state.range() / 2)];
    std::find(parsed->cdnIds().begin(), parsed->cdnIds().end(), h.first);
    // EXPECT_EQ(found != parsed->cdnIds().end(), h.second);
  }
}

BENCHMARK(parserLookup)->Arg(10);
BENCHMARK(parserLookup)->Arg(100);
BENCHMARK(parserLookup)->Arg(1000);

static void viaHeaderGenerator(int size, std::string& via_header,
                               std::vector<std::pair<std::string, bool>>& hosts) {

  //       "1.0 scp1.ericsson.com, 1.1 scp2.ericsson.com, HTTP/2.0 scp3.ericsson.com";
  std::vector<absl::string_view> domains = {"vodafone", "ericsson", "orange"};
  std::vector<absl::string_view> suffix = {"de", "gr", "com"};
  std::vector<absl::string_view> protocol = {"HTTP/1.1", "HTTP/2.0", "1.0", "2.0"};
  for (auto i = 0; i < size; i++) {
    int suffix_indx = rand() % suffix.size();
    int domains_indx = rand() % domains.size();
    int protocol_indx = rand() % protocol.size();
    absl::StrAppend(&via_header, protocol[protocol_indx], " scp", i, domains[domains_indx],
                    suffix[suffix_indx], ", ");
    // hosts is half the size of via contents
    if (i % 2 == 0) {
      if (rand() % 100 < 35) {
        // 35% of size/2 are true a hit
        hosts.emplace_back(std::make_pair(
            absl::StrCat("scp", i, domains[domains_indx], suffix[suffix_indx]), true));
      } else {
        // not existant host
        hosts.emplace_back(std::make_pair(
            absl::StrCat("scp00", i, domains[domains_indx], suffix[suffix_indx]), false));
      }
    }
  }
  via_header.resize(via_header.size() - 2);
}
// Via: 1.0 fred, 1.1 p.example.net

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy