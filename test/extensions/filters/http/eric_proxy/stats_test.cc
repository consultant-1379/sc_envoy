#include <string>

#include "source/extensions/filters/http/eric_proxy/stats.h"

#include "test/mocks/stats/mocks.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

TEST(EricProxyStats, ScreeningStatsString) {
  Stats::IsolatedStoreImpl store;
  Stats::Scope& scope{*store.rootScope()};
  auto build_screening_counter_string =
      [&scope](std::shared_ptr<EricProxyFilterConfig> config, const std::string& fetch_prefix, const std::string& sc_name, const std::string& sr_name
               /*const std::string& counter_name*/) -> std::string {
    EricProxyStats stats(config, scope, fetch_prefix);
    Stats::Counter& counter = stats.buildScreeningCounter(sc_name, sr_name, stats.rejectIn()); //(eankokt) todo: parameterize counter name
    return counter.name();
  };

  {
    std::shared_ptr<EricProxyFilterConfig> config = nullptr;
    std::string fetched_prefix = "ingress.n8e.West1.g3p.ingress";
    std::string sc_name = "Case1";
    std::string sr_name = "Rule1";
    std::string screening_stat_string =
        build_screening_counter_string(config, fetched_prefix, sc_name, sr_name);
    std::string expected_stat_string =
        "http.eric_proxy.n8e.West1.s8c3.Case1.s8r3.Rule1.ms_reject_message_in_req_total";
    EXPECT_EQ(expected_stat_string, screening_stat_string);
  }
}

TEST(EricProxyStats, NfInstanceExtraction) {
  Stats::IsolatedStoreImpl store;
  Stats::Scope& scope{*store.rootScope()};
  auto extract_nfinstance = [&scope](std::shared_ptr<EricProxyFilterConfig> config, const std::string& fetched_prefix) -> const std::string {
    EricProxyStats stats(config, scope, fetched_prefix);
    return stats.extractNfInstance();
  };

  {
    std::shared_ptr<EricProxyFilterConfig> config = nullptr;
    std::string fetched_prefix = "ingress.n8e.West1.g3p.ingress";
    std::string extracted_nfinstance = extract_nfinstance(config, fetched_prefix);
    std::string expected_nfinstance_string =
        "West1";
    EXPECT_EQ(expected_nfinstance_string, extracted_nfinstance);
  }
}

} // namespace EricProxy
} // namespace Dynamo
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
