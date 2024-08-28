#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "test/test_common/utility.h"
#include "test/mocks/http/mocks.h"
#include "source/common/common/base64.h"
#include "source/common/common/logger.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <array>
#include <iostream>
#include <tuple>
#include "benchmark/benchmark.h"
#include "include/nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using json = nlohmann::json;

std::string json_doc_str = R"(
{
  "subscriberIdentifier": "imsi-460030700000001",
  "nfConsumerIdentification": {
    "nFName": "123e-e8b-1d3-a46-421",
    "nFIPv4Address": "192.168.0.1",
    "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
    "nFPLMNID": {
      "mcc": "311",
      "mnc": "280"
    },
    "nodeFunctionality": "SMF"
  },
  "invocationTimeStamp": "2019-03-28T14:30:50Z",
  "invocationSequenceNumber": 0,
  "multipleUnitUsage": [
    {
      "ratingGroup": 100,
      "requestedUnit": {
        "time": 123,
        "totalVolume": 211,
        "uplinkVolume": 123,
        "downlinkVolume": 1234,
        "serviceSpecificUnits": 6543
      },
      "uPFID": "123e-e8b-1d3-a46-421"
    }
  ],
  "pDUSessionChargingInformation": {
    "chargingId": 123,
    "userInformation": {
      "servedGPSI": "msisdn-77117777",
      "servedPEI": "imei-234567891098765",
      "unauthenticatedFlag": true,
      "roamerInOut": "OUT_BOUND"
    },
    "userLocationinfo": {
      "eutraLocation": {
        "tai": {
          "plmnId": {
            "mcc": "374",
            "mnc": "645"
          },
          "tac": "ab01"
        },
        "ecgi": {
          "plmnId": {
            "mcc": "374",
            "mnc": "645"
          },
          "eutraCellId": "abcAB12"
        },
        "ageOfLocationInformation": 32766,
        "ueLocationTimestamp": "2019-03-28T14:30:50Z",
        "geographicalInformation": "234556ABCDEF2345",
        "geodeticInformation": "ABCDEFAB123456789023",
        "globalNgenbId": {
          "plmnId": {
            "mcc": "374",
            "mnc": "645"
          },
          "n3IwfId": "ABCD123",
          "ngRanNodeId": "MacroNGeNB-abc92"
        }
      },
      "nrLocation": {
        "tai": {
          "plmnId": {
            "mcc": "374",
            "mnc": "645"
          },
          "tac": "ab01"
        },
        "ncgi": {
          "plmnId": {
            "mcc": "374",
            "mnc": "645"
          },
          "nrCellId": "ABCabc123"
        },
        "ageOfLocationInformation": 1,
        "ueLocationTimestamp": "2019-03-28T14:30:50Z",
        "geographicalInformation": "AB12334765498F12",
        "geodeticInformation": "AB12334765498F12ACBF",
        "globalGnbId": {
          "plmnId": {
            "mcc": "374",
            "mnc": "645"
          },
          "n3IwfId": "ABCD123",
          "ngRanNodeId": "MacroNGeNB-abc92"
        }
      },
      "n3gaLocation": {
        "n3gppTai": {
          "plmnId": {
            "mcc": "374",
            "mnc": "645"
          },
          "tac": "ab01"
        },
        "n3IwfId": "ABCD123",
        "ueIpv4Addr": "192.168.0.1",
        "ueIpv6Addr": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
        "portNumber": 1
      }
    },
    "userLocationTime": "2019-03-28T14:30:50Z",
    "uetimeZone": "+05:30",
    "pduSessionInformation": {
      "networkSlicingInfo": {
        "sNSSAI": {
          "sst": 0,
          "sd": "Aaa123"
        }
      },
      "pduSessionID": 1,
      "pduType": "IPV4",
      "sscMode": "SSC_MODE_1",
      "hPlmnId": {
        "mcc": "374",
        "mnc": "645"
      },
      "servingNodeID": [
        {
          "plmnId": {
            "mcc": "311",
            "mnc": "280"
          },
          "amfId": "ABab09"
        }
      ],
      "servingNetworkFunctionID": {
        "servingNetworkFunctionName": "SMF",
        "servingNetworkFunctionInstanceid": "SMF_Instanceid_1",
        "gUAMI": {
          "plmnId": {
            "mcc": "311",
            "mnc": "280"
          },
          "amfId": "ABab09"
        }
      },
      "ratType": "EUTRA",
      "dnnId": "DN-AAA",
      "chargingCharacteristics": "AB",
      "chargingCharacteristicsSelectionMode": "HOME_DEFAULT",
      "startTime": "2019-03-28T14:30:50Z",
      "3gppPSDataOffStatus": "ACTIVE",
      "pduAddress": {
        "pduIPv4Address": "192.168.0.1",
        "pduIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
        "pduAddressprefixlength": 0,
        "IPv4dynamicAddressFlag": true,
        "IPv6dynamicAddressFlag": false
      },
      "qoSInformation": null,
      "servingCNPlmnId": {
        "mcc": "311",
        "mnc": "280"
      }
    },
    "unitCountInactivityTimer": 125
  }
}

)";

json json_doc = json::parse(json_doc_str);

class MyLogger : public Logger::Loggable<Logger::Id::eric_proxy> {

public:
  // void log_info() { ENVOY_LOG(info, "{}", json_doc.dump()); }
  // void log_debug() { ENVOY_LOG(debug, "{}", json_doc.dump()); }
  void log_info() { ENVOY_LOG(info, "{}", "test"); }
  void log_debug() { ENVOY_LOG(debug, "{}", "test"); }
  void log_trace() { ENVOY_LOG(trace, "{}", "test"); }
};

static void BM_ReadJsonWithPointer(benchmark::State& state) {

  // Positive test: SUPI
  std::string pointer1{"/subscriberIdentifier"};

  StatusOr<std::string> result;

  for (auto _ : state) {
    // This code gets timed
    result = EricProxyFilter::readFromJsonWithPointer(json_doc_str, pointer1);
  }
  ASSERT_TRUE(result.ok());
  EXPECT_EQ(*result, "imsi-460030700000001");
}
BENCHMARK(BM_ReadJsonWithPointer);

static void BM_CreateJsonStatusOr(benchmark::State& state) {

  StatusOr<json> result;
  for (auto _ : state) {
    // This code gets timed
    result = absl::StatusOr<json>(json_doc); 
  }
  ASSERT_TRUE(result.ok());
}
BENCHMARK(BM_CreateJsonStatusOr);

static void BM_ENVOY_LOG_INFO(benchmark::State& state) {
  MyLogger logger;
  for (auto _ : state) {
    // This code gets timed
    logger.log_info();
  }
}
BENCHMARK(BM_ENVOY_LOG_INFO);

static void BM_ENVOY_LOG_DEBUG(benchmark::State& state) {
  ENVOY_SPDLOG_LEVEL(debug);
  MyLogger logger;
  for (auto _ : state) {
    // This code gets timed
    logger.log_debug();
  }
}
BENCHMARK(BM_ENVOY_LOG_DEBUG);

static void BM_ENVOY_LOG_TRACE(benchmark::State& state) {
  ENVOY_SPDLOG_LEVEL(debug);
  MyLogger logger;
  for (auto _ : state) {
    // This code gets timed
    logger.log_trace();
  }
}
BENCHMARK(BM_ENVOY_LOG_TRACE);

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
