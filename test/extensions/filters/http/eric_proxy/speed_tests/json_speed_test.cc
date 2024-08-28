#include "include/nlohmann/json.hpp"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <iostream>

#include "benchmark/benchmark.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

using json = nlohmann::json;

const json orig_doc = R"(
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

)"_json;





//TEST(EricProxyJsonTest, TestJsonPatch) {
static void BM_JsonPatchAdd(benchmark::State& state) {

    json patch = R"([{ "op": "default_op", "path": "default_path", "value": "default_value"}])"_json;


    std::string input_value = "\"supi-added\"";
     

    json json_input_value = json::parse(input_value);

    patch.at(0).at("op") = "add";
    patch.at(0).at("path") = "/subscriberIdentifier_added";
    patch.at(0).at("value") = json_input_value;

//    std::cout << "Testing patches >" << patch.dump() << std::endl;

  //  std::cout << "Testing patch >" << patch.dump() << std::endl;
  json patched_doc;  
  for (auto _ : state) {

    // This code gets timed
    // apply the patch
    patched_doc = orig_doc.patch(patch);
  }

 

  // output original and patched document
  //std::cout << std::setw(4) << doc << "\n\n" << std::setw(4) << patched_doc << std::endl;

}

BENCHMARK(BM_JsonPatchAdd);

static void BM_JsonAdd(benchmark::State& state) {

  // std::string input_value = "supi-added";
  std::string input_value = "\"supi-added\"";

  json::json_pointer jptr;
  // jptr = json::json_pointer("/a/1/c/subscriberIdentifier_added");
  jptr = json::json_pointer("/subscriberIdentifier");

  json mod_json = orig_doc;

  for (auto _ : state) {
    // This code gets timed
    if (mod_json.at(jptr) != nullptr) {
      mod_json.at(jptr) = json::parse(input_value);
    }
  }

  // output original and patched document
  // std::cout << std::setw(4) << doc << "\n\n" << std::endl;
}
BENCHMARK(BM_JsonAdd);

static void BM_JsonDump(benchmark::State& state) {

  for (auto _ : state) {
    // This code gets timed
    orig_doc.dump();
  }

}
BENCHMARK(BM_JsonDump);


static void BM_JsonParse(benchmark::State& state) {

  std::string doc_str = orig_doc.dump();
 
  json jdoc;
  for (auto _ : state) {
    // This code gets timed
    jdoc = json::parse(doc_str);
  }

}
BENCHMARK(BM_JsonParse);

static void BM_JsonReadWithPointer(benchmark::State& state) {

  json element;
  json::json_pointer jptr = json::json_pointer("/subscriberIdentifier");

  for (auto _ : state) {
    // This code gets timed
    element = orig_doc.at(jptr);
  }
  ASSERT_EQ(element, "imsi-460030700000001");
}
BENCHMARK(BM_JsonReadWithPointer);

static void BM_JsonCreateJsonPointer(benchmark::State& state) {

  for (auto _ : state) {
    // This code gets timed
    json::json_pointer jptr = json::json_pointer("/subscriberIdentifier");
  }
}

BENCHMARK(BM_JsonCreateJsonPointer);
static void BM_JsonFlatten(benchmark::State& state) {

  std::string doc_str = orig_doc.dump();
  json jdoc;
  for (auto _ : state) {
    // This code gets timed
    jdoc = orig_doc.flatten();
  }

}
BENCHMARK(BM_JsonFlatten);

static void BM_JsonUnflatten(benchmark::State& state) {

  std::string doc_str = orig_doc.dump();
  json jflat, junflat;
  
  jflat = orig_doc.flatten();
  for (auto _ : state) {
    // This code gets timed
    jflat.unflatten();
  }

}
BENCHMARK(BM_JsonUnflatten);

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
