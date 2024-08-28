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

#include "benchmark/benchmark.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using json = nlohmann::basic_json<>;

using JsonOperationProtoConfig = envoy::extensions::filters::http::eric_proxy::v3::JsonOperation;

json doc = R"(
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

// class EricProxyJsonOperationsTest : public ::testing::Test {
// protected:
//   RootContext root_ctx_;
//   RunContext run_ctx_ = RunContext(&root_ctx_);
//   Http::MockStreamDecoderFilterCallbacks decoder_callbacks_;

//   void SetUp() override {
//     EXPECT_CALL(decoder_callbacks_, connection()).Times(testing::AtLeast(0));
//     EXPECT_CALL(decoder_callbacks_, streamId()).Times(testing::AtLeast(0));
//   }
// };

/**
 * ADD BENCHMARK TESTS
 *
 */

/**
 * PATH: exists
 * ELEMENT: does not exists
 *
 * EXP. RESULT:  value is added
 *
 * standard JSON Patch behaviour
 *
 **/

// TEST_F(EricProxyJsonOperationsTest, AddToJson_string_value_path_exists_element_does_not_exist) {
static void BM_AddToJson_string_value_path_exists_element_does_not_exist(benchmark::State& state) {

  RootContext root_ctx_;
  RunContext run_ctx_ = RunContext(&root_ctx_);
  Http::MockStreamDecoderFilterCallbacks decoder_callbacks_;

  EXPECT_CALL(decoder_callbacks_, connection()).Times(testing::AtLeast(0));
  EXPECT_CALL(decoder_callbacks_, streamId()).Times(testing::AtLeast(0));

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'supi_added'
  json_pointer:
    term_string: "/subscriberIdentifier_added"
  if_path_not_exists:  DO_NOTHING
  if_element_exists:  NO_ACTION
  )EOF";

  //json orig_json = orig_json_doc;
  json orig_json = doc;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

  absl::StatusOr<std::shared_ptr<json>> op_result;

  for (auto _ : state) {
    // This code gets timed
    op_result = json_operation.execute();
  }
    ASSERT_TRUE(op_result.ok());
}

BENCHMARK(BM_AddToJson_string_value_path_exists_element_does_not_exist);

// TEST_F(EricProxyJsonOperationsTest, AddToJson_string_value_path_exists_element_does_not_exist) {
static void BM_AddToJson_string_value_path_does_not_exists_create(benchmark::State& state) {

  RootContext root_ctx_;
  RunContext run_ctx_ = RunContext(&root_ctx_);
  Http::MockStreamDecoderFilterCallbacks decoder_callbacks_;

  EXPECT_CALL(decoder_callbacks_, connection()).Times(testing::AtLeast(0));
  EXPECT_CALL(decoder_callbacks_, streamId()).Times(testing::AtLeast(0));

  const std::string yaml = R"EOF(
add_to_json:    
  value:
    term_string: 'supi_added'
  json_pointer:
    term_string: "/newpath/subscriberIdentifier_added"
  if_path_not_exists:  CREATE
  if_element_exists:  NO_ACTION
  )EOF";

  //json orig_json = orig_json_doc;
  json orig_json = doc;

  JsonOperationProtoConfig json_op_config;
  TestUtility::loadFromYamlAndValidate(yaml, json_op_config);

  auto json_operation = JsonOpWrapper(json_op_config, orig_json, &decoder_callbacks_, run_ctx_);

  absl::StatusOr<std::shared_ptr<json>> op_result;

  for (auto _ : state) {
    // This code gets timed
    op_result = json_operation.execute();
  }
  //ASSERT_TRUE(op_result.ok());
  // output original and patched document
  //std::cout << std::setw(4) << op_result.value().dump() << "\n\n" << std::endl;
}

  BENCHMARK(BM_AddToJson_string_value_path_does_not_exists_create);





} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
