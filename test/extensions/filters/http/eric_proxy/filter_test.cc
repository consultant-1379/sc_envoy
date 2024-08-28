#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/extensions/filters/http/eric_proxy/tfqdn_codec.h"
#include "test/test_common/utility.h"
#include "test/mocks/http/mocks.h"
#include "source/common/common/base64.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <array>
#include <iostream>
#include <tuple>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

std::string nrf_discovery_result{R"(
{
    "validityPeriod": 60,
    "nfInstances": [{
        "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
        "nfInstanceName": "nfInstanceName_1",
        "nfType": "AUSF",
        "nfServices": [{
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "fqdn": "FQDN.example1.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP",
                "port": 9091
            }]
        }]
    }, {
        "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce101",
        "nfInstanceName": "nfInstanceName_2",
        "nfType": "AUSF",
        "nfServices": [{
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "fqdn": "FQDN1.example2.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP",
                "port": 9092
            }]
          }, {
            "serviceInstanceId": null,
            "serviceName": "nausf-auth",
            "versions": [],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "fqdn": "FQDN2.example2.com",
            "ipEndPoints": [{
                "ipv4Address": "10.11.12.253",
                "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
                "transport": "TCP",
                "port": 9093
            }]
        }]
    }],
    "searchId": null,
    "numNfInstComplete": null,
    "preferredSearch": null,
    "nrfSupportedFeatures": "nausf-auth"
}
  )"};

std::string nlf_lookup_result{R"(
{
  "validityPeriod": 60,
  "nfInstances": [
    {
      "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
      "nfInstanceName": "nfInstanceName_1",
      "nfType": "AUSF",
      "fqdn": "FQDN_1.example.com",
      "priority": 1,
      "capacity": 60000,
      "nfSetIdList": ["setA"],
      "nfServices": [
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce100",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "FQDN_1_1.example.com",
          "priority": 1,
          "capacity": 60000,
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9091
            }
          ]
        },
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce101",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "FQDN_1_2.example.com",
          "priority": 2,
          "capacity": 60000,
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9092
            }
          ]
        }
      ]
    },
    {
      "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce101",
      "nfInstanceName": "nfInstanceName_2",
      "nfType": "AUSF",
      "fqdn": "FQDN_2.example.com",
      "priority": 1,
      "capacity": 60000,
      "nfSetIdList": ["setB"],
      "nfServices": [
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce102",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "FQDN_2_1.example.com",
          "priority": 3,
          "capacity": 60000,
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9093
            }
          ]
        },
        {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce103",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "FQDN_2_2.example.com",
          "priority": 4,
          "capacity": 60000,
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9094
            },
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9095
            }
          ]
        }
      ]
    }
  ],
  "searchId": null,
  "numNfInstComplete": null,
  "preferredSearch": null,
  "nrfSupportedFeatures": "nausf-auth"
}
)"};

std::string nlf_lookup_result_nfServiceList{R"(
{
  "validityPeriod": 60,
  "nfInstances": [
    {
      "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce100",
      "nfInstanceName": "nfInstanceName_1",
      "nfType": "AUSF",
      "fqdn": "FQDN_1.example.com",
      "priority": 1,
      "capacity": 60000,
      "nfSetIdList": ["setA"],
      "nfServiceList": {
        "3ec8ac0b-265e-4165-86e9-e0735e6ce100": {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce100",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "FQDN_1_1.example.com",
          "priority": 1,
          "capacity": 60000,
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9091
            }
          ]
        },
        "3ec8ac0b-265e-4165-86e9-e0735e6ce101": {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce101",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "FQDN_1_2.example.com",
          "priority": 2,
          "capacity": 60000,
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9092
            }
          ]
        }
      }
    },
    {
      "nfInstanceId": "2ec8ac0b-265e-4165-86e9-e0735e6ce101",
      "nfInstanceName": "nfInstanceName_2",
      "nfType": "AUSF",
      "fqdn": "FQDN_2.example.com",
      "priority": 1,
      "capacity": 60000,
      "nfSetIdList": ["setB"],
      "nfServiceList": {
        "3ec8ac0b-265e-4165-86e9-e0735e6ce102": {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce102",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "FQDN_2_1.example.com",
          "priority": 3,
          "capacity": 60000,
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9093
            }
          ]
        },
        "3ec8ac0b-265e-4165-86e9-e0735e6ce103": {
          "serviceInstanceId": "3ec8ac0b-265e-4165-86e9-e0735e6ce103",
          "serviceName": "nausf-auth",
          "versions": [],
          "scheme": "https",
          "fqdn": "FQDN_2_2.example.com",
          "priority": 4,
          "capacity": 60000,
          "ipEndPoints": [
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9094
            },
            {
              "ipv4Address": "10.11.12.253",
              "ipv6Address": "2001:1b70:8230:5501:4401:3301:2201:1101",
              "transport": "TCP",
              "port": 9095
            }
          ]
        }
      }
    }
  ],
  "searchId": null,
  "numNfInstComplete": null,
  "preferredSearch": null,
  "nrfSupportedFeatures": "nausf-auth"
}
)"};

// Test 3gpp-Sbi-target-apiHost extraction of the host part
TEST(EricProxyFilterTest, TestHostPart) {
  std::array<std::tuple<std::string, std::string, bool>, 29> patterns{
      std::make_tuple("1.2.3.4", "1.2.3.4:80", false),
      std::make_tuple("https://1.2.3.4", "1.2.3.4:443", true),
      std::make_tuple("1.2.3.4/a/b/", "1.2.3.4:80", false),
      std::make_tuple("http://1.2.3.4", "1.2.3.4:80", false),
      std::make_tuple("1.2.3.4:0", "1.2.3.4:0", false),
      std::make_tuple("1.2.3.4:0/path", "1.2.3.4:0", false),
      std::make_tuple("https://1.2.3.4:0", "1.2.3.4:0", true),
      std::make_tuple("https://1.2.3.4:0/path", "1.2.3.4:0", true),
      std::make_tuple("https://1.2.3.4/path", "1.2.3.4:443", true),
      std::make_tuple("0.0.0.0:4000", "0.0.0.0:4000", false),
      std::make_tuple("127.0.0.1:0", "127.0.0.1:0", false),
      std::make_tuple("[::]:0", "[::]:0", false),
      std::make_tuple("http://[::]:0", "[::]:0", false),
      std::make_tuple("http://[::]:0/abc", "[::]:0", false),
      std::make_tuple("[::]", "[::]:80", false),
      std::make_tuple("[1::2:3]:0", "[1::2:3]:0", false),
      std::make_tuple("[a::1]:80", "[a::1]:80", false),
      std::make_tuple("[a:b:c:d::]:0", "[a:b:c:d::]:0", false),
      std::make_tuple("example.com", "example.com:80", false),
      std::make_tuple("https://example.com", "example.com:443", true),
      std::make_tuple("example.com:8000", "example.com:8000", false),
      std::make_tuple("http://example.com:8000", "example.com:8000", false),
      std::make_tuple("https://example.com:8000", "example.com:8000", true),
      std::make_tuple("http://example.com:8000/path/to/endpoint?a=b&c=d", "example.com:8000",
                      false),
      std::make_tuple("https://example.com:8000/path/to/endpoint?a=b&c=d", "example.com:8000",
                      true),
      std::make_tuple("example.com:abc", "example.com:abc", false),
      std::make_tuple("localhost:10000", "localhost:10000", false),
      std::make_tuple("localhost", "localhost:80", false),
      std::make_tuple("", "", false)};
  for (const auto& pattern : patterns) {
    std::cout << "Testing >" << std::get<0>(pattern) << "<" << std::endl;
    const auto& host_header = std::get<0>(pattern);
    const auto& expected_host = std::get<1>(pattern);
    const auto& is_https = std::get<2>(pattern);
    Http::TestRequestHeaderMapImpl dummy_headers;
    EXPECT_EQ(EricProxyFilter::extractHostAndPort(host_header, dummy_headers), expected_host);
    EXPECT_EQ(dummy_headers.has("x-scheme-https"), is_https);
  }
}

TEST(EricProxyFilterTest, TestReadJsonWithPointerMalformed1) {
  // Malformed str_body: last closing } is missing
  std::string str_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
            "nFName": "123e-e8b-1d3-a46-421",
            "nFIPv4Address": "192.168.0.1",
            "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
            "nFPLMNID": {
                "mcc": "311",
                "mnc": "280"
            },
            "nodeFunctionality": "SMF"
        }
      )"};
  std::string pointer{"/subscriberIdentifier"};
  auto result = EricProxyFilter::readFromJsonWithPointer(str_body, pointer);
  EXPECT_FALSE(result.ok());
  EXPECT_TRUE(absl::IsInvalidArgument(result.status()));
}

TEST(EricProxyFilterTest, TestReadJsonWithPointerMalformed2) {
  // Malformed str_body: second key has no quotes at the beginning
  std::string str_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        nfConsumerIdentification": {
            "nFName": "123e-e8b-1d3-a46-421",
            "nFIPv4Address": "192.168.0.1",
            "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
            "nFPLMNID": {
                "mcc": "311",
                "mnc": "280"
            },
            "nodeFunctionality": "SMF"
        }
      )"};
  std::string pointer{"/subscriberIdentifier"};
  auto result = EricProxyFilter::readFromJsonWithPointer(str_body, pointer);
  EXPECT_FALSE(result.ok());
  EXPECT_TRUE(absl::IsInvalidArgument(result.status()));
}

TEST(EricProxyFilterTest, TestReadJsonWithPointer) {
  std::string str_body{R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
            "nFName": "123e-e8b-1d3-a46-421",
            "nFIPv4Address": "192.168.0.1",
            "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
            "nFPLMNID": {
                "mcc": "311",
                "mnc": 280
            },
            "nodeFunctionality": "SMF"
        }
      }
      )"};
  // Positive test: SUPI
  std::string pointer1{"/subscriberIdentifier"};
  auto result1 = EricProxyFilter::readFromJsonWithPointer(str_body, pointer1);
  EXPECT_TRUE(result1.ok());
  EXPECT_EQ(*result1, "imsi-460001357924610");

  // Positive test: JSON pointer with several levels
  std::string pointer4{"/nfConsumerIdentification/nFPLMNID/mcc"};
  auto result4 = EricProxyFilter::readFromJsonWithPointer(str_body, pointer4);
  EXPECT_TRUE(result4.ok());
  EXPECT_EQ(*result4, "311");

  // Positive test: convert number to string
  std::string pointer5{"/nfConsumerIdentification/nFPLMNID/mnc"};
  auto result5 = EricProxyFilter::readFromJsonWithPointer(str_body, pointer5);
  EXPECT_TRUE(result5.ok());
  EXPECT_EQ(*result5, "280"_json);

  // Positive test: get whole object as string, compare with expected
  std::string pointer6{"/nfConsumerIdentification/nFPLMNID"};
  auto result6 = EricProxyFilter::readFromJsonWithPointer(str_body, pointer6);
  EXPECT_TRUE(result6.ok());
  EXPECT_EQ(*result6, R"({"mcc":"311","mnc":280})"_json);

  // Positive test: get whole object as string
  std::string pointer3{"/nfConsumerIdentification"};
  EXPECT_TRUE(EricProxyFilter::readFromJsonWithPointer(str_body, pointer3).ok());

  // Negative test: query for non-existing element -> null value
  std::string pointer2{"/doesNotExist"};
  auto result2 = EricProxyFilter::readFromJsonWithPointer(str_body, pointer2);
  EXPECT_TRUE(result2.ok());
  EXPECT_EQ(*result2, Json()); // = json null

  // Negative test: query for non-existing element -> null value
  std::string pointer7{"/nfConsumerIdentification/*/fqdn"};
  auto result7 = EricProxyFilter::readFromJsonWithPointer(str_body, pointer7);
  EXPECT_TRUE(result7.ok());
  EXPECT_EQ(*result7, Json()); // = json null
}

//------------------------------------------------------------------------
// Body Modification

class EricProxyFilterBodyModTest : public ::testing::Test {
protected:
  // modifyJson calls ENVOY_STREAM_LOG, so we need to mock decoder_callbacks
  Http::MockStreamDecoderFilterCallbacks decoder_callbacks_;

  void SetUp() override {
    EXPECT_CALL(decoder_callbacks_, connection()).Times(testing::AtLeast(0));
    EXPECT_CALL(decoder_callbacks_, streamId()).Times(testing::AtLeast(0));
  }
};
// Map single string to another string
TEST_F(EricProxyFilterBodyModTest, TestModifyBodyAppendToSingleString) {
  std::string str_body{R"(
{
  "last": "smith",
  "name": "joe",
  "age": 43,
  "married": true,
  "hobbies": ["riding", "swimming", "reading", "chilling"],
  "level1": {"a": "b", "level2": ["k", "l", "m"], "c": "d"},
  "l1": [{"k": "K", "l3": ["L", "M"], "c": "d"}, {"x": "X", "l3": ["Y", "Z"]}],
  "partly": [{"A":"AA", "B":"BB"}, {"A":"aa", "C":"cc"}]
}
  )"};
  {
    std::vector<std::string> targets{"/name"};
    auto json_body_sp = std::make_shared<Json>(Json::parse(str_body));
    auto mod_operation = EricProxyFilter::modifyJson(&decoder_callbacks_, json_body_sp, targets,
                                                     [](auto& str) { return str + "achim"; });
    EXPECT_TRUE(mod_operation.ok());
    // printf("#### Body:: %s\n", body.c_str());
    auto result = EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(), targets.at(0));
    EXPECT_TRUE(result.ok());
    EXPECT_EQ(*result, "joeachim");
  }

  {
    std::vector<std::string> targets{"/name", "/hobbies/2"};
    auto json_body_sp = std::make_shared<Json>(Json::parse(str_body));
    auto mod_operation = EricProxyFilter::modifyJson(&decoder_callbacks_, json_body_sp, targets,
                                                     [](auto& str) { return str + "achim"; });
    EXPECT_TRUE(mod_operation.ok());
    // printf("#### Body:: %s\n", body.c_str());
    {
      auto result = EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(), targets.at(0));
      EXPECT_TRUE(result.ok());
      EXPECT_EQ(*result, "joeachim");
    }
    {
      auto result = EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(), targets.at(1));
      EXPECT_TRUE(result.ok());
      EXPECT_EQ(*result, "readingachim");
    }
  }
  {
    std::vector<std::string> targets{"/partly/*/A", "/partly/*/B", "/partly/*/C"};
    auto json_body_sp = std::make_shared<Json>(Json::parse(str_body));
    auto mod_operation = EricProxyFilter::modifyJson(&decoder_callbacks_, json_body_sp, targets,
                                                     [](auto& str) { return str + "_mod"; });
    EXPECT_TRUE(mod_operation.ok());
    // printf("#### Body:: %s\n", body.c_str());
    {
      auto result = EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(),
                                                             std::string("/partly/0/A"));
      EXPECT_TRUE(result.ok());
      EXPECT_EQ(*result, "AA_mod");
    }
    {
      auto result = EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(),
                                                             std::string("/partly/0/B"));
      EXPECT_TRUE(result.ok());
      EXPECT_EQ(*result, "BB_mod");
    }
    {
      auto result = EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(),
                                                             std::string("/partly/1/A"));
      EXPECT_TRUE(result.ok());
      EXPECT_EQ(*result, "aa_mod");
    }
    {
      auto result = EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(),
                                                             std::string("/partly/1/C"));
      EXPECT_TRUE(result.ok());
      EXPECT_EQ(*result, "cc_mod");
    }
  }

  {
    std::vector<std::string> targets{"/hobbies/*"};
    auto json_body_sp = std::make_shared<Json>(Json::parse(str_body));
    auto mod_operation = EricProxyFilter::modifyJson(&decoder_callbacks_, json_body_sp, targets,
                                                     [](auto& str) { return str + "_hobby"; });
    EXPECT_TRUE(mod_operation.ok());
    // printf("#### Body: hobbies: %s\n", body.c_str());
    {
      auto result =
          EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(), std::string("/hobbies/0"));
      EXPECT_TRUE(result.ok());
      EXPECT_EQ(*result, "riding_hobby");
    }
    {
      auto result =
          EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(), std::string("/hobbies/3"));
      EXPECT_TRUE(result.ok());
      EXPECT_EQ(*result, "chilling_hobby");
    }
  }
  {
    std::vector<std::string> targets{"/level1/level2/*"};
    auto json_body_sp = std::make_shared<Json>(Json::parse(str_body));
    auto mod_operation = EricProxyFilter::modifyJson(&decoder_callbacks_, json_body_sp, targets,
                                                     [](auto& str) { return str + "_mod"; });
    EXPECT_TRUE(mod_operation.ok());
    // printf("#### Body: level1/level2: %s\n", body.c_str());
    {
      auto result = EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(),
                                                             std::string("/level1/level2/0"));
      EXPECT_TRUE(result.ok());
      EXPECT_EQ(*result, "k_mod");
    }
    {
      auto result = EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(),
                                                             std::string("/level1/level2/1"));
      EXPECT_TRUE(result.ok());
      EXPECT_EQ(*result, "l_mod");
    }
    {
      auto result = EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(),
                                                             std::string("/level1/level2/2"));
      EXPECT_TRUE(result.ok());
      EXPECT_EQ(*result, "m_mod");
    }
  }
  {
    std::vector<std::string> targets{"/l1/*/l3/*"};
    auto json_body_sp = std::make_shared<Json>(Json::parse(str_body));
    auto mod_operation = EricProxyFilter::modifyJson(&decoder_callbacks_, json_body_sp, targets,
                                                     [](auto& str) { return str + "_ext"; });
    EXPECT_TRUE(mod_operation.ok());
    // printf("#### Body: l1/*/l3/*: %s\n", body.c_str());
    {
      {
        auto result = EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(),
                                                               std::string("/l1/0/l3/0"));
        EXPECT_TRUE(result.ok());
        EXPECT_EQ(*result, "L_ext");
      }
      {
        auto result = EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(),
                                                               std::string("/l1/0/l3/1"));
        EXPECT_TRUE(result.ok());
        EXPECT_EQ(*result, "M_ext");
      }
      {
        auto result = EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(),
                                                               std::string("/l1/1/l3/1"));
        EXPECT_TRUE(result.ok());
        EXPECT_EQ(*result, "Z_ext");
      }
      { // unchanged
        auto result =
            EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(), std::string("/l1/0/k"));
        EXPECT_TRUE(result.ok());
        EXPECT_EQ(*result, "K");
      }
    }
  }
}

// Map single string with a key-value table
TEST_F(EricProxyFilterBodyModTest, TestModifyBodyKvtEncSingleString) {
  // JSON-Pointer:             /nfInstances/nfServices/fqdn
  // Extended JSON-Pointer *:  /nfInstances/*/nfServices/*/fqdn
  //
  // Results:                  /nfInstances/0/nfServices/0/fqdn  -> FQDN.example1.com
  //                           /nfInstances/1/nfServices/0/fqdn  -> FQDN1.example2.com
  //                           /nfInstances/1/nfServices/1/fqdn  -> FQDN2.example2.com
  auto str_body = nrf_discovery_result;
  auto json_body_sp = std::make_shared<Json>(Json::parse(str_body));
  std::vector<std::string> targets{"/nfInstances/*/nfServices/*/fqdn"};
  auto mod_operation = EricProxyFilter::modifyJson(&decoder_callbacks_, json_body_sp, targets,
                                                   [](auto& str) { return str + "_converted"; });
  EXPECT_TRUE(mod_operation.ok());
  {
    auto result = EricProxyFilter::readFromJsonWithPointer(
        json_body_sp->dump(), std::string("/nfInstances/0/nfServices/0/fqdn"));
    EXPECT_TRUE(result.ok());
    EXPECT_EQ(*result, "FQDN.example1.com_converted");
  }
  {
    auto result = EricProxyFilter::readFromJsonWithPointer(
        json_body_sp->dump(), std::string("/nfInstances/1/nfServices/0/fqdn"));
    EXPECT_TRUE(result.ok());
    EXPECT_EQ(*result, "FQDN1.example2.com_converted");
  }
  {
    auto result = EricProxyFilter::readFromJsonWithPointer(
        json_body_sp->dump(), std::string("/nfInstances/1/nfServices/1/fqdn"));
    EXPECT_TRUE(result.ok());
    EXPECT_EQ(*result, "FQDN2.example2.com_converted");
  }
}

#ifdef FINISHED
// Map array of strings with a key-value table
TEST(EricProxyFilterTest, TestModifyBodyKvtEncArrayOfStrings) {}
#endif

// Base64-encode single string
TEST_F(EricProxyFilterBodyModTest, TestModifyBodyB64EncSingleString) {
  auto str_body = nrf_discovery_result;
  auto json_body_sp = std::make_shared<Json>(Json::parse(str_body));
  std::vector<std::string> targets{"/nrfSupportedFeatures"};
  auto mod_operation =
      EricProxyFilter::modifyJson(&decoder_callbacks_, json_body_sp, targets, [](auto& str) {
        return Base64::encode(str.c_str(), str.length(), false);
      });
  EXPECT_TRUE(mod_operation.ok());
  {
    auto result = EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(), targets.at(0));
    EXPECT_TRUE(result.ok());
    EXPECT_EQ(*result, "bmF1c2YtYXV0aA");
  }
}

// Base64-encode array of strings
TEST_F(EricProxyFilterBodyModTest, TestModifyBodyB64EncArrayOfStrings) {
  auto str_body = nrf_discovery_result;
  auto json_body_sp = std::make_shared<Json>(Json::parse(str_body));
  std::vector<std::string> targets{"/nfInstances/*/nfServices/*/fqdn"};
  auto mod_operation =
      EricProxyFilter::modifyJson(&decoder_callbacks_, json_body_sp, targets, [](auto& str) {
        return Base64::encode(str.c_str(), str.length(), false);
      });
  EXPECT_TRUE(mod_operation.ok());
  {
    auto result = EricProxyFilter::readFromJsonWithPointer(
        json_body_sp->dump(), std::string("/nfInstances/0/nfServices/0/fqdn"));
    EXPECT_TRUE(result.ok());
    EXPECT_EQ(*result, "RlFETi5leGFtcGxlMS5jb20");
  }
  {
    auto result = EricProxyFilter::readFromJsonWithPointer(
        json_body_sp->dump(), std::string("/nfInstances/1/nfServices/0/fqdn"));
    EXPECT_TRUE(result.ok());
    EXPECT_EQ(*result, "RlFETjEuZXhhbXBsZTIuY29t");
  }
  {
    auto result = EricProxyFilter::readFromJsonWithPointer(
        json_body_sp->dump(), std::string("/nfInstances/1/nfServices/1/fqdn"));
    EXPECT_TRUE(result.ok());
    EXPECT_EQ(*result, "RlFETjIuZXhhbXBsZTIuY29t");
  }
}

// TFQDN-encode single string
TEST_F(EricProxyFilterBodyModTest, TestModifyBodyTFQDNEncSingleString) {
  auto str_body = nrf_discovery_result;
  auto json_body_sp = std::make_shared<Json>(Json::parse(str_body));
  std::vector<std::string> targets{"/nrfSupportedFeatures"};
  auto mod_operation =
      EricProxyFilter::modifyJson(&decoder_callbacks_, json_body_sp, targets,
                                  [](auto& str) { return TfqdnCodec::encode(str); });
  EXPECT_TRUE(mod_operation.ok());
  {
    auto result = EricProxyFilter::readFromJsonWithPointer(json_body_sp->dump(), targets.at(0));
    EXPECT_TRUE(result.ok());
    EXPECT_EQ(*result, "nQ9-auth");
  }
}

// TFQDN-encode an array of strings
TEST_F(EricProxyFilterBodyModTest, TestModifyBodyTFQDNEncArrayOfStrings) {
  auto str_body = nrf_discovery_result;
  auto json_body_sp = std::make_shared<Json>(Json::parse(str_body));
  std::vector<std::string> targets{"/nfInstances/*/nfServices/*/fqdn"};
  auto mod_operation =
      EricProxyFilter::modifyJson(&decoder_callbacks_, json_body_sp, targets,
                                  [](auto& str) { return TfqdnCodec::encode(str); });
  EXPECT_TRUE(mod_operation.ok());
  {
    auto result = EricProxyFilter::readFromJsonWithPointer(
        json_body_sp->dump(), std::string("/nfInstances/0/nfServices/0/fqdn"));
    EXPECT_TRUE(result.ok());
    EXPECT_EQ(*result, "fZqdnvexample1vcom");
  }
  {
    auto result = EricProxyFilter::readFromJsonWithPointer(
        json_body_sp->dump(), std::string("/nfInstances/1/nfServices/0/fqdn"));
    EXPECT_TRUE(result.ok());
    EXPECT_EQ(*result, "fZqdn1vexample2vcom");
  }
  {
    auto result = EricProxyFilter::readFromJsonWithPointer(
        json_body_sp->dump(), std::string("/nfInstances/1/nfServices/1/fqdn"));
    EXPECT_TRUE(result.ok());
    EXPECT_EQ(*result, "fZqdn2vexample2vcom");
  }
}

//------------------------------------------------------------------------
// Test authorityIsOnlyOwnFqdn
TEST(EricProxyFilterTest, TestAuthorityIsOnlyOwnFqdn) {
  std::array<std::tuple<std::string, std::string, bool>, 11> inputs{
      std::make_tuple("sepp.ericsson.se", "sepp.ericsson.se", true),
      std::make_tuple("sepp.ericsson.se", "SEPP.ERICSSON.se", true),
      std::make_tuple("sepp.ERICSSON.SE", "sepp.ericsson.se", true),
      std::make_tuple("sepp.ericsson.se:8080", "sepp.ericsson.se", true),
      std::make_tuple("10.20.30.40:8080", "10.20.30.40", true),
      std::make_tuple("[fe80:20:30ab::deaf]:8080", "[fe80:20:30ab::deaf]", true),
      std::make_tuple("[fe80:20:30ab::deaf]:8080", "fe80:20:30ab::deaf", true),
      std::make_tuple("[fe80:20:30ab::deaf]", "fe80:20:30ab::deaf", true),
      std::make_tuple("fe80:20:30ab::deaf", "fe80:20:30ab::deaf", true),
      std::make_tuple("depp.ericsson.se", "sepp.ericsson.se", false),
      std::make_tuple("sepp.ericsson.se", "sepp.ericsson.se.com", false),
  };
  for (const auto& input : inputs) {
    const auto& authority = std::get<0>(input);
    const auto& own_fqdn = std::get<1>(input);
    const auto& expected = std::get<2>(input);
    std::cout << "Testing >" << authority << "< vs. >" << own_fqdn << "<" << std::endl;
    EXPECT_EQ(EricProxyFilter::authorityIsOnlyOwnFqdn(authority, own_fqdn), expected);
  }
}

//------------------------------------------------------------------------
// Test replaceHostPortInUrlFromOtherUrl()
// Successfully replace the host and port in full and correct urls:
TEST(EricProxyFilterTest, TestReplaceHostPortInUrlFromOtherUrl1) {
  std::string source{"https://abc.de.com:80/path/to/resource?param1&param2"};
  std::string target{"correct.new.host:9000"};
  auto result = EricProxyFilter::replaceHostPortInUrl(source, target, "");
  EXPECT_EQ(result, "https://correct.new.host:9000/path/to/resource?param1&param2");
}

// Successfully replace host&port in urls without path and query string and port:
TEST(EricProxyFilterTest, TestReplaceHostPortInUrlFromOtherUrl2) {
  std::string source{"https://abc.de.com"};
  std::string target{"correct.new.host:9000"};
  auto result = EricProxyFilter::replaceHostPortInUrl(source, target, "");
  // The trailing slash is automatically added by envoy and is ok:
  EXPECT_EQ(result, "https://correct.new.host:9000/");
}

// Unsuccessfully replace host+port: the source url is not correct:
// it lacks the schema.  Expected value is the unmodified source url.
TEST(EricProxyFilterTest, TestReplaceHostPortInUrlFromOtherUrl3) {
  std::string source{"abc.de.com:80/path/to/resource?param1&param2"}; // no schema!
  std::string target{"correct.new.host/other/path"};
  auto result = EricProxyFilter::replaceHostPortInUrl(source, target, "");
  EXPECT_EQ(result, "abc.de.com:80/path/to/resource?param1&param2");
}

//========================================================================
// Option D
//========================================================================

//-----------------------Test selectNfOnPriority()------------------------

// NF services have different priorities but same capacities
TEST(EricProxyFilterTest, TestSelectNfOnPriority1) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 2;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 3;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 4;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 60000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value(), NfInstance({"FQDN_1_1.example.com:9091", "setA",
                                        "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}));
}

// NF services have same priorities but different capacities
TEST(EricProxyFilterTest, TestSelectNfOnPriority2) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 1;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  NfInstance c{"FQDN_1_1.example.com:9091", "setA", "2ec8ac0b-265e-4165-86e9-e0735e6ce100"};

  EXPECT_TRUE(result.value() == NfInstance({"FQDN_1_1.example.com:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_2_1.example.com:9093", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have different priorities and capacities
TEST(EricProxyFilterTest, TestSelectNfOnPriority3) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());

  EXPECT_TRUE(result.value() == NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have different priorities and capacities
// where one NF service does not contain priority and
// there is no priority on corresponding NF instance
// level as well
TEST(EricProxyFilterTest, TestSelectNfOnPriority4) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).erase("priority");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).erase("priority");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have different priorities and capacities
// where one NF service does not contain priority but
// there is a priority on corresponding NF instance
// level
TEST(EricProxyFilterTest, TestSelectNfOnPriority5) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).erase("priority");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_2_1.example.com:9093", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have different priorities and capacities
// where one NF service does not contain capacity and
// there is no capacity on corresponding NF instance
// level as well
TEST(EricProxyFilterTest, TestSelectNfOnPriority6) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).erase("capacity");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).erase("capacity");
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have different priorities and capacities
// where one NF service does not contain capacity but
// there is a capacity on corresponding NF instance
// level
TEST(EricProxyFilterTest, TestSelectNfOnPriority7) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).erase("capacity");
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_2_1.example.com:9093", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have different priorities and capacities
// where first NF service does not contain priority and
// there is no priority on corresponding NF instance
// level as well
TEST(EricProxyFilterTest, TestSelectNfOnPriority8) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("priority");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("priority");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have different priorities and capacities
// where first NF service does not contain priority but
// there is a priority on corresponding NF instance
// level
TEST(EricProxyFilterTest, TestSelectNfOnPriority9) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("priority");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"FQDN_1_1.example.com:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have different priorities and capacities
// where first NF service does not contain capacity and
// there is no capacity on corresponding NF instance
// level as well
TEST(EricProxyFilterTest, TestSelectNfOnPriority10) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("capacity");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("capacity");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have different priorities and capacities
// where first NF service does not contain capacity but
// there is a capacity on corresponding NF instance
// level
TEST(EricProxyFilterTest, TestSelectNfOnPriority11) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("capacity");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"FQDN_1_1.example.com:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have no priorities but different capacities
// and there are no priorities on corresponding NF instance
// levels as well
TEST(EricProxyFilterTest, TestSelectNfOnPriority12) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("priority");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("priority");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).erase("priority");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).erase("priority");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).erase("priority");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).erase("priority");
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"FQDN_1_1.example.com:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_2_1.example.com:9093", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have no priorities but different capacities
// but there are priorities on corresponding NF instance
// levels
TEST(EricProxyFilterTest, TestSelectNfOnPriority13) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("priority");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).erase("priority");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("priority") = 1;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).erase("priority");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).erase("priority");
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"FQDN_1_1.example.com:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_2_1.example.com:9093", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have same priorities but no capacities
// and there are no capacities on corresponding NF
// instance levels as well
TEST(EricProxyFilterTest, TestSelectNfOnPriority14) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("capacity");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("capacity");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).erase("capacity");
  json_body.at("nfInstances").at(1).erase("capacity");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).erase("capacity");
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 1;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).erase("capacity");
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"FQDN_1_1.example.com:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_2_1.example.com:9093", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have same priorities but no capacities
// but there are capacities on corresponding NF
// instance levels
TEST(EricProxyFilterTest, TestSelectNfOnPriority15) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("capacity");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).erase("capacity");
  json_body.at("nfInstances").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).erase("capacity");
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 1;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).erase("capacity");
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"FQDN_1_1.example.com:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_2_1.example.com:9093", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have no priorities and no capacities
// and there are no priorities and capacities on
// corresponding NF instance levels as well
TEST(EricProxyFilterTest, TestSelectNfOnPriority16) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("priority");
  json_body.at("nfInstances").at(0).erase("capacity");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("priority");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("capacity");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).erase("priority");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).erase("capacity");
  json_body.at("nfInstances").at(1).erase("priority");
  json_body.at("nfInstances").at(1).erase("capacity");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).erase("priority");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).erase("capacity");
  json_body.at("nfInstances").at(1).at("nfServices").at(1).erase("priority");
  json_body.at("nfInstances").at(1).at("nfServices").at(1).erase("capacity");
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"FQDN_1_1.example.com:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"FQDN_2_1.example.com:9093", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2_2.example.com:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have different priorities but same capacities
// where FQDN is missing from highest priority NF service
// and there is no FQDN on corresponding NF instance level
// as well. Therefore, IPv4 address in IP endpoint should
// be present instead of FQDN in preferred host.
TEST(EricProxyFilterTest, TestSelectNfOnPriority17) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 2;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 3;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 4;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 60000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value(),
            NfInstance({"10.11.12.253:9091", "setA", "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}));
}

// NF services have different priorities but same capacities
// where FQDN is missing from highest priority NF service
// and there is no FQDN on corresponding NF instance level
// as well. Also, there is no IPv4 address present in IP
// endpoint. Therefore, all IPv4 addresses from IPv4
// addresses list in NF instance should be considered
// as a candidate for preferred host.
TEST(EricProxyFilterTest, TestSelectNfOnPriority18) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("fqdn");
  json_body.at("nfInstances")
      .at(0)
      .push_back({"ipv4Addresses", std::vector{"10.11.12.251", "10.11.12.252"}});
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances")
      .at(0)
      .at("nfServices")
      .at(0)
      .at("ipEndPoints")
      .at(0)
      .erase("ipv4Address");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 2;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 3;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 4;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 60000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"10.11.12.251:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"10.11.12.252:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}));
}

// NF services have different priorities but same capacities
// where FQDN is missing from highest priority NF service
// and there is no FQDN on corresponding NF instance level
// as well. Also, there is no IPv4 address present neither
// in IP endpoint nor in NF instance. Therefore, the
// highest priority endpoint should be ignored and
// the FQDN of next higher priority endpoint
// should be present in preferred host.
TEST(EricProxyFilterTest, TestSelectNfOnPriority19) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances")
      .at(0)
      .at("nfServices")
      .at(0)
      .at("ipEndPoints")
      .at(0)
      .erase("ipv4Address");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 2;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 3;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 4;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 60000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value(), NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                        "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}));
}

// NF services have different priorities but same capacities
// where FQDN is missing from highest priority NF service
// and there is no FQDN on corresponding NF instance level
// as well. Therefore, IPv6 address in IP endpoint should
// be present instead of FQDN in preferred host.
TEST(EricProxyFilterTest, TestSelectNfOnPriority20) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 2;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 3;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 4;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 60000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv6);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value(), NfInstance({"[2001:1b70:8230:5501:4401:3301:2201:1101]:9091", "setA",
                                        "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}));
}

// NF services have different priorities but same capacities
// where FQDN is missing from highest priority NF service
// and there is no FQDN on corresponding NF instance level
// as well. Also, there is no IPv6 address present in IP
// endpoint. Therefore, all IPv6 addresses from IPv6
// addresses list in NF instance should be considered
// as a candidate for preferred host.
TEST(EricProxyFilterTest, TestSelectNfOnPriority21) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("fqdn");
  json_body.at("nfInstances")
      .at(0)
      .push_back({"ipv6Addresses", std::vector{"2001:1b70:8230:5501:4401:3301:2201:1102",
                                               "2001:1b70:8230:5501:4401:3301:2201:1103"}});
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances")
      .at(0)
      .at("nfServices")
      .at(0)
      .at("ipEndPoints")
      .at(0)
      .erase("ipv6Address");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 2;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 3;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 4;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 60000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv6);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"[2001:1b70:8230:5501:4401:3301:2201:1102]:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"[2001:1b70:8230:5501:4401:3301:2201:1103]:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}));
}

// NF services have different priorities but same capacities
// where FQDN is missing from highest priority NF service
// and there is no FQDN on corresponding NF instance level
// as well. Also, there is no IPv6 address present neither
// in IP endpoint nor in NF instance. Therefore, the
// highest priority endpoint should be ignored and
// the FQDN of next higher priority endpoint
// should be present in preferred host.
TEST(EricProxyFilterTest, TestSelectNfOnPriority22) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances")
      .at(0)
      .at("nfServices")
      .at(0)
      .at("ipEndPoints")
      .at(0)
      .erase("ipv6Address");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 2;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 3;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 4;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 60000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv6);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value(), NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                        "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}));
}

// NF services have different priorities but same capacities
// where FQDN is missing from highest priority NF service
// but there is a FQDN on corresponding NF instance level.
// Therefore, NF instance FQDN should be present in
// preferred host.
TEST(EricProxyFilterTest, TestSelectNfOnPriority23) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("fqdn") = "FQDN_1.example.com";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 2;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 3;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 4;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 60000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value(), NfInstance({"FQDN_1.example.com:9091", "setA",
                                        "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}));
}

// NF services have different priorities but same capacities
// where port is not defined for the endpoint and scheme
// is http for that endpoint.
TEST(EricProxyFilterTest, TestSelectNfOnPriority24) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("ipEndPoints").at(0).erase("port");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 2;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 3;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 4;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 60000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value(), NfInstance({"FQDN_1_1.example.com:80", "setA",
                                        "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}));
}

// NF services have different priorities but same capacities
// where port is not defined for the endpoint and scheme
// is https for that endpoint.
TEST(EricProxyFilterTest, TestSelectNfOnPriority25) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "https";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("ipEndPoints").at(0).erase("port");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 2;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 3;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 4;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 60000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value(), NfInstance({"FQDN_1_1.example.com:443", "setA",
                                        "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}));
}

// NF services have different priorities and capacities
// where two endpoints have same hostname. So, only
// first endpoint will be considered.
TEST(EricProxyFilterTest, TestSelectNfOnPriority26) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("ipEndPoints").at(0).erase("port");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("ipEndPoints").at(0).erase("port");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value(), NfInstance({"FQDN_2_1.example.com:9093", "setB",
                                        "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have different priorities but same capacities
// where ipEndPoints is not defined for the highest priority
// endpoint but it should be present in preferred host.
TEST(EricProxyFilterTest, TestSelectNfOnPriority27) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "https";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("ipEndPoints");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 2;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 3;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 4;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 60000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value(), NfInstance({"FQDN_1_1.example.com:443", "setA",
                                        "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}));
}

// NF services have different priorities and capacities
// where two endpoints have same hostname. So, only
// first endpoint will be considered and capacity
// is not distributed for the ignored endpoint.
TEST(EricProxyFilterTest, TestSelectNfOnPriority28) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("scheme") = "https";
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).erase("ipEndPoints");
  json_body.at("nfInstances").at(1).at("nfServices").at(1).erase("fqdn");
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("scheme") = "https";
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("ipEndPoints").at(1).erase("port");
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"FQDN_2.example.com:443", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NLF lookup result have nfServiceList.
// NF services have different priorities and capacities
// where two endpoints have same hostname. So, only
// first endpoint will be considered and capacity
// is not distributed for the ignored endpoint.
TEST(EricProxyFilterTest, TestSelectNfOnPriority29) {
  Json json_body = Json::parse(nlf_lookup_result_nfServiceList);
  json_body.at("nfInstances")
      .at(0)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce100")
      .at("priority") = 8;
  json_body.at("nfInstances")
      .at(0)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce100")
      .at("capacity") = 50000;
  json_body.at("nfInstances")
      .at(0)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce101")
      .at("priority") = 8;
  json_body.at("nfInstances")
      .at(0)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce101")
      .at("capacity") = 30000;
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce102")
      .erase("fqdn");
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce102")
      .at("scheme") = "https";
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce102")
      .at("priority") = 5;
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce102")
      .at("capacity") = 10000;
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce102")
      .erase("ipEndPoints");
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce103")
      .erase("fqdn");
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce103")
      .at("scheme") = "https";
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce103")
      .at("priority") = 5;
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce103")
      .at("capacity") = 10000;
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce103")
      .at("ipEndPoints")
      .at(1)
      .erase("port");
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"FQDN_2.example.com:443", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"FQDN_2.example.com:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have different priorities and capacities
// where ip version is dual stack, FQDN is missing from
// highest priority NF services and there is no FQDN on
// corresponding NF instance level as well. Therefore,
// both IPv4 and IPv6 addresses in IP endpoint should
// be considered as a candidate for preferred host.
TEST(EricProxyFilterTest, TestSelectNfOnPriority30) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).erase("fqdn");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).erase("fqdn");
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::DualStack);
  EXPECT_TRUE(result.ok());

  EXPECT_TRUE(result.value() == NfInstance({"10.11.12.253:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"[2001:1b70:8230:5501:4401:3301:2201:1101]:9092", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"10.11.12.253:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"[2001:1b70:8230:5501:4401:3301:2201:1101]:9094", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"10.11.12.253:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}) ||
              result.value() == NfInstance({"[2001:1b70:8230:5501:4401:3301:2201:1101]:9095", "setB",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce101"}));
}

// NF services have different priorities but same capacities
// where ip version is dual stack, FQDN is missing from
// highest priority NF service and there is no FQDN on
// corresponding NF instance level as well. Also, there
// is no IPv4 address is present in IP endpoint but IPv6
// address is present. Therefore, IPv6 address in IP endpoint
// should be present instead of FQDN in preferred host and no
// IPv4 addresses from IPv4 addresses list and no IPv4 addresses
// from IPv4 addresses list in NF instance should be considered
// as a candidate for preferred host.
TEST(EricProxyFilterTest, TestSelectNfOnPriority31) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("fqdn");
  json_body.at("nfInstances")
      .at(0)
      .push_back({"ipv4Addresses", std::vector{"10.11.12.251", "10.11.12.252"}});
  json_body.at("nfInstances")
      .at(0)
      .push_back({"ipv6Addresses", std::vector{"2001:1b70:8230:5501:4401:3301:2201:1102",
                                               "2001:1b70:8230:5501:4401:3301:2201:1103"}});
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances")
      .at(0)
      .at("nfServices")
      .at(0)
      .at("ipEndPoints")
      .at(0)
      .erase("ipv4Address");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 2;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 3;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 4;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 60000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::DualStack);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value(), NfInstance({"[2001:1b70:8230:5501:4401:3301:2201:1101]:9091", "setA",
                                        "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}));
}

// NF services have different priorities but same capacities
// where ip version is dual stack, FQDN is missing from
// highest priority NF service and there is no FQDN on
// corresponding NF instance level as well. Also, there
// is no IPv4 address and IPv6 address present in IP
// endpoint. Therefore, all IPv4 addresses from IPv4
// addresses list and all IPv6 addresses from IPv6
// addresses list in NF instance should be considered
// as a candidate for preferred host.
TEST(EricProxyFilterTest, TestSelectNfOnPriority32) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("fqdn");
  json_body.at("nfInstances")
      .at(0)
      .push_back({"ipv4Addresses", std::vector{"10.11.12.251", "10.11.12.252"}});
  json_body.at("nfInstances")
      .at(0)
      .push_back({"ipv6Addresses", std::vector{"2001:1b70:8230:5501:4401:3301:2201:1102",
                                               "2001:1b70:8230:5501:4401:3301:2201:1103"}});
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances")
      .at(0)
      .at("nfServices")
      .at(0)
      .at("ipEndPoints")
      .at(0)
      .erase("ipv4Address");
  json_body.at("nfInstances")
      .at(0)
      .at("nfServices")
      .at(0)
      .at("ipEndPoints")
      .at(0)
      .erase("ipv6Address");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 2;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 3;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 4;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 60000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::DualStack);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.value() == NfInstance({"10.11.12.251:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"10.11.12.252:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"[2001:1b70:8230:5501:4401:3301:2201:1102]:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}) ||
              result.value() == NfInstance({"[2001:1b70:8230:5501:4401:3301:2201:1103]:9091", "setA",
                                            "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}));
}

// NF services have different priorities but same capacities
// where ip version is dual stack, FQDN is missing from
// highest priority NF service and there is no FQDN on
// corresponding NF instance level as well. Also, there
// is no IPv4 address and no IPv6 address present neither
// in IP endpoint nor in NF instance. Therefore, the
// highest priority endpoint should be ignored and
// the FQDN of next higher priority endpoint
// should be present in preferred host.
TEST(EricProxyFilterTest, TestSelectNfOnPriority33) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances")
      .at(0)
      .at("nfServices")
      .at(0)
      .at("ipEndPoints")
      .at(0)
      .erase("ipv4Address");
  json_body.at("nfInstances")
      .at(0)
      .at("nfServices")
      .at(0)
      .at("ipEndPoints")
      .at(0)
      .erase("ipv6Address");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 2;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 3;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 4;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 60000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::DualStack);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value(), NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                        "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}));
}

// NF services have different priorities but same capacities
// where ip version is default, FQDN is missing from
// highest priority NF service and there is no FQDN on
// corresponding NF instance level as well but the
// IPv4 address and IPv6 address are present in IP endpoint.
// Therefore, the highest priority endpoint should be ignored
// and the FQDN of next higher priority endpoint should be
// present in preferred host.
TEST(EricProxyFilterTest, TestSelectNfOnPriority34) {
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 1;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 2;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 3;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 60000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 4;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 60000;
  const auto result = EricProxyFilter::selectNfOnPriority(json_body, IPver::Default);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value(), NfInstance({"FQDN_1_2.example.com:9092", "setA",
                                        "2ec8ac0b-265e-4165-86e9-e0735e6ce100"}));
}

//--------------------Test selectTarsForRemoteRouting()-------------------

//---------Test selectTarsForRemoteRouting() for remote round robin-------

// NF services have different priorities and capacities.
// Number of reselections are more than the total
// number of TaRs extracted.
TEST(EricProxyFilterTest, TestSelectTarsForRemoteRouting_RoundRobin1) {
  const uint32_t num_reselections = 10;
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result =
      EricProxyFilter::selectTarsForRemoteRouting(json_body, num_reselections, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value().size(), 5);
  for (uint32_t idx = 0; idx < 3; idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://FQDN_1_2.example.com:9092" ||
                result.value().at(idx) == "https://FQDN_2_2.example.com:9094" ||
                result.value().at(idx) == "https://FQDN_2_2.example.com:9095");
  }
  for (uint32_t idx = 3; idx < result.value().size(); idx++) {
    EXPECT_TRUE(result.value().at(idx) == "http://FQDN_1_1.example.com:9091" ||
                result.value().at(idx) == "https://FQDN_2_1.example.com:9093");
  }
}

// NF services have different priorities and capacities.
// Number of reselections are less than the total
// number of TaRs extracted.
TEST(EricProxyFilterTest, TestSelectTarsForRemoteRouting_RoundRobin2) {
  const uint32_t num_reselections = 3;
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result =
      EricProxyFilter::selectTarsForRemoteRouting(json_body, num_reselections, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value().size(), 4);
  for (uint32_t idx = 0; idx < 3; idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://FQDN_1_2.example.com:9092" ||
                result.value().at(idx) == "https://FQDN_2_2.example.com:9094" ||
                result.value().at(idx) == "https://FQDN_2_2.example.com:9095");
  }
  for (uint32_t idx = 3; idx < result.value().size(); idx++) {
    EXPECT_TRUE(result.value().at(idx) == "http://FQDN_1_1.example.com:9091" ||
                result.value().at(idx) == "https://FQDN_2_1.example.com:9093");
  }
}

// NF services have different priorities and capacities.
// Number of reselections are more than the total
// number of TaRs extracted.
// Two endpoints have same TaR where only first endpoint
// will be considered.
TEST(EricProxyFilterTest, TestSelectTarsForRemoteRouting_RoundRobin3) {
  const uint32_t num_reselections = 10;
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("ipEndPoints").at(0).erase("port");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("ipEndPoints").at(0).erase("port");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result =
      EricProxyFilter::selectTarsForRemoteRouting(json_body, num_reselections, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value().size(), 4);
  for (uint32_t idx = 0; idx < 2; idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://FQDN_2_2.example.com:9094" ||
                result.value().at(idx) == "https://FQDN_2_2.example.com:9095");
  }
  for (uint32_t idx = 2; idx < result.value().size(); idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://FQDN_1.example.com:443" ||
                result.value().at(idx) == "https://FQDN_2_1.example.com:9093");
  }
}

// NF services have different priorities and capacities.
// Number of reselections are more than the total
// number of TaRs extracted.
// Two endpoints have same hostname. So, only
// first endpoint will be considered and capacity
// is not distributed for the ignored endpoint.
TEST(EricProxyFilterTest, TestSelectTarsForRemoteRouting_RoundRobin4) {
  const uint32_t num_reselections = 10;
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("scheme") = "https";
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).erase("ipEndPoints");
  json_body.at("nfInstances").at(1).at("nfServices").at(1).erase("fqdn");
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("scheme") = "https";
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("ipEndPoints").at(1).erase("port");
  const auto result =
      EricProxyFilter::selectTarsForRemoteRouting(json_body, num_reselections, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value().size(), 4);
  for (uint32_t idx = 0; idx < 2; idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://FQDN_1_2.example.com:9092" ||
                result.value().at(idx) == "https://FQDN_2.example.com:9094");
  }
  for (uint32_t idx = 2; idx < result.value().size(); idx++) {
    EXPECT_TRUE(result.value().at(idx) == "http://FQDN_1_1.example.com:9091" ||
                result.value().at(idx) == "https://FQDN_2.example.com:443");
  }
}

// NF services have different priorities but same capacities.
// Number of reselections are more than the total
// number of TaRs extracted.
// Extracted TaRs should belong to the specific nf-set-id only.
TEST(EricProxyFilterTest, TestSelectTarsForRemoteRouting_RoundRobin5) {
  const uint32_t num_reselections = 10;
  const std::string nf_set_id = "setA";
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 20000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 20000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 20000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 20000;
  const auto result = EricProxyFilter::selectTarsForRemoteRouting(json_body, num_reselections,
                                                                  IPver::IPv4, nf_set_id);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value().size(), 2);
  for (uint32_t idx = 0; idx < 1; idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://FQDN_1_2.example.com:9092");
  }
  for (uint32_t idx = 1; idx < result.value().size(); idx++) {
    EXPECT_TRUE(result.value().at(idx) == "http://FQDN_1_1.example.com:9091");
  }
}

// NLF lookup result have nfServiceList.
// NF services have different priorities and capacities.
// Number of reselections are more than the total
// number of TaRs extracted.
// Two endpoints have same hostname. So, only
// first endpoint will be considered and capacity
// is not distributed for the ignored endpoint.
TEST(EricProxyFilterTest, TestSelectTarsForRemoteRouting_RoundRobin6) {
  const uint32_t num_reselections = 10;
  Json json_body = Json::parse(nlf_lookup_result_nfServiceList);
  json_body.at("nfInstances")
      .at(0)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce100")
      .at("scheme") = "http";
  json_body.at("nfInstances")
      .at(0)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce100")
      .at("priority") = 8;
  json_body.at("nfInstances")
      .at(0)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce100")
      .at("capacity") = 50000;
  json_body.at("nfInstances")
      .at(0)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce101")
      .at("priority") = 5;
  json_body.at("nfInstances")
      .at(0)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce101")
      .at("capacity") = 30000;
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce102")
      .erase("fqdn");
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce102")
      .at("scheme") = "https";
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce102")
      .at("priority") = 8;
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce102")
      .at("capacity") = 10000;
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce102")
      .erase("ipEndPoints");
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce103")
      .erase("fqdn");
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce103")
      .at("scheme") = "https";
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce103")
      .at("priority") = 5;
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce103")
      .at("capacity") = 10000;
  json_body.at("nfInstances")
      .at(1)
      .at("nfServiceList")
      .at("3ec8ac0b-265e-4165-86e9-e0735e6ce103")
      .at("ipEndPoints")
      .at(1)
      .erase("port");
  const auto result =
      EricProxyFilter::selectTarsForRemoteRouting(json_body, num_reselections, IPver::IPv4);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value().size(), 4);
  for (uint32_t idx = 0; idx < 2; idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://FQDN_1_2.example.com:9092" ||
                result.value().at(idx) == "https://FQDN_2.example.com:9094");
  }
  for (uint32_t idx = 2; idx < result.value().size(); idx++) {
    EXPECT_TRUE(result.value().at(idx) == "http://FQDN_1_1.example.com:9091" ||
                result.value().at(idx) == "https://FQDN_2.example.com:443");
  }
}

// NF services have different priorities and capacities
// where ip version is dual stack, FQDN is missing from
// highest priority NF services and there is no FQDN on
// corresponding NF instance level as well. Therefore,
// both IPv4 and IPv6 addresses in IP endpoint should
// be considered for the TaR list.
// Number of reselections are more than the total
// number of TaRs extracted.
TEST(EricProxyFilterTest, TestSelectTarsForRemoteRouting_RoundRobin7) {
  const uint32_t num_reselections = 10;
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).erase("fqdn");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).erase("fqdn");
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result =
      EricProxyFilter::selectTarsForRemoteRouting(json_body, num_reselections, IPver::DualStack);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value().size(), 8);
  for (uint32_t idx = 0; idx < 6; idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://10.11.12.253:9092" ||
                result.value().at(idx) == "https://[2001:1b70:8230:5501:4401:3301:2201:1101]:9092" ||
                result.value().at(idx) == "https://10.11.12.253:9094" ||
                result.value().at(idx) == "https://[2001:1b70:8230:5501:4401:3301:2201:1101]:9094" ||
                result.value().at(idx) == "https://10.11.12.253:9095" ||
                result.value().at(idx) == "https://[2001:1b70:8230:5501:4401:3301:2201:1101]:9095");
  }
  for (uint32_t idx = 6; idx < result.value().size(); idx++) {
    EXPECT_TRUE(result.value().at(idx) == "http://FQDN_1_1.example.com:9091" ||
                result.value().at(idx) == "https://FQDN_2_1.example.com:9093");
  }
}

//----------Test selectTarsForRemoteRouting() for remote preferred--------

// NF services have different priorities and capacities.
// Number of reselections are more than the total
// number of TaRs extracted.
TEST(EricProxyFilterTest, TestSelectTarsForRemoteRouting_Preferred1) {
  const uint32_t num_retries = 2;
  const uint32_t num_reselections = 10;
  const std::string preferred_tar = "https://FQDN_2_2.example.com:9094";
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectTarsForRemoteRouting(
      json_body, num_reselections, IPver::IPv4, absl::nullopt, num_retries, preferred_tar);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value().size(), num_retries + 5);
  for (uint32_t idx = 0; idx < num_retries + 1; idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://FQDN_2_2.example.com:9094");
  }
  for (uint32_t idx = num_retries + 1; idx < 5; idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://FQDN_1_2.example.com:9092" ||
                result.value().at(idx) == "https://FQDN_2_2.example.com:9095");
  }
  for (uint32_t idx = 5; idx < result.value().size(); idx++) {
    EXPECT_TRUE(result.value().at(idx) == "http://FQDN_1_1.example.com:9091" ||
                result.value().at(idx) == "https://FQDN_2_1.example.com:9093");
  }
}

// NF services have different priorities and capacities.
// Number of reselections are less than the total
// number of TaRs extracted.
TEST(EricProxyFilterTest, TestSelectTarsForRemoteRouting_Preferred2) {
  const uint32_t num_retries = 2;
  const uint32_t num_reselections = 3;
  const std::string preferred_tar = "https://FQDN_2_2.example.com:9094";
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectTarsForRemoteRouting(
      json_body, num_reselections, IPver::IPv4, absl::nullopt, num_retries, preferred_tar);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value().size(), num_retries + 4);
  for (uint32_t idx = 0; idx < num_retries + 1; idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://FQDN_2_2.example.com:9094");
  }
  for (uint32_t idx = num_retries + 1; idx < 5; idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://FQDN_1_2.example.com:9092" ||
                result.value().at(idx) == "https://FQDN_2_2.example.com:9095");
  }
  for (uint32_t idx = 5; idx < result.value().size(); idx++) {
    EXPECT_TRUE(result.value().at(idx) == "http://FQDN_1_1.example.com:9091" ||
                result.value().at(idx) == "https://FQDN_2_1.example.com:9093");
  }
}

// NF services have different priorities and capacities.
// Number of reselections are more than the total
// number of TaRs extracted.
// Two endpoints have same TaR where only first endpoint
// will be considered.
TEST(EricProxyFilterTest, TestSelectTarsForRemoteRouting_Preferred3) {
  const uint32_t num_retries = 2;
  const uint32_t num_reselections = 10;
  const std::string preferred_tar = "https://FQDN_2_2.example.com:9094";
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 50000;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("ipEndPoints").at(0).erase("port");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).erase("fqdn");
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 30000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("ipEndPoints").at(0).erase("port");
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 10000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 10000;
  const auto result = EricProxyFilter::selectTarsForRemoteRouting(
      json_body, num_reselections, IPver::IPv4, absl::nullopt, num_retries, preferred_tar);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value().size(), num_retries + 4);
  for (uint32_t idx = 0; idx < num_retries + 1; idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://FQDN_2_2.example.com:9094");
  }
  for (uint32_t idx = num_retries + 1; idx < 4; idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://FQDN_2_2.example.com:9095");
  }
  for (uint32_t idx = 4; idx < result.value().size(); idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://FQDN_1.example.com:443" ||
                result.value().at(idx) == "https://FQDN_2_1.example.com:9093");
  }
}

// NF services have different priorities but same capacities.
// Number of reselections are more than the total
// number of TaRs extracted.
// Extracted TaRs should belong to the specific nf-set-id only.
TEST(EricProxyFilterTest, TestSelectTarsForRemoteRouting_Preferred4) {
  const uint32_t num_retries = 2;
  const uint32_t num_reselections = 10;
  const std::string preferred_tar = "https://FQDN_1_2.example.com:9092";
  const std::string nf_set_id = "setA";
  Json json_body = Json::parse(nlf_lookup_result);
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("scheme") = "http";
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(0).at("nfServices").at(0).at("capacity") = 20000;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("priority") = 5;
  json_body.at("nfInstances").at(0).at("nfServices").at(1).at("capacity") = 20000;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(0).at("capacity") = 20000;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("priority") = 8;
  json_body.at("nfInstances").at(1).at("nfServices").at(1).at("capacity") = 20000;
  const auto result = EricProxyFilter::selectTarsForRemoteRouting(
      json_body, num_reselections, IPver::IPv4, nf_set_id, num_retries, preferred_tar);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value().size(), num_retries + 2);
  for (uint32_t idx = 0; idx < num_retries + 1; idx++) {
    EXPECT_TRUE(result.value().at(idx) == "https://FQDN_1_2.example.com:9092");
  }
  for (uint32_t idx = num_retries + 1; idx < result.value().size(); idx++) {
    EXPECT_TRUE(result.value().at(idx) == "http://FQDN_1_1.example.com:9091");
  }
}

//========================================================================
// Scrambling/Mapping and Descrambling/Demapping
//========================================================================

//------------------------------------------------------------------------
// Test splitUriForMapping()

TEST(EricProxyFilterTest, TestSplitUriForMapping1) {
  std::string uri = "https://abc.de.com:80/path/to/resource?param1&param2";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result,
            std::make_tuple("https://", "abc.de.com", ":80/path/to/resource?param1&param2"));
}

TEST(EricProxyFilterTest, TestSplitUriForMapping2) {
  std::string uri = "https://abc.de.com:80/path/to/resource/";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result, std::make_tuple("https://", "abc.de.com", ":80/path/to/resource/"));
}

TEST(EricProxyFilterTest, TestSplitUriForMapping3) {
  std::string uri = "https://abc.de.com:80/path/to/resource";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result, std::make_tuple("https://", "abc.de.com", ":80/path/to/resource"));
}

TEST(EricProxyFilterTest, TestSplitUriForMapping4) {
  std::string uri = "https://abc.de.com:80/";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result, std::make_tuple("https://", "abc.de.com", ":80/"));
}

TEST(EricProxyFilterTest, TestSplitUriForMapping5) {
  std::string uri = "https://abc.de.com:80";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result, std::make_tuple("https://", "abc.de.com", ":80"));
}

TEST(EricProxyFilterTest, TestSplitUriForMapping6) {
  std::string uri = "https://abc.de.com/path/to/resource?param1&param2";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result, std::make_tuple("https://", "abc.de.com", "/path/to/resource?param1&param2"));
}

TEST(EricProxyFilterTest, TestSplitUriForMapping7) {
  std::string uri = "https://abc.de.com/";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result, std::make_tuple("https://", "abc.de.com", "/"));
}

TEST(EricProxyFilterTest, TestSplitUriForMapping8) {
  std::string uri = "https://abc.de.com";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result, std::make_tuple("https://", "abc.de.com", ""));
}

TEST(EricProxyFilterTest, TestSplitUriForMapping9) {
  std::string uri = "abc.de.com:80/path/to/resource?param1&param2";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result, std::make_tuple("", "abc.de.com", ":80/path/to/resource?param1&param2"));
}

TEST(EricProxyFilterTest, TestSplitUriForMapping10) {
  std::string uri = "abc.de.com:80/path/to/resource/";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result, std::make_tuple("", "abc.de.com", ":80/path/to/resource/"));
}

TEST(EricProxyFilterTest, TestSplitUriForMapping11) {
  std::string uri = "abc.de.com:80/path/to/resource";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result, std::make_tuple("", "abc.de.com", ":80/path/to/resource"));
}

TEST(EricProxyFilterTest, TestSplitUriForMapping12) {
  std::string uri = "abc.de.com:80/";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result, std::make_tuple("", "abc.de.com", ":80/"));
}

TEST(EricProxyFilterTest, TestSplitUriForMapping13) {
  std::string uri = "abc.de.com:80";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result, std::make_tuple("", "abc.de.com", ":80"));
}

TEST(EricProxyFilterTest, TestSplitUriForMapping14) {
  std::string uri = "abc.de.com/path/to/resource?param1&param2";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result, std::make_tuple("", "abc.de.com", "/path/to/resource?param1&param2"));
}

TEST(EricProxyFilterTest, TestSplitUriForMapping15) {
  std::string uri = "abc.de.com/";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result, std::make_tuple("", "abc.de.com", "/"));
}

TEST(EricProxyFilterTest, TestSplitUriForMapping16) {
  std::string uri = "abc.de.com";
  const auto result = EricProxyFilter::splitUriForMapping(uri);
  EXPECT_EQ(result, std::make_tuple("", "abc.de.com", ""));
}

//------------------------------------------------------------------------
// Test splitLabels()

TEST(EricProxyFilterTest, TestSplitLabels1) {
  std::string labels = "";
  const auto result = EricProxyFilter::splitLabels(labels);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "FQDN is in invalid 3gpp format");
}

TEST(EricProxyFilterTest, TestSplitLabels2) {
  std::string labels = "abc";
  const auto result = EricProxyFilter::splitLabels(labels);
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(result.value().size(), 1);
  EXPECT_EQ(result.value().at(0), "abc");
}

TEST(EricProxyFilterTest, TestSplitLabels3) {
  std::string labels = "abc.";
  const auto result = EricProxyFilter::splitLabels(labels);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "FQDN is in invalid 3gpp format");
}

TEST(EricProxyFilterTest, TestSplitLabels4) {
  std::string labels = ".abc";
  const auto result = EricProxyFilter::splitLabels(labels);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "FQDN is in invalid 3gpp format");
}

TEST(EricProxyFilterTest, TestSplitLabels5) {
  std::string labels = ".abc.";
  const auto result = EricProxyFilter::splitLabels(labels);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "FQDN is in invalid 3gpp format");
}

TEST(EricProxyFilterTest, TestSplitLabels6) {
  std::string labels = "abc.123";
  const auto result = EricProxyFilter::splitLabels(labels);
  EXPECT_EQ(result.value().size(), 2);
  EXPECT_EQ(result.value().at(0), "abc");
  EXPECT_EQ(result.value().at(1), "123");
}

TEST(EricProxyFilterTest, TestSplitLabels7) {
  std::string labels = "abc.123.";
  const auto result = EricProxyFilter::splitLabels(labels);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "FQDN is in invalid 3gpp format");
}

TEST(EricProxyFilterTest, TestSplitLabels8) {
  std::string labels = "abc.123.def";
  const auto result = EricProxyFilter::splitLabels(labels);
  EXPECT_EQ(result.value().size(), 3);
  EXPECT_EQ(result.value().at(0), "abc");
  EXPECT_EQ(result.value().at(1), "123");
  EXPECT_EQ(result.value().at(2), "def");
}

//------------------------------------------------------------------------
// Test splitUriForScrambling()

TEST(EricProxyFilterTest, TestSplitUriForScrambling1) {
  std::string uri =
      "https://abc.5gc.mnc123.mcc123.3gppnetwork.org:80/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(result.ok());
  const auto& [scheme, labels, plmn, portAndResource] = result.value();
  EXPECT_EQ(scheme, "https://");
  EXPECT_EQ(labels.size(), 1);
  EXPECT_EQ(labels.at(0), "abc");
  EXPECT_EQ(plmn, ".5gc.mnc123.mcc123.3gppnetwork.org");
  EXPECT_EQ(portAndResource, ":80/path/to/resource?param1&param2");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling2) {
  std::string uri = "https://abc.5gc.mnc123.mcc123.3gppnetwork.org:80/path/to/resource/";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(result.ok());
  const auto& [scheme, labels, plmn, portAndResource] = result.value();
  EXPECT_EQ(scheme, "https://");
  EXPECT_EQ(labels.size(), 1);
  EXPECT_EQ(labels.at(0), "abc");
  EXPECT_EQ(plmn, ".5gc.mnc123.mcc123.3gppnetwork.org");
  EXPECT_EQ(portAndResource, ":80/path/to/resource/");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling3) {
  std::string uri = "https://abc.5gc.mnc123.mcc123.3gppnetwork.org:80/path/to/resource";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(result.ok());
  const auto& [scheme, labels, plmn, portAndResource] = result.value();
  EXPECT_EQ(scheme, "https://");
  EXPECT_EQ(labels.size(), 1);
  EXPECT_EQ(labels.at(0), "abc");
  EXPECT_EQ(plmn, ".5gc.mnc123.mcc123.3gppnetwork.org");
  EXPECT_EQ(portAndResource, ":80/path/to/resource");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling4) {
  std::string uri = "https://abc.5gc.mnc123.mcc123.3gppnetwork.org:80/";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(result.ok());
  const auto& [scheme, labels, plmn, portAndResource] = result.value();
  EXPECT_EQ(scheme, "https://");
  EXPECT_EQ(labels.size(), 1);
  EXPECT_EQ(labels.at(0), "abc");
  EXPECT_EQ(plmn, ".5gc.mnc123.mcc123.3gppnetwork.org");
  EXPECT_EQ(portAndResource, ":80/");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling5) {
  std::string uri = "https://abc.5gc.mnc123.mcc123.3gppnetwork.org:80";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(result.ok());
  const auto& [scheme, labels, plmn, portAndResource] = result.value();
  EXPECT_EQ(scheme, "https://");
  EXPECT_EQ(labels.size(), 1);
  EXPECT_EQ(labels.at(0), "abc");
  EXPECT_EQ(plmn, ".5gc.mnc123.mcc123.3gppnetwork.org");
  EXPECT_EQ(portAndResource, ":80");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling6) {
  std::string uri = "https://abc.5gc.mnc123.mcc123.3gppnetwork.org/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(result.ok());
  const auto& [scheme, labels, plmn, portAndResource] = result.value();
  EXPECT_EQ(scheme, "https://");
  EXPECT_EQ(labels.size(), 1);
  EXPECT_EQ(labels.at(0), "abc");
  EXPECT_EQ(plmn, ".5gc.mnc123.mcc123.3gppnetwork.org");
  EXPECT_EQ(portAndResource, "/path/to/resource?param1&param2");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling7) {
  std::string uri = "https://abc.5gc.mnc123.mcc123.3gppnetwork.org/";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(result.ok());
  const auto& [scheme, labels, plmn, portAndResource] = result.value();
  EXPECT_EQ(scheme, "https://");
  EXPECT_EQ(labels.size(), 1);
  EXPECT_EQ(labels.at(0), "abc");
  EXPECT_EQ(plmn, ".5gc.mnc123.mcc123.3gppnetwork.org");
  EXPECT_EQ(portAndResource, "/");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling8) {
  std::string uri = "https://abc.5gc.mnc123.mcc123.3gppnetwork.org";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(result.ok());
  const auto& [scheme, labels, plmn, portAndResource] = result.value();
  EXPECT_EQ(scheme, "https://");
  EXPECT_EQ(labels.size(), 1);
  EXPECT_EQ(labels.at(0), "abc");
  EXPECT_EQ(plmn, ".5gc.mnc123.mcc123.3gppnetwork.org");
  EXPECT_EQ(portAndResource, "");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling9) {
  std::string uri = "abc.5gc.mnc123.mcc123.3gppnetwork.org:80/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "URI is invalid");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling10) {
  std::string uri = "abc.5gc.mnc123.mcc123.3gppnetwork.org:80";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(result.ok());
  const auto& [scheme, labels, plmn, portAndResource] = result.value();
  EXPECT_EQ(scheme, "");
  EXPECT_EQ(labels.size(), 1);
  EXPECT_EQ(labels.at(0), "abc");
  EXPECT_EQ(plmn, ".5gc.mnc123.mcc123.3gppnetwork.org");
  EXPECT_EQ(portAndResource, ":80");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling11) {
  std::string uri = "abc.5gc.mnc123.mcc123.3gppnetwork.org/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "URI is invalid");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling12) {
  std::string uri = "abc.5gc.mnc123.mcc123.3gppnetwork.org";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(result.ok());
  const auto& [scheme, labels, plmn, portAndResource] = result.value();
  EXPECT_EQ(scheme, "");
  EXPECT_EQ(labels.size(), 1);
  EXPECT_EQ(labels.at(0), "abc");
  EXPECT_EQ(plmn, ".5gc.mnc123.mcc123.3gppnetwork.org");
  EXPECT_EQ(portAndResource, "");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling13) {
  std::string uri = "ab://abc.5gc.mnc123.mcc123.3gppnetwork.org:80/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "scheme is invalid");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling14) {
  std::string uri = "https://ab_cd:80/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "URI is invalid");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling15) {
  std::string uri =
      "https://abc.5gc.mnc123.mcc123.3gppnetwork.org:80000/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "URI is invalid");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling16) {
  std::string uri = "https://10.10.10.10:80/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "IP address is present");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling17) {
  std::string uri =
      "https://[2001:1b70:8230:5501:4401:3301:2201:1102]:80/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "IP address is present");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling18) {
  std::string uri = "ab_cd:80";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "authority (host + port) is invalid");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling19) {
  std::string uri = "abc.5gc.mnc123.mcc123.3gppnetwork.org:80000";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "authority (host + port) is invalid");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling20) {
  std::string uri = "10.10.10.10:80";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "IP address is present");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling21) {
  std::string uri = "10.10.10.10";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "IP address is present");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling22) {
  std::string uri = "[2001:1b70:8230:5501:4401:3301:2201:1102]:80";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "IP address is present");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling23) {
  std::string uri = "[2001:1b70:8230:5501:4401:3301:2201:1102]";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "IP address is present");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling24) {
  std::string uri =
      "https://abc.5GC.mnc123.mcc123.3GPPnetwork.org:80/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(result.ok());
  const auto& [scheme, labels, plmn, portAndResource] = result.value();
  EXPECT_EQ(scheme, "https://");
  EXPECT_EQ(labels.size(), 1);
  EXPECT_EQ(labels.at(0), "abc");
  EXPECT_EQ(plmn, ".5GC.mnc123.mcc123.3GPPnetwork.org");
  EXPECT_EQ(portAndResource, ":80/path/to/resource?param1&param2");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling25) {
  std::string uri = "https://abc.mnc123.mcc123.3gppnetwork.org:80/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "FQDN is in invalid 3gpp format");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling26) {
  std::string uri =
      "https://abc.5gc.mnc1234.mcc1234.3gppnetwork.org:80/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "FQDN is in invalid 3gpp format");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling27) {
  std::string uri = "https://.5gc.mnc123.mcc123.3gppnetwork.org:80/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "FQDN is in invalid 3gpp format");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling28) {
  std::string uri =
      "https://abc..5gc.mnc123.mcc123.3gppnetwork.org:80/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "FQDN is in invalid 3gpp format");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling29) {
  std::string uri =
      "https://.abc.5gc.mnc123.mcc123.3gppnetwork.org:80/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "FQDN is in invalid 3gpp format");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling30) {
  std::string uri =
      "https://.abc..5gc.mnc123.mcc123.3gppnetwork.org:80/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(!result.ok());
  EXPECT_EQ(result.status().message(), "FQDN is in invalid 3gpp format");
}

TEST(EricProxyFilterTest, TestSplitUriForScrambling31) {
  std::string uri =
      "https://abc1.def1.5gc.mnc123.mcc123.3gppnetwork.org:80/path/to/resource?param1&param2";
  const auto regex_valid_plmn = std::regex(
      "(.*)(\\.5gc\\.mnc\\d{3}\\.mcc\\d{3}\\.3gppnetwork\\.org)", std::regex_constants::icase);
  const auto result = EricProxyFilter::splitUriForScrambling(uri, regex_valid_plmn);
  EXPECT_TRUE(result.ok());
  const auto& [scheme, labels, plmn, portAndResource] = result.value();
  EXPECT_EQ(scheme, "https://");
  EXPECT_EQ(labels.size(), 2);
  EXPECT_EQ(labels.at(0), "abc1");
  EXPECT_EQ(labels.at(1), "def1");
  EXPECT_EQ(plmn, ".5gc.mnc123.mcc123.3gppnetwork.org");
  EXPECT_EQ(portAndResource, ":80/path/to/resource?param1&param2");
}

//-----------------------Test scramble()------------------------

TEST(EricProxyFilterTest, TestScramble1) {
  const std::string original_string = "fqdn";
  const std::string generation_prefix = "AB101";
  const std::string key_string = "abcdefgh12345678abcdefgh12345678";
  const std::string iv_string = "abcdef123456";
  ENVOY_LOG_MISC(trace, "id: {}, key: {}, iv: {}", generation_prefix, key_string, iv_string);
  const unsigned char* key = reinterpret_cast<const unsigned char*>(key_string.c_str());
  const unsigned char* iv = reinterpret_cast<const unsigned char*>(iv_string.c_str());
  const auto result = EricProxyFilter::scramble(original_string, key, iv, generation_prefix);
  ENVOY_LOG_MISC(trace, "result: {}", result);
  EXPECT_TRUE(result == "AB101C5CCFSLYEWY5E");
}

TEST(EricProxyFilterTest, TestScramble2) {
  const std::string original_string = "fqdn";
  const std::string key_string = "abcdefgh12345678abcdefgh12345678";
  const std::string iv_string = "abcdef123456";
  ENVOY_LOG_MISC(trace, "key: {}, iv: {}", key_string, iv_string);
  const unsigned char* key = reinterpret_cast<const unsigned char*>(key_string.c_str());
  const unsigned char* iv = reinterpret_cast<const unsigned char*>(iv_string.c_str());
  const auto result = EricProxyFilter::scramble(original_string, key, iv);
  ENVOY_LOG_MISC(trace, "result: {}", result);
  EXPECT_TRUE(result == "C5CCFSLYEWY5E");
}

//-----------------------Test descramble()------------------------

TEST(EricProxyFilterTest, TestDescramble1) {
  std::string scrambled_string = "AB101C5CCFSLYEWY5E";
  std::string generation_prefix = scrambled_string.substr(0, 5);
  scrambled_string = scrambled_string.substr(5);
  const std::string key_string = "abcdefgh12345678abcdefgh12345678";
  const std::string iv_string = "abcdef123456";
  ENVOY_LOG_MISC(trace, "id: {}, key: {}, iv: {}", generation_prefix, key_string, iv_string);
  const unsigned char* key = reinterpret_cast<const unsigned char*>(key_string.c_str());
  const unsigned char* iv = reinterpret_cast<const unsigned char*>(iv_string.c_str());
  const auto result = EricProxyFilter::descramble(scrambled_string, key, iv);
  ENVOY_LOG_MISC(trace, "result: {}", result);
  EXPECT_TRUE(result == "fqdn");
}

TEST(EricProxyFilterTest, TestDescramble2) {
  std::string scrambled_string = "AB101C5CCFSLYEWY5E";
  std::string generation_prefix = scrambled_string.substr(0, 5);
  scrambled_string = scrambled_string.substr(5);
  const std::string key_string = "bbcdefgh12345678abcdefgh12345678";
  const std::string iv_string = "abcdef123456";
  ENVOY_LOG_MISC(trace, "id: {}, key: {}, iv: {}", generation_prefix, key_string, iv_string);
  const unsigned char* key = reinterpret_cast<const unsigned char*>(key_string.c_str());
  const unsigned char* iv = reinterpret_cast<const unsigned char*>(iv_string.c_str());
  const auto result = EricProxyFilter::descramble(scrambled_string, key, iv);
  ENVOY_LOG_MISC(trace, "result: {}", result);
  EXPECT_TRUE(result.empty());
}

TEST(EricProxyFilterTest, TestDescramble3) {
  std::string scrambled_string = "AB101C5CCFSLYEWY5E";
  std::string generation_prefix = scrambled_string.substr(0, 5);
  scrambled_string = scrambled_string.substr(5);
  const std::string key_string = "abcdefgh12345678abcdefgh12345678";
  const std::string iv_string = "bbcdef123456";
  ENVOY_LOG_MISC(trace, "id: {}, key: {}, iv: {}", generation_prefix, key_string, iv_string);
  const unsigned char* key = reinterpret_cast<const unsigned char*>(key_string.c_str());
  const unsigned char* iv = reinterpret_cast<const unsigned char*>(iv_string.c_str());
  const auto result = EricProxyFilter::descramble(scrambled_string, key, iv);
  ENVOY_LOG_MISC(trace, "result: {}", result);
  EXPECT_TRUE(result.empty());
}

TEST(EricProxyFilterTest, TestDescramble4) {
  std::string scrambled_string = "AB101C5CCFSLYEWY5A";
  std::string generation_prefix = scrambled_string.substr(0, 5);
  scrambled_string = scrambled_string.substr(5);
  const std::string key_string = "abcdefgh12345678abcdefgh12345678";
  const std::string iv_string = "abcdef123456";
  ENVOY_LOG_MISC(trace, "id: {}, key: {}, iv: {}", generation_prefix, key_string, iv_string);
  const unsigned char* key = reinterpret_cast<const unsigned char*>(key_string.c_str());
  const unsigned char* iv = reinterpret_cast<const unsigned char*>(iv_string.c_str());
  const auto result = EricProxyFilter::descramble(scrambled_string, key, iv);
  ENVOY_LOG_MISC(trace, "result: {}", result);
  EXPECT_TRUE(result.empty());
}

TEST(EricProxyFilterTest, TestDescramble5) {
  std::string scrambled_string = "AB101C";
  std::string generation_prefix = scrambled_string.substr(0, 5);
  scrambled_string = scrambled_string.substr(5);
  const std::string key_string = "abcdefgh12345678abcdefgh12345678";
  const std::string iv_string = "abcdef123456";
  ENVOY_LOG_MISC(trace, "id: {}, key: {}, iv: {}", generation_prefix, key_string, iv_string);
  const unsigned char* key = reinterpret_cast<const unsigned char*>(key_string.c_str());
  const unsigned char* iv = reinterpret_cast<const unsigned char*>(iv_string.c_str());
  const auto result = EricProxyFilter::descramble(scrambled_string, key, iv);
  ENVOY_LOG_MISC(trace, "result: {}", result);
  EXPECT_TRUE(result.empty());
}

TEST(EricProxyFilterTest, TestDescramble6) {
  std::string scrambled_string = "AB101C5CCFSLY";
  std::string generation_prefix = scrambled_string.substr(0, 5);
  scrambled_string = scrambled_string.substr(5);
  const std::string key_string = "abcdefgh12345678abcdefgh12345678";
  const std::string iv_string = "abcdef123456";
  ENVOY_LOG_MISC(trace, "id: {}, key: {}, iv: {}", generation_prefix, key_string, iv_string);
  const unsigned char* key = reinterpret_cast<const unsigned char*>(key_string.c_str());
  const unsigned char* iv = reinterpret_cast<const unsigned char*>(iv_string.c_str());
  const auto result = EricProxyFilter::descramble(scrambled_string, key, iv);
  ENVOY_LOG_MISC(trace, "result: {}", result);
  EXPECT_TRUE(result.empty());
}

TEST(EricProxyFilterTest, TestDescramble7) {
  std::string scrambled_string = "AB101C5CCFSLYEWY5";
  std::string generation_prefix = scrambled_string.substr(0, 5);
  scrambled_string = scrambled_string.substr(5);
  const std::string key_string = "abcdefgh12345678abcdefgh12345678";
  const std::string iv_string = "abcdef123456";
  ENVOY_LOG_MISC(trace, "id: {}, key: {}, iv: {}", generation_prefix, key_string, iv_string);
  const unsigned char* key = reinterpret_cast<const unsigned char*>(key_string.c_str());
  const unsigned char* iv = reinterpret_cast<const unsigned char*>(iv_string.c_str());
  const auto result = EricProxyFilter::descramble(scrambled_string, key, iv);
  ENVOY_LOG_MISC(trace, "result: {}", result);
  EXPECT_TRUE(result.empty());
}

TEST(EricProxyFilterTest, TestDescramble8) {
  std::string scrambled_string = "AB101C5CCFSLYEWY5EA";
  std::string generation_prefix = scrambled_string.substr(0, 5);
  scrambled_string = scrambled_string.substr(5);
  const std::string key_string = "abcdefgh12345678abcdefgh12345678";
  const std::string iv_string = "abcdef123456";
  ENVOY_LOG_MISC(trace, "id: {}, key: {}, iv: {}", generation_prefix, key_string, iv_string);
  const unsigned char* key = reinterpret_cast<const unsigned char*>(key_string.c_str());
  const unsigned char* iv = reinterpret_cast<const unsigned char*>(iv_string.c_str());
  const auto result = EricProxyFilter::descramble(scrambled_string, key, iv);
  ENVOY_LOG_MISC(trace, "result: {}", result);
  EXPECT_TRUE(result.empty());
}

TEST(EricProxyFilterTest, TestDescramble9) {
  std::string scrambled_string = "AB101C5CCFSLYEWY5EAA";
  std::string generation_prefix = scrambled_string.substr(0, 5);
  scrambled_string = scrambled_string.substr(5);
  const std::string key_string = "abcdefgh12345678abcdefgh12345678";
  const std::string iv_string = "abcdef123456";
  ENVOY_LOG_MISC(trace, "id: {}, key: {}, iv: {}", generation_prefix, key_string, iv_string);
  const unsigned char* key = reinterpret_cast<const unsigned char*>(key_string.c_str());
  const unsigned char* iv = reinterpret_cast<const unsigned char*>(iv_string.c_str());
  const auto result = EricProxyFilter::descramble(scrambled_string, key, iv);
  ENVOY_LOG_MISC(trace, "result: {}", result);
  EXPECT_TRUE(result.empty());
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
