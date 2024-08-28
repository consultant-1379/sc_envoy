#include "source/extensions/filters/http/eric_proxy/tfqdn_codec.h"
#include "test/test_common/utility.h"
#include "gtest/gtest.h"
#include <vector>
#include <string>
#include <tuple>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

class EricProxyTfqdnCodecTest : public ::testing::Test {};

TEST_F(EricProxyTfqdnCodecTest, basic_encode_decode) {
  std::vector<std::string> decoded_values = {
    "abcdefghijklmnopqrsrtuvwxyz0123456789-:.%_!$'()*,;=[]", // all possible/allowed chars
    "ud",  // test if it would test for "udm" and go out-of-bounds
    ".5gc.mnc.mcc.3gppnetwork.orgamfausf",
    "bsfdrahsshttp://https://ipupsmme",
    "nefnrfnssfpcfpcrfpgwscpsecfseppsgw",
    "smfsmsfudmudrudsfupf",
    "nfudm2.mnc.123.mcc.321.ericsson.se:15713",
    "nfudm2.5gc.mnc123.mcc321.3gppnetwork.org:15713",
    "http://nfsepp5.5gc.mnc123.mcc321.3gppnetwork.org:15713",
    "https://nfsepp5.5gc.mnc123.mcc321.3gppnetwork.org:15713",
    "http://nfnef5.5gc.mnc123.mcc321.3gppnetwork.org:15713",
    "http://jumpstart.5gc.mnc123.mcc321.3gppnetwork.org:15713",
    "http://quickstart.5gc.mnc123.mcc321.3gppnetwork.org:15713",
    "http://[fe80::1ff:fe23:4567:890a%25eth0]/",
    "http://[2001:0db8:85a3:08d3::0370:7344]:8080/",
    "2001:0db8:85a3::/48",
    "",
  };

  for (const auto& decoded_value: decoded_values) {
    auto encoded_value = TfqdnCodec::encode(decoded_value);
    std::cout << "Input: " << decoded_value << ", output: " << encoded_value << std::endl;
    // Check that only allowed characters are used:
    const std::string allowed{"abcdefghijklmnopqrstuvwxyz0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"};
    EXPECT_TRUE(std::all_of(encoded_value.begin(), encoded_value.end(),
          [allowed](char c){return allowed.find(c) != std::string::npos;}));
    // Check that both the upper- as well as the lower-case encoded string
    // can be decoded:
    std::string encoded_value_uppercase = encoded_value;
    std::transform(encoded_value_uppercase.begin(), encoded_value_uppercase.end(),
        encoded_value_uppercase.begin(), ::toupper);

    EXPECT_EQ(TfqdnCodec::decode(encoded_value), decoded_value);
    EXPECT_EQ(TfqdnCodec::decode(encoded_value_uppercase), decoded_value);
  }
}

// Test corrupt inputs to ensure no crashes or other unwanted behaviour happen
TEST_F(EricProxyTfqdnCodecTest, decode_corrupt) {
#define T(a,b) std::make_tuple(a, b)
  std::vector<std::tuple<std::string, std::string>> inputs = {
    T("abcq", ""), // nothing after the escape-character
    T("abcz", "") // nothing after the escape-character
  };

  for (const auto& input: inputs) {
    const auto& encoded_value = std::get<0>(input);
    const auto& expected_decoded_value = std::get<1>(input);
    auto decoded_value = TfqdnCodec::decode(encoded_value);
    EXPECT_EQ(decoded_value, expected_decoded_value);
  }

}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
