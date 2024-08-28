#include "source/extensions/filters/http/eric_proxy/tfqdn_codec.h"
#include "source/common/common/base32.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <cstdlib>

#include "benchmark/benchmark.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

static void BM_TfqdnEncode(benchmark::State& state) {

std::vector<std::string> decoded_values = {
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


for (auto decoded_value: decoded_values) {
  std::string encoded_value;
  
  for (auto _ : state) {
    // This code gets timed
    encoded_value = TfqdnCodec::encode(decoded_value);
    //TfqdnCodec::encode("nfudm2.5gc.mnc123.mcc321.3gppnetwork.org:15713");

  }
  EXPECT_EQ(TfqdnCodec::decode(encoded_value), decoded_value);
}
  //std::cout << std::setw(4) << doc << "\n\n" << std::setw(4) << patched_doc << std::endl;
}

BENCHMARK(BM_TfqdnEncode);


static void BM_TfqdnDecode(benchmark::State& state) {

std::vector<std::string> decoded_values = {
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


for (auto decoded_value: decoded_values) {
  std::string encoded_value = TfqdnCodec::encode(decoded_value);
  for (auto _ : state) {
    // This code gets timed
    EXPECT_EQ(TfqdnCodec::decode(encoded_value), decoded_value);
  }
}
  //std::cout << std::setw(4) << doc << "\n\n" << std::setw(4) << patched_doc << std::endl;
}

BENCHMARK(BM_TfqdnDecode);


static void BM_TfqdnBase32Encode(benchmark::State& state) {

std::vector<std::string> decoded_values = {
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


for (auto decoded_value: decoded_values) {
  std::string encoded_value;
  
  for (auto _ : state) {
    // This code gets timed
    encoded_value = Base32::encode(decoded_value.c_str(),decoded_value.length(), false);

  }
  EXPECT_EQ(Base32::decodeWithoutPadding(encoded_value), decoded_value);
}
  //std::cout << std::setw(4) << doc << "\n\n" << std::setw(4) << patched_doc << std::endl;
}

BENCHMARK(BM_TfqdnBase32Encode);

static void BM_TfqdnBase32Decode(benchmark::State& state) {

std::vector<std::string> decoded_values = {
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


for (auto decoded_value: decoded_values) {
  std::string encoded_value =Base32::encode(decoded_value.c_str(),decoded_value.length(), false);
  
  for (auto _ : state) {
    // This code gets timed
   EXPECT_EQ(Base32::decodeWithoutPadding(encoded_value), decoded_value);
  }
}
  //std::cout << std::setw(4) << doc << "\n\n" << std::setw(4) << patched_doc << std::endl;
}

BENCHMARK(BM_TfqdnBase32Decode);

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
