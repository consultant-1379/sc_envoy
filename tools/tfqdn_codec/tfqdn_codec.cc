// Decoder and Encoder for TFQDNs in SEPP
// 2022-05-09 eedala

#include <getopt.h>
#include <iostream>

#define CODEC_TOOL
#include "../../source/extensions/filters/http/eric_proxy/tfqdn_codec.h"

// Dummy to ignore ENVOY_LOG
#define trace "trace"
#define ENVOY_LOG(level, fmt, ...) (1)

// Include the source so that the above #define works
#include "../../source/extensions/filters/http/eric_proxy/tfqdn_codec.cc"

int main(int argc, char** argv) {
  switch(getopt(argc, argv, "d:e:h"))
  {
    case 'd':
      std::cout << Envoy::Extensions::HttpFilters::EricProxy::TfqdnCodec::decode(optarg) << std::endl;
      return(0);
    case 'e':
      std::cout << Envoy::Extensions::HttpFilters::EricProxy::TfqdnCodec::encode(optarg) << std::endl;
      return(0);
    case 'h':
      std::cout << "Usage:" << std::endl
                << argv[0] << " [-e <input>]|[-d <input>]|<input>..." << std::endl
                << "  -e <input>    Encode the input and print it" << std::endl
                << "  -d <input>    Decode the input and print it" << std::endl
                << " <input>...     Encode and Decode the input(s) and print them" << std::endl;
      return(0);
    default: {
      if (argc > 1) {
        for (int i = 1; i < argc; i++) {
          std::string input = argv[i];
          auto output_encoded = Envoy::Extensions::HttpFilters::EricProxy::TfqdnCodec::encode(input);
          auto output_decoded = Envoy::Extensions::HttpFilters::EricProxy::TfqdnCodec::decode(input);
          std::cout << "Input:   " << input << "  (" << input.length() << " characters)" << std::endl;
          std::cout << "Encoded: " << output_encoded
                    << "  (" << output_encoded.length() << " characters)" << std::endl;
          std::cout << "Decoded: " << output_decoded
                    << "  (" << output_decoded.length() << " characters)" << std::endl;
          if (i < argc - 1) {
            std::cout << std::endl;
          }
        }
        return 0;
      } else {
        std::cerr << "Usage: " << argv[0] << " <(t)fqdn-string>" << std::endl;
        return 1;
      }
    }
  }
}

