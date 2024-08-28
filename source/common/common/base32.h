#pragma once

#include <cstdint>
#include <string>

#include "absl/strings/string_view.h"

namespace Envoy {

/**
 * A utility class to support base32 encoding, which is defined in RFC4648 Section 6.
 * See https://tools.ietf.org/html/rfc4648#section-6
 *
 * Adapted from Envoy's Base64 class.
 */
class Base32 {
public:
  /**
   * Base32 encode an input char buffer with a given length.
   * @param input char array to encode.
   * @param length of the input array.
   */
  static std::string encode(const char* input, uint64_t length);

  /**
   * Base32 encode an input char buffer with a given length.
   * @param input char array to encode.
   * @param length of the input array.
   * @param whether add padding at the end of the output.
   */
  static std::string encode(const char* input, uint64_t length, bool add_padding);

  /**
   * Base32 decode an input string. Padding is required.
   * @param input supplies the input to decode.
   *
   * Note, decoded string may contain '\0' at any position, it should be treated as a sequence of
   * bytes.
   */
  static std::string decode(const std::string& input);

  /**
   * Base32 decode an input string. Padding is not required.
   * @param input supplies the input to decode.
   *
   * Note, decoded string may contain '\0' at any position, it should be treated as a sequence of
   * bytes.
   */
  static std::string decodeWithoutPadding(absl::string_view input);
};


} // namespace Envoy
