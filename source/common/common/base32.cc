#include "source/common/common/base32.h"

#include <cstdint>
#include <string>

#include "source/common/common/assert.h"
#include "source/common/common/empty_string.h"

#include "absl/container/fixed_array.h"

namespace Envoy {
namespace {

// clang-format off
constexpr char CHAR_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Reverse mapping: Index into this table is the ASCII code of
// the input character, the value is the 5-bit-value for the output.
// This table is case-insensitive, so that 'A' and 'a' both map to zero,
// i.e. it doesn't matter if the case of the input is upper or lower.
constexpr unsigned char REVERSE_LOOKUP_TABLE[256] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,  // 0-9
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,  // 10-19
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,  // 20-29
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,  // 30-39
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,  // 40-49
    26, 27, 28, 29, 30, 31, 64, 64, 64, 64,  // 50-59
    64, 64, 64, 64, 64, 0,  1,  2,  3,  4,   // 60-69
     5,  6, 7,  8,  9,  10, 11, 12, 13, 14,  // 70-79
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24,  // 80-89
    25, 64, 64, 64, 64, 64, 64,  0,  1,  2,  // 90-99
     3,  4,  5,  6,  7,  8,  9, 10, 11, 12,  //100-109
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22,  //110-119
    23, 24, 25, 64, 64, 64, 64, 64, 64, 64,  //120-129
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64};

// clang-format on

inline bool decodeBase(const uint8_t cur_char, uint64_t pos, std::string& ret,
                       const unsigned char* const reverse_lookup_table) {
  const unsigned char c = reverse_lookup_table[static_cast<uint32_t>(cur_char)];
  if (c == 64) {
    // Invalid character
    return false;
  }

  switch (pos % 8) {
  case 0:
    ret.push_back(c << 3);
    break;
  case 1:
    ret.back() |= c >> 2;
    ret.push_back(c << 6);
    break;
  case 2:
    ret.back() |= c << 1;
    break;
  case 3:
    ret.back() |= c >> 4;
    ret.push_back(c << 4);
    break;
  case 4:
    ret.back() |= c >> 1;
    ret.push_back(c << 7);
    break;
  case 5:
    ret.back() |= c << 2;
    break;
  case 6:
    ret.back() |= c >> 3;
    ret.push_back(c << 5);
    break;
  case 7:
    ret.back() |= c;
    break;
  }
  return true;
}

inline bool decodeLast(const uint8_t cur_char, uint64_t pos, std::string& ret,
                       const unsigned char* const reverse_lookup_table) {
  const unsigned char c = reverse_lookup_table[static_cast<uint32_t>(cur_char)];
  if (c == 64) {
    // Invalid character
    return false;
  }

  switch (pos % 8) {
  case 0:
    return false;
  case 1:
    ret.back() |= c >> 2;
    return (c & 0b11) == 0;
  case 2:
    return false;
  case 3:
    ret.back() |= c >> 4;
    return (c & 0b1111) == 0;
  case 4:
    ret.back() |= c >> 1;
    return (c & 0b1) == 0;
  case 5:
    return false;
  case 6:
    ret.back() |= c >> 3;
    return (c & 0b111) == 0;
  case 7:
    ret.back() |= c;
    break;
  }
  return true;
}

inline void encodeBase(const uint8_t cur_char, uint64_t pos, uint8_t& next_c, std::string& ret,
                       const char* const char_table) {
  switch (pos % 5) {
  case 0: // M
    ret.push_back(char_table[cur_char >> 3]);
    next_c = (cur_char & 0x07) << 2;
    break;
  case 1: // a
    ret.push_back(char_table[next_c | (cur_char >> 6)]);
    ret.push_back(char_table[(cur_char >> 1) & 0x1f]);
    next_c = (cur_char & 0x01) << 4;
    break;
  case 2: // n
    ret.push_back(char_table[next_c | (cur_char >> 4)]);
    next_c = (cur_char & 0x0f) << 1;
    break;
  case 3: // y
    ret.push_back(char_table[next_c | (cur_char >> 7)]);
    ret.push_back(char_table[(cur_char >> 2) & 0x1f]);
    next_c = (cur_char & 0x03) << 3;
    break;
  case 4: // (space)
    ret.push_back(char_table[next_c | (cur_char >> 5)]);
    ret.push_back(char_table[cur_char & 0x1f]);
    next_c = 0;
    break;
  }
}

inline void encodeLast(uint64_t pos, uint8_t last_char, std::string& ret,
                       const char* const char_table, bool add_padding) {
  switch (pos % 5) {
  case 1:
    ret.push_back(char_table[last_char]);
    if (add_padding) {
      ret.push_back('=');
      ret.push_back('=');
      ret.push_back('=');
      ret.push_back('=');
      ret.push_back('=');
      ret.push_back('=');
    }
    break;
  case 2:
    ret.push_back(char_table[last_char]);
    if (add_padding) {
      ret.push_back('=');
      ret.push_back('=');
      ret.push_back('=');
      ret.push_back('=');
    }
    break;
  case 3:
    ret.push_back(char_table[last_char]);
    if (add_padding) {
      ret.push_back('=');
      ret.push_back('=');
      ret.push_back('=');
    }
    break;
  case 4:
    ret.push_back(char_table[last_char]);
    if (add_padding) {
      ret.push_back('=');
    }
    break;
  default:
    break;
  }
}

} // namespace

std::string Base32::decode(const std::string& input) {
  if (input.length() % 4) {
    return EMPTY_STRING;
  }
  return decodeWithoutPadding(input);
}

std::string Base32::decodeWithoutPadding(absl::string_view input) {
  if (input.empty()) {
    return EMPTY_STRING;
  }

  // At most last six chars can be '='.
  size_t n = input.length();
  while (n > 0 && (input[n - 1] == '=')) {
    n--;
  }
  // Last position before "valid" padding character.
  uint64_t last = n - 1;
  // Determine output length.
  size_t max_length = (n + 5) / 8 * 5;
  if (n % 8 == 2) {
    max_length += 1;
  }
  else if (n % 8 == 4) {
    max_length -= 3;
  }
  else if (n % 8 == 5) {
    max_length -= 2;
  }
  else if (n % 8 == 7) {
    max_length -= 1;
  }

  std::string ret;
  ret.reserve(max_length);
  for (uint64_t i = 0; i < last; ++i) {
    if (!decodeBase(input[i], i, ret, REVERSE_LOOKUP_TABLE)) {
      return EMPTY_STRING;
    }
  }

  if (!decodeLast(input[last], last, ret, REVERSE_LOOKUP_TABLE)) {
    return EMPTY_STRING;
  }

  ASSERT(ret.size() == max_length);
  return ret;
}

std::string Base32::encode(const char* input, uint64_t length) {
  return encode(input, length, true);
}

std::string Base32::encode(const char* input, uint64_t length, bool add_padding) {
  uint64_t output_length = (length + 2) / 5 * 8;
  std::string ret;
  ret.reserve(output_length);

  uint64_t pos = 0;
  uint8_t next_c = 0;

  for (uint64_t i = 0; i < length; ++i) {
    encodeBase(input[i], pos++, next_c, ret, CHAR_TABLE);
  }

  encodeLast(pos, next_c, ret, CHAR_TABLE, add_padding);

  return ret;
}
} // namespace Envoy
