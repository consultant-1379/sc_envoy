#include <string>
#include <algorithm>
#include "source/common/common/empty_string.h"
#include "tfqdn_codec.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {


// Encode a given FQDN into a TFQDN and returns it.
// This function has no limitation on the length of the FQDN or TFQDN,
// and it does not limit the TFQDN.
std::string TfqdnCodec::encode(absl::string_view input, Http::StreamDecoderFilterCallbacks* cb) {
  std::string input_lc = absl::AsciiStrToLower(input);
  auto input_length = input_lc.size();
  if (cb) {
    ENVOY_STREAM_LOG(trace, "tfqdn encoding input:{}, length:{}", *cb, input_lc, input_length);
  }
  std::string encoded_str;
  encoded_str.reserve(130); // avoids re-allocations, we expect only 63
  unsigned long pos = 0; // index in input from where to read the next character

// Some macros to make the swtich() statement easier to read:
#define DIRECT_ENCODE_AND_BREAK encoded_str.push_back(c); pos++; break;
#define REPLACE_ENCODE_AND_BREAK(new_val) encoded_str.push_back((new_val)); pos++; break;
#define ESC_Q_ENCODE_AND_BREAK(new_val, consumed) encoded_str.push_back('Q'); encoded_str.push_back((new_val)); pos += (consumed); break;
#define ESC_Z_ENCODE_AND_BREAK(new_val) encoded_str.push_back('Z'); encoded_str.push_back((new_val)); pos++; break;

  while (pos < input_length) {
    const char& c{input_lc.at(pos)};
    switch (c) {
      case '-': DIRECT_ENCODE_AND_BREAK
      case '.':
        if ((pos + 3 < input_length) && (input_lc.at(pos + 1) == 'm') &&
            (input_lc.at(pos + 2) == 'c') && (input_lc.at(pos + 3) == 'c')) {
          ESC_Q_ENCODE_AND_BREAK('m', 4);
        } else if ((pos + 7 < input_length) && (input_lc.at(pos + 1) == '5') &&
                   (input_lc.at(pos + 2) == 'g') && (input_lc.at(pos + 3) == 'c') &&
                   (input_lc.at(pos + 4) == '.') && (input_lc.at(pos + 5) == 'm') &&
                   (input_lc.at(pos + 6) == 'n') && (input_lc.at(pos + 7) == 'c')) {
          ESC_Q_ENCODE_AND_BREAK('5', 8);
        } else if ((pos + 15 < input_length) && (input_lc.at(pos + 1) == '3') &&
                   (input_lc.at(pos + 2) == 'g') && (input_lc.at(pos + 3) == 'p') &&
                   (input_lc.at(pos + 4) == 'p') && (input_lc.at(pos + 5) == 'n') &&
                   (input_lc.at(pos + 6) == 'e') && (input_lc.at(pos + 7) == 't') &&
                   (input_lc.at(pos + 8) == 'w') && (input_lc.at(pos + 9) == 'o') &&
                   (input_lc.at(pos + 10) == 'r') && (input_lc.at(pos + 11) == 'k') &&
                   (input_lc.at(pos + 12) == '.') && (input_lc.at(pos + 13) == 'o') &&
                   (input_lc.at(pos + 14) == 'r') && (input_lc.at(pos + 15) == 'g')) {
          ESC_Q_ENCODE_AND_BREAK('3', 16);
        } else
          REPLACE_ENCODE_AND_BREAK('v')
      case '0': // fall-through
      case '1': // fall-through
      case '2': // fall-through
      case '3': // fall-through
      case '4': // fall-through
      case '5': // fall-through
      case '6': // fall-through
      case '7': // fall-through
      case '8': // fall-through
      case '9': DIRECT_ENCODE_AND_BREAK
      case ':': REPLACE_ENCODE_AND_BREAK('j')
      case 'a':
        if ((pos + 2 < input_length) && (input_lc.at(pos + 1) == 'm') &&
            (input_lc.at(pos + 2) == 'f')) {
          ESC_Q_ENCODE_AND_BREAK('a', 3);
        } else if ((pos + 3 < input_length) && (input_lc.at(pos + 1) == 'u') &&
                   (input_lc.at(pos + 2) == 's') && (input_lc.at(pos + 3) == 'f')) {
          ESC_Q_ENCODE_AND_BREAK('9', 4);
        } else
          DIRECT_ENCODE_AND_BREAK
      case 'b':
        if ((pos + 2 < input_length) && (input_lc.at(pos + 1) == 's') &&
            (input_lc.at(pos + 2) == 'f')) {
          ESC_Q_ENCODE_AND_BREAK('b', 3);
        } else
          DIRECT_ENCODE_AND_BREAK
      case 'c': DIRECT_ENCODE_AND_BREAK
      case 'd':
        if ((pos + 2 < input_length) && (input_lc.at(pos + 1) == 'r') &&
            (input_lc.at(pos + 2) == 'a')) {
          ESC_Q_ENCODE_AND_BREAK('r', 3);
        } else
          DIRECT_ENCODE_AND_BREAK
      case 'e': // fall-through
      case 'f': // fall-through
      case 'g': DIRECT_ENCODE_AND_BREAK
      case 'h':
        if ((pos + 2 < input_length) && (input_lc.at(pos + 1) == 's') &&
            (input_lc.at(pos + 2) == 's')) {
          ESC_Q_ENCODE_AND_BREAK('l', 3);
        } else if ((pos + 6 < input_length) && (input_lc.at(pos + 1) == 't') &&
                   (input_lc.at(pos + 2) == 't') && (input_lc.at(pos + 3) == 'p')) {
          if ((pos + 7 < input_length) && (input_lc.at(pos + 4) == 's') &&
              (input_lc.at(pos + 5) == ':') && (input_lc.at(pos + 6) == '/') &&
              (input_lc.at(pos + 7) == '/')) {
            ESC_Q_ENCODE_AND_BREAK('s', 8);
          } else if ((input_lc.at(pos + 4) == ':') && (input_lc.at(pos + 5) == '/') &&
                     (input_lc.at(pos + 6) == '/')) {
            ESC_Q_ENCODE_AND_BREAK('h', 7);
          } else
            DIRECT_ENCODE_AND_BREAK
        } else
          DIRECT_ENCODE_AND_BREAK
      case 'i':
        if ((pos + 5 < input_length) && (input_lc.at(pos + 1) == 'p') &&
            (input_lc.at(pos + 2) == 'u') && (input_lc.at(pos + 3) == 'p') &&
            (input_lc.at(pos + 4) == 's')) {
          ESC_Q_ENCODE_AND_BREAK('i', 5);
        } else
          DIRECT_ENCODE_AND_BREAK
      case 'j': ESC_Z_ENCODE_AND_BREAK('j');
      case 'k': // fall-through
      case 'l': DIRECT_ENCODE_AND_BREAK
      case 'm':
        if ((pos + 2 < input_length) && (input_lc.at(pos + 1) == 'm') &&
            (input_lc.at(pos + 2) == 'e')) {
          ESC_Q_ENCODE_AND_BREAK('o', 3);
        } else
          DIRECT_ENCODE_AND_BREAK
      case 'n':
        if ((pos + 2 < input_length) && (input_lc.at(pos + 1) == 'e') &&
            (input_lc.at(pos + 2) == 'f')) {
          ESC_Q_ENCODE_AND_BREAK('8', 3);
        } else if ((pos + 2 < input_length) && (input_lc.at(pos + 1) == 'r') &&
                   (input_lc.at(pos + 2) == 'f')) {
          ESC_Q_ENCODE_AND_BREAK('n', 3);
        } else if ((pos + 3 < input_length) && (input_lc.at(pos + 1) == 's') &&
                   (input_lc.at(pos + 2) == 's') && (input_lc.at(pos + 3) == 'f')) {
          ESC_Q_ENCODE_AND_BREAK('k', 4);
        } else
          DIRECT_ENCODE_AND_BREAK
      case 'o': DIRECT_ENCODE_AND_BREAK
      case 'p':
        if ((pos + 2 < input_length) && (input_lc.at(pos + 1) == 'c')) {
          if ((pos + 3 < input_length) && (input_lc.at(pos + 2) == 'r') &&
              (input_lc.at(pos + 3) == 'f')) {
            ESC_Q_ENCODE_AND_BREAK('1', 4);
          } else if (input_lc.at(pos + 2) == 'f') {
            ESC_Q_ENCODE_AND_BREAK('p', 3);
          } else
            DIRECT_ENCODE_AND_BREAK
        } else if ((pos + 2 < input_length) && (input_lc.at(pos + 1) == 'g') &&
                   (input_lc.at(pos + 2) == 'w')) {
          ESC_Q_ENCODE_AND_BREAK('t', 3);
        } else
          DIRECT_ENCODE_AND_BREAK
      case 'q': ESC_Z_ENCODE_AND_BREAK('q');
      case 'r': DIRECT_ENCODE_AND_BREAK
      case 's':
        if ((pos + 2 < input_length) && (input_lc.at(pos + 1) == 'c') &&
            (input_lc.at(pos + 2) == 'p')) {
          ESC_Q_ENCODE_AND_BREAK('w', 3);
        } else if ((pos + 3 < input_length) && (input_lc.at(pos + 1) == 'e')) {
          if ((input_lc.at(pos + 2) == 'c') && (input_lc.at(pos + 3) == 'f')) {
            ESC_Q_ENCODE_AND_BREAK('d', 4);
          } else if ((input_lc.at(pos + 2) == 'p') && (input_lc.at(pos + 3) == 'p')) {
            ESC_Q_ENCODE_AND_BREAK('e', 4);
          } else
            DIRECT_ENCODE_AND_BREAK
        } else if ((pos + 2 < input_length) && (input_lc.at(pos + 1) == 'g') &&
                   (input_lc.at(pos + 2) == 'w')) {
          ESC_Q_ENCODE_AND_BREAK('g', 3);
        } else if ((pos + 2 < input_length) && (input_lc.at(pos + 1) == 'm')) {
          if ((pos + 3 < input_length) && (input_lc.at(pos + 2) == 's') &&
              (input_lc.at(pos + 3) == 'f')) {
            ESC_Q_ENCODE_AND_BREAK('x', 4);
          } else if (input_lc.at(pos + 2) == 'f') {
            ESC_Q_ENCODE_AND_BREAK('f', 3);
          } else
            DIRECT_ENCODE_AND_BREAK
        } else
          DIRECT_ENCODE_AND_BREAK
      case 't': DIRECT_ENCODE_AND_BREAK
      case 'u':
        if ((pos + 2 < input_length) && (input_lc.at(pos + 1) == 'd')) {
          if (input_lc.at(pos + 2) == 'm') {
            ESC_Q_ENCODE_AND_BREAK('u', 3);
          } else if (input_lc.at(pos + 2) == 'r') {
            ESC_Q_ENCODE_AND_BREAK('y', 3);
          } else if ((pos + 3 < input_length) && (input_lc.at(pos + 2) == 's') &&
                     (input_lc.at(pos + 3) == 'f')) {
            ESC_Q_ENCODE_AND_BREAK('z', 4);
          } else
            DIRECT_ENCODE_AND_BREAK
        } else if ((pos + 2 < input_length) && (input_lc.at(pos + 1) == 'p') &&
                   (input_lc.at(pos + 2) == 'f')) {
          ESC_Q_ENCODE_AND_BREAK('0', 3);
        } else
          DIRECT_ENCODE_AND_BREAK
      case 'v': ESC_Z_ENCODE_AND_BREAK('v');
      case 'w': // fall-through
      case 'x': // fall-through
      case 'y': DIRECT_ENCODE_AND_BREAK
      case 'z': ESC_Z_ENCODE_AND_BREAK('z');
      case '%': ESC_Z_ENCODE_AND_BREAK('a')
      case '_': ESC_Z_ENCODE_AND_BREAK('b')
      case '!': ESC_Z_ENCODE_AND_BREAK('c')
      case '$': ESC_Z_ENCODE_AND_BREAK('d')
      case '\'': ESC_Z_ENCODE_AND_BREAK('e')
      case '(': ESC_Z_ENCODE_AND_BREAK('f')
      case ')': ESC_Z_ENCODE_AND_BREAK('g')
      case '*': ESC_Z_ENCODE_AND_BREAK('h')
      case ',': ESC_Z_ENCODE_AND_BREAK('i')
      case ';': ESC_Z_ENCODE_AND_BREAK('k')
      case '=': ESC_Z_ENCODE_AND_BREAK('l')
      case '[': ESC_Z_ENCODE_AND_BREAK('m')
      case ']': ESC_Z_ENCODE_AND_BREAK('n')
      case '/': ESC_Z_ENCODE_AND_BREAK('o')
      default:
        //ENVOY_LOG(error, "Unexpected character to encode into TFQDN: '{}'", c);
        DIRECT_ENCODE_AND_BREAK
        break;
    }
  }
  if (cb) { ENVOY_STREAM_LOG(trace, "encoded_str:         {}, length:{}", *cb, encoded_str, encoded_str.length());}
  return encoded_str;
}

// Direct decoding means than one character in the encoded string is decoded into one character
// in the decoded string. this is mainly mapping each character to itself, except for:
// - The escape characters q and z: These are mapped to Q and Z to indicate a decoding error
//   when the q or z is the last character of the encoded string
// - v is mapped to . (because . is expected more often in FQDNs than v)
// - j is mapped to : (because : is expected more often in FQDNs than j)
const char direct_decode_table[] = {
  /*          0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F  */
  /* 0x00 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0x10 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0x20 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '-', '?', '?',
  /* 0x30 */ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '?', '?', '?', '?', '?', '?',
  /* 0x40 */ '?', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', ':', 'k', 'l', 'm', 'n', 'o',
  /* 0x50 */ 'p', '?', 'r', 's', 't', 'u', '.', 'w', 'x', 'y', '?', '?', '?', '?', '?', '?',
  /* 0x60 */ '?', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', ':', 'k', 'l', 'm', 'n', 'o',
  /* 0x70 */ 'p', '?', 'r', 's', 't', 'u', '.', 'w', 'x', 'y', '?', '?', '?', '?', '?', '?',
  /* 0x80 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0x90 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0xA0 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0xB0 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0xC0 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0xD0 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0xE0 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0xF0 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
};

// The Escape-Q encoding results in a string.
// The index into this table is the character following the "q" in the encoded string.
// The strings below are the decoded values.
const std::string esc_q_decode_table[] = {
  /*          0       1       2       3       4       5       6       7       8       9       A       B       C       D       E       F  */
  /* 0x00 */ "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",
  /* 0x10 */ "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",
  /* 0x20 */ "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",
  /* 0x30 */ "upf",  "pcrf", "?",    ".3gppnetwork.org",
                                             "?",    ".5gc.mnc",
                                                             "?",    "?",    "nef",  "ausf", "?",    "?",    "?",    "?",    "?",    "?",
  /* 0x40 */ "?",    "amf",  "bsf",  "?",    "secf", "sepp", "smf",  "sgw",  "http://",
                                                                                     "ipups","j",    "nssf", "hss",  ".mcc", "nrf",  "mme",
  /* 0x50 */ "pcf",  "q",    "dra",  "https://",
                                             "pgw",  "udm",  "v",    "scp",  "smsf", "udr",  "udsf", "?",    "?",    "?",    "?",    "?",
  /* 0x60 */ "?",    "amf",  "bsf",  "?",    "secf", "sepp", "smf",  "sgw",  "http://",
                                                                                     "ipups","j",    "nssf", "hss",  ".mcc", "nrf",  "mme",
  /* 0x70 */ "pcf",  "q",    "dra",  "https://",
                                             "pgw",  "udm",  "v",    "scp",  "smsf", "udr",  "udsf", "?",    "?",    "?",    "?",    "?",
  /* 0x80 */ "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",
  /* 0x90 */ "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",
  /* 0xA0 */ "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",
  /* 0xB0 */ "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",
  /* 0xC0 */ "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",
  /* 0xD0 */ "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",
  /* 0xE0 */ "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",
  /* 0xF0 */ "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",    "?",
};

// The Escape-Z encoding results always in a single decoded character (Escape-q encoding
// always results in a multi-character string).
// The index into this table is the character following the "z" in the encoded string.
// The characters below are the decoded characters.
const char esc_z_decode_table[] = {
  /*          0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F  */
  /* 0x00 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0x10 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0x20 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0x30 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0x40 */ '?', '%', '_', '!', '$', '\'','(', ')', '*', ',', 'j', ';', '=', '[', ']', '/',
  /* 0x50 */ '?', 'q', '?', '?', '?', '?', 'v', '?', '?', '?', 'z', '?', '?', '?', '?', '?',
  /* 0x60 */ '?', '%', '_', '!', '$', '\'','(', ')', '*', ',', 'j', ';', '=', '[', ']', '/',
  /* 0x70 */ '?', 'q', '?', '?', '?', '?', 'v', '?', '?', '?', 'z', '?', '?', '?', '?', '?',
  /* 0x80 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0x90 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0xA0 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0xB0 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0xC0 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0xD0 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0xE0 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  /* 0xF0 */ '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
};

// Decode a given TFQDN back into the original FQDN and return it.
// This function can handle TFQDN and FQDN longer than the 63 character limit
// mentioned in the RFC.
// Return the decoded TFQDN or EMPTY_STRING on error
std::string TfqdnCodec::decode(absl::string_view input, Http::StreamDecoderFilterCallbacks* cb) {
  std::string input_lc = absl::AsciiStrToLower(input);
  auto input_length = input_lc.size();
  if (cb) {
    ENVOY_STREAM_LOG(trace, "tfqdn decoding input:{}, length:{}", *cb, input_lc, input_length);
  }
  std::string decoded_str;
  decoded_str.reserve(130); // avoids re-allocations, we expect only 63
  unsigned long pos = 0; // index in input from where to read the next character

  while (pos < input_length) {
    const unsigned char& c = reinterpret_cast<const unsigned char&>(input_lc.at(pos));
    // Escape-Q encoded?
    if (c == 'q') {
      if (pos + 1 < input_length) {
        const unsigned char& c2 = reinterpret_cast<const unsigned char&>(input_lc.at(pos + 1));
        decoded_str.append(esc_q_decode_table[c2]);
        pos += 2;
      } else {
        if (cb) {
          ENVOY_STREAM_LOG(debug, "encoded_str ends in 'q'. Is it truncated?: {}\n", *cb, input_lc);
        }
        return EMPTY_STRING;
      }
    // Escape-Z encoded?
    } else if (c == 'z') {
      if(pos + 1 < input_length) {
        const unsigned char& c2 = reinterpret_cast<const unsigned char&>(input_lc.at(pos + 1));
        decoded_str.push_back(esc_z_decode_table[c2]);
        pos += 2;
      } else {
        if (cb) {
          ENVOY_STREAM_LOG(debug, "encoded_str ends in 'z'. Is it truncated?: {}\n", *cb, input_lc);
        }
        return EMPTY_STRING;
      }
    // Direct-encoded
    } else {
      decoded_str.push_back(direct_decode_table[c]);
      pos++;
    }
  }

  if (cb) { ENVOY_STREAM_LOG(trace, "decoded_str:         {}\n", *cb, decoded_str);}
  // If the decoded string contains no '?' then decoding was successful:
  if (decoded_str.find('?') == std::string::npos) {
    return decoded_str;
  } else {
    if (cb) { ENVOY_STREAM_LOG(trace, "decoded_str contains '?': {}\n", *cb, decoded_str);}
    return EMPTY_STRING;
  }
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
