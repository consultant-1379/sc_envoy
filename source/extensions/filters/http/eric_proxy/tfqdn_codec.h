#pragma once

#include <string>

// CODEC_TOOL is defined when compiling this file standalone for the command-line
// decoder/encoder tool. It is not defined when compiling for Envoy.
// See /tools/tfqdn_codec/ for the tool.
#ifndef CODEC_TOOL
#include "source/common/common/logger.h"
#include "envoy/http/filter.h"

#endif

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

/**
 * A Utility class to convert between FQDN and Telescopic-FQDN (TFQDN).
 */
#ifdef CODEC_TOOL
class TfqdnCodec {
#else
class TfqdnCodec : public Logger::Loggable<Logger::Id::eric_proxy> {
#endif
public:
  static std::string encode(absl::string_view input,
                            Http::StreamDecoderFilterCallbacks* decoder_callbacks = nullptr);
  static std::string decode(absl::string_view,
                            Http::StreamDecoderFilterCallbacks* decoder_callbacks = nullptr);
};


} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
