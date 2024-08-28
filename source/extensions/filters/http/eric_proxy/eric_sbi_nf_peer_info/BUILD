load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

# extension to add sbi nf peer info header
# 3 classes to handle headers for local reply, requests and responses
# uses metadata to pass information to router
# sbi_nf_peer_info_values contains constants for this extension

envoy_extension_package()

envoy_cc_library(
  name = "sbi_nf_peer_info_lib",
  srcs = [
    "sbi_nf_peer_info.cc",
    "sbi_nf_peer_info_local_response.cc",
    "sbi_nf_peer_info_request_meta.cc",
    "sbi_nf_peer_info_response_meta.cc"
  ],
  hdrs = [
    "sbi_nf_peer_info.h",
    "sbi_nf_peer_info_int.h",
    "sbi_nf_peer_info_values.h",
    "sbi_nf_peer_info_local_response.h",
    "sbi_nf_peer_info_request_meta.h",
    "sbi_nf_peer_info_response_meta.h"
    ],
  external_deps = [],
  deps = [
    "//envoy/http:header_map_interface",
    "//source/common/http:headers_lib",
    "//source/common/http:header_map_lib",
    "//source/common/http:header_utility_lib",
    "@envoy_api//envoy/extensions/filters/http/eric_proxy/v3:pkg_cc_proto",
  ],
)