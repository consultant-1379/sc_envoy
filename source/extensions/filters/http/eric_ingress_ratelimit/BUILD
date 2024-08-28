load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

# Ratelimit L7 HTTP filter

envoy_extension_package()

envoy_cc_library(
    name = "ingress_ratelimit_lib",
    srcs = [
        "ratelimit.cc",
        "ingress_ratelimit_config.cc",
        "retry_after_header_format.cc",
        "rl_stats.cc"
    ],
    hdrs = [
        "ratelimit.h",
        "ingress_ratelimit_config.h",
        "rl_stats.h"
    ],
    external_deps = [
        "json",
    ],
    deps = [
        "//envoy/http:codes_interface",
        "//envoy/http:filter_interface",
        "//envoy/http:header_map_interface",
        "//source/common/http:codes_lib",
        "//source/common/http:headers_lib",
        "//source/common/http:header_map_lib",
        "//source/common/http:header_utility_lib",
        "//source/common/http:utility_lib",
        "//source/common/common:assert_lib",
        "//source/common/common:empty_string",
        "//source/common/common:enum_to_int",
        "//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy_api//envoy/extensions/filters/http/eric_ingress_ratelimit/v3:pkg_cc_proto",
    ],
)



envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":ingress_ratelimit_lib",
        "//envoy/http:filter_interface",
        "//envoy/registry",
        "//source/common/config:utility_lib",
        "//source/common/protobuf:utility_lib",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/extensions/filters/http/eric_ingress_ratelimit/v3:pkg_cc_proto",
    ],
)
