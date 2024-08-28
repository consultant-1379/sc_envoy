load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "eric_omit_host_metadata_dynamic_predicate_lib",
    hdrs = ["eric_omit_host_metadata_dynamic.h"],
    deps = [
        "//envoy/upstream:retry_interface",
        "//source/common/config:metadata_lib",
        "//source/common/config:well_known_names",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":eric_omit_host_metadata_dynamic_predicate_lib",
        "//envoy/registry",
        "//envoy/upstream:retry_interface",
        "@envoy_api//envoy/extensions/retry/host/eric_omit_host_metadata_dynamic/v3:pkg_cc_proto",
    ],
)
