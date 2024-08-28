load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "eric_reselect_priorities_lib",
    srcs = ["eric_reselect_priorities.cc"],
    hdrs = ["eric_reselect_priorities.h"],
    deps = [
        "//envoy/upstream:retry_interface",
        "//source/common/upstream:load_balancer_lib",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":eric_reselect_priorities_lib",
        "//envoy/registry",
        "//envoy/upstream:retry_interface",
        "//source/common/protobuf",
        "@envoy_api//envoy/extensions/retry/priority/eric_reselect_priorities/v3:pkg_cc_proto",
    ],
)
