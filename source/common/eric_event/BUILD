load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_library(
    name = "eric_event_reporter_lib",
    srcs = ["eric_event_reporter.cc"],
    hdrs = ["eric_event_reporter.h"],
    deps = [
      "//source/common/common:logger_lib",
      "//source/common/eric_event:eric_event_lib",
      "//source/common/stream_info:eric_event_state_lib",

    ],
)

envoy_cc_library(
    name = "eric_event_lib",
    hdrs = ["eric_event.h"],
    srcs = ["eric_event.cc"],
    external_deps = ["abseil_optional", "abseil_strings"],
    deps = [
      "//source/common/protobuf:utility_lib_header",
      "//source/common/formatter:substitution_format_utility_lib",
     ],
)
