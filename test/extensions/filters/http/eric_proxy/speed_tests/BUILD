load(
    "//bazel:envoy_build_system.bzl",
    "envoy_benchmark_test",
    "envoy_cc_benchmark_binary",
)

licenses(["notice"])  # Apache 2

envoy_cc_benchmark_binary(
    name = "json_operations_speed_test",
    srcs = ["json_operations_speed_test.cc"],
    external_deps = ["benchmark","json"],
    deps = [
        "//source/extensions/filters/http/eric_proxy:config",
        "//source/extensions/filters/http/eric_proxy:filter_lib",
        "@envoy_api//envoy/extensions/filters/http/eric_proxy/v3:pkg_cc_proto",
        "//test/mocks/server:factory_context_mocks",
        "//test/mocks/server:instance_mocks",
        "//test/test_common:utility_lib",
    ],
)

envoy_benchmark_test(
    name = "json_operations_speed_test_benchmark_test",
    benchmark_binary = "json_operations_speed_test",
)

envoy_cc_benchmark_binary(
    name = "json_speed_test",
    srcs = ["json_speed_test.cc"],
    external_deps = ["benchmark", "json"],
    deps = [
        "//source/extensions/filters/http/eric_proxy:config",
        "//source/extensions/filters/http/eric_proxy:filter_lib",
        "@envoy_api//envoy/extensions/filters/http/eric_proxy/v3:pkg_cc_proto",
        "//test/mocks/server:factory_context_mocks",
        "//test/mocks/server:instance_mocks",
        "//test/test_common:utility_lib",
    ],
)

envoy_benchmark_test(
    name = "json_speed_test_benchmark_test",
    benchmark_binary = "json_speed_test",
)

envoy_cc_benchmark_binary(
    name = "filter_speed_test",
    srcs = ["filter_speed_test.cc"],
    external_deps = ["benchmark", "json"],
    deps = [
        "//source/extensions/filters/http/eric_proxy:config",
        "//source/extensions/filters/http/eric_proxy:filter_lib",
        "@envoy_api//envoy/extensions/filters/http/eric_proxy/v3:pkg_cc_proto",
        "//test/mocks/server:factory_context_mocks",
        "//test/mocks/server:instance_mocks",
        "//test/test_common:utility_lib",
    ],
)

envoy_benchmark_test(
    name = "filter_speed_test_benchmark_test",
    benchmark_binary = "filter_speed_test",
)


envoy_cc_benchmark_binary(
    name = "tfqdn_codec_speed_test",
    srcs = ["tfqdn_codec_speed_test.cc"],
    external_deps = ["benchmark", "json"],
    deps = [
        "//source/extensions/filters/http/eric_proxy:filter_lib",
        "//source/common/common:base32_lib",
    ],
)

envoy_benchmark_test(
    name = "tfqdn_codec_speed_test_benchmark_test",
    benchmark_binary = "tfqdn_codec_speed_test",
)

envoy_cc_benchmark_binary(
    name = "search_replace_speed_test",
    srcs = ["search_replace_speed_test.cc"],
    external_deps = ["benchmark"],
    deps = [
        "@com_googlesource_code_re2//:re2",
    ],
)

envoy_benchmark_test(
    name = "search_replace_speed_test_benchmark_test",
    benchmark_binary = "search_replace_speed_test",
)

envoy_cc_benchmark_binary(
    name = "regex_test",
    srcs = ["regex_test.cc"],
    external_deps = ["benchmark"],
    deps = [
        "//test/mocks/server:factory_context_mocks",
        "//test/mocks/server:instance_mocks",
        "//test/test_common:utility_lib",
        "//source/extensions/filters/http/eric_proxy:config",
        "//source/extensions/filters/http/eric_proxy:filter_lib",
        "@envoy_api//envoy/extensions/filters/http/eric_proxy/v3:pkg_cc_proto",
        "//source/extensions/filters/http/cdn_loop:parser_lib",
        "//test/test_common:status_utility_lib",
    ],
)

envoy_benchmark_test(
    name = "regex_match_speed_benchmark_test",
    benchmark_binary = "regex_test",
)

envoy_cc_benchmark_binary(
    name = "fast_mod_test",
    srcs = ["fast_mod.cc"],
    external_deps = ["benchmark"],
    deps = [
        "//test/mocks/server:factory_context_mocks",
        "//test/mocks/server:instance_mocks",
        "//test/test_common:utility_lib",
        "//test/test_common:status_utility_lib",
    ],
)

envoy_benchmark_test(
    name = "fast_mod_benchmark_test",
    benchmark_binary = "fast_mod_test",
)
