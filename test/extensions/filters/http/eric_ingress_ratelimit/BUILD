load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
)
load("//test/extensions:extensions_build_system.bzl",
     "envoy_extension_cc_test",
)

licenses(["notice"])  # Apache 2



envoy_extension_cc_test(
    name = "filter_config_test",
    srcs = ["filter_config_test.cc"],
    extension_names = ["envoy.filters.http.eric_ingress_ratelimit"],
    size = "small",
    deps = [
        "//source/extensions/filters/http/eric_ingress_ratelimit:config",
        "//source/extensions/filters/http/eric_ingress_ratelimit:ingress_ratelimit_lib",
        "@envoy_api//envoy/extensions/filters/http/eric_ingress_ratelimit/v3:pkg_cc_proto",
        "//test/mocks/server:factory_context_mocks",
        "//test/mocks/server:instance_mocks",
        "//test/test_common:utility_lib",
    ],
)

envoy_extension_cc_test(
    name = "ratelimit_nw_test",
    srcs = ["ratelimit_nw_test.cc"],
    extension_names = ["envoy.filters.http.eric_ingress_ratelimit"],
    external_deps = ["json"],
    size = "small",
    deps = [
        "//test/integration:http_integration_lib",
        "//source/extensions/filters/http/buffer:config",
        "//source/extensions/filters/http/cdn_loop:config",
        "//envoy/http:codes_interface",
        "//envoy/http:filter_interface",
        "//source/extensions/filters/http/eric_ingress_ratelimit:ingress_ratelimit_lib",
        "//test/mocks/http:http_mocks",
        "//test/test_common:utility_lib",
        "//source/extensions/filters/http/eric_ingress_ratelimit:config",
        "@envoy_api//envoy/extensions/filters/http/buffer/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/http/cdn_loop/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/http/eric_ingress_ratelimit/v3:pkg_cc_proto",
    ],
)


envoy_extension_cc_test(
    name = "ratelimit_rp_test",
    srcs = ["base_integration_test.h", "base_integration_test.cc", "ratelimit_rp_test.cc"],
    extension_names = ["envoy.filters.http.eric_ingress_ratelimit"],
    external_deps = ["json"],
    size = "small",
    deps = [
        "//test/integration:http_integration_lib",
        "//test/extensions/transport_sockets/tls/integration:ssl_integration_test",
        "//source/extensions/filters/http/buffer:config",
        "//source/extensions/filters/http/cdn_loop:config",
        "//envoy/http:codes_interface",
        "//envoy/http:filter_interface",
        "//source/extensions/filters/http/eric_ingress_ratelimit:ingress_ratelimit_lib",
        "//test/mocks/http:http_mocks",
        "//test/test_common:utility_lib",
        "//source/extensions/filters/http/eric_ingress_ratelimit:config",
        "@envoy_api//envoy/extensions/filters/http/buffer/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/http/cdn_loop/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/http/eric_ingress_ratelimit/v3:pkg_cc_proto",
    ],
)


envoy_extension_cc_test(
    name = "retry_after_header_test",
    srcs = ["retry_after_header_test.cc"],
    extension_names = ["envoy.filters.http.eric_ingress_ratelimit"],
    external_deps = ["json"],

    size = "small",
    deps = [
        "//source/extensions/filters/http/eric_ingress_ratelimit:ingress_ratelimit_lib",
        "//test/test_common:utility_lib",
        "//test/test_common:simulated_time_system_lib",

    ],
)