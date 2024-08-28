
load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
)
load("//test/extensions:extensions_build_system.bzl",
     "envoy_extension_cc_test",
     "envoy_extension_cc_test_library",
)

licenses(["notice"])  # Apache 2


# envoy_extension_cc_test(
#     name = "nf_pool_reselection_override_host_test",
#     srcs = ["nf_pool_reselection_override_host_test.cc"],
#     size = "small",
#     extension_names = ["envoy.filters.http.eric_proxy"],
#     deps = [
#         "//test/extensions/filters/http/eric_proxy/failover:base_failover_lib",
#         "//test/integration:http_integration_lib",
#         "//envoy/http:codes_interface",
#         "//envoy/http:filter_interface",
#         "//source/extensions/filters/http/eric_proxy:filter_lib",
#         "//test/mocks/http:http_mocks",
#         "//test/test_common:utility_lib",
#         "//source/extensions/clusters/aggregate:cluster",
#         "//source/extensions/retry/priority/eric_reselect_priorities:config",
#         "//source/extensions/retry/host/eric_omit_host_metadata_dynamic:config",
#         "//source/extensions/retry/host/previous_hosts:config",
#         "//source/extensions/filters/http/eric_proxy:config",
#         "@envoy_api//envoy/extensions/filters/http/eric_proxy/v3:pkg_cc_proto",
#     ],
# )

envoy_extension_cc_test(
    name = "cds_update_test",
    srcs = ["cds_update_test.cc"],
    size = "small",
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "//test/extensions/filters/http/eric_proxy/failover:base_failover_lib",
        "//source/common/config:protobuf_link_hacks",
        "//source/common/protobuf:utility_lib",
        "//test/common/grpc:grpc_client_integration_lib",
        "//test/config:v2_link_hacks",
        "//test/mocks/runtime:runtime_mocks",
        "//test/test_common:network_utility_lib",
        "//test/test_common:resources_lib",
        "@envoy_api//envoy/config/cluster/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/discovery/v3:pkg_cc_proto",
    ],
)

envoy_extension_cc_test_library(
    name = "base_failover_lib",
    srcs = ["base_failover.h"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "//test/integration:http_integration_lib",
        "//envoy/http:codes_interface",
        "//envoy/http:filter_interface",
        "//source/extensions/filters/http/eric_proxy:filter_lib",
        "//test/mocks/http:http_mocks",
        "//test/test_common:utility_lib",
        "//source/extensions/clusters/aggregate:cluster",
        "//source/extensions/filters/http/cdn_loop:config",
        "//source/extensions/retry/priority/eric_reselect_priorities:config",
        "//source/extensions/retry/host/eric_omit_host_metadata_dynamic:config",
        "//source/extensions/retry/host/eric_loop_prevention:config",
        "//source/extensions/retry/host/previous_hosts:config",
        "//source/extensions/filters/http/eric_proxy:config",
        "@envoy_api//envoy/extensions/filters/http/eric_proxy/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/http/cdn_loop/v3:pkg_cc_proto",

    ],
)


envoy_extension_cc_test_library(
    name = "base_dual_stack_lib",
    srcs = ["base_dual_stack.h"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "//test/integration:http_integration_lib",
        "//envoy/http:codes_interface",
        "//envoy/http:filter_interface",
        "//source/extensions/filters/http/eric_proxy:filter_lib",
        "//test/mocks/http:http_mocks",
        "//test/test_common:utility_lib",
        "//source/extensions/clusters/aggregate:cluster",
        "//source/extensions/filters/http/cdn_loop:config",
        "//source/extensions/retry/priority/eric_reselect_priorities:config",
        "//source/extensions/retry/host/eric_omit_host_metadata_dynamic:config",
        "//source/extensions/retry/host/eric_loop_prevention:config",
        "//source/extensions/retry/host/previous_hosts:config",
        "//source/extensions/filters/http/eric_proxy:config",
        "@envoy_api//envoy/extensions/filters/http/eric_proxy/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/http/cdn_loop/v3:pkg_cc_proto",

    ],
)


envoy_extension_cc_test(
    name = "retry_reselection_test",
    srcs = ["retry_reselection_test.cc"],
    size = "small",
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "//test/extensions/filters/http/eric_proxy/failover:base_failover_lib",
    ],
)

envoy_extension_cc_test(
    name = "outlier_detection_test",
    srcs = ["outlier_detection_test.cc"],
    size = "small",
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "//test/extensions/filters/http/eric_proxy/failover:base_failover_lib",
    ],
)



envoy_extension_cc_test(
    name = "loop_prevention_test",
    srcs = ["loop_prevention.cc"],
    size = "small",
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "//test/extensions/filters/http/eric_proxy/failover:base_failover_lib",
    ],
)


envoy_extension_cc_test(
    name = "dual_stack_routing_test",
    srcs = ["dual_stack_routing_test.cc"],
    size = "small",
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "//test/extensions/filters/http/eric_proxy/failover:base_failover_lib",
    ],
)


envoy_extension_cc_test(
    name = "dual_stack_loop_prevention_test",
    srcs = ["dual_stack_loop_prevention_test.cc"],
    size = "small",
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "//test/extensions/filters/http/eric_proxy/failover:base_failover_lib",
    ],
)


envoy_extension_cc_test(
    name = "dual_stack_outlier_test",
    srcs = ["dual_stack_outlier_test.cc"],
    size = "small",
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "//test/extensions/filters/http/eric_proxy/failover:base_failover_lib",
    ],
)


