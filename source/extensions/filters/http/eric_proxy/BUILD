load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "filter_lib",
    hdrs = [
        "contexts.h",
        "condition.h",
        "wrappers.h",
        "condition_config.h",
        "filter.h",
        "body.h",
        "proxy_filter_config.h",
        "stats.h",
        "json_operations.h",
        "json_utils.h",
        "tfqdn_codec.h",
        "alarm_notifier.h",
        "search_and_replace.h"
    ],
    srcs = [
        "actions_body.cc",
        "actions_discovery.cc",
        "actions_header.cc",
        "actions_json_body.cc",
        "actions_log.cc",
        "actions_misc.cc",
        "actions_routing.cc",
        "actions_lookup.cc",
        "actions_query.cc",
        "alarm_notifier.cc",
        "body.cc",
        "condition_config.cc",
        "contexts.cc",
        "filter.cc",
        "filter_phase_processing.cc",
        "firewall.cc",
        "json_operations.cc",
        "json_utils.cc",
        "proxy_filter_config.cc",
        "scp.cc",
        "sepp.cc",
        "stats.cc",
        "tfqdn_codec.cc",
        "wrappers.cc",
        "search_and_replace.cc"

    ],
    visibility = ["//visibility:public"],
    external_deps = [
        "json",
    ],
    deps = [
        "//envoy/http:codes_interface",
        "//envoy/http:filter_interface",
        "//envoy/http:header_map_interface",
        "//source/common/common:logger_lib",
        "//source/common/common:random_generator_lib",
        "//source/common/common:statusor_lib",
        "//source/common/eric_event:eric_event_lib",
        "//source/common/eric_event:eric_event_reporter_lib",
        "//source/common/http:codes_lib",
        "//source/common/http:headers_lib",
        "//source/common/http:header_map_lib",
        "//source/common/http:header_utility_lib",
        "//source/common/http:utility_lib",
        "//source/common/network:cidr_range_lib",
        "//source/common/common:base32_lib",
        "//source/common/stream_info:eric_proxy_state_lib",
        "//source/common/stream_info:eric_event_state_lib",
        "//source/extensions/common/tap:eric_tap_utility_lib",
        "//source/extensions/retry/host/previous_hosts:config",
        "//source/extensions/filters/http/common:pass_through_filter_lib",
        "@com_googlesource_code_re2//:re2",
        "@envoy_api//envoy/extensions/filters/http/eric_proxy/v3:pkg_cc_proto",
        "//source/extensions/filters/http/eric_proxy/eric_sbi_nf_peer_info:sbi_nf_peer_info_lib"
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":filter_lib",
        "//envoy/http:filter_interface",
        "//envoy/registry",
        "//envoy/server:factory_context_interface",
        "//source/common/common:statusor_lib",
        "//source/extensions/filters/http:well_known_names",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/extensions/filters/http/eric_proxy/v3:pkg_cc_proto",
    ],
)
