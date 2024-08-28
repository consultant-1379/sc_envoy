load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
)
load("//test/extensions:extensions_build_system.bzl",
     "envoy_extension_cc_test",
      "envoy_extension_cc_test_library",

)

licenses(["notice"])  # Apache 2

envoy_extension_cc_test_library(
    name = "eric_proxy_test_lib",
    srcs = ["base_integration_test.h","base_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "//envoy/http:codes_interface",   
        "//envoy/http:filter_interface",

        "//source/common/common:base64_lib",
        "//source/common/common:base32_lib",
        "//source/common/stats:stats_lib",
        "//source/extensions/filters/http/buffer:config",
        "//source/extensions/filters/http/cdn_loop:config",
        "//source/extensions/filters/http/eric_proxy:config",
        "//source/extensions/filters/http/eric_proxy:filter_lib",
        "//source/extensions/filters/http/header_to_metadata:config",        

        "//test/extensions/filters/http/eric_proxy/config_utils:pluggable_configurator_lib",
        "//test/extensions/filters/http/eric_proxy/failover:base_failover_lib",
        "//test/extensions/filters/http/eric_proxy:pluggable_configurator_lib_old",
        # "//test/extensions/transport_sockets/tls/integration:ssl_integration_test",
        "//test/integration:http_integration_lib",
        "//test/integration:integration_lib",
        "//test/integration:socket_interface_swap_lib",
        "//test/integration/filters:encoder_decoder_buffer_filter_lib",
        "//test/integration/filters:invalid_header_filter_lib",
        "//test/integration/filters:local_reply_during_encoding_data_filter_lib",
        "//test/integration/filters:local_reply_during_encoding_filter_lib",
        "//test/integration/filters:local_reply_with_metadata_filter_lib",  
        "//test/mocks/http:http_mocks",
        "//test/mocks/server:factory_context_mocks",
        "//test/mocks/server:instance_mocks",
        "//test/mocks/stats:stats_mocks",
        "//test/test_common:utility_lib",

        "@envoy_api//envoy/config/bootstrap/v3:pkg_cc_proto",
        "@envoy_api//envoy/config/cluster/v3:pkg_cc_proto",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",   
        "@envoy_api//envoy/extensions/filters/http/cdn_loop/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/http/eric_proxy/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/network/http_connection_manager/v3:pkg_cc_proto",


    ]
)

envoy_extension_cc_test(
    name = "scp_tar_dfp_integration_test",
    srcs = ["scp_tar_dfp_integration_test.cc"],
    size = "small",
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "eric_proxy_test_lib"
    ],
)


envoy_extension_cc_test_library(
    name = "pluggable_configurator_lib_old",
    srcs = ["pluggable_configurator.h"],
        extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "//test/integration:http_integration_lib",
        "//source/extensions/clusters/aggregate:cluster",
    ],
)
envoy_extension_cc_test(
    name = "integration_test",
    srcs = ["integration_test.cc"],
    size = "small",
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "multi_header_integration_test",
    srcs = ["multi_header_integration_test.cc"],
    size = "small",
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "message_data_extraction_overwrite_test",
    srcs = ["message_data_extraction_overwrite_test.cc"],
    size = "small",
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "sepp_tfqdn_integration_test",
    srcs = ["sepp_tfqdn_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "server_header_integration_test",
    srcs = ["server_header_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "server_sbi_nf_peer_info_header_integration_test",
    srcs = ["sbi_nf_peer_info_header_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "per_nf_counters_integration_test",
    srcs = ["per_nf_counters_int_test.cc"],
    size = "small",
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "eric_proxy_test_lib",
    ],
)

envoy_extension_cc_test(
    name = "sepp_th_integration_test",
    srcs = ["sepp_th_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "sepp_th_ip_hiding_integration_test",
    srcs = ["sepp_th_ip_hiding_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "medium",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "sepp_th_fqdn_scrambling_integration_test",
    srcs = ["sepp_th_fqdn_scrambling_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "sepp_th_nrf_fqdn_mapping_integration_test",
    srcs = ["sepp_th_nrf_fqdn_mapping_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "routing_stage_dir_resp_reject_counters_integration_test",
    srcs = ["routing_stage_dir_resp_reject_counters_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "egress_screening_integration_test",
    srcs = ["egress_screening_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "sepp_tfqdn_router_test",
    srcs = ["sepp_tfqdn_router_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "sepp_tfqdn_router_integration_test",
    srcs = ["sepp_tfqdn_router_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "sepp_unique_per_rp_integration_test",
    srcs = ["sepp_unique_per_rp_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "fd_integration_test",
    srcs = ["fd_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "screening_integration_test",
    srcs = ["screening_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "counters_integration_test",
    srcs = ["counters_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "action_log_integration_test",
    srcs = ["action_log_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "ct_integration_test",
    srcs = ["ct_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "nf_disc_integration_test",
    srcs = ["nf_disc_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "message_validation_integration_test",
    srcs = ["message_validation_integration_test.cc"],
    size = "small",
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "eric_proxy_test_lib"
    ],
)

# Since we have a new reselection logic, we do not need this test.
# There is already a similar test retry_reselection_test in
# failover folder but all the scenarios are not migrated
# yet to this new test, so till then we are keeping this
# test but not including it in test runs

# envoy_extension_cc_test(
#     name = "nf_pool_reselection_integration_test",
#     srcs = ["nf_pool_reselection_integration_test.cc"],
#     size = "small",
#     extension_names = ["envoy.filters.http.eric_proxy"],
#     deps = [
#         "//test/integration:http_integration_lib",
#         "//envoy/http:codes_interface",
#         "//envoy/http:filter_interface",
#         "//source/extensions/filters/http/eric_proxy:filter_lib",
#         "//test/mocks/http:http_mocks",
#         "//test/test_common:utility_lib",
#         "//source/extensions/clusters/aggregate:cluster",
#         "//source/extensions/retry/priority/previous_priorities:config",
#         "//source/extensions/retry/host/omit_host_metadata:config",
#         "//source/extensions/filters/http/eric_proxy:config",
#         "@envoy_api//envoy/extensions/filters/http/eric_proxy/v3:pkg_cc_proto",
#     ],
# )

envoy_extension_cc_test(
    name = "scp_producer_id_integration_test",
    srcs = ["scp_producer_id_integration_test.cc"],
    size = "small",
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "remote_routing_integration_test",
    srcs = ["remote_routing_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "keep_auth_header_integration_test",
    srcs = ["keep_auth_header_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "stats_test",
    srcs = ["stats_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "body_test",
    srcs = ["body_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "body_integration_test",
    srcs = ["body_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "json_body_integration_test",
    srcs = ["json_body_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "json_conf_checks_integration_test",
    srcs = ["json_conf_checks_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "usfw_llc_integration_test",
    srcs = ["usfw_llc_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "usfw_usoc_integration_test",
    srcs = ["usfw_usoc_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],

)

envoy_extension_cc_test(
    name = "filter_config_test",
    srcs = ["filter_config_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "condition_test",
    srcs = ["condition_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "contexts_test",
    srcs = ["contexts_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "service_classifier_test",
    srcs = ["service_classifier_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    data = [
        "//test/extensions/filters/http/eric_proxy/test_data:yaml"
    ],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "filter_test",
    srcs = ["filter_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "json_test",
    srcs = ["json_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    external_deps = [
        "json",
    ],    
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "json_utils_test",
    srcs = ["json_utils_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    external_deps = [
        "json",
    ],    
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "json_operations_test",
    srcs = ["json_operations_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)
envoy_extension_cc_test(
    name = "json_modify_operations_test",
    srcs = ["json_modify_operations_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)
envoy_extension_cc_test(
    name = "json_mod_op_search_and_replace_test",
    srcs = ["json_mod_op_search_and_replace_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)
envoy_extension_cc_test(
    name = "search_and_replace_test",
    srcs = ["search_and_replace_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)
envoy_extension_cc_test(
    name = "api_prefix_integration_test",
    srcs = ["api_prefix_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)
envoy_extension_cc_test(
    name = "tfqdn_codec_test",
    srcs = ["tfqdn_codec_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)


envoy_extension_cc_test(
    name = "local_reply_integration_test",
    srcs = ["local_reply_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
     data = [
        "//test/extensions/filters/http/eric_proxy/test_data:yaml"
    ],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_extension_cc_test(
    name = "via_header_integration_test",
    srcs = ["via_header_integration_test.cc"],
    extension_names = ["envoy.filters.http.eric_proxy"],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)

envoy_cc_test(
    name = "local_reply_test",
    srcs = ["local_reply_test.cc"],
    data = [
        "//test/extensions/filters/http/eric_proxy/test_data:yaml"
    ],
    external_deps = [
        "json",
    ],
    size = "small",
    deps = [
        "eric_proxy_test_lib"
    ],
)
