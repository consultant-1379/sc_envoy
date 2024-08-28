load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
    "envoy_extension_cc_test_library",
)

envoy_extension_cc_test_library(
    name = "pluggable_configurator_lib",
    hdrs = [
        "pluggable_configurator.h",
        "cluster_configurator.h",
        "basic_cluster_configurator.h",
        "endpoint_md_cluster_md_configurator.h",
        "metadata_builder.h",
        # "route_configurator.h",
        # "basic_route_configurator.h"
    ],
    extension_names = ["envoy.filters.http.eric_proxy"],
    deps = [
        "//test/integration:http_integration_lib",
        "//source/extensions/clusters/aggregate:cluster"
    ],
)