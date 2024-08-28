#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "base_integration_test.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"
#include <ostream>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

class EricProxyFilterSeppUniqueHandlingPerRpIntegrationTest
    : public EricProxyIntegrationTestBase,
      public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterSeppUniqueHandlingPerRpIntegrationTest()
      : EricProxyIntegrationTestBase(
            Http::CodecClient::Type::HTTP1, GetParam(),
            EricProxyFilterSeppUniqueHandlingPerRpIntegrationTest::ericProxyHttpProxyConfig()) {}
  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);

    HttpIntegrationTest::initialize();
  }

  std::string getCounters(const std::vector<Stats::CounterSharedPtr>& counters,
                          const std::vector<absl::string_view> greps) {
    // returns true if name contains all greps
    const auto contains = [&greps](const std::string& name) -> bool {
      if (greps.empty()) {
        return true;
      }
      for (const auto g : greps) {
        if (!g.empty() && name.find(g) == std::string::npos) {
          return false;
        } else {
          continue;
        }
      }
      return true;
    };
    std::vector<Stats::CounterSharedPtr> sorted_counters;
    for (const auto& counter : counters) {
      if (!contains(counter->name())) {
        continue;
      } else {
        sorted_counters.push_back(counter);
      }
    }
    std::sort(sorted_counters.begin(), sorted_counters.end(),
              [](const Stats::CounterSharedPtr a, const Stats::CounterSharedPtr b) -> bool {
                return a->name() > b->name();
              });
    std::string res = "";
    res += "counter_map = {";
    for (const auto& counter : sorted_counters) {
      absl::StrAppend(&res, "\n", "{\"", counter->name(), "\", \"", counter->value(), "\"},");
    }
    absl::StrAppend(&res, "\n}");
    return res;
  }

  // Common configuration that sets the start-routingcase
  std::string ericProxyHttpProxyConfig() {
    return absl::StrCat(ConfigHelper::baseConfig(), fmt::format(R"EOF(
    filter_chains:
      filters:
        name: http
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: config_test
          delayed_close_timeout:
            nanos: 100
          http_filters:
            name: envoy.filters.http.router
          codec_type: HTTP1
          access_log:
            name: accesslog
            filter:
              not_health_check_filter:  {{}}
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
              path: {}
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - name: route2
                match:
                  prefix: "/"
                  headers:
                    - name: x-eric-proxy
                      present_match: true
                      invert_match: true
                route:
                  cluster_header: not_used
              - name: route1
                match:
                  prefix: "/"
                route:
                  cluster_header: x-cluster
  )EOF",
                                                                Platform::null_device_path));
  }
};

class EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl
    : public EricProxyIntegrationTestSsl,
      public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl()
      : EricProxyIntegrationTestSsl(GetParam()) {}
  void SetUp() override {}
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  std::string getCounters(const std::vector<Stats::CounterSharedPtr>& counters,
                          const std::vector<absl::string_view> greps) {
    // returns true if name contains all greps
    const auto contains = [&greps](const std::string& name) -> bool {
      if (greps.empty()) {
        return true;
      }
      for (const auto g : greps) {
        if (!g.empty() && name.find(g) == std::string::npos) {
          return false;
        } else {
          continue;
        }
      }
      return true;
    };
    std::vector<Stats::CounterSharedPtr> sorted_counters;
    for (const auto& counter : counters) {
      if (!contains(counter->name())) {
        continue;
      } else {
        sorted_counters.push_back(counter);
      }
    }
    std::sort(sorted_counters.begin(), sorted_counters.end(),
              [](const Stats::CounterSharedPtr a, const Stats::CounterSharedPtr b) -> bool {
                return a->name() > b->name();
              });
    std::string res = "";
    res += "counter_map = {";
    for (const auto& counter : sorted_counters) {
      absl::StrAppend(&res, "\n", "{\"", counter->name(), "\", \"", counter->value(), "\"},");
    }
    absl::StrAppend(&res, "\n}");
    return res;
  }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);

    HttpIntegrationTest::initialize();
  }
};

// Configuration for http filter with route MD
const std::string config_route_md = R"EOF(
    name: local_route
    virtual_hosts:
    - name: local_service
      domains: ["*"]
      routes:
      - name: route2
        match:
          prefix: "/"
          headers:
            - name: x-eric-proxy
              present_match: true
              invert_match: true
        route:
          cluster_header: not_used
      - name: route1
        match:
          prefix: "/"
        route:
          cluster_header: x-cluster
  )EOF";

// Configuration for http filter with route MD for n32c, where the ineligible_sans include the
// SAN in the client certificate (=n32c handshake not passed)
const std::string config_route_md_n32c_fail = R"EOF(
    name: local_route
    virtual_hosts:
    - name: local_service
      domains: ["*"]
      routes:
      - name: route2
        match:
          prefix: "/"
          headers:
            - name: x-eric-proxy
              present_match: true
              invert_match: true
        metadata: { filter_metadata: { envoy.filters.http.eric_proxy: { "ineligible_sans" : ["lyft1.com", "lyft.com"], "ineligible_sans_version" : 1 } } }
        route:
          cluster_header: not_used
      - name: route1
        match:
          prefix: "/"
        route:
          cluster_header: none 
  )EOF";

// Configuration for http filter with route MD for n32c, where the ineligible_sans do not match
// with the SAN in the client certificate (=n32c handshake passed)
const std::string config_route_md_n32c_succ = R"EOF(
    name: local_route
    virtual_hosts:
    - name: local_service
      domains: ["*"]
      routes:
      - name: route2
        match:
          prefix: "/"
          headers:
            - name: x-eric-proxy
              present_match: true
              invert_match: true
        metadata: { filter_metadata: { envoy.filters.http.eric_proxy: { "ineligible_sans" : ["lyft2.com", "lyft3.com"], "ineligible_sans_version" : 1 } } }
        route:
          cluster_header: not_used
      - name: route1
        match:
          prefix: "/"
        route:
          cluster_header: x-cluster 
  )EOF";

// Configuration for testing unique handling per RP, incl. the KvTables to map from domain names
// to 1) the start filter-case configured for this RP or 2) the configured name of this RP
const std::string config_unique = R"EOF(
    name: envoy.filters.http.eric_proxy
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
      name: sepp_router
      node_type: SEPP
      own_fqdn: sepp.own_plmn.com
      own_external_port: 3777
      rp_name_table : rp_san_to_name
      request_filter_cases:
        routing:
          ext_nw:
            name: "external network"
            ext_nw_fc_config_list:
            - per_rp_fc_config:
                rp_to_fc_map:
                  rp_A: rp_A_routing
                  ext: default_routing
                  external_plmn: default_routing

      callback_uri_klv_table: callback_uris
      key_list_value_tables:
        - name: callback_uris
          entries:
            - key: test_api_name_1
              value:
                - /nfInstances/*/nfServices/*/test_api_1_cb_uri_1
                - /nfInstances/*/nfServices/*/test_api_1_cb_uri_2
            - key: test_api_name_2
              value:
                - /nfInstances/*/nfServices/*/test_api_2_cb_uri_1
                - /nfInstances/*/nfServices/*/test_api_2_cb_uri_2
      key_value_tables:
        - name: rp_san_to_name
          entries:
            - key: rp_A.ext_plmn.com
              value: rp_A
            - key: 'sepp.mcc262.mnc234.3gpp.org'
              value: ext
            - key: 'www.lyft.com'
              value: external_plmn
      nf_types_requiring_t_fqdn:
        - SMF
        - PCF
      filter_cases:
        - name: default_routing
          filter_data:
          - name: apiRoot_data
            header: 3gpp-Sbi-target-apiRoot
            extractor_regex: eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
          - name: apiRoot_header
            header: 3gpp-Sbi-target-apiRoot
            variable_name:  apiRoot_hdr
          - name: chfsim_data
            header: 3gpp-Sbi-target-apiRoot
            extractor_regex: eric-(?P<chfsim>chfsim-\d+?)-.+
          - name: apiRoot_data2
            header: 3gpp-Sbi-target-apiRoot2
            variable_name: mcc
          - name: new_fqdn_value
            header: new_fqdn
            variable_name: new_fqdn
          - name: location_header
            header: location
            extractor_regex: (?P<pre>https?://)(?P<mid>[^/]+)(?P<post>/.*)
          filter_rules:
          - name: csepp_to_rp_A
            condition:
              op_and:
                arg1:
                  op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
                arg2:
                  op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
            actions:
            - action_route_to_roaming_partner:
                roaming_partner_name: rp_A
                routing_behaviour: ROUND_ROBIN
          - name: psepp_to_dfw
            condition:
              op_and:
                arg1:
                  op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456'}}
                arg2:
                  op_and:
                    arg1:
                      op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
                    arg2:
                      op_or:
                        arg1:
                          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-6'}}
                        arg2:
                          op_or:
                            arg1:
                              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-7'}}
                            arg2:
                              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-8'}}
            actions:
            - action_route_to_pool:
                pool_name:
                  term_string: cluster_0
                routing_behaviour: ROUND_ROBIN
          - name: psepp_to_pref
            condition:
              op_and:
                arg1:
                  op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
                arg2:
                  op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
            actions:
            - action_route_to_pool:
                pool_name:
                  term_string: occ
                routing_behaviour: ROUND_ROBIN
                preserve_if_indirect: TARGET_API_ROOT
                preferred_target:
                  term_header: "3gpp-Sbi-target-apiRoot"
          - name: direct_response_plain
            condition:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '987' }}
            actions:
            - action_reject_message:
                status: 543
                title: "reject test"
                message_format: PLAIN_TEXT
      roaming_partners:
        - name: rp_A
          pool_name: sepp_rp_A
  )EOF";

// Configuration for testing unique handling per RP with message screening.
// Only ingress-screening and routing are configured.
// Ingress-screening is done the same regardless of the roaming-partner.
// Routing is done differently per roaming-partner.
const std::string config_unique_ms_ph1_ph6_routing = R"EOF(
    name: envoy.filters.http.eric_proxy
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
      name: sepp_router
      node_type: SEPP
      own_fqdn: sepp.own_plmn.com
      own_external_port: 3777
      rp_name_table : rp_san_to_name
      callback_uri_klv_table: callback_uris
      request_filter_cases:
        in_request_screening:
          ext_nw:
            name: "external network"
            ext_nw_fc_config_list:
            - start_fc_for_all_rp: sc_ph1
        routing:
          ext_nw:
            name: "external network"
            ext_nw_fc_config_list:
            - per_rp_fc_config:
                rp_to_fc_map:
                  rp_A: rp_A_routing
                  ext: default_routing
                  external_plmn: default_routing
                default_fc_for_rp_not_found: default_routing
      response_filter_cases:
        out_response_screening:
          ext_nw:
            name: "external network"
            ext_nw_fc_config_list:
            - start_fc_for_all_rp: sc_ph6
      key_value_tables:
        - name: rp_san_to_name
          entries:
            - key: rp_A.ext_plmn.com
              value: rp_A
            - key: 'sepp.mcc262.mnc234.3gpp.org'
              value: ext
            - key: lyft.com
              value: external_plmn
      key_list_value_tables:
        - name: callback_uris
          entries:
            - key: test_api_name_1
              value:
                - /nfInstances/*/nfServices/*/test_api_1_cb_uri_1
                - /nfInstances/*/nfServices/*/test_api_1_cb_uri_2
            - key: test_api_name_2
              value:
                - /nfInstances/*/nfServices/*/test_api_2_cb_uri_1
                - /nfInstances/*/nfServices/*/test_api_2_cb_uri_2
      nf_types_requiring_t_fqdn:
        - SMF
        - PCF
      filter_cases:
        - name: sc_ph1
          filter_rules:
          - name: dummy_ph1
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-it-header-name-added
                value:
                  term_string: x-it-header-value-added-screening_ph1
                if_exists: NO_ACTION 
        - name: sc_ph6
          filter_rules:
          - name: dummy_ph6
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-added-by-response_ph6
                value:
                  term_string: x-it-header-value-added-screening_ph6
                if_exists: NO_ACTION
        - name: default_routing
          filter_data:
          - name: apiRoot_data
            header: 3gpp-Sbi-target-apiRoot
            extractor_regex: eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
          - name: apiRoot_header
            header: 3gpp-Sbi-target-apiRoot
            variable_name:  apiRoot_hdr
          - name: chfsim_data
            header: 3gpp-Sbi-target-apiRoot
            extractor_regex: eric-(?P<chfsim>chfsim-\d+?)-.+
          - name: apiRoot_data2
            header: 3gpp-Sbi-target-apiRoot2
            variable_name: mcc
          - name: new_fqdn_value
            header: new_fqdn
            variable_name: new_fqdn
          - name: location_header
            header: location
            extractor_regex: (?P<pre>https?://)(?P<mid>[^/]+)(?P<post>/.*)
          filter_rules:
          - name: psepp_to_dfw
            condition:
              op_and:
                arg1:
                  op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mnc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456'}}
                arg2:
                  op_and:
                    arg1:
                      op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '456' }}
                    arg2:
                      op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: chfsim }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: 'chfsim-6'}}
            actions:
            - action_route_to_pool:
                pool_name:
                  term_string: cluster_0
                routing_behaviour: PREFERRED
                preserve_if_indirect: TARGET_API_ROOT
                preferred_target:
                  term_header: "3gpp-Sbi-target-apiRoot"
      roaming_partners:
        - name: rp_A
          pool_name: sepp_rp_A
)EOF";

// Configuration for testing unique handling per RP with message screening. The KvTable to
// match from domain names to RP names is included only in the message screening filter
// instance (because RP counters should not be created and stepped twice by both, message
// screening and routing filter instances) while the KvTable for selecting the start
// filter-case stays in the configuration for the routing filter instance, see further below.
const std::string config_unique_ms_ph1_ph6_modify_status = R"EOF(
    name: envoy.filters.http.eric_proxy
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
      name: screening_ph1_ph6
      node_type: SEPP
      own_fqdn: sepp.own_plmn.com
      own_external_port: 3777
      rp_name_table : rp_san_to_name
      request_filter_cases:
        in_request_screening:
          ext_nw:
            name: "external network"
            ext_nw_fc_config_list:
            - start_fc_for_all_rp: sc_ph1
      response_filter_cases:
        out_response_screening:
          ext_nw:
            name: "external network"
            ext_nw_fc_config_list:
            - start_fc_for_all_rp: sc_ph6
      key_value_tables:
        - name: rp_san_to_name
          entries:
            - key: rp_A.ext_plmn.com
              value: rp_A
            - key: 'sepp.mcc262.mnc234.3gpp.org'
              value: ext
            - key: lyft.com
              value: external_plmn
      filter_cases:
        - name: sc_ph1
          filter_rules:
          - name: dummy_ph1
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-it-header-name-added
                value:
                  term_string: x-it-header-value-added-screening_ph1
                if_exists: NO_ACTION
            - action_reject_message:
                status: 543
                title: "reject test"
                message_format: PLAIN_TEXT
        - name: sc_ph6
          filter_rules:
          - name: dummy_ph6
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-added-by-response_ph6
                value:
                  term_string: x-it-header-value-added-screening_ph6
                if_exists: NO_ACTION
            - action_modify_status_code:
                status: 402
                detail: "test details ignored"
                message_format: PLAIN_TEXT
)EOF";

// DND-33285: Screening case in SEPP external network triggered multiple times
// Configuration: The rp_to_fc_map has 3 RPs defined, and default_fc_for_rp_not_found is
// configured as well.
// A request comes in for an RP not in the rp_to_fc_map. It is expected that the
// filter-case configured in default_fc_for_rp_not_found is executed exactly one time.
const std::string config_dnd_33285 = R"EOF(
    name: envoy.filters.http.eric_proxy
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
      name: ingress_screening_dnd33285
      node_type: SEPP
      own_fqdn: sepp.own_plmn.com
      own_external_port: 3777
      rp_name_table : rp_san_to_name
      request_filter_cases:
        in_request_screening:
          ext_nw:
            name: "external network"
            ext_nw_fc_config_list:
            - per_rp_fc_config:
                rp_to_fc_map:
                  rp_A: sc_ph1_for_configured_RP
                  rp_C: sc_ph1_for_configured_RP
                  rp_D: sc_ph1_for_configured_RP
                default_fc_for_rp_not_found: sc_ph1_default

      key_value_tables:
        - name: rp_san_to_name
          entries:
            - key: rp_A.ext_plmn.com
              value: rp_A
            - key: rp_B.ext_plmn.com
              value: rp_B
            - key: rp_C.ext_plmn.com
              value: rp_C
      filter_cases:
        - name: sc_ph1_for_configured_RP
          filter_rules:
          - name: dummy_ph1
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-header-for-configured-RP
                value:
                  term_string: value-for-configured-RP
                if_exists: ADD
            - action_route_to_pool:
                pool_name:
                  term_string: wrong_pool
                routing_behaviour: ROUND_ROBIN
        - name: sc_ph1_default
          filter_rules:
          - name: dummy_ph1_default
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-header-for-default-fc
                value:
                  term_string: only-one-expected
                if_exists: ADD
            - action_route_to_pool:
                pool_name:
                  term_string: cluster_0
                routing_behaviour: ROUND_ROBIN

)EOF";

// DND-33287 Screening/routing cases in SEPP external network not triggered without
// any RP references
// Configuration: The rp_to_fc_map is not configured, but default_fc_for_rp_not_found is
// configured.
// A request comes in for an RP. It is expected that the filter-case configured in
// default_fc_for_rp_not_found is executed.
// The bug is that no filter case is executed at all.
const std::string config_dnd_33287 = R"EOF(
    name: envoy.filters.http.eric_proxy
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
      name: ingress_screening_dnd33287
      node_type: SEPP
      own_fqdn: sepp.own_plmn.com
      own_external_port: 3777
      rp_name_table : rp_san_to_name
      request_filter_cases:
        in_request_screening:
          ext_nw:
            name: "external network"
            ext_nw_fc_config_list:
            - per_rp_fc_config:
                default_fc_for_rp_not_found: sc_ph1_default

      key_value_tables:
        - name: rp_san_to_name
          entries:
            - key: rp_A.ext_plmn.com
              value: rp_A
      filter_cases:
        - name: sc_ph1_default
          filter_rules:
          - name: dummy_ph1_default
            condition:
              term_boolean: true
            actions:
            - action_add_header:
                name: x-header-for-default-fc
                value:
                  term_string: only-one-expected
                if_exists: ADD
            - action_route_to_pool:
                pool_name:
                  term_string: cluster_0
                routing_behaviour: ROUND_ROBIN

)EOF";

//------------------------------------------------------------------------
// Configuration for the Envoy Header-to-Metadata filter. Useful to inject Metadata
// into test-cases. This filter is not present in official deployments.
const std::string config_header_to_metadata = R"EOF(
name: envoy.filters.http.header_to_metadata
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.header_to_metadata.v3.Config
  request_rules:
    - header: x-eric-sepp-test-san
      on_header_present:
        metadata_namespace: eric.proxy.test
        key: test_san
        type: STRING
    - header: x-eric-sepp-test-rp-name
      on_header_present:
        metadata_namespace: eric.proxy.test
        key: test_rp_name
        type: STRING
)EOF";

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

//------------------------------------------------------------------------
//------ UNIQUE HANDLING COUNTERS PER RP - TESTS PER STATUS CODE ---------
//------------------------------------------------------------------------

// Name: UniqueHandlingExtToInt2xx
// Description: Sample request from a RP (SSL) is answered with a fake
// upstream response of status code 200
// Expected Result:
// - The 2xx response is forwarded downstream to the RP and the counters
//   'downstream_rq_2xx' and 'downstream_rq_total' for this RP are stepped to 1
TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl, TestUniqueHandlingExtToInt2xx) {
  config_helper_.addFilter(config_unique);

  initializeWithRouteConfigFromYaml(config_route_md);

  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"content-length", std::to_string(fake_body.length())}};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeRequestWithBody(request_headers, fake_body);

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr upstream_request_;

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, upstream_request_));

  // Send fake upstream response:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(fake_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}};
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(fake_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());

  // verify headers in upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "cluster_0"));

  // Print all counters
  ENVOY_LOG(trace, printCounters(test_server_));
  // Verify response status code
  EXPECT_EQ("200", response->headers().getStatusValue());

  // Counter Evaluation - downstream_rq_total counter
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_"
                               "total_per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_total")->value());
  // Counter Evaluation - downstream_rq_2xx counter
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_"
                               "2xx_per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_2xx")->value());

  codec_client_->close();
}

// Name: UniqueHandlingExtToInt3xx
// Description: Sample request from a RP (SSL) is answered with a fake
// upstream response of status code 302
// Expected Result:
// - The 3xx response is forwarded downstream to the RP and the counters
//   'downstream_rq_3xx' and 'downstream_rq_total' for this RP are stepped to 1
TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl, TestUniqueHandlingExtToInt3xx) {
  config_helper_.addFilter(config_unique);

  initializeWithRouteConfigFromYaml(config_route_md);

  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"content-length", std::to_string(fake_body.length())}};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeRequestWithBody(request_headers, fake_body);

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr upstream_request_;

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, upstream_request_));

  // Send fake upstream response:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "302"},
      {"content-length", std::to_string(fake_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}};
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(fake_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());

  // verify headers in upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "cluster_0"));

  // Print all counters
  ENVOY_LOG(trace, printCounters(test_server_));

  // Verify response status code
  EXPECT_EQ("302", response->headers().getStatusValue());

  // Counter Evaluation - downstream_rq_total counter
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_"
                               "total_per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_total")->value());
  // Counter Evaluation - downstream_rq_3xx counter
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_3xx_"
                               "per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_3xx")->value());

  codec_client_->close();
}

// Name: UniqueHandlingExtToInt4xx
// Description: Sample request from a RP (SSL) is answered with a fake
// upstream response of status code 409
// Expected Result:
// - The 4xx response is forwarded downstream to the RP and the counters
//   'downstream_rq_4xx' and 'downstream_rq_total' for this RP are stepped to 1
TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl, TestUniqueHandlingExtToInt4xx) {
  config_helper_.addFilter(config_unique);

  initializeWithRouteConfigFromYaml(config_route_md);

  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"content-length", std::to_string(fake_body.length())}};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeRequestWithBody(request_headers, fake_body);

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr upstream_request_;

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, upstream_request_));

  // Send fake upstream response:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "409"},
      {"content-length", std::to_string(fake_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}};
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(fake_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());

  // verify headers in upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "cluster_0"));

  // Print all counters
  ENVOY_LOG(trace, printCounters(test_server_));

  // Verify response status code
  EXPECT_EQ("409", response->headers().getStatusValue());

  // Counter Evaluation - downstream_rq_total counter
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_"
                               "total_per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_total")->value());
  // Counter Evaluation - downstream_rq_4xx counter
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_4xx_"
                               "per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_4xx")->value());

  codec_client_->close();
}

// Name: UniqueHandlingExtToInt5xx
// Description: Sample request from a RP (SSL) is answered with a fake
// upstream response of status code 503
// Expected Result:
// - The 5xx response is forwarded downstream to the RP and the counters
//   'downstream_rq_5xx' and 'downstream_rq_total' for this RP are stepped to 1
TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl, TestUniqueHandlingExtToInt5xx) {
  config_helper_.addFilter(config_unique);

  initializeWithRouteConfigFromYaml(config_route_md);

  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"content-length", std::to_string(fake_body.length())}};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeRequestWithBody(request_headers, fake_body);

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr upstream_request_;

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, upstream_request_));

  // Send fake upstream response:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "503"},
      {"content-length", std::to_string(fake_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}};
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(fake_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());

  // verify headers in upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "cluster_0"));

  // Print all counters
  ENVOY_LOG(trace, printCounters(test_server_));

  // Verify response status code
  EXPECT_EQ("503", response->headers().getStatusValue());

  // Counter Evaluation - downstream_rq_total counter
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_"
                               "total_per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_total")->value());
  // Counter Evaluation - downstream_rq_5xx counter
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_5xx_"
                               "per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_5xx")->value());

  codec_client_->close();
}

// Description: Sample request from a RP (SSL) is answered with a fake upstream
// response of status code 100, followed by another response of status code 200.
// Only the 200 Ok is forwarded downstream.
// Note: the 1xx HTTP status code shall actually not be used within the 3GPP NFs,
// still it is good to verify that we can handle it and that 1xx counters would
// be stepped, if such a status code is received from another NF.
// Name: TestUniqueHandlingExtToInt1xx2xx
// Expected Result:
// - Only the 200 response is forwarded downstream to the RP and the counters
//   'downstream_rq_2xx' and 'downstream_rq_total' for this RP are stepped once.
// - 1xx counters are stepped for upstream only.
TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl, TestUniqueHandlingExtToInt1xx2xx) {
  config_helper_.addFilter(config_unique);

  initializeWithRouteConfigFromYaml(config_route_md);

  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"content-length", std::to_string(fake_body.length())}};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeRequestWithBody(request_headers, fake_body);

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr upstream_request_;

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, upstream_request_));

  // Send fake upstream responses, first 100 CONTINUE, then 200 OK:
  Http::TestResponseHeaderMapImpl response_headers_100{{":status", "100"}};
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};

  upstream_request_->encode1xxHeaders(response_headers_100);
  upstream_request_->encodeHeaders(response_headers, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());

  // verify headers in upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "cluster_0"));

  // Print all counters
  ENVOY_LOG(trace, printCounters(test_server_));

  // Verify response status code
  EXPECT_EQ("200", response->headers().getStatusValue());

  // Counter Evaluation - downstream_rq_total counter
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_total")->value());
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_"
                               "total_per_roaming_partner")
                     ->value());

  // Counter Evaluation - rq_xx counters
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_2xx")->value());
  EXPECT_EQ(0UL, test_server_->counter("http.config_test.downstream_rq_1xx")->value());
  EXPECT_EQ(1UL, test_server_->counter("cluster.cluster_0.upstream_rq_1xx")->value());
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_2xx_"
                               "per_roaming_partner")
                     ->value());

  codec_client_->close();
}

//------------------------------------------------------------------------
//------ UNIQUE HANDLING COUNTERS PER RP - LOCAL REPLY TESTS -------------
//------------------------------------------------------------------------

// Name: UniqueHandlingExtToIntDirectRespReject
// Description: Sample request from a RP (SSL) matches a filter rule that
// triggers an action_reject_message with status code 543.
// Expected Result:
// - The request is rejected with status code 543 and the respective counters
//   'downstream_rq_5xx' and 'downstream_rq_total' for this RP are stepped to 1
TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl,
       TestUniqueHandlingExtToIntDirectRespReject) {
  config_helper_.addFilter(config_unique);

  initializeWithRouteConfigFromYaml(config_route_md);

  // Send a request that matches the direct response (action_reject_message) filter rule
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-987-mcc-987:80"}};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);

  ASSERT_TRUE(response->waitForEndStream());

  // Verify response
  EXPECT_EQ("543", response->headers().getStatusValue());
  EXPECT_EQ("text/plain", response->headers().getContentTypeValue());
  EXPECT_EQ("reject test", response->body());
  EXPECT_EQ(fmt::format("{}", response->body().size()), response->headers().getContentLengthValue());

  // Print all counters
  ENVOY_LOG(trace, printCounters(test_server_));

  // Counter Evaluation - downstream_rq_total counter
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_total")->value());
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_"
                               "total_per_roaming_partner")
                     ->value());

  // Counter Evaluation - rq_xx counters
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_5xx")->value());
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_5xx_"
                               "per_roaming_partner")
                     ->value());

  codec_client_->close();
}

// Name: UniqueHandlingExtToIntModifyStatusCode
// Description: Sample request from a RP (SSL) matches a filter rule that
// triggers an action_modify_status_code, that changes the status code to 402.
// Expected Result:
// - The request is responded with status code 402 and the respective counters
//   'downstream_rq_4xx' and 'downstream_rq_total' for this RP are stepped to 1
TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl,
       TestUniqueHandlingExtToIntModifyStatusCode) {
  config_helper_.addFilter(config_unique_ms_ph1_ph6_modify_status);
  initializeWithRouteConfigFromYaml(config_route_md);

  // Send a request that matches the local reply (action_modify_status_code) filter rule
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-987-mcc-987:80"}};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);

  ASSERT_TRUE(response->waitForEndStream());

  // Verify status code
  EXPECT_EQ("402", response->headers().getStatusValue()); // modified status code

  // Print all counters
  ENVOY_LOG(trace, printCounters(test_server_));

  // Counter Evaluation - downstream_rq_total counter
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_total")->value());
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_total_per_roaming_partner")
                     ->value());

  // Counter Evaluation - rq_4xx counters (modified status code)
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_4xx")->value());
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_4xx_"
                               "per_roaming_partner")
                     ->value());

  codec_client_->close();
}

//------------------------------------------------------------------------
//------ UNIQUE HANDLING COUNTERS PER RP - MESSAGE SCREENING TESTS -------
//------------------------------------------------------------------------

// Name: UniqueHandlingExtToIntMessageScreening
// Description: This TC configures unique handling in the routing filter instance
// together with another filter instance for message screening. In this case the RP
// counters should be stepped from the message screening filter instance instead
// of from the routing filter instance. A sample request is coming from a RP and
// is expected to be successful (200 OK).
// Expected Result:
// - The request is responded with status code 200 OK and the respective counters
//   'downstream_rq_2xx' and 'downstream_rq_total' for this RP are stepped to 1
TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl,
       TestUniqueHandlingExtToIntMessageScreening) {
  config_helper_.addFilter(config_unique_ms_ph1_ph6_routing);

  initializeWithRouteConfigFromYaml(config_route_md);

  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"content-length", std::to_string(fake_body.length())}};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeRequestWithBody(request_headers, fake_body);

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr upstream_request_;

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, upstream_request_));

  // Send fake upstream response:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(fake_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}};
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(fake_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());

  // verify headers in upstream request
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "cluster_0"));

  // Print all counters
  ENVOY_LOG(trace, printCounters(test_server_));

  // Verify response
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_THAT(
      upstream_request_->headers(),
      Http::HeaderValueOf("x-it-header-name-added", "x-it-header-value-added-screening_ph1"));
  EXPECT_THAT(response->headers(), Http::HeaderValueOf("x-added-by-response_ph6",
                                                       "x-it-header-value-added-screening_ph6"));

  // Counter Evaluation - downstream_rq_total counter
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_"
                               "total_per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_total")->value());
  // Counter Evaluation - downstream_rq_2xx counter
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_2xx_"
                               "per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_2xx")->value());

  codec_client_->close();
}

//------------------------------------------------------------------------
//------ UNIQUE HANDLING PER RP - NON-SSL TESTS --------------------------
//------------------------------------------------------------------------
// could be used to test a Unique Handling per RP configuration for
// non-SSL requests, e.g. requests coming from the internal PLMN to be
// properly tagged as 'origin_int' and routed via the start filter-case
// configured for the own-plmn.

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterSeppUniqueHandlingPerRpIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTest, TestUniqueHandlingPerRp) {
  GTEST_SKIP() << "Skipping TC because it is not testing unique handling. Can be used to create "
                  "tests of unique handling for requests coming from own PLMN.";
  config_helper_.addFilter(config_unique);
  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "MVZGSYZNMNUGM43JNUWTMLLNNZRS2NBVGYWW2Y3DFU2DKNR2GM3TONY.sepp.own_plmn.com"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(headers, 0, default_response_headers_, 0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "cluster_0"));

  codec_client_->close();
}

//------------------------------------------------------------------------
//------ DND-33285 Screening case in SEPP external network triggered multiple times
// Configuration: The rp_to_fc_map has 3 RPs defined, and default_fc_for_rp_not_found is
// configured as well.
// A request comes in for an RP not in the rp_to_fc_map. It is expected that the
// filter-case configured in default_fc_for_rp_not_found is executed exactly one time.
// This means that a header is added to the request only once, not three times.
TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl,
       TestUniqueHandlingExtToIntDND33285) {
  config_helper_.addFilter(config_dnd_33285);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-987-mcc-987:80"},
      {"x-eric-sepp-test-san", "rp_Z.ext_plmn.com"},
      {"x-eric-sepp-test-rp-name", "rp_Z"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(request_headers, 0, default_response_headers_, 0);

  // Check that the test went to the filter-case for the unconfigured RP.
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "cluster_0"));

  // This header must be present extactly once (if the bug is present, the header
  // is repeated three times because we have three non-matching RPs in the configuration):
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("x-header-for-default-fc", "only-one-expected"));

  codec_client_->close();
}

//------------------------------------------------------------------------
//------ DND-33287 Screening/routing cases in SEPP external network not
//-------triggered without any RP references------------------------------
// Configuration: No rp_to_fc_map is defined, but default_fc_for_rp_not_found is
// configured as well.
// Configuration: The rp_to_fc_map is not configured, but default_fc_for_rp_not_found is
// configured.
// A request comes in for an RP. It is expected that the filter-case configured in
// default_fc_for_rp_not_found is executed.
// The bug is that no filter case is executed at all.
TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl,
       TestUniqueHandlingExtToIntDND33287) {
  config_helper_.addFilter(config_dnd_33287);
  config_helper_.addFilter(config_header_to_metadata);

  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"3gpp-Sbi-target-apiRoot", "http://eric-chfsim-1-mnc-987-mcc-987:80"},
      {"x-eric-sepp-test-san", "rp_Z.ext_plmn.com"},
      {"x-eric-sepp-test-rp-name", "rp_Z"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(request_headers, 0, default_response_headers_, 0);

  // Check that the test went to the filter-case for the unconfigured RP.
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "cluster_0"));

  // This header must be present extactly once (if the bug is present, the header
  // is repeated three times because we have three non-matching RPs in the configuration):
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("x-header-for-default-fc", "only-one-expected"));

  codec_client_->close();
}

// Name: TestN32cHandshakeRejection
// Description: N32c handshake ineligible_sans in route metadata are configured
// to match the SAN in the client certificate so that a sample request is rejected
// Expected Result:
// - The request is rejected and a local reply with status code 403 is sent
// - The request is not forwarded upstream -> upstream counters equal zero
TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl, TestN32cHandshakeRejection) {
  config_helper_.addFilter(config_unique);
  initializeWithRouteConfigFromYaml(config_route_md_n32c_fail);

  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"content-length", std::to_string(fake_body.length())}};

  const Json expected_body{
      R"({"status": 403, "title": "Forbidden", "cause": "-", "detail": "n32c_handshake_unsuccessful"})"_json};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeRequestWithBody(request_headers, fake_body);

  // wait for the response to finish, upstream is not expected because of local reply/rejection
  ASSERT_TRUE(response->waitForEndStream());

  // Print all counters
  ENVOY_LOG(trace, printCounters(test_server_));

  // Verify response status code
  EXPECT_EQ("403", response->headers().getStatusValue());
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // Counter Evaluation - downstream_rq_total counter
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_"
                               "total_per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_total")->value());
  // Counter Evaluation - downstream_rq_xx counters
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_4xx_"
                               "per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_4xx")->value());
  // Counter Evaluation - upstream counters
  EXPECT_EQ(0UL, test_server_->counter("cluster.cluster_0.upstream_cx_total")->value());
  EXPECT_EQ(0UL, test_server_->counter("cluster.cluster_0.upstream_rq_total")->value());
  codec_client_->close();
}

// Name: TestN32cHandshakeRejection
// Description: N32c handshake ineligible_sans in route metadata are configured
// to match the SAN in the client certificate so that a sample request is rejected
// Expected Result:
// - The request is rejected and a local reply with status code 403 is sent
// - The request is not forwarded upstream -> upstream counters equal zero
TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl, TestN32cRejectionCaseInsensitive) {
  config_helper_.addFilter(config_unique);
  initializeWithRouteConfigFromYaml(
      std::regex_replace(config_route_md_n32c_fail, std::regex("lyft.com"), "LyFT.com"));

  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"content-length", std::to_string(fake_body.length())}};

  const Json expected_body{
      R"({"status": 403, "title": "Forbidden", "cause": "-", "detail": "n32c_handshake_unsuccessful"})"_json};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeRequestWithBody(request_headers, fake_body);

  // wait for the response to finish, upstream is not expected because of local reply/rejection
  ASSERT_TRUE(response->waitForEndStream());

  // Print all counters
  ENVOY_LOG(trace, printCounters(test_server_));

  // Verify response status code
  EXPECT_EQ("403", response->headers().getStatusValue());
  EXPECT_EQ(expected_body, Json::parse(response->body()));

  // Counter Evaluation - downstream_rq_total counter
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_"
                               "total_per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_total")->value());
  // Counter Evaluation - downstream_rq_xx counters
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_4xx_"
                               "per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_4xx")->value());
  // Counter Evaluation - upstream counters
  EXPECT_EQ(0UL, test_server_->counter("cluster.cluster_0.upstream_cx_total")->value());
  EXPECT_EQ(0UL, test_server_->counter("cluster.cluster_0.upstream_rq_total")->value());
  codec_client_->close();
}

// Name: TestN32cHandshakePassed
// Description: N32c handshake ineligible_sans in route metadata are configured to
// NOT match the SAN in the client certificate so that a sample request is successful
// Expected Result:
// - The request is accepted and forwarded upstream -> upstream counters equal 1
// - A positive response with status code 200 is sent back
TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl, TestN32cHandshakePassed) {
  config_helper_.addFilter(config_unique);

  initializeWithRouteConfigFromYaml(config_route_md_n32c_succ);

  // A short fake body is good enough for this test
  std::string fake_body{R"({"validityPeriod": 60})"};

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "eric-chfsim-6-mnc-456-mcc-456:3777"},
      {"content-length", std::to_string(fake_body.length())}};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;

  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));

  auto response = codec_client_->makeRequestWithBody(request_headers, fake_body);

  FakeHttpConnectionPtr fake_upstream_connection;
  FakeStreamPtr upstream_request_;

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, upstream_request_));

  // Send fake upstream response:
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"},
      {"content-length", std::to_string(fake_body.length())},
      {"content-type", "application/json"},
      {"location", "https://abc.def.com/nchf-convergedcharging/v2/chargingdata/23432h23h"}};
  upstream_request_->encodeHeaders(response_headers, false);
  Buffer::OwnedImpl response_data(fake_body);
  upstream_request_->encodeData(response_data, true);

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  ASSERT_TRUE(fake_upstream_connection->close());

  // Print all counters
  ENVOY_LOG(trace, printCounters(test_server_));

  // Verify response status code
  EXPECT_EQ("200", response->headers().getStatusValue());

  // Counter Evaluation - downstream_rq_total counter
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_"
                               "total_per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_total")->value());
  // Counter Evaluation - downstream_rq_xx counters
  EXPECT_EQ(1UL, test_server_
                     ->counter("http.ingress.n8e.g3p.ingress.r12r.external_plmn.downstream_rq_2xx_"
                               "per_roaming_partner")
                     ->value());
  EXPECT_EQ(1UL, test_server_->counter("http.config_test.downstream_rq_2xx")->value());
  // Counter Evaluation - upstream counters
  EXPECT_EQ(1UL,
  test_server_->counter("cluster.cluster_0.upstream_cx_total")->value());
  EXPECT_EQ(1UL,
  test_server_->counter("cluster.cluster_0.upstream_rq_total")->value());

  codec_client_->close();
}

//------------------------------------------------------------------------------------
//------ DND-60151 3gpp-sbi-originating-network-id header handling -------------------
//------------------------------------------------------------------------------------
// Configuration for testing 3gpp-sbi-network-id header handling
const std::string network_id_ext = R"EOF(
    name: envoy.filters.http.eric_proxy
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
      name: sepp_router
      node_type: SEPP
      own_fqdn: sepp.own_plmn.com
      own_external_port: 3777
      plmn_ids:
        primary_plmn_id:
          mnc: "011"
          mcc: "263"
        additional_plmn_ids:
          - mcc: "263"
            mnc: "022"
      rp_name_table : rp_san_to_name
      callback_uri_klv_table: callback_uris
      request_filter_cases:
        in_request_screening:
          ext_nw:
            name: "external network"
            ext_nw_fc_config_list:
            - start_fc_for_all_rp: sc_ph1
        routing:
          ext_nw:
            name: "external network"
            ext_nw_fc_config_list:
            - per_rp_fc_config:
                rp_to_fc_map:
                  rp_A: default_routing
                  ext: default_routing
                  external_plmn: default_routing
                default_fc_for_rp_not_found: default_routing
      key_value_tables:
        - name: rp_san_to_name
          entries:
            - key: rp_A.ext_plmn.com
              value: rp_A
            - key: 'sepp.mcc262.mnc234.3gpp.org'
              value: rp_A
            - key: 'www.lyft.com'
              value: rp_A
      filter_cases:
        - name: sc_ph1
          filter_rules:
          - name: dummy_ph1
            condition:
              op_equals_case_insensitive: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'x-fix-network-id'}, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'true'}}
            actions:
            - action_modify_header:
                name: 3gpp-sbi-originating-network-id
                replace_value:
                  term_string: " 262-02"
        - name: default_routing
          filter_rules:
          - name: psepp_to_dfw
            condition:
              term_boolean: true
            actions:
            - action_route_to_pool:
                pool_name:
                  term_string: cluster_0
                routing_behaviour: ROUND_ROBIN
      roaming_partners:
        - name: rp_A
          pool_name: sepp_rp_A
          plmn_ids:
            primary_plmn_id:
              mnc: "01"
              mcc: "262"
            additional_plmn_ids:
              - mcc: "262"
                mnc: "02"
)EOF";

// Configuration for testing 3gpp-sbi-network-id header handling
const std::string network_id_own = R"EOF(
    name: envoy.filters.http.eric_proxy
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
      name: sepp_router
      node_type: SEPP
      own_fqdn: sepp.own_plmn.com
      own_internal_port: 80
      plmn_ids:
        primary_plmn_id:
          mnc: "011"
          mcc: "263"
        additional_plmn_ids:
          - mcc: "263"
            mnc: "022"
      callback_uri_klv_table: callback_uris
      request_filter_cases:
        routing:
          own_nw:
            name: "internal_network"
            start_fc_list:
              - default_routing
      filter_cases: 
        - name: default_routing
          filter_rules:
          - name: psepp_to_dfw
            condition:
              term_boolean: true
            actions:
            - action_route_to_pool:
                pool_name:
                  term_string: cluster_0
                routing_behaviour: ROUND_ROBIN
      roaming_partners:
        - name: rp_A
          pool_name: sepp_rp_A
          plmn_ids:
            primary_plmn_id:
              mnc: "01"
              mcc: "262"
            additional_plmn_ids:
              - mcc: "262"
                mnc: "02"
)EOF";

// Name: NetworkIdHeaderFromExt
// Description: Three requests from a rp_A (SSL)
// * Req_1 with valid originating-network-id header based on configured plmn ids (primary).
//   Request gets forwarded correctly, 200 response
// * Req_2  with invalid header value, but corrected by screening. Request gets forwarded correctly,
// 200 response
// * Req_3 with invalid header value, not corrected. Request gets dropped

TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTestSsl, NetworkIdHeaderFromExt) {
  config_helper_.addFilter(network_id_ext);
  initializeWithRouteConfigFromYaml(config_route_md);
  Http::TestRequestHeaderMapImpl request_headers{{":method", "GET"},
                                                 {":path", "/test_api_name_1/v1/"},
                                                 {":authority", "sepp.own_plmn.com:3777"},
                                                 {"3gpp-Sbi-Originating-Network-Id", " 262-01"}};

  ConnectionCreationFunction creator = [&]() -> Network::ClientConnectionPtr {
    return makeSslClientConnection(
        Ssl::ClientSslTransportOptions().setAlpn(true).setSan(san_to_match_));
  };
  ConnectionCreationFunction* create_connection = &creator;
  codec_client_ = makeHttpConnection(
      create_connection ? ((*create_connection)()) : makeClientConnection((lookupPort("http"))));
  // auto response = codec_client_->makeRequestWithBody(request_headers, fake_body);
  // Req_1
  auto response = sendRequestAndWaitForResponse(request_headers, 0, default_response_headers_, 0);

  // FakeHttpConnectionPtr fake_upstream_connection;
  // FakeStreamPtr upstream_request_;
  // ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  // ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, upstream_request_));

  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());
  // verify headers in upstream request

  // originating-network-id header still wrong but corrected with screening
  request_headers.setCopy(Http::LowerCaseString("3gpp-Sbi-Originating-Network-Id"), "263-02");

  request_headers.setCopy(Http::LowerCaseString("x-fix-network-id"), "true");
  // Req_2
  response = sendRequestAndWaitForResponse(request_headers, 0, default_response_headers_, 0);

  // response = codec_client_->makeRequestWithBody(request_headers, fake_body);
  // ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
  // ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, upstream_request_));
  // upstream_request_->encodeData(response_data, true);
  // wait for the response and close the fake upstream connection
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  // ASSERT_TRUE(fake_upstream_connection->close());
  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  // req_3
  request_headers.setCopy(Http::LowerCaseString("x-fix-network-id"), "false");
  response = codec_client_->makeHeaderOnlyRequest(request_headers);
  ASSERT_TRUE(response->waitForReset());

  codec_client_->close();
}

// Name: NetworkIdHeaderFromInt
// Description: Requests from internal network
// First contains no orignating-network-id header, request forwarded and header appended
// based on configuration
// Second comes with header but wrong values, message rejected
TEST_P(EricProxyFilterSeppUniqueHandlingPerRpIntegrationTest, NetworkIdHeaderFromInt) {
  config_helper_.addFilter(network_id_own);
  HttpIntegrationTest::initialize();

  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/test_api_name_1/v1/"},
      {":authority", "sepp.own_plmn.com:80"},
  };

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = sendRequestAndWaitForResponse(headers, 0, default_response_headers_, 0);

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());

  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));
  EXPECT_THAT(upstream_request_->headers(), Http::HeaderValueOf("x-cluster", "cluster_0"));
  EXPECT_THAT(upstream_request_->headers(),
              Http::HeaderValueOf("3gpp-Sbi-Originating-Network-Id",
                                  "263-011; src: SEPP-sepp.own_plmn.com"));

  // second request, correct header
  headers.setCopy(Http::LowerCaseString("3gpp-Sbi-Originating-Network-Id"),
                  "263-22; src: SEPP-sepp.own_plmn.com");
  response = sendRequestAndWaitForResponse(headers, 0, default_response_headers_, 0);

  // second request, wrong header, reject message
  headers.setCopy(Http::LowerCaseString("3gpp-Sbi-Originating-Network-Id"),
                  "263-092; src: SEPP-sepp.own_plmn.com");
  response = codec_client_->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  const Json expected_reject_body{
      R"({"status": 400, "title": "Bad Request", "cause": "UNSPECIFIED_MSG_FAILURE", "detail": "plmn_id_mismatch"})"_json};
  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ("application/problem+json", response->headers().getContentTypeValue());
  EXPECT_EQ(expected_reject_body, Json::parse(response->body()));

  codec_client_->close();
}

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
