#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.h"
#include "envoy/extensions/filters/http/eric_proxy/v3/eric_proxy.pb.validate.h"
#include "source/extensions/filters/http/eric_proxy/config.h"
#include "source/extensions/filters/http/eric_proxy/proxy_filter_config.h"
#include "source/common/protobuf/protobuf.h"

#include "test/mocks/server/factory_context.h"
#include "test/mocks/server/instance.h"
#include "test/mocks/upstream/cluster_manager.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

using EricProxyFilterProtoConfig =
    envoy::extensions::filters::http::eric_proxy::v3::EricProxyConfig;

//TEST(PredExpTest, Dummy) {
// ASSERT_TRUE(1==1);
//}

// Tests that a valid config with one filter-case is properly consumed.
TEST(EricProxyFilterConfigTest, SimpleConfig) {
  const std::string yaml = R"EOF(
own_internal_port: 80
filter_cases:
  - name: default-rc
  )EOF";

  EricProxyFilterProtoConfig proto_config;
  TestUtility::loadFromYamlAndValidate(yaml, proto_config);

  testing::NiceMock<Server::Configuration::MockFactoryContext> context;
  EricProxyFilterFactory factory;

  auto cb = factory.createFilterFactoryFromProto(proto_config, "stats", context);
  Http::MockFilterChainFactoryCallbacks filter_callbacks;
  EXPECT_CALL(filter_callbacks, addStreamFilter(_));
  cb.value()(filter_callbacks);
}

// Tests that a valid config with multiple filter-case is properly consumed.
TEST(EricProxyFilterConfigTest, MultipleRcConfig) {
  const std::string yaml = R"EOF(
own_internal_port: 80
filter_cases:
  - name: default-rc
  - name: rc-1
  - name: rc-2
  )EOF";

  EricProxyFilterProtoConfig proto_config;
  TestUtility::loadFromYamlAndValidate(yaml, proto_config);

  testing::NiceMock<Server::Configuration::MockFactoryContext> context;
  EricProxyFilterFactory factory;

  auto cb = factory.createFilterFactoryFromProto(proto_config, "stats", context);
  Http::MockFilterChainFactoryCallbacks filter_callbacks;
  EXPECT_CALL(filter_callbacks, addStreamFilter(_));
  cb.value()(filter_callbacks);
}

// Tests that a valid config with multiple filter-case is properly consumed.
TEST(EricProxyFilterConfigTest, TestGetReqData) {
  const std::string yaml = R"EOF(
own_internal_port: 80
filter_cases:
  - name: default-rc
  - name: rc-1
  - name: rc-2
  )EOF";

  EricProxyFilterProtoConfig proto_config;
  TestUtility::loadFromYamlAndValidate(yaml, proto_config);

  Upstream::MockClusterManager cluster_manager_;
  auto config = std::make_shared<EricProxyFilterConfig>(proto_config, cluster_manager_);
  ASSERT_EQ(3,config->filterCases().size());
}

// Tests that a valid config with multiple filter-case is properly consumed.
TEST(EricProxyFilterConfigTest, TestGetVarData) {
  const std::string yaml = R"EOF(
own_internal_port: 80
filter_cases:
  - name: default_routing
    filter_data:
    - name: apiRoot_data
      header: 3gpp-Sbi-target-apiRoot
      extractor_regex: eric-chfsim-\d+-mnc-(?P<mnc>\d+)-mcc-(?P<mcc>\d+)
    - name: chfsim_data
      header: 3gpp-Sbi-target-apiRoot
      extractor_regex: eric-(?P<chfsim>chfsim-\d+?)-.+
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
            term_string: universal_pool
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
roaming_partners:
  - name: rp_A
    pool_name: sepp_rp_A
  )EOF";

  EricProxyFilterProtoConfig proto_config;
  TestUtility::loadFromYamlAndValidate(yaml, proto_config);
  Upstream::MockClusterManager cluster_manager_;

  auto config = std::make_shared<EricProxyFilterConfig>(proto_config, cluster_manager_) ;
  RootContext& root_cxt = config->rootContext();

  ASSERT_EQ(1,config->filterCases().size());
  ASSERT_EQ("sepp_rp_A",config->rpPoolName("rp_A"));

  ASSERT_TRUE(root_cxt.hasVarName("mnc"));
  ASSERT_TRUE(root_cxt.hasVarName("mcc"));
  ASSERT_TRUE(root_cxt.hasVarName("chfsim"));
}

}
}
}
}
