#include "envoy/extensions/filters/http/eric_ingress_ratelimit/v3/eric_ingress_ratelimit.pb.h"
#include "envoy/extensions/filters/http/eric_ingress_ratelimit/v3/eric_ingress_ratelimit.pb.validate.h"
#include "source/extensions/filters/http/eric_ingress_ratelimit/config.h"
#include "source/extensions/filters/http/eric_ingress_ratelimit/ingress_ratelimit_config.h"
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
namespace IngressRateLimitFilter {

using EricIngressRatelimitFilterProtoConfig =
    envoy::extensions::filters::http::eric_ingress_ratelimit::v3::IngressRateLimit;

//TEST(PredExpTest, Dummy) {
// ASSERT_TRUE(1==1);
//}

// Tests that a valid config with the required fields is properly consumed.
TEST(EricProxyFilterConfigTest, SimpleConfig) {
  const std::string yaml = R"EOF(
namespace: SEPP
rate_limit_service:
  service_error_action:
    action_pass_message: true
  service_cluster_name: foo
limits:
- network:
    bucket_action:
      bucket_name: ingress=GRLname.nw=internal_network
      over_limit_action: 
        action_drop_message: true
watermarks:
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
- 1.4
  )EOF";

  EricIngressRatelimitFilterProtoConfig proto_config;
  TestUtility::loadFromYamlAndValidate(yaml, proto_config);

  testing::NiceMock<Server::Configuration::MockFactoryContext> context;
  RateLimitFilterConfig factory;

  Http::FilterFactoryCb cb = factory.createFilterFactoryFromProto(proto_config, "stats", context);
  Http::MockFilterChainFactoryCallbacks filter_callbacks;
  EXPECT_CALL(filter_callbacks, addStreamFilter(_));
  cb(filter_callbacks);

}

//more to come



}
}
}
}
