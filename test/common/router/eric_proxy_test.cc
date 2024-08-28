#include "envoy/http/filter.h"
#include "source/common/router/eric_proxy.h"
#include "source/common/protobuf/protobuf.h"

#include "test/mocks/server/factory_context.h"
#include "test/mocks/server/instance.h"

#include "test/common/http/common.h"
#include "test/common/router/router_test_base.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/local_info/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/router/mocks.h"
#include "test/mocks/runtime/mocks.h"
#include "test/mocks/ssl/mocks.h"
#include "test/mocks/tracing/mocks.h"
#include "test/mocks/upstream/cluster_manager.h"
#include "test/mocks/upstream/host.h"
#include "test/mocks/stream_info/mocks.h"
#include "test/test_common/environment.h"
#include "test/test_common/printers.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/test_runtime.h"
#include "test/test_common/utility.h"


#include "test/common/router/router_test_base.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <memory>
#include <string>

namespace Envoy {
namespace Router {

using testing::AtLeast;
using ::testing::ElementsAre;
using ::testing::NiceMock;
using ::testing::Pair;
using ::testing::Return;
using ::testing::ReturnPointee;
using ::testing::ReturnRef;

class EricProxyTarListTest : public ::testing::Test {
protected:
  Http::MockStreamDecoderFilterCallbacks decoder_callbacks_;

  void SetUp() override {
    EXPECT_CALL(decoder_callbacks_, connection()).Times(testing::AtLeast(0));
    EXPECT_CALL(decoder_callbacks_, streamId()).Times(testing::AtLeast(0));
  }
};


TEST_F(EricProxyTarListTest, EricProxyTarListTest_basic) {

  std::shared_ptr<TarList> tar_list_ = std::make_shared<TarList>(&decoder_callbacks_);
  EXPECT_TRUE(tar_list_ != nullptr);

  std::vector<std::string> tar_values;
  tar_values.push_back("http://eric-chfsim-1-mnc-123-mcc-123:80");
  tar_values.push_back("tar_val1");
  tar_values.push_back("tar_val2");
  tar_values.push_back("tar_val3");  

  ProtobufWkt::Struct metadata;
  auto& tar_values_md = *(*metadata.mutable_fields())["target-api-root-values"].mutable_list_value();
  for (auto tar_val: tar_values){
    tar_values_md.add_values()->set_string_value(tar_val);
  }
  
  ::google::protobuf::Map<std::string, ::google::protobuf::Struct> cb_filter_md;
  cb_filter_md["eric_proxy"] =  metadata;

  tar_list_->setTarValuesFromMd(&cb_filter_md);

  for (int i = 0; i < 10 ; i++ )
    for (auto tar_val: tar_values) EXPECT_EQ(tar_list_->getNextTarValue(), tar_val );
  
}

// if TarList does not fin the TaR Values in dyn. MD getNextTarValue should return an empty string
TEST_F(EricProxyTarListTest, EricProxyTarListTest_no_tar_values_in_md) {

  std::shared_ptr<TarList> tar_list_ = std::make_shared<TarList>(&decoder_callbacks_);
  EXPECT_TRUE(tar_list_ != nullptr);

  ProtobufWkt::Struct metadata;
  
  ::google::protobuf::Map<std::string, ::google::protobuf::Struct> cb_filter_md;
  cb_filter_md["eric_proxy"] =  metadata;

  tar_list_->setTarValuesFromMd(&cb_filter_md);
  EXPECT_EQ(tar_list_->getNextTarValue(), "" );
  
}

// if TarList was not set up with dyn. MD getNextTarValue should return an empty string
TEST_F(EricProxyTarListTest, EricProxyTarListTest_set_tar_values_not_called) {

  std::shared_ptr<TarList> tar_list_ = std::make_shared<TarList>(&decoder_callbacks_);
  EXPECT_TRUE(tar_list_ != nullptr);
  EXPECT_EQ(tar_list_->getNextTarValue(), "" );
  
}

class RouterTestPreserveDiscoveryHeaders : public RouterTestBase {
public:
  RouterTestPreserveDiscoveryHeaders()
      : RouterTestBase(false, true, false, Protobuf::RepeatedPtrField<std::string>{}) {}

  envoy::config::core::v3::Metadata getHostMetaDataIndirect() {
    return TestUtility::parseYaml<envoy::config::core::v3::Metadata>(
        R"EOF(
        filter_metadata:
          envoy.eric_proxy:
            support: [Indirect]
      )EOF");
  }
  envoy::config::core::v3::Metadata getHostMetaDataNf() {
    return TestUtility::parseYaml<envoy::config::core::v3::Metadata>(
        R"EOF(
        filter_metadata:
          envoy.eric_proxy:
            support: [NF]
      )EOF");
  }


};

class MockRetryOptionsPredicate : public Upstream::RetryOptionsPredicate {
public:
  MOCK_METHOD(UpdateOptionsReturn, updateOptions, (const UpdateOptionsParameters& parameters),
              (const));
};

// Test cases for preserving discovery parameters for indirect routing
TEST_F(RouterTestPreserveDiscoveryHeaders, EricProxy_preserve_disc_par_if_indirect_basic) {

  std::vector<std::string> disc_params_to_preserved;
  auto i=1;
  while (i < 4) {
    disc_params_to_preserved.push_back("par" + std::to_string(i));
    i++;
  }

  ProtobufWkt::Struct metadata;
  // if preserving (remote-round-robin) shoud be tied to the "target-api-root-processing"
  *(*metadata.mutable_fields())["target-api-root-processing"].mutable_string_value() = "true";
  *(*metadata.mutable_fields())["target-api-root-value"].mutable_string_value() = "TaRValue1";

  auto& disc_params_to_preserved_md =
      *(*metadata.mutable_fields())["disc-parameters-to-be-preserved-if-indirect"].mutable_list_value();

  for (auto disc_param : disc_params_to_preserved) {
    disc_params_to_preserved_md.add_values()->set_string_value(disc_param);
  }
  
  // set dynamic metadata like setDynamicMetadata("eric_proxy", metadata) would do
  (*callbacks_.stream_info_.metadata_.mutable_filter_metadata())["eric_proxy"] = metadata;

  auto host_metadata_indirect = std::make_shared<envoy::config::core::v3::Metadata>(getHostMetaDataIndirect());
  auto host_metadata_nf = std::make_shared<envoy::config::core::v3::Metadata>(getHostMetaDataNf());

  std::shared_ptr<NiceMock<Envoy::Upstream::MockHostDescription>> host(
      new NiceMock<Envoy::Upstream::MockHostDescription>());

  cm_.thread_local_cluster_.conn_pool_.host_ = host;
  ON_CALL(*host, metadata()).WillByDefault(Return(host_metadata_nf));

  Http::TestRequestHeaderMapImpl headers{
    {"x-envoy-retry-on", "5xx"}, 
    {"x-envoy-internal", "true"},
    {"3gpp-Sbi-target-apiRoot", "TaR1"},  
    {"3gpp-Sbi-Discovery-par1", "disc-par1-val1"}, 
    {"3gpp-Sbi-Discovery-par2", "disc-par1-val2"}, 
    {"3gpp-Sbi-Discovery-par3", "disc-par1-val3"}, 
    {"3gpp-Sbi-Discovery-par4", "disc-par1-val4"}, 
    };

//--- from EnvoyAttemptCountInRequestUpdatedInRetries

  auto retry_options_predicate = std::make_shared<MockRetryOptionsPredicate>();
  callbacks_.route_->route_entry_.retry_policy_.retry_options_predicates_.emplace_back(
      retry_options_predicate);

  setIncludeAttemptCountInRequest(true);

  NiceMock<Http::MockRequestEncoder> encoder1;
  Http::ResponseDecoder* response_decoder = nullptr;
  expectNewStreamWithImmediateEncoder(encoder1, &response_decoder, Http::Protocol::Http10);
  expectResponseTimerCreate();

//  Http::TestRequestHeaderMapImpl headers{{"x-envoy-retry-on", "5xx"}, {"x-envoy-internal", "true"}};
  cm_.thread_local_cluster_.conn_pool_.host_->hostname_ = "scooby.doo.1";
  HttpTestUtility::addDefaultHeaders(headers);
  router_.decodeHeaders(headers, true);
  EXPECT_EQ(1U,
            callbacks_.route_->route_entry_.virtual_cluster_.stats().upstream_rq_total_.value());

  // Initial request has 1 attempt.
  EXPECT_EQ(1, atoi(std::string(headers.getEnvoyAttemptCountValue()).c_str()));

  // 5xx response.
  router_.retry_state_->expectHeadersRetry();
  Upstream::RetryOptionsPredicate::UpdateOptionsReturn update_options_return{
      std::make_shared<Network::Socket::Options>()};
  EXPECT_CALL(*retry_options_predicate, updateOptions(_)).WillOnce(Return(update_options_return));
  Http::ResponseHeaderMapPtr response_headers1(
      new Http::TestResponseHeaderMapImpl{{":status", "503"}});
  EXPECT_CALL(cm_.thread_local_cluster_.conn_pool_.host_->outlier_detector_,
              putHttpResponseCode(503));
  // NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
  response_decoder->decodeHeaders(std::move(response_headers1), true);
  EXPECT_TRUE(verifyHostUpstreamStats(0, 1));

  // Verify retry options predicate return values have been updated.
  EXPECT_EQ(update_options_return.new_upstream_socket_options_.value(),
            router_.upstreamSocketOptions());


  //--->
  // check after 1st call (NF) 
  EXPECT_FALSE(headers.has("3gpp-Sbi-Discovery-par1"));
  EXPECT_FALSE(headers.has("3gpp-Sbi-Discovery-par2"));
  EXPECT_FALSE(headers.has("3gpp-Sbi-Discovery-par3"));
  EXPECT_FALSE(headers.has("3gpp-Sbi-Discovery-par4"));

  EXPECT_FALSE(headers.has("3gpp-Sbi-target-apiRoot"));

  //--->

  cm_.thread_local_cluster_.conn_pool_.host_->hostname_ = "scooby.doo.2";
  ON_CALL(*host, metadata()).WillByDefault(Return(host_metadata_indirect));

  // We expect the 5xx response to kick off a new request.
  EXPECT_CALL(encoder1.stream_, resetStream(_)).Times(0);
  NiceMock<Http::MockRequestEncoder> encoder2;
  expectNewStreamWithImmediateEncoder(encoder2, &response_decoder, Http::Protocol::Http10);
  router_.retry_state_->callback_();
  EXPECT_EQ(2U,
            callbacks_.route_->route_entry_.virtual_cluster_.stats().upstream_rq_total_.value());

  // The retry should cause the header to increase to 2.
  EXPECT_EQ(2, atoi(std::string(headers.getEnvoyAttemptCountValue()).c_str()));

  // Normal response.
  EXPECT_CALL(*router_.retry_state_, shouldRetryHeaders(_, _, _)).WillOnce(Return(RetryStatus::No));
  EXPECT_CALL(cm_.thread_local_cluster_.conn_pool_.host_->health_checker_, setUnhealthy(_))
      .Times(0);
  Http::ResponseHeaderMapPtr response_headers2(
      new Http::TestResponseHeaderMapImpl{{":status", "200"}});
  EXPECT_CALL(cm_.thread_local_cluster_.conn_pool_.host_->outlier_detector_,
              putHttpResponseCode(200));
  response_decoder->decodeHeaders(std::move(response_headers2), true);
  EXPECT_TRUE(verifyHostUpstreamStats(1, 1));
  EXPECT_EQ(2, callbacks_.stream_info_.attemptCount().value());




// ---

  EXPECT_TRUE(headers.has("3gpp-Sbi-Discovery-par1"));
  EXPECT_TRUE(headers.has("3gpp-Sbi-Discovery-par2"));
  EXPECT_TRUE(headers.has("3gpp-Sbi-Discovery-par3"));
  EXPECT_FALSE(headers.has("3gpp-Sbi-Discovery-par4"));

  EXPECT_TRUE(headers.has("3gpp-Sbi-target-apiRoot"));

}

// Test cases for preserving ALL discovery parameters for indirect routing
TEST_F(RouterTestPreserveDiscoveryHeaders, EricProxy_preserve_all_disc_par_if_indirect) {

  ProtobufWkt::Struct metadata;

  // if preserving (remote-round-robin) shoud be tied to the "target-api-root-processing"
  *(*metadata.mutable_fields())["target-api-root-processing"].mutable_string_value() = "true";
  *(*metadata.mutable_fields())["target-api-root-value"].mutable_string_value() = "TaRValue1";

  // preserve ALL discovery params
  *(*metadata.mutable_fields())["preserve-all-disc-parameters-if-indirect"].mutable_string_value() = "true";

  // set dynamic metadata like setDynamicMetadata("eric_proxy", metadata) would do
  (*callbacks_.stream_info_.metadata_.mutable_filter_metadata())["eric_proxy"] = metadata;

  NiceMock<Http::MockRequestEncoder> encoder;
  Http::ResponseDecoder* response_decoder = nullptr;
  expectNewStreamWithImmediateEncoder(encoder, &response_decoder, Http::Protocol::Http10);
  expectResponseTimerCreate();

  cm_.thread_local_cluster_.conn_pool_.host_->hostname_ = "scooby.doo.1";

  auto host_metadata = std::make_shared<envoy::config::core::v3::Metadata>(
      TestUtility::parseYaml<envoy::config::core::v3::Metadata>(
          R"EOF(
        filter_metadata:
          envoy.eric_proxy:
            support: [Indirect]
      )EOF"));

  std::shared_ptr<NiceMock<Envoy::Upstream::MockHostDescription>> host(
      new NiceMock<Envoy::Upstream::MockHostDescription>());

  cm_.thread_local_cluster_.conn_pool_.host_ = host;
  ON_CALL(*host, metadata()).WillByDefault(Return(host_metadata));

  Http::TestRequestHeaderMapImpl headers{
    {"3gpp-Sbi-target-apiRoot", "TaR1"},  
    {"3gpp-Sbi-Discovery-par1", "disc-par1-val1"}, 
    {"3gpp-Sbi-Discovery-par2", "disc-par1-val2"}, 
    {"3gpp-Sbi-Discovery-par3", "disc-par1-val3"}, 
    {"3gpp-Sbi-Discovery-par4", "disc-par1-val4"}, 
    };

  HttpTestUtility::addDefaultHeaders(headers);
  router_.decodeHeaders(headers, false);
  Buffer::OwnedImpl data;
  router_.decodeData(data, true);

  EXPECT_TRUE(headers.has("3gpp-Sbi-Discovery-par1"));
  EXPECT_TRUE(headers.has("3gpp-Sbi-Discovery-par2"));
  EXPECT_TRUE(headers.has("3gpp-Sbi-Discovery-par3"));
  EXPECT_TRUE(headers.has("3gpp-Sbi-Discovery-par4"));

  EXPECT_TRUE(headers.has("3gpp-Sbi-target-apiRoot"));

  EXPECT_EQ(1U,
            callbacks_.route_->route_entry_.virtual_cluster_.stats().upstream_rq_total_.value());

  Http::ResponseHeaderMapPtr response_headers(
      new Http::TestResponseHeaderMapImpl{{":status", "200"}});
  response_decoder->decodeHeaders(std::move(response_headers), true);
  EXPECT_TRUE(verifyHostUpstreamStats(1, 0));
}


// Test cases for removing discovery parameters for direct routing unconditionally
// no dyn. MD for preservation is set
TEST_F(RouterTestPreserveDiscoveryHeaders, EricProxy_remove_all_disc_par_if_direct_basic_no_preserve_md) { 
  ::google::protobuf::Map<std::string, ::google::protobuf::Struct> cb_filter_md;

  NiceMock<Http::MockRequestEncoder> encoder;
  Http::ResponseDecoder* response_decoder = nullptr;
  expectNewStreamWithImmediateEncoder(encoder, &response_decoder, Http::Protocol::Http10);
  expectResponseTimerCreate();

  cm_.thread_local_cluster_.conn_pool_.host_->hostname_ = "scooby.doo.1";

  auto host_metadata = std::make_shared<envoy::config::core::v3::Metadata>(
      TestUtility::parseYaml<envoy::config::core::v3::Metadata>(
          R"EOF(
        filter_metadata:
          envoy.eric_proxy:
            support: [NF]
      )EOF"));

  std::shared_ptr<NiceMock<Envoy::Upstream::MockHostDescription>> host(
      new NiceMock<Envoy::Upstream::MockHostDescription>());

  cm_.thread_local_cluster_.conn_pool_.host_ = host;
  ON_CALL(*host, metadata()).WillByDefault(Return(host_metadata));

  // do not provide 3gpp-Sbi-Discovery-  headers
  Http::TestRequestHeaderMapImpl headers{
      {"3gpp-Sbi-Discovery-par1", "disc-par1-val1"},
      {"3gpp-Sbi-Discovery-par2", "disc-par1-val2"},
      {"3gpp-Sbi-Discovery-par3", "disc-par1-val3"},
      {"3gpp-Sbi-Discovery-par3", "disc-par1-val3"},
  };

  HttpTestUtility::addDefaultHeaders(headers);
  router_.decodeHeaders(headers, false);
  Buffer::OwnedImpl data;
  router_.decodeData(data, true);

  EXPECT_FALSE(headers.has("3gpp-Sbi-Discovery-par1"));
  EXPECT_FALSE(headers.has("3gpp-Sbi-Discovery-par2"));
  EXPECT_FALSE(headers.has("3gpp-Sbi-Discovery-par3"));

  EXPECT_EQ(1U,
            callbacks_.route_->route_entry_.virtual_cluster_.stats().upstream_rq_total_.value());

  Http::ResponseHeaderMapPtr response_headers(
      new Http::TestResponseHeaderMapImpl{{":status", "200"}});
  response_decoder->decodeHeaders(std::move(response_headers), true);
  EXPECT_TRUE(verifyHostUpstreamStats(1, 0));
}



TEST_F(RouterTestPreserveDiscoveryHeaders, UpstreamTimeout) {
  NiceMock<Http::MockRequestEncoder> encoder;
  Http::ResponseDecoder* response_decoder = nullptr;
  expectNewStreamWithImmediateEncoder(encoder, &response_decoder, Http::Protocol::Http10);

  expectResponseTimerCreate();

  Http::TestRequestHeaderMapImpl headers{{"x-envoy-retry-on", "5xx"}, {"x-envoy-internal", "true"}};
  HttpTestUtility::addDefaultHeaders(headers);
  router_.decodeHeaders(headers, false);
  Buffer::OwnedImpl data;
  router_.decodeData(data, true);
  EXPECT_EQ(1U,
            callbacks_.route_->route_entry_.virtual_cluster_.stats().upstream_rq_total_.value());

  EXPECT_CALL(callbacks_.stream_info_,
              setResponseFlag(StreamInfo::ResponseFlag::UpstreamRequestTimeout));
  EXPECT_CALL(encoder.stream_, resetStream(Http::StreamResetReason::LocalReset));
  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "504"}, {"content-length", "24"}, {"content-type", "text/plain"}};
  EXPECT_CALL(callbacks_, encodeHeaders_(HeaderMapEqualRef(&response_headers), false));
  EXPECT_CALL(callbacks_, encodeData(_, true));
  EXPECT_CALL(*router_.retry_state_, shouldRetryReset(_, _, _)).Times(0);
  EXPECT_CALL(cm_.thread_local_cluster_.conn_pool_.host_->outlier_detector_,
              putResult(Upstream::Outlier::Result::LocalOriginTimeout, _));
  response_timeout_->invokeCallback();

  EXPECT_EQ(1U,
            cm_.thread_local_cluster_.cluster_.info_->stats_store_.counter("upstream_rq_timeout")
                .value());
  EXPECT_EQ(1U,
            callbacks_.route_->route_entry_.virtual_cluster_.stats().upstream_rq_timeout_.value());
  EXPECT_EQ(1UL, cm_.thread_local_cluster_.conn_pool_.host_->stats().rq_timeout_.value());
  EXPECT_TRUE(verifyHostUpstreamStats(0, 1));
}





// Also verify retry options predicates work.
TEST_F(RouterTestPreserveDiscoveryHeaders, EnvoyAttemptCountInRequestUpdatedInRetries) {
  auto retry_options_predicate = std::make_shared<MockRetryOptionsPredicate>();
  callbacks_.route_->route_entry_.retry_policy_.retry_options_predicates_.emplace_back(
      retry_options_predicate);

  setIncludeAttemptCountInRequest(true);

  NiceMock<Http::MockRequestEncoder> encoder1;
  Http::ResponseDecoder* response_decoder = nullptr;
  expectNewStreamWithImmediateEncoder(encoder1, &response_decoder, Http::Protocol::Http10);
  expectResponseTimerCreate();

  Http::TestRequestHeaderMapImpl headers{{"x-envoy-retry-on", "5xx"}, {"x-envoy-internal", "true"}};
  cm_.thread_local_cluster_.conn_pool_.host_->hostname_ = "scooby.doo.1";
  HttpTestUtility::addDefaultHeaders(headers);
  router_.decodeHeaders(headers, true);
  EXPECT_EQ(1U,
            callbacks_.route_->route_entry_.virtual_cluster_.stats().upstream_rq_total_.value());

  // Initial request has 1 attempt.
  EXPECT_EQ(1, atoi(std::string(headers.getEnvoyAttemptCountValue()).c_str()));

  // 5xx response.
  router_.retry_state_->expectHeadersRetry();
  Upstream::RetryOptionsPredicate::UpdateOptionsReturn update_options_return{
      std::make_shared<Network::Socket::Options>()};
  EXPECT_CALL(*retry_options_predicate, updateOptions(_)).WillOnce(Return(update_options_return));
  Http::ResponseHeaderMapPtr response_headers1(
      new Http::TestResponseHeaderMapImpl{{":status", "503"}});
  EXPECT_CALL(cm_.thread_local_cluster_.conn_pool_.host_->outlier_detector_,
              putHttpResponseCode(503));
  // NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
  response_decoder->decodeHeaders(std::move(response_headers1), true);
  EXPECT_TRUE(verifyHostUpstreamStats(0, 1));

  // Verify retry options predicate return values have been updated.
  EXPECT_EQ(update_options_return.new_upstream_socket_options_.value(),
            router_.upstreamSocketOptions());

  cm_.thread_local_cluster_.conn_pool_.host_->hostname_ = "scooby.doo.2";

  // We expect the 5xx response to kick off a new request.
  EXPECT_CALL(encoder1.stream_, resetStream(_)).Times(0);
  NiceMock<Http::MockRequestEncoder> encoder2;
  expectNewStreamWithImmediateEncoder(encoder2, &response_decoder, Http::Protocol::Http10);
  router_.retry_state_->callback_();
  EXPECT_EQ(2U,
            callbacks_.route_->route_entry_.virtual_cluster_.stats().upstream_rq_total_.value());

  // The retry should cause the header to increase to 2.
  EXPECT_EQ(2, atoi(std::string(headers.getEnvoyAttemptCountValue()).c_str()));

  // Normal response.
  EXPECT_CALL(*router_.retry_state_, shouldRetryHeaders(_, _, _)).WillOnce(Return(RetryStatus::No));
  EXPECT_CALL(cm_.thread_local_cluster_.conn_pool_.host_->health_checker_, setUnhealthy(_))
      .Times(0);
  Http::ResponseHeaderMapPtr response_headers2(
      new Http::TestResponseHeaderMapImpl{{":status", "200"}});
  EXPECT_CALL(cm_.thread_local_cluster_.conn_pool_.host_->outlier_detector_,
              putHttpResponseCode(200));
  response_decoder->decodeHeaders(std::move(response_headers2), true);
  EXPECT_TRUE(verifyHostUpstreamStats(1, 1));
  EXPECT_EQ(2, callbacks_.stream_info_.attemptCount().value());
}

} // namespace Router
} // namespace Envoy
