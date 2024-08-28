#include "envoy/http/codes.h"
#include "include/nlohmann/json.hpp"

#include "source/common/http/header_utility.h"
#include "source/common/local_reply/local_reply.h"

#include "test/mocks/http/mocks.h"
#include "test/mocks/server/factory_context.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/utility.h"
#include "test/test_common/environment.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <iostream>
#include <iterator>
#include <ostream>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

const Http::Code TestInitCode = Http::Code::OK;
const std::string TestInitBody = "Init body text";
const absl::string_view TestInitContentType = "content-type";

class LocalReplyTest : public testing::Test {
public:
  LocalReplyTest() : stream_info_(time_system_.timeSystem(), nullptr) { resetData(TestInitCode); }

  void resetData(Http::Code code) {
    code_ = code;
    body_ = TestInitBody;
    content_type_ = TestInitContentType;
  }
  void resetData(uint32_t code) { resetData(static_cast<Http::Code>(code)); }

  Http::Code code_;
  std::string body_;
  absl::string_view content_type_;  
  std::string path_ = TestEnvironment::substitute("{{ test_rundir }}/test/extensions/filters/http/eric_proxy/test_data/local_reply.yaml");
  std::unique_ptr<Envoy::Stats::IsolatedStoreImpl> stats_ = std::make_unique<Stats::IsolatedStoreImpl>();
  std::unique_ptr<Envoy::Api::Api> api_ = Api::createApiForTest(*stats_);

  Http::TestRequestHeaderMapImpl request_headers_{{":method", "GET"}, {":path", "/bar/foo"}};
  Http::TestResponseHeaderMapImpl response_headers_;
  Event::SimulatedTimeSystem time_system_;
  StreamInfo::StreamInfoImpl stream_info_;

  envoy::extensions::filters::network::http_connection_manager::v3::LocalReplyConfig config_;
  NiceMock<Server::Configuration::MockFactoryContext> context_;
};

TEST_F(LocalReplyTest, SmallTest) {
  TestUtility::loadFromFile(path_, config_, *api_);
  auto local = LocalReply::Factory::create(config_, context_);

  resetData(400);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(400));

  nlohmann::json expected_body{R"({
      "status": 400,
      "title":"Bad Request",
      "cause":"MANDATORY_IE_MISSING",
      "detail":null
      })"_json};

  EXPECT_EQ(expected_body, nlohmann::json::parse(body_));
}

TEST_F(LocalReplyTest, TestPathRejected) {
  TestUtility::loadFromFile(path_, config_, *api_);
  auto local = LocalReply::Factory::create(config_, context_);

  // Test E_MPR flag
  resetData(404);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::MissingPathRejected);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(400));

  nlohmann::json expected_body{R"({
      "status": 400,
      "title":"Bad Request",
      "cause":"MANDATORY_IE_MISSING",
      "detail":null
      })"_json};

  EXPECT_EQ(expected_body, nlohmann::json::parse(body_));

  // Test E_APR flag
  resetData(404);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::AbsolutePathRejected);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(400));

  nlohmann::json expected_body_2{R"({
      "status": 400,
      "title":"Bad Request",
      "cause":"UNSPECIFIED_MSG_FAILURE",
      "detail":null
      })"_json};

  EXPECT_EQ(expected_body_2, nlohmann::json::parse(body_));
}

TEST_F(LocalReplyTest, TestTimeOutFlags) {
  TestUtility::loadFromFile(path_, config_, *api_);
  auto local = LocalReply::Factory::create(config_, context_);
  ProtobufWkt::Struct metadata;

  nlohmann::json expected_body_500_NF_FAILOVER{R"({
      "status": 500,
      "title":"Internal Server Error",
      "cause":"NF_FAILOVER",
      "detail":null
  })"_json};

  nlohmann::json expected_body_504_TARGET_NF_NOT_REACHABLE{R"({
      "status": 504,
      "title":"Gateway Timeout",
      "cause":"TARGET_NF_NOT_REACHABLE",
      "detail":null
  })"_json};


  // Test SI flag

  // strict routing --> 500 NF_FAILOVER
  resetData(408);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "STRICT";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::StreamIdleTimeout);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(500));
  EXPECT_EQ(expected_body_500_NF_FAILOVER, nlohmann::json::parse(body_));

  // dynamic forwarding / STRICT_DFP --> 500 NF_FAILOVER
  resetData(408);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "STRICT_DFP";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::StreamIdleTimeout);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(500));
  EXPECT_EQ(expected_body_500_NF_FAILOVER, nlohmann::json::parse(body_));

  // preferred routing --> 504 TARGET_NF_NOT_REACHABLE
  resetData(408);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "PREFERRED";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::StreamIdleTimeout);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(504));
  EXPECT_EQ(expected_body_504_TARGET_NF_NOT_REACHABLE, nlohmann::json::parse(body_));

  // round robin --> 504 TARGET_NF_NOT_REACHABLE
  resetData(408);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "ROUND_ROBIN";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::StreamIdleTimeout);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(504));
  EXPECT_EQ(expected_body_504_TARGET_NF_NOT_REACHABLE, nlohmann::json::parse(body_));

  // Test for former filter without considering routing behavior
  // resetData(408);
  // *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "";
  // stream_info_.setDynamicMetadata("eric_proxy", metadata);
  // stream_info_.setResponseFlag(StreamInfo::ResponseFlag::StreamIdleTimeout);
  // local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  // EXPECT_EQ(content_type_, "application/problem+json");
  // EXPECT_EQ(code_, static_cast<Http::Code>(500));
  // EXPECT_EQ(expected_body_500_NF_FAILOVER, nlohmann::json::parse(body_));


  // Test DT flag

  // strict routing --> 500 NF_FAILOVER
  resetData(408);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "STRICT";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::DurationTimeout);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(500));
  EXPECT_EQ(expected_body_500_NF_FAILOVER, nlohmann::json::parse(body_));

  // dynamic forwarding / STRICT_DFP --> 500 NF_FAILOVER
  resetData(408);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "STRICT_DFP";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::DurationTimeout);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(500));
  EXPECT_EQ(expected_body_500_NF_FAILOVER, nlohmann::json::parse(body_));

  // preferred routing --> 504 TARGET_NF_NOT_REACHABLE
  resetData(408);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "PREFERRED";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::DurationTimeout);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(504));
  EXPECT_EQ(expected_body_504_TARGET_NF_NOT_REACHABLE, nlohmann::json::parse(body_));

  // round robin --> 504 TARGET_NF_NOT_REACHABLE
  resetData(408);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "ROUND_ROBIN";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::DurationTimeout);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(504));
  EXPECT_EQ(expected_body_504_TARGET_NF_NOT_REACHABLE, nlohmann::json::parse(body_));

  // Test for former filter, not considering routing behavior --> 500 NF_FAILOVER
  // resetData(408);
  // *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "";
  // stream_info_.setDynamicMetadata("eric_proxy", metadata);
  // stream_info_.setResponseFlag(StreamInfo::ResponseFlag::DurationTimeout);
  // local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  // EXPECT_EQ(content_type_, "application/problem+json");
  // EXPECT_EQ(expected_body_500_NF_FAILOVER, nlohmann::json::parse(body_));


  // Test UT
  resetData(408);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "STRICT";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::UpstreamRequestTimeout);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(500));
  EXPECT_EQ(expected_body_500_NF_FAILOVER, nlohmann::json::parse(body_));

  resetData(408);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "PREFERRED";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::UpstreamRequestTimeout);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(504));
  EXPECT_EQ(expected_body_504_TARGET_NF_NOT_REACHABLE, nlohmann::json::parse(body_));

  resetData(408);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "ROUND_ROBIN";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::UpstreamRequestTimeout);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(504));
  EXPECT_EQ(expected_body_504_TARGET_NF_NOT_REACHABLE, nlohmann::json::parse(body_));

  // Test UMSDR
  resetData(408);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::UpstreamMaxStreamDurationReached);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "STRICT";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(500));
  EXPECT_EQ(expected_body_500_NF_FAILOVER, nlohmann::json::parse(body_));

  resetData(408);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::UpstreamMaxStreamDurationReached);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "ROUND_ROBIN";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(504));
  EXPECT_EQ(expected_body_504_TARGET_NF_NOT_REACHABLE, nlohmann::json::parse(body_));

  resetData(408);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::UpstreamMaxStreamDurationReached);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "PREFERRED";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(code_, static_cast<Http::Code>(504));
  EXPECT_EQ(expected_body_504_TARGET_NF_NOT_REACHABLE, nlohmann::json::parse(body_));
}

TEST_F(LocalReplyTest, TestLowVersion) {
  TestUtility::loadFromFile(path_, config_, *api_);
  auto local = LocalReply::Factory::create(config_, context_);

  nlohmann::json expected_body{R"({
      "status": 400,
      "title":"Bad Request",
      "cause":"UNSPECIFIED_MSG_FAILURE",
      "detail":null
      })"_json};

  resetData(426);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(400));
}

TEST_F(LocalReplyTest, Test_RL_Error) {
  TestUtility::loadFromFile(path_, config_, *api_);
  auto local = LocalReply::Factory::create(config_, context_);

  nlohmann::json expected_body{R"({
      "status": 500,
      "title":"Internal Server Error",
      "cause":"SYSTEM_FAILURE",
      "detail":null
      })"_json};

  resetData(500);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::RateLimitServiceError);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(500));
}

TEST_F(LocalReplyTest, TestUpstreamResetBeforeResponseStarted) {
  TestUtility::loadFromFile(path_, config_, *api_);
  auto local = LocalReply::Factory::create(config_, context_);
  ProtobufWkt::Struct metadata;

  nlohmann::json expected_body_strict{R"({
      "status": 500,
      "title":"Internal Server Error",
      "cause":"NF_FAILOVER",
      "detail":null
      })"_json};
  nlohmann::json expected_body_preferred{R"({
      "status": 504,
      "title":"Gateway Timeout",
      "cause":"TARGET_NF_NOT_REACHABLE",
      "detail":null
      })"_json};

  // Row 33 in 3gpp_services_and_interfaces table
  resetData(502);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "STRICT";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::UpstreamProtocolError);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body_strict, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(500));

  // Row 34 in 3gpp_services_and_interfaces table
  resetData(502);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "PREFERRED";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::UpstreamProtocolError);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body_preferred, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(504));

  // Row 35 in 3gpp_services_and_interfaces table
  resetData(503);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "STRICT";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::UpstreamConnectionFailure);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body_strict, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(500));

  resetData(503);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "PREFERRED";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::UpstreamConnectionFailure);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body_preferred, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(504));

  resetData(503);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "ROUND_ROBIN";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::UpstreamConnectionFailure);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body_preferred, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(504));

  resetData(503);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "PREFERRED";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::UpstreamRemoteReset);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body_preferred, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(504));
}

TEST_F(LocalReplyTest, TestSystemFailure) {
  TestUtility::loadFromFile(path_, config_, *api_);
  auto local = LocalReply::Factory::create(config_, context_);

  nlohmann::json expected_body{R"({
      "status": 500,
      "title":"Internal Server Error",
      "cause":"SYSTEM_FAILURE",
      "detail":null
      })"_json};
  resetData(502);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(500));

  resetData(503);
  ProtobufWkt::Struct metadata;
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "STRICT_DFP";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(500));

  // DPE
  resetData(503);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::DownstreamProtocolError);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(500));

  // NC
  resetData(400);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::NoClusterFound);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(500));
}

TEST_F(LocalReplyTest, TestNoHealthyUpstream) {
  TestUtility::loadFromFile(path_, config_, *api_);
  auto local = LocalReply::Factory::create(config_, context_);
  ProtobufWkt::Struct metadata;

  nlohmann::json expected_body_strict{R"({
      "status": 500,
      "title":"Internal Server Error",
      "cause":"NF_FAILOVER",
      "detail":null
      })"_json};
  nlohmann::json expected_body_preferred{R"({
      "status": 504,
      "title":"Gateway Timeout",
      "cause":"TARGET_NF_NOT_REACHABLE",
      "detail":null
      })"_json};

  resetData(503);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "STRICT";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::NoHealthyUpstream);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body_strict, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(500));

  resetData(503);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "ROUND_ROBIN";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::NoHealthyUpstream);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body_preferred, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(504));

  resetData(503);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "PREFERRED";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::NoHealthyUpstream);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body_preferred, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(504));
}

TEST_F(LocalReplyTest, TestRequestRateLimit) {
  TestUtility::loadFromFile(path_, config_, *api_);
  auto local = LocalReply::Factory::create(config_, context_);

  nlohmann::json expected_body{R"({
      "status": 429,
      "title":"Too Many Requests",
      "cause":"NF_CONGESTION_RISK",
      "detail":null
      })"_json};

  resetData(503);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::RateLimitServiceError);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  std::cerr << "SIZE: " << stream_info_.dynamicMetadata().filter_metadata_size() << std::endl;
  EXPECT_EQ(expected_body, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(429));
}

TEST_F(LocalReplyTest, TestUpstreamResponseTimeout) {
  TestUtility::loadFromFile(path_, config_, *api_);
  auto local = LocalReply::Factory::create(config_, context_);
  ProtobufWkt::Struct metadata;

  nlohmann::json expected_body_strict{R"({
      "status": 500,
      "title":"Internal Server Error",
      "cause":"NF_FAILOVER",
      "detail":null
      })"_json};
  nlohmann::json expected_body_preferred{R"({
      "status": 504,
      "title":"Gateway Timeout",
      "cause":"TARGET_NF_NOT_REACHABLE",
      "detail":null
      })"_json};

  resetData(504);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "STRICT";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::UpstreamRequestTimeout);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body_strict, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(500));

  resetData(504);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "ROUND_ROBIN";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::UpstreamRequestTimeout);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body_preferred, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(504));

  resetData(504);
  *(*metadata.mutable_fields())["routing-behaviour"].mutable_string_value() = "PREFERRED";
  stream_info_.setDynamicMetadata("eric_proxy", metadata);
  stream_info_.setResponseFlag(StreamInfo::ResponseFlag::UpstreamRequestTimeout);
  local->rewrite(&request_headers_, response_headers_, stream_info_, code_, body_, content_type_);
  EXPECT_EQ(content_type_, "application/problem+json");
  EXPECT_EQ(expected_body_preferred, nlohmann::json::parse(body_));
  EXPECT_EQ(code_, static_cast<Http::Code>(504));
}

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy