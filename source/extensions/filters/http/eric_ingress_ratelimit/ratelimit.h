#pragma once

#include <map>
#include <memory>
#include <string>
#include "source/common/http/utility.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"
#include "source/extensions/filters/http/eric_ingress_ratelimit/ingress_ratelimit_config.h"
#include "envoy/http/async_client.h"
#include "source/common/http/message_impl.h"
#include "source/extensions/filters/http/eric_ingress_ratelimit/rl_stats.h"
#include "re2/re2.h"
#include "include/nlohmann/json.hpp"


namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IngressRateLimitFilter {

enum class LimitType {
  NW, // network type limit
  RP, // rp type limit
};

using RateLimit = envoy::extensions::filters::http::eric_ingress_ratelimit::v3::RateLimit;
using RejectMessageBodyType =
    envoy::extensions::filters::http::eric_ingress_ratelimit::v3::MessageBodyType;
using Json = nlohmann::json;

class LookupCallbacks : public Http::AsyncClient::Callbacks {
public:
  LookupCallbacks(std::function<void(Http::ResponseMessagePtr&&)>&& on_success,
                  std::function<void(Http::AsyncClient::FailureReason)>&& on_fail)
      : on_success_(on_success), on_fail_(on_fail) {}
  // Http::AsyncClient::Callbacks
  void onSuccess(const Http::AsyncClient::Request&, Http::ResponseMessagePtr&& m) override {
    on_success_(std::forward<Http::ResponseMessagePtr>(m));
  }
  void onFailure(const Http::AsyncClient::Request&, Http::AsyncClient::FailureReason f) override {
    on_fail_(f);
  }
  void onBeforeFinalizeUpstreamSpan(Tracing::Span&, const Http::ResponseHeaderMap*) override {}

private:
  const std::function<void(Http::ResponseMessagePtr&&)> on_success_;
  const std::function<void(Http::AsyncClient::FailureReason)> on_fail_;
};


using Sec = std::chrono::seconds;


class RetryAfterHeaderFormat {

public:
  
   static std::string getHttpDateFromJsonBody(const Json::iterator& it);
   static std::string getSecondsJsonBody(const Json::iterator& it);
private:
     static constexpr char wday_name[][4] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
  };
  static constexpr char mon_name[][4] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
  };
  template <typename TimePoint>
  static std::string to_string(const TimePoint& time_point);
  static std::string asctime(const struct tm *timeptr);
  static std::string appendZero(int tu) { return tu < 10 ? absl::StrCat(0,tu) : std::to_string(tu);};
   static std::chrono::time_point<std::chrono::system_clock,
                                std::chrono::milliseconds> parseRaFromJsonBody(const Json::iterator& it);


};


using std::placeholders::_1;

class EricIngressRateLimitFilter : public Http::PassThroughFilter,
                                   public Logger::Loggable<Logger::Id::eric_ingress_ratelimit> {
public:
  EricIngressRateLimitFilter(std::shared_ptr<EricIngressRateLimitConfig>,
                             const std::chrono::time_point<std::chrono::system_clock>,
                             const std::chrono::milliseconds, std::shared_ptr<std::vector<float>>,
                             const RateLimitStatsSharedPtr& stats);
  ~EricIngressRateLimitFilter() override;

  // Http::StreamFilterBase
  void onDestroy() override;

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap&, bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap& trailers) override;
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks&) override;

  // Http::StreamEncoderFilter
  Http::Filter1xxHeadersStatus encode1xxHeaders(Http::ResponseHeaderMap& headers) override;
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap&, bool end_stream) override;
  Http::FilterDataStatus encodeData(Buffer::Instance& data, bool end_stream) override;
  Http::FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap& trailers) override;
  Http::FilterMetadataStatus encodeMetadata(Http::MetadataMap&) override;
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks&) override;

  // RateLimit::RequestCallbacks
  // void complete() override; after query is completed

  // cleanup activities called by onDestroy()
  void cleanup();

  // a struct holding references to the actual bucket action pair
  // as well as the kind of limit and the entity name used for statistics
  struct BucketActionInfo {
    std::string name;
    BucketActionPair bucket_action_pair;
    LimitType type;
  };

private:
  enum class State { NotStarted, Calling, Complete, Responded };
  void initiateCall();
  void contactRlfService();
  void populateResponseHeaders(Http::HeaderMap& response_headers, bool from_local_reply);
  void executeAction(const ActionProfile&, std::optional<std::string>);
  std::optional<std::string> constructBucketName(const RateLimit&);
  std::unique_ptr<Http::RequestHeaderMapImpl> prepareRlfServiceHeaders();
  void appendBodyToRlfServiceRequest(Http::RequestMessagePtr&);
  const std::shared_ptr<EricIngressRateLimitConfig> config_;
  const std::chrono::time_point<std::chrono::system_clock> config_updated_at_;
  const std::chrono::milliseconds timeout_;
  const std::shared_ptr<std::vector<float>> watermarks_;
  State state_{State::NotStarted};
  bool initiating_call_{};
  const std::string logHeaders(const Http::RequestOrResponseHeaderMap&) const;
  void processRlfLookupBodyOK(const std::string&);
  void processRlfLookupErrors(const absl::string_view& status);
  Http::RequestHeaderMap* request_headers_{};
  std::optional<BucketActionInfo> getBucketActionPairForLimit(const RateLimit&);

  // For direct response/local reply/reject-message (see ratelimit filter):
  Http::ResponseHeaderMapPtr response_headers_to_add_;
  void sendLocalReplyWithSpecificContentType(int status_code,
                                             const absl::optional<std::string>& content_type,
                                             const std::string& message,
                                             const absl::string_view response_code_details);

  // Register callback functions for Limit lookup
  void onRlfLookupSuccess(Http::ResponseMessagePtr&&);
  void onRlfLookupFailure(Http::AsyncClient::FailureReason);
  LookupCallbacks lookup_callbacks_ =
      LookupCallbacks(std::bind(&EricIngressRateLimitFilter::onRlfLookupSuccess, this, _1),
                      std::bind(&EricIngressRateLimitFilter::onRlfLookupFailure, this, _1));
  Http::AsyncClient::Request* lookup_request_ = nullptr;
  std::vector<BucketActionInfo> bucket_actions_list_;
  const std::optional<std::string> getRpNameForWildcardSanOrDn(const std::string&);
  const RateLimitStatsSharedPtr stats_;
  void updateResponseCounters(std::optional<BucketActionInfo> info, const CounterType flavor);
};

} // namespace IngressRateLimitFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy