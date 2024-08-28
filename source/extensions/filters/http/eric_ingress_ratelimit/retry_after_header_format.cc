#include "ratelimit.h"
#include <string>
#include "absl/strings/str_format.h"

template <typename TimePoint>
std::string
Envoy::Extensions::HttpFilters::IngressRateLimitFilter::RetryAfterHeaderFormat::to_string(
    const TimePoint& time_point) {
  return std::to_string(time_point.time_since_epoch().count());
}

std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>
Envoy::Extensions::HttpFilters::IngressRateLimitFilter::RetryAfterHeaderFormat::parseRaFromJsonBody(
    const Json::iterator& it) {
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> time_point_ms(
        static_cast<std::chrono::milliseconds>(it.value()["ra"]));

    return time_point_ms;
  
}

std::string
Envoy::Extensions::HttpFilters::IngressRateLimitFilter::RetryAfterHeaderFormat::getSecondsJsonBody(
    const Json::iterator& it) {

  auto time_point_ms = RetryAfterHeaderFormat::parseRaFromJsonBody(it);
  auto val_s = std::chrono::ceil<Sec>(time_point_ms);
  return RetryAfterHeaderFormat::to_string(val_s);
}

std::string Envoy::Extensions::HttpFilters::IngressRateLimitFilter::RetryAfterHeaderFormat::
    getHttpDateFromJsonBody(const Json::iterator& it) {

  auto time_point_ms = RetryAfterHeaderFormat::parseRaFromJsonBody(it);
  std::time_t now_t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  // rounded up "ra" value
  auto val_s = (std::chrono::ceil<Sec>(time_point_ms));

  std::time_t sec_t = std::chrono::system_clock::to_time_t(val_s);
  std::time_t final_t = now_t + sec_t;

  struct tm* ptm = gmtime(&final_t);

  return RetryAfterHeaderFormat::asctime(ptm);
}

std::string Envoy::Extensions::HttpFilters::IngressRateLimitFilter::RetryAfterHeaderFormat::asctime(
    const struct tm* timeptr) {

  // Date: Wed, 21 Oct 2015 07:28:00 GMT
  return absl::StrFormat("Date: %s, %02d %s %4d %02d:%02d:%02d GMT", wday_name[timeptr->tm_wday],
                         timeptr->tm_mday, mon_name[timeptr->tm_mon], 1900 + timeptr->tm_year,
                         timeptr->tm_hour, timeptr->tm_min, timeptr->tm_sec);
}
