#include "source/extensions/filters/http/eric_ingress_ratelimit/ingress_ratelimit_config.h"
#include <algorithm>
#include <optional>
#include <tuple>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IngressRateLimitFilter {

EricIngressRateLimitConfig::EricIngressRateLimitConfig(
    const envoy::extensions::filters::http::eric_ingress_ratelimit::v3::IngressRateLimit&
        proto_config,
    Upstream::ClusterManager& cm)
    : proto_config_(proto_config), cluster_manager_(cm) {

  // check action type
  // if rp populate rp_bucket_action_table_
  for (auto action_it = std::begin(limits()); action_it != std::end(limits()); action_it++) {
    if (action_it->has_roaming_partner()) {
      std::for_each(action_it->roaming_partner().rp_bucket_action_table().begin(),
                    action_it->roaming_partner().rp_bucket_action_table().end(), [&](auto entry) {
                      // three maps are populated here: dn_to_rp_table_ containing mappings of configured DNs to corresponding RPs
                      // rp_bucket_action_pair containing RPs with their bucket_action_pair (bucket config) if exists
                      //dn_to_re2_regex_table_ used as an optimization for wildcard certificate matching
                      dn_to_rp_table_[entry.first] = entry.second.rp_name();
                      if (entry.second.has_bucket_action_pair()) {
                        //rp_bucket_action_pair_table_ only contains rps with bucket action config
                        rp_bucket_action_pair_table_[entry.second.rp_name()] = entry.second.bucket_action_pair();
                      }
                      // populate the table containing configured domain names (strings) to their
                      // precompiled regexes used during runtime for wildcard certificate matches
                      precompileRegexforDn(entry.first);
                    });

    } else if (action_it->has_network()) {
      // The network name in case a network limit is configured is used for counters,
      // and can be defined at config time
      // only one network limit can exist per listener (thus per filter)
      auto& bucket_name = action_it->network().bucket_action().bucket_name();
      std::size_t found = bucket_name.rfind('=');
      if (found != std::string::npos) {
        network_name_ = bucket_name.substr(found + 1, bucket_name.length());

      } else {
        PANIC("Configured bucket name does not follow the correct format");
      }
    }
  }
  // the :path header of the request sent to the rlf service can be defined at config time
  rlf_service_path_header_ = absl::StrCat("/nrlf-ratelimiting/v0/tokens/", nameSpace());
}

void EricIngressRateLimitConfig::precompileRegexforDn(const std::string dn) {
  const std::string wildcard_quoted = "\\*";
  auto pattern_regex = RE2::QuoteMeta(dn);
  auto wildcard_start_pos = pattern_regex.find(wildcard_quoted);
  if (wildcard_start_pos != std::string::npos) {
    auto wildcard_in_regex = "[^.]*";
    if (absl::StartsWith(pattern_regex, wildcard_quoted)) {
      // We do not want to match e.g. *.ericsson.se with .ericsson.se.
      wildcard_in_regex = "[^.]+";
    }
    pattern_regex =
        pattern_regex.replace(wildcard_start_pos, wildcard_quoted.length(), wildcard_in_regex);
  }
  dn_to_re2_regex_table_.emplace(dn,absl::AsciiStrToLower(pattern_regex));
};

} // namespace IngressRateLimitFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy