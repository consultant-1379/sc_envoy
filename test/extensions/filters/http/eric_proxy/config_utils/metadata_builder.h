#pragma once

#include <string>
#include <vector>
#include <map>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

class MetadataBuilder {
public:
  static const std::string getMetadata(const std::string& owner,
                                       std::map<std::string, std::string>&& md_map) {
    return getMetadata(owner, {{}}, std::move(md_map));
  }

  static const std::string
  getMetadata(const std::string& owner,
              std::map<std::string, std::vector<std::string>>&& md_map_as_list) {
    return getMetadata(owner, std::move(md_map_as_list), {{}});
  }

  static const std::string
  getMetadata(const std::string& owner,
              std::map<std::string, std::vector<std::string>>&& md_map_as_list,
              std::map<std::string, std::string>&& md_map) {
    std::string res;
    int padding = 12;
    absl::StrAppend(&res, host_md_prefix, owner, ":\n");
    for (const auto& entry : md_map_as_list) {
      absl::StrAppend(&res, std::string(padding, ' '), entry.first, ": ",
                      fmt::format("[\"{}\"]", fmt::join(entry.second, "\",\"")), "\n");
    }
    for (const auto& entry : md_map) {
      absl::StrAppend(&res, std::string(padding, ' '), entry.first, ": '", entry.second, "'\n");
    }
    return res;
  }

  static const std::string getClusterMetadata(
      const std::string& owner,
      std::map<std::string, std::vector<std::map<std::string, std::string>>>&& md_map) {
    std::string res;
    int padding = 6;
    absl::StrAppend(&res, cluster_md_prefix, owner, ":\n");
    for (const auto& entry : md_map) {
      absl::StrAppend(&res, std::string(padding, ' '), entry.first, ":\n");
      for (const auto& vec_entry : entry.second) {
        // std::string(padding, ' '), "- "
        absl::StrAppend(&res, std::string(padding, ' '), "- ");
        for (const auto& inner_entry : vec_entry) {
          absl::StrAppend(&res, inner_entry.first, ": '", inner_entry.second, "'\n",
                          std::string(padding + 2, ' '));
        }
        res.resize(res.size() - padding - 2);
      }
    }
    // res.resize(res.size() - padding);

    return res;
  }

  static inline const std::string host_md_prefix = R"EOF(metadata:
        filter_metadata:
          )EOF";

  static inline const std::string cluster_md_prefix = R"EOF(metadata:
  filter_metadata:
    )EOF";
};

// int main() {
//     std::map<std::string, std::vector<std::string>> support{
//         {"support", {"NF", "TFQDN"}}, {"pool", {"manasou"}}};
//     std::map<std::string, std::string> fqdn{{"interplmn_fqdn", "foo.bar.se"}};

//     std::map<std::string, std::vector<std::map<std::string, std::string>>>
//         indirect{
//             {"inter.nf2.eric.se:80",
//              {{{"ip", "10.10.10.1:80"}, {"fqdn", "nf2.eric.se:80"}}}},
//             {
//                 "nf3.eric.se:80",
//                 {{{"ip", "20.20.20.1:80"}, {"fqdn", "scp1.eric.se:85"}},
//                  {{"ip", "30.30.30.3:80"}, {"fqdn", "scp2.eric.se:85"}}},
//             },
//             {
//                 "nf4.eric.se:80",
//                 {{{"ip", "20.20.20.1:80"}, {"fqdn", "scp1.eric.se:85"}},
//                  {{"ip", "30.30.30.3:80"}, {"fqdn", "scp2.eric.se:85"}}},
//             },
//             {"inter.nf2.eric.se:80",
//              {{{"ip", "10.10.10.1:80"}, {"fqdn", "nf2.eric.se:80"}}}},
//         };

//     std::cout << MetadataBuilder::getMetadata("eric_proxy", support, fqdn);
//     std::cout << MetadataBuilder::getClusterMetadata("envoy.eric_proxy.cluster",
//                                                      indirect);
// }

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy