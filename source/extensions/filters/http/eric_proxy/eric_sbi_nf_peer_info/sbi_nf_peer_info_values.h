#pragma once

#include "source/common/http/header_map_impl.h"
#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// sbi peer info header tockens
class SbiNfPeerInfoHeaderValues {
public:
  const Http::LowerCaseString Root{"3gpp-Sbi-NF-Peer-Info"};
  const std::string SrcInst{"srcinst"};
  const std::string SrcServInst{"srcservinst"};
  const std::string SrcScp{"srcscp"};
  const std::string SrcSepp{"srcsepp"};
  const std::string DstInst{"dstinst"};
  const std::string DstServInst{"dstservinst"};
  const std::string DstScp{"dstscp"};
  const std::string DstSepp{"dstsepp"};
};

// Metadata's keys.
class SbiMetadataKeyValues {
public:
  const std::string filter{"eric_proxy.sbi_nf_peer_info"};
  const std::string original_request_header_path{"original_request_header"};
  const std::string updated_request_header_path{"updated_request_header"};
  const std::string request_out_screening_is_on{"request_out_screening_is_on"};

  const std::string node_type_path{"node_type"};
  const std::string own_fqdn{"own_fqdn"};
  const std::string nf_peer_info_handling_is_on{"nf_peer_info_handling_is_on"};

  const std::string host_meta_root_{"envoy.eric_proxy"};
  const std::string selected_node_type_path_{"nf_type"};  // host meta
  const std::string nf_instance_id_path_{"nfInstanceId"}; // host meta
};

using SbiNfPeerInfoHeaders = ConstSingleton<SbiNfPeerInfoHeaderValues>;
using SbiMetadataKeys = ConstSingleton<SbiMetadataKeyValues>;

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy