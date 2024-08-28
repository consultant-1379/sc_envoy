#pragma once

#include <cstdint>
#include <string>

#include "envoy/ssl/connection.h"

#include "source/common/common/logger.h"
#include "source/extensions/transport_sockets/tls/utility.h"

#include "absl/types/optional.h"
#include "openssl/ssl.h"
#include "re2/re2.h"


namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

using EpochTime = std::chrono::time_point<std::chrono::system_clock>;
// An implementation wraps struct SSL in BoringSSL.
class ConnectionInfoImplBase : public Ssl::ConnectionInfo, 
                               protected Logger::Loggable<Logger::Id::connection>{
public:
  // Ssl::ConnectionInfo
  bool peerCertificatePresented() const override;
  std::optional<std::string> getRoamingPartnerName(std::map<std::string, std::string>& kv_table, std::map<const std::string,  const RE2>& dn_to_re2_regex_table, const EpochTime& config_updated_at) const override;
  double& n32cInfoTimestamp() const override;
  bool& n32cHandshakeState() const override;
  absl::Span<const std::string> uriSanLocalCertificate() const override;
  const std::string& sha256PeerCertificateDigest() const override;
  const std::string& sha1PeerCertificateDigest() const override;
  const std::string& serialNumberPeerCertificate() const override;
  const std::string& issuerPeerCertificate() const override;
  const std::string& subjectPeerCertificate() const override;
  const std::string& subjectLocalCertificate() const override;
  absl::Span<const std::string> uriSanPeerCertificate() const override;
  const std::string& urlEncodedPemEncodedPeerCertificate() const override;
  const std::string& urlEncodedPemEncodedPeerCertificateChain() const override;
  absl::Span<const std::string> dnsSansPeerCertificate() const override;
  absl::Span<const std::string> dnsSansLocalCertificate() const override;
  absl::Span<const std::string> ipSansPeerCertificate() const override;
  absl::Span<const std::string> ipSansLocalCertificate() const override;
  absl::optional<SystemTime> validFromPeerCertificate() const override;
  absl::optional<SystemTime> expirationPeerCertificate() const override;
  const std::string& sessionId() const override;
  uint16_t ciphersuiteId() const override;
  std::string ciphersuiteString() const override;
  const std::string& tlsVersion() const override;
  const std::string& alpn() const override;
  const std::string& sni() const override;

  virtual SSL* ssl() const PURE;

protected:
  mutable std::vector<std::string> cached_uri_san_local_certificate_;
  mutable std::string cached_sha_256_peer_certificate_digest_;
  mutable std::string cached_sha_1_peer_certificate_digest_;
  mutable std::string cached_serial_number_peer_certificate_;
  mutable std::string cached_issuer_peer_certificate_;
  mutable std::string cached_subject_peer_certificate_;
  mutable std::string cached_subject_local_certificate_;
  mutable std::vector<std::string> cached_uri_san_peer_certificate_;
  mutable std::string cached_url_encoded_pem_encoded_peer_certificate_;
  mutable std::string cached_url_encoded_pem_encoded_peer_cert_chain_;
  mutable std::vector<std::string> cached_dns_san_peer_certificate_;
  mutable std::vector<std::string> cached_dns_san_local_certificate_;
  mutable std::vector<std::string> cached_ip_san_peer_certificate_;
  mutable std::vector<std::string> cached_ip_san_local_certificate_;
  mutable std::string cached_session_id_;
  mutable std::string cached_tls_version_;
  // the following are related to sepp specific functionality
  mutable std::optional<std::string> roaming_partner_name_;
  mutable EpochTime last_config_update_ = std::chrono::system_clock::time_point::min();
  mutable bool cached_n32c_handshake_completed_ = false;
  mutable double cached_n32c_timestamp_ = 0;
  mutable std::string alpn_;
  mutable std::string sni_;
};

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
