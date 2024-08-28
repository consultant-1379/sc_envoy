#include "source/extensions/transport_sockets/tls/connection_info_impl_base.h"

#include "source/common/common/hex.h"

#include "absl/strings/str_replace.h"
#include "absl/strings/match.h"

#include "openssl/err.h"
#include "openssl/x509v3.h"
#include <cstdint>
#include <optional>

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

bool ConnectionInfoImplBase::peerCertificatePresented() const {
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  return cert != nullptr;
}

absl::Span<const std::string> ConnectionInfoImplBase::uriSanLocalCertificate() const {
  if (!cached_uri_san_local_certificate_.empty()) {
    return cached_uri_san_local_certificate_;
  }

  // The cert object is not owned.
  X509* cert = SSL_get_certificate(ssl());
  if (!cert) {
    ASSERT(cached_uri_san_local_certificate_.empty());
    return cached_uri_san_local_certificate_;
  }
  cached_uri_san_local_certificate_ = Utility::getSubjectAltNames(*cert, GEN_URI);
  return cached_uri_san_local_certificate_;
}

absl::Span<const std::string> ConnectionInfoImplBase::dnsSansLocalCertificate() const {
  if (!cached_dns_san_local_certificate_.empty()) {
    return cached_dns_san_local_certificate_;
  }

  X509* cert = SSL_get_certificate(ssl());
  if (!cert) {
    ASSERT(cached_dns_san_local_certificate_.empty());
    return cached_dns_san_local_certificate_;
  }
  cached_dns_san_local_certificate_ = Utility::getSubjectAltNames(*cert, GEN_DNS);
  return cached_dns_san_local_certificate_;
}

absl::Span<const std::string> ConnectionInfoImplBase::ipSansLocalCertificate() const {
  if (!cached_ip_san_local_certificate_.empty()) {
    return cached_ip_san_local_certificate_;
  }

  X509* cert = SSL_get_certificate(ssl());
  if (!cert) {
    ASSERT(cached_ip_san_local_certificate_.empty());
    return cached_ip_san_local_certificate_;
  }
  cached_ip_san_local_certificate_ = Utility::getSubjectAltNames(*cert, GEN_IPADD);
  return cached_ip_san_local_certificate_;
}

const std::string& ConnectionInfoImplBase::sha256PeerCertificateDigest() const {
  if (!cached_sha_256_peer_certificate_digest_.empty()) {
    return cached_sha_256_peer_certificate_digest_;
  }
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_sha_256_peer_certificate_digest_.empty());
    return cached_sha_256_peer_certificate_digest_;
  }

  std::vector<uint8_t> computed_hash(SHA256_DIGEST_LENGTH);
  unsigned int n;
  X509_digest(cert.get(), EVP_sha256(), computed_hash.data(), &n);
  RELEASE_ASSERT(n == computed_hash.size(), "");
  cached_sha_256_peer_certificate_digest_ = Hex::encode(computed_hash);
  return cached_sha_256_peer_certificate_digest_;
}

const std::string& ConnectionInfoImplBase::sha1PeerCertificateDigest() const {
  if (!cached_sha_1_peer_certificate_digest_.empty()) {
    return cached_sha_1_peer_certificate_digest_;
  }
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_sha_1_peer_certificate_digest_.empty());
    return cached_sha_1_peer_certificate_digest_;
  }

  std::vector<uint8_t> computed_hash(SHA_DIGEST_LENGTH);
  unsigned int n;
  X509_digest(cert.get(), EVP_sha1(), computed_hash.data(), &n);
  RELEASE_ASSERT(n == computed_hash.size(), "");
  cached_sha_1_peer_certificate_digest_ = Hex::encode(computed_hash);
  return cached_sha_1_peer_certificate_digest_;
}

const std::string& ConnectionInfoImplBase::urlEncodedPemEncodedPeerCertificate() const {
  if (!cached_url_encoded_pem_encoded_peer_certificate_.empty()) {
    return cached_url_encoded_pem_encoded_peer_certificate_;
  }
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_url_encoded_pem_encoded_peer_certificate_.empty());
    return cached_url_encoded_pem_encoded_peer_certificate_;
  }

  bssl::UniquePtr<BIO> buf(BIO_new(BIO_s_mem()));
  RELEASE_ASSERT(buf != nullptr, "");
  RELEASE_ASSERT(PEM_write_bio_X509(buf.get(), cert.get()) == 1, "");
  const uint8_t* output;
  size_t length;
  RELEASE_ASSERT(BIO_mem_contents(buf.get(), &output, &length) == 1, "");
  absl::string_view pem(reinterpret_cast<const char*>(output), length);
  cached_url_encoded_pem_encoded_peer_certificate_ = absl::StrReplaceAll(
      pem, {{"\n", "%0A"}, {" ", "%20"}, {"+", "%2B"}, {"/", "%2F"}, {"=", "%3D"}});
  return cached_url_encoded_pem_encoded_peer_certificate_;
}

const std::string& ConnectionInfoImplBase::urlEncodedPemEncodedPeerCertificateChain() const {
  if (!cached_url_encoded_pem_encoded_peer_cert_chain_.empty()) {
    return cached_url_encoded_pem_encoded_peer_cert_chain_;
  }

  STACK_OF(X509)* cert_chain = SSL_get_peer_full_cert_chain(ssl());
  if (cert_chain == nullptr) {
    ASSERT(cached_url_encoded_pem_encoded_peer_cert_chain_.empty());
    return cached_url_encoded_pem_encoded_peer_cert_chain_;
  }

  for (uint64_t i = 0; i < sk_X509_num(cert_chain); i++) {
    X509* cert = sk_X509_value(cert_chain, i);

    bssl::UniquePtr<BIO> buf(BIO_new(BIO_s_mem()));
    RELEASE_ASSERT(buf != nullptr, "");
    RELEASE_ASSERT(PEM_write_bio_X509(buf.get(), cert) == 1, "");
    const uint8_t* output;
    size_t length;
    RELEASE_ASSERT(BIO_mem_contents(buf.get(), &output, &length) == 1, "");

    absl::string_view pem(reinterpret_cast<const char*>(output), length);
    cached_url_encoded_pem_encoded_peer_cert_chain_ = absl::StrCat(
        cached_url_encoded_pem_encoded_peer_cert_chain_,
        absl::StrReplaceAll(
            pem, {{"\n", "%0A"}, {" ", "%20"}, {"+", "%2B"}, {"/", "%2F"}, {"=", "%3D"}}));
  }
  return cached_url_encoded_pem_encoded_peer_cert_chain_;
}

absl::Span<const std::string> ConnectionInfoImplBase::uriSanPeerCertificate() const {
  if (!cached_uri_san_peer_certificate_.empty()) {
    return cached_uri_san_peer_certificate_;
  }

  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_uri_san_peer_certificate_.empty());
    return cached_uri_san_peer_certificate_;
  }
  cached_uri_san_peer_certificate_ = Utility::getSubjectAltNames(*cert, GEN_URI);
  return cached_uri_san_peer_certificate_;
}

absl::Span<const std::string> ConnectionInfoImplBase::dnsSansPeerCertificate() const {
  if (!cached_dns_san_peer_certificate_.empty()) {
    return cached_dns_san_peer_certificate_;
  }

  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_dns_san_peer_certificate_.empty());
    return cached_dns_san_peer_certificate_;
  }
  cached_dns_san_peer_certificate_ = Utility::getSubjectAltNames(*cert, GEN_DNS);
  return cached_dns_san_peer_certificate_;
}

absl::Span<const std::string> ConnectionInfoImplBase::ipSansPeerCertificate() const {
  if (!cached_ip_san_peer_certificate_.empty()) {
    return cached_ip_san_peer_certificate_;
  }

  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_ip_san_peer_certificate_.empty());
    return cached_ip_san_peer_certificate_;
  }
  cached_ip_san_peer_certificate_ = Utility::getSubjectAltNames(*cert, GEN_IPADD, true);
  return cached_ip_san_peer_certificate_;
}

uint16_t ConnectionInfoImplBase::ciphersuiteId() const {
  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl());
  if (cipher == nullptr) {
    return 0xffff;
  }

  // From the OpenSSL docs:
  //    SSL_CIPHER_get_id returns |cipher|'s id. It may be cast to a |uint16_t| to
  //    get the cipher suite value.
  return static_cast<uint16_t>(SSL_CIPHER_get_id(cipher));
}

std::string ConnectionInfoImplBase::ciphersuiteString() const {
  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl());
  if (cipher == nullptr) {
    return {};
  }

  return SSL_CIPHER_get_name(cipher);
}

const std::string& ConnectionInfoImplBase::tlsVersion() const {
  if (!cached_tls_version_.empty()) {
    return cached_tls_version_;
  }
  cached_tls_version_ = SSL_get_version(ssl());
  return cached_tls_version_;
}

const std::string& ConnectionInfoImplBase::alpn() const {
  if (alpn_.empty()) {
    const unsigned char* proto;
    unsigned int proto_len;
    SSL_get0_alpn_selected(ssl(), &proto, &proto_len);
    if (proto != nullptr) {
      alpn_ = std::string(reinterpret_cast<const char*>(proto), proto_len);
    }
  }
  return alpn_;
}

const std::string& ConnectionInfoImplBase::sni() const {
  if (sni_.empty()) {
    const char* proto = SSL_get_servername(ssl(), TLSEXT_NAMETYPE_host_name);
    if (proto != nullptr) {
      sni_ = std::string(proto);
    }
  }
  return sni_;
}

const std::string& ConnectionInfoImplBase::serialNumberPeerCertificate() const {
  if (!cached_serial_number_peer_certificate_.empty()) {
    return cached_serial_number_peer_certificate_;
  }
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_serial_number_peer_certificate_.empty());
    return cached_serial_number_peer_certificate_;
  }
  cached_serial_number_peer_certificate_ = Utility::getSerialNumberFromCertificate(*cert.get());
  return cached_serial_number_peer_certificate_;
}

const std::string& ConnectionInfoImplBase::issuerPeerCertificate() const {
  if (!cached_issuer_peer_certificate_.empty()) {
    return cached_issuer_peer_certificate_;
  }
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_issuer_peer_certificate_.empty());
    return cached_issuer_peer_certificate_;
  }
  cached_issuer_peer_certificate_ = Utility::getIssuerFromCertificate(*cert);
  return cached_issuer_peer_certificate_;
}

const std::string& ConnectionInfoImplBase::subjectPeerCertificate() const {
  if (!cached_subject_peer_certificate_.empty()) {
    return cached_subject_peer_certificate_;
  }
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_subject_peer_certificate_.empty());
    return cached_subject_peer_certificate_;
  }
  cached_subject_peer_certificate_ = Utility::getSubjectFromCertificate(*cert);
  return cached_subject_peer_certificate_;
}

const std::string& ConnectionInfoImplBase::subjectLocalCertificate() const {
  if (!cached_subject_local_certificate_.empty()) {
    return cached_subject_local_certificate_;
  }
  X509* cert = SSL_get_certificate(ssl());
  if (!cert) {
    ASSERT(cached_subject_local_certificate_.empty());
    return cached_subject_local_certificate_;
  }
  cached_subject_local_certificate_ = Utility::getSubjectFromCertificate(*cert);
  return cached_subject_local_certificate_;
}

absl::optional<SystemTime> ConnectionInfoImplBase::validFromPeerCertificate() const {
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    return absl::nullopt;
  }
  return Utility::getValidFrom(*cert);
}

absl::optional<SystemTime> ConnectionInfoImplBase::expirationPeerCertificate() const {
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    return absl::nullopt;
  }
  return Utility::getExpirationTime(*cert);
}

const std::string& ConnectionInfoImplBase::sessionId() const {
  if (!cached_session_id_.empty()) {
    return cached_session_id_;
  }
  SSL_SESSION* session = SSL_get_session(ssl());
  if (session == nullptr) {
    ASSERT(cached_session_id_.empty());
    return cached_session_id_;
  }

  unsigned int session_id_length = 0;
  const uint8_t* session_id = SSL_SESSION_get_id(session, &session_id_length);
  cached_session_id_ = Hex::encode(session_id, session_id_length);
  return cached_session_id_;
}


std::optional<std::string>
ConnectionInfoImplBase::getRoamingPartnerName(std::map<std::string, std::string>& dn_to_rp_table, std::map<const std::string,  const RE2>& dn_to_re2_regex_table, const EpochTime& config_updated_at) const {
  
  if (roaming_partner_name_ && config_updated_at <= last_config_update_) {
    return roaming_partner_name_;
  }
  else {
    // invalidate any chached rp name and refresh last_config_update_
    last_config_update_ = config_updated_at;
    roaming_partner_name_.reset();

  }

  if (dn_to_rp_table.empty()) {
    return std::nullopt;
  }
   const std::string wildcard_quoted = "\\*";

  // For SSL connections read the domain names from the CN/SAN information in the certificate and
  // match it on the SAN -> RP KvTAble to find the current Roaming Partner name.
  absl::Span<const std::string> cert_san_span = dnsSansPeerCertificate();
  if (cert_san_span.length() == 0) {
    ENVOY_LOG(warn, "No SAN information available for this connection.");
    return std::nullopt;
  }
  for (const auto& san : cert_san_span) {
    std::map<std::string, std::string>::const_iterator rp_name_it = dn_to_rp_table.find(san);
    //exact match failed, check for wildcards
    if (rp_name_it == dn_to_rp_table.end()) {
      for (auto dn_it = std::begin(dn_to_re2_regex_table); dn_it != std::end(dn_to_re2_regex_table);
           dn_it++) {
        const auto&  dn = dn_it->first;
        if (dn.find('*') != std::string::npos) {     
          const auto& dn = dn_it->first;

          // Attempt regex match for all configured wildcard DNs. Fetch the precompiled regex and
          // attempt a full match with supplied SAN
          if (RE2::FullMatch(absl::AsciiStrToLower(san), dn_it->second)) {
            ENVOY_LOG(trace, "Match found: DN={}, SAN={}", dn, san);
            rp_name_it = dn_to_rp_table.find(dn);
            if (rp_name_it != dn_to_rp_table.end()) {
              ENVOY_LOG(debug, "Found Roaming Partner name {} for wildcard match DN {} SAN {}",
                        rp_name_it->second, dn, san);
              roaming_partner_name_.emplace(rp_name_it->second);

              return roaming_partner_name_;
            } else {
              ENVOY_LOG(warn,
                        "No Roaming Partner name found for successful wildcard match DN {} SAN {}",
                        dn, san);
              roaming_partner_name_.reset();
              return roaming_partner_name_;
            }
          }
        } else if (san.find('*') != std::string::npos) {
            ENVOY_LOG(trace, "Wild-card found in SAN={}", san);
            absl::string_view match_type{"DN"};
            absl::string_view match_string = dn;

            auto pattern_regex = RE2::QuoteMeta(san);
            ENVOY_LOG(trace, "Quoted pattern={}, {}={}", pattern_regex, match_type, match_string);
            auto wildcard_start_pos = pattern_regex.find(wildcard_quoted);
            if (wildcard_start_pos != std::string::npos) {
              auto wildcard_in_regex = "[^.]*";
              if (absl::StartsWith(pattern_regex, wildcard_quoted)) {
                // We do not want to match e.g. *.ericsson.se with .ericsson.se.
                wildcard_in_regex = "[^.]+";
              }
              pattern_regex =
                  pattern_regex.replace(wildcard_start_pos, wildcard_quoted.length(), wildcard_in_regex);
              ENVOY_LOG(trace, "Wild-card quoted pattern={}, {}={}", pattern_regex, match_type,
                        match_string);
              if (RE2::FullMatch(absl::AsciiStrToLower(match_string),
                                  absl::AsciiStrToLower(pattern_regex))) {
                ENVOY_LOG(trace, "Match found: DN={}, SAN={}", dn, san);
                rp_name_it = dn_to_rp_table.find(dn);
                if (rp_name_it != dn_to_rp_table.end()) {
                  ENVOY_LOG(debug, "Found Roaming Partner name {} for wildcard match DN {} SAN {}",
                            rp_name_it->second, dn, san);
                  roaming_partner_name_.emplace(rp_name_it->second);
                  return roaming_partner_name_;
                } else {
                  ENVOY_LOG(warn,
                            "No Roaming Partner name found for successful wildcard match DN {} SAN {}",
                            dn, san);
                  roaming_partner_name_.reset();
                  return roaming_partner_name_;

                }
              }
            }
        }
      }
    } else {
        //exacth match
        const std::string& rp_name = rp_name_it->second;
        if (!rp_name.empty()) {
          ENVOY_LOG(debug, "Found Roaming Partner name {} for exact-matched SAN {}", rp_name, san);
          roaming_partner_name_.emplace(rp_name);
        } else {
          ENVOY_LOG(warn, "Roaming Partner name is an empty string for exact-matched SAN {}", san);
         roaming_partner_name_.reset();
        }
        return roaming_partner_name_;
      }
  }
  ENVOY_LOG(warn,
            "Matched {} SANs on the KvTable but could not find a matching roaming partner name",
            cert_san_span.length());
  roaming_partner_name_.reset();
  return roaming_partner_name_;
}

bool& ConnectionInfoImplBase::n32cHandshakeState() const {
  return cached_n32c_handshake_completed_;
}

double& ConnectionInfoImplBase::n32cInfoTimestamp() const { return cached_n32c_timestamp_; }

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
