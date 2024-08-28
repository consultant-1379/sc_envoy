#pragma once

#include "source/extensions/transport_sockets/tls/cert_validator/cert_validator.h"
#include "source/extensions/transport_sockets/tls/cert_validator/san_matcher.h"
#include "source/extensions/transport_sockets/tls/stats.h"

#include "source/common/common/c_smart_ptr.h"

#include "openssl/ssl.h"
#include "openssl/x509v3.h"
#include <utility>

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

using X509StorePtr = CSmartPtr<X509_STORE, X509_STORE_free>;

class SEPPValidator : public CertValidator {
public:
  SEPPValidator(SslStats& stats, TimeSource& time_source)
      : stats_(stats), time_source_(time_source){};
  SEPPValidator(const Envoy::Ssl::CertificateValidationContextConfig* config, SslStats& stats,
                TimeSource& time_source);
  ~SEPPValidator() override = default;

  // override strat Tls::CertValidator
  void addClientValidationContext(SSL_CTX* context, bool require_client_cert) override;
  int doSynchronousVerifyCertChain(
      X509_STORE_CTX* store_ctx, Ssl::SslExtendedSocketInfo* ssl_extended_info, X509& leaf_cert,
      const Network::TransportSocketOptions* transport_socket_options);
  ValidationResults
  doVerifyCertChain(STACK_OF(X509)& cert_chain, Ssl::ValidateResultCallbackPtr callback,
                    const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options,
                    SSL_CTX& ssl_ctx,
                    const CertValidator::ExtraValidationContext& validation_context, bool is_server,
                    absl::string_view host_name) override;
  int initializeSslContexts(std::vector<SSL_CTX*> contexts, bool provides_certificates) override;
  void updateDigestForSessionId(bssl::ScopedEVP_MD_CTX& md, uint8_t hash_buffer[EVP_MAX_MD_SIZE],
                                unsigned hash_length) override;
  absl::optional<uint32_t> daysUntilFirstCertExpires() const override;
  std::string getCaFileName() const override { return "Does not support"; };
  Envoy::Ssl::CertificateDetailsPtr getCaCertInformation() const override;
  // override end Tls::CertValidator

  X509_STORE* getTrustStore(X509* leaf_cert);
  bool matchSubjectAltName(X509& leaf_cert);

  std::vector<std::pair<X509StorePtr, std::vector<SanMatcherPtr>>>& trustStores() {
    return trust_sepp_stores_;
  };

private:
  SslStats& stats_;
  TimeSource& time_source_;

  bool allow_expired_certificate_{false};
  std::vector<std::pair<X509StorePtr, std::vector<SanMatcherPtr>>> trust_sepp_stores_;
  std::vector<SanMatcherPtr> subject_alt_name_matchers_{};
  std::vector<bssl::UniquePtr<X509>> ca_certs_;
  bool verifyCertChainUsingTrustStores(X509& leaf_cert, STACK_OF(X509)* cert_chain,
                                       X509_VERIFY_PARAM* verify_param, std::string& error_details);
};

DECLARE_FACTORY(SEPPValidatorFactory);

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
