#include "source/extensions/transport_sockets/tls/cert_validator/eric_sepp/eric_sepp_validator.h"
#include "source/extensions/transport_sockets/tls/cert_validator/factory.h"

#include "envoy/extensions/transport_sockets/tls/v3/sepp_validator_config.pb.h"

#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/config/utility.h"
#include "source/common/config/datasource.h"
#include "source/extensions/transport_sockets/tls/cert_validator/utility.h"
#include <algorithm>

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

using SEPPConfig = envoy::extensions::transport_sockets::tls::v3::SEPPCertValidatorConfig;

SEPPValidator::SEPPValidator(const Envoy::Ssl::CertificateValidationContextConfig* config,
                             SslStats& stats, TimeSource& time_source)
    : stats_(stats), time_source_(time_source) {
  ASSERT(config != nullptr);
  allow_expired_certificate_ = config->allowExpiredCertificate();

  SEPPConfig sepp_message;
  Config::Utility::translateOpaqueConfig(config->customValidatorConfig().value().typed_config(),
                                         ProtobufMessage::getStrictValidationVisitor(),
                                         sepp_message);

  if (!config->subjectAltNameMatchers().empty()) {
    for (const envoy::extensions::transport_sockets::tls::v3::SubjectAltNameMatcher& matcher :
         config->subjectAltNameMatchers()) {
      auto san_matcher = createStringSanMatcher(matcher);
      if (san_matcher == nullptr) {
        throw EnvoyException(
            absl::StrCat("Failed to create string SAN matcher of type ", matcher.san_type()));
      }
      subject_alt_name_matchers_.push_back(std::move(san_matcher));
    }
  }

  const auto size = sepp_message.trust_stores_size();

  trust_sepp_stores_.reserve(size);

  for (const auto& message_ts : sepp_message.trust_stores()) {

    auto cert = Config::DataSource::read(message_ts.trusted_ca(), true, config->api());
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(const_cast<char*>(cert.data()), cert.size()));
    RELEASE_ASSERT(bio != nullptr, "");
    bssl::UniquePtr<STACK_OF(X509_INFO)> list(
        PEM_X509_INFO_read_bio(bio.get(), nullptr, nullptr, nullptr));
    if (list == nullptr || sk_X509_INFO_num(list.get()) == 0) {
      throw EnvoyException(
          absl::StrCat("Failed to load trusted CA certificate for ", message_ts.name()));
    }
    auto store = X509StorePtr(X509_STORE_new());
    bool has_crl = false;
    for (const X509_INFO* item : list.get()) {
      if (item->x509) {
        X509_STORE_add_cert(store.get(), item->x509);
        ca_certs_.push_back(bssl::UniquePtr<X509>(item->x509));
        X509_up_ref(item->x509);
      }
      if (item->crl) {
        has_crl = true;
        X509_STORE_add_crl(store.get(), item->crl);
      }
    }

    if (has_crl) {
      X509_STORE_set_flags(store.get(), X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    }

    auto matchers = std::vector<SanMatcherPtr>();
    matchers.reserve(message_ts.matchers_size());

    for (const auto& m : message_ts.matchers()) {
      auto san_matcher = createStringSanMatcher(m);
      if (san_matcher == nullptr) {
        throw EnvoyException(
            absl::StrCat("Failed to create string SAN matcher of type ", m.san_type()));
      }
      matchers.emplace_back(std::move(san_matcher));
    }
    trust_sepp_stores_.emplace_back(std::make_pair(std::move(store), std::move(matchers)));
  }
};

void SEPPValidator::addClientValidationContext(SSL_CTX* context, bool) {
  bssl::UniquePtr<STACK_OF(X509_NAME)> list(sk_X509_NAME_new(
      [](auto* a, auto* b) -> int { return X509_NAME_cmp(*a, *b); }));

  for (auto& ca : ca_certs_) {
    X509_NAME* name = X509_get_subject_name(ca.get());

    // Check for duplicates.
    if (sk_X509_NAME_find(list.get(), nullptr, name)) {
      continue;
    }

    bssl::UniquePtr<X509_NAME> name_dup(X509_NAME_dup(name));
    if (name_dup == nullptr || !sk_X509_NAME_push(list.get(), name_dup.release())) {
      throw EnvoyException(absl::StrCat("Failed to load trusted client CA certificate"));
    }
  }
  SSL_CTX_set_client_CA_list(context, list.release());
}

void SEPPValidator::updateDigestForSessionId(bssl::ScopedEVP_MD_CTX& md, uint8_t* hash_buffer,
                                             unsigned int hash_length) {
  int rc;
  for (auto& ca : ca_certs_) {
    rc = X509_digest(ca.get(), EVP_sha256(), hash_buffer, &hash_length);
    RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));
    RELEASE_ASSERT(hash_length == SHA256_DIGEST_LENGTH,
                   fmt::format("invalid SHA256 hash length {}", hash_length));
    rc = EVP_DigestUpdate(md.get(), hash_buffer, hash_length);
    RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));
  }
}

int SEPPValidator::initializeSslContexts(std::vector<SSL_CTX*>, bool) {
  return SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
};

int SEPPValidator::doSynchronousVerifyCertChain(X509_STORE_CTX* store_ctx,
                                                Ssl::SslExtendedSocketInfo* ssl_extended_info,
                                                X509& leaf_cert,
                                                const Network::TransportSocketOptions*) {
  // retrieves an internal pointer to the stack of untrusted certificates associated with ctx.
  STACK_OF(X509)* cert_chain = X509_STORE_CTX_get0_untrusted(store_ctx);
  X509_VERIFY_PARAM* verify_param = X509_STORE_CTX_get0_param(store_ctx);
  std::string error_details;
  const bool verified =
      verifyCertChainUsingTrustStores(leaf_cert, cert_chain, verify_param, error_details);

  if (ssl_extended_info) {
    ssl_extended_info->setCertificateValidationStatus(
        verified ? Envoy::Ssl::ClientValidationStatus::Validated
                 : Envoy::Ssl::ClientValidationStatus::Failed);
  }
  return verified ? 1 : 0;
}

bool SEPPValidator::verifyCertChainUsingTrustStores(X509& leaf_cert, STACK_OF(X509)* cert_chain,
                                                    X509_VERIFY_PARAM* verify_param,
                                                    std::string& error_details) {
  // Get trust store for the SAN on leaf certificate
  auto trust_store = getTrustStore(&leaf_cert);
  if (!trust_store) {
    error_details = "verify cert failed: no trust bundle store";
    stats_.fail_verify_error_.inc();
    return 0;
  }

  bssl::UniquePtr<X509_STORE_CTX> new_store_ctx(X509_STORE_CTX_new());
  if (!X509_STORE_CTX_init(new_store_ctx.get(), trust_store, &leaf_cert, cert_chain) ||
      !X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(new_store_ctx.get()), verify_param)) {
    error_details = "verify cert failed: init and setup X509_STORE_CTX";
    stats_.fail_verify_error_.inc();
    return 0;
  }
  if (allow_expired_certificate_) {
    CertValidatorUtil::setIgnoreCertificateExpiration(new_store_ctx.get());
  }
  auto ret = X509_verify_cert(new_store_ctx.get());
  if (!ret) {
    error_details = absl::StrCat("verify cert failed: ",
                                 Utility::getX509VerificationErrorInfo(new_store_ctx.get()));
    stats_.fail_verify_error_.inc();
    return false;
  }

  // Do SAN matching.
  const bool san_match = subject_alt_name_matchers_.empty() ? true : matchSubjectAltName(leaf_cert);
  if (!san_match) {
    error_details = "verify cert failed: SAN match";
    stats_.fail_verify_error_.inc();
  }

  return san_match;
}

ValidationResults SEPPValidator::doVerifyCertChain(
    STACK_OF(X509)& cert_chain, Ssl::ValidateResultCallbackPtr /*callback*/,
    const Network::TransportSocketOptionsConstSharedPtr& /*transport_socket_options*/,
    SSL_CTX& ssl_ctx, const CertValidator::ExtraValidationContext& /*validation_context*/,
    bool /*is_server*/, absl::string_view /*host_name*/) {
  if (sk_X509_num(&cert_chain) == 0) {
    stats_.fail_verify_error_.inc();
    return {ValidationResults::ValidationStatus::Failed,
            Envoy::Ssl::ClientValidationStatus::NotValidated, absl::nullopt,
            "verify cert failed: empty cert chain"};
  }
  X509* leaf_cert = sk_X509_value(&cert_chain, 0);
  std::string error_details;
  const bool verified = verifyCertChainUsingTrustStores(
      *leaf_cert, &cert_chain, SSL_CTX_get0_param(&ssl_ctx), error_details);

  return verified ? ValidationResults{ValidationResults::ValidationStatus::Successful,
                                      Envoy::Ssl::ClientValidationStatus::Validated, absl::nullopt,
                                      absl::nullopt}
                  : ValidationResults{ValidationResults::ValidationStatus::Failed,
                                      Envoy::Ssl::ClientValidationStatus::Failed, absl::nullopt,
                                      error_details};
}

bool SEPPValidator::matchSubjectAltName(X509& leaf_cert) {
  bssl::UniquePtr<GENERAL_NAMES> san_names(static_cast<GENERAL_NAMES*>(
      X509_get_ext_d2i(&leaf_cert, NID_subject_alt_name, nullptr, nullptr)));
  // We must not have san_names == nullptr here because this function is called after the
  // SPIFFE cert validation algorithm succeeded, which requires exactly one URI SAN in the leaf
  // cert.
  ASSERT(san_names != nullptr,
         "san_names should have at least one name after SPIFFE cert validation");

  for (const GENERAL_NAME* general_name : san_names.get()) {
    for (const auto& config_san_matcher : subject_alt_name_matchers_) {
      if (config_san_matcher->match(general_name)) {
        return true;
      }
    }
  }
  return false;
}

X509_STORE* SEPPValidator::getTrustStore(X509* leaf_cert) {
  bssl::UniquePtr<GENERAL_NAMES> san_names(static_cast<GENERAL_NAMES*>(
      X509_get_ext_d2i(leaf_cert, NID_subject_alt_name, nullptr, nullptr)));

  if (!san_names) {
    return nullptr;
  }

  for (const GENERAL_NAME* general_name : san_names.get()) {
    // Here I am checking only DNS
    if (general_name->type != GEN_DNS) {
      continue;
    }

    for (const auto& ts : trust_sepp_stores_) {
      for (const auto& m : ts.second) {
        if (m->match(general_name)) {
          return ts.first.get();
        }
      }
    }
  }
  return nullptr;
}

absl::optional<uint32_t> SEPPValidator::daysUntilFirstCertExpires() const {
  if (ca_certs_.empty()) {
    return absl::make_optional(std::numeric_limits<uint32_t>::max());
  }
  absl::optional<uint32_t> ret = absl::make_optional(std::numeric_limits<uint32_t>::max());
  for (auto& cert : ca_certs_) {
    const absl::optional<uint32_t> tmp = Utility::getDaysUntilExpiration(cert.get(), time_source_);
    if (!tmp.has_value()) {
      return absl::nullopt;
    } else if (tmp.value() < ret.value()) {
      ret = tmp;
    }
  }
  return ret;
}
Envoy::Ssl::CertificateDetailsPtr SEPPValidator::getCaCertInformation() const {
  if (ca_certs_.empty()) {
    return nullptr;
  }
  // So temporarily we return the first CA's info here.
  return Utility::certificateDetails(ca_certs_[0].get(), getCaFileName(), time_source_);
}

class SEPPValidatorFactory : public CertValidatorFactory {
public:
  CertValidatorPtr createCertValidator(const Envoy::Ssl::CertificateValidationContextConfig* config,
                                       SslStats& stats, TimeSource& time_source) override {
    return std::make_unique<SEPPValidator>(config, stats, time_source);
  }

  std::string name() const override { return "envoy.tls.cert_validator.sepp"; }
};

REGISTER_FACTORY(SEPPValidatorFactory, CertValidatorFactory);

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
