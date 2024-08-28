#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "source/extensions/filters/http/eric_proxy/contexts.h"
#include "source/extensions/filters/http/eric_proxy/wrappers.h"
#include "test/test_common/utility.h"
#include "test/test_common/environment.h"
#include "include/nlohmann/json.hpp"

#include "gtest/gtest.h"
#include <regex>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

class TestServiceClassifier : public ServiceClassifierConfigBase {
public:
  void setApiName(const std::string& api_name) { api_name_ = api_name; }
  void setApiVersions(const std::vector<std::string>& api_versions) { api_versions_ = api_versions; }
  void setResourceMatchers(const std::vector<std::string>& resource_matchers) {
    resource_matchers_ = {};
    for (const auto& resource_matcher : resource_matchers) {
      resource_matchers_.push_back(std::make_pair(resource_matcher, std::regex(resource_matcher)));
    }
  }
  void setIsNotification(const bool& is_notification) { is_notification_ = is_notification; }
  void setMethods(const std::vector<std::string>& methods) { methods_ = methods; }
};

//-------------------------------------------------------------------------------------------------
// Tests service classifier eval()
TEST(EricProxyFilterServiceClassifierTest, TestScEval) {
  RootContext root_ctx;
  RunContext run_ctx = RunContext(&root_ctx);
  Http::TestRequestHeaderMapImpl headers {
      {":method", "POST"},
      {":path", "/nudm-comm/v1/nf-instances/abc/someop"}
  };
  run_ctx.setReqHeaders(&headers);
  EricProxyFilter::populateServiceContext(run_ctx, nullptr);

  // Fake Conf.
  TestServiceClassifier test_classifier;

  // Positive tests

  test_classifier.setApiName("nudm-comm");
  test_classifier.setApiVersions({"v1"});
  test_classifier.setResourceMatchers({"/nf-instances/.*/someop"});
  test_classifier.setMethods({"POST"});
  ENVOY_LOG_MISC(trace, "Check if request matches: {}", test_classifier.debugString());
  EXPECT_TRUE(test_classifier.eval(&run_ctx));

  test_classifier.setApiVersions({"v1", "v2"});
  test_classifier.setMethods({"GET", "POST"});
  test_classifier.setResourceMatchers({"/nf-instances/.*/someop", "/nf-instances/.*/someop2"});
  test_classifier.setIsNotification(false);
  ENVOY_LOG_MISC(trace, "Check if request matches: {}", test_classifier.debugString());
  EXPECT_TRUE(test_classifier.eval(&run_ctx));

  test_classifier.setApiName("");
  test_classifier.setMethods({""});
  ENVOY_LOG_MISC(trace, "Check if request matches: {}", test_classifier.debugString());
  EXPECT_TRUE(test_classifier.eval(&run_ctx));

  test_classifier.setApiVersions({"", "v2"});
  test_classifier.setMethods({"GET", ""});
  ENVOY_LOG_MISC(trace, "Check if request matches: {}", test_classifier.debugString());
  EXPECT_TRUE(test_classifier.eval(&run_ctx));

  // Negative tests

  test_classifier.setApiName("nnrf-disc");
  ENVOY_LOG_MISC(trace, "Check if request matches: {}", test_classifier.debugString());
  EXPECT_FALSE(test_classifier.eval(&run_ctx));

  test_classifier.setApiName("nudm-comm");
  test_classifier.setApiVersions({"v2"});
  ENVOY_LOG_MISC(trace, "Check if request matches: {}", test_classifier.debugString());
  EXPECT_FALSE(test_classifier.eval(&run_ctx));

  test_classifier.setApiVersions({"v1"});
  test_classifier.setResourceMatchers({"/nf-instances/.*/someop2"});
  ENVOY_LOG_MISC(trace, "Check if request matches: {}", test_classifier.debugString());
  EXPECT_FALSE(test_classifier.eval(&run_ctx));

  test_classifier.setResourceMatchers({"/nf-instances/.*/someop"});
  test_classifier.setMethods({"GET"});
  ENVOY_LOG_MISC(trace, "Check if request matches: {}", test_classifier.debugString());
  EXPECT_FALSE(test_classifier.eval(&run_ctx));

  test_classifier.setMethods({"POST"});
  test_classifier.setIsNotification(true);
  ENVOY_LOG_MISC(trace, "Check if request matches: {}", test_classifier.debugString());
  EXPECT_FALSE(test_classifier.eval(&run_ctx));
}

//-------------------------------------------------------------------------------------------------
// Tests default allowed/denied service operations

const std::vector<std::tuple<std::string, std::string, std::string>> default_allowed_requests {
  {"POST", "/nsmf-pdusession/v1/sm-contexts", ""},
  {"POST", "/nsmf-pdusession/v1/sm-contexts", "Nsmf_PDUSession_smContextStatusNotification"},
  {"POST", "/nsmf-pdusession/v1/sm-contexts", "Nsmf_PDUSession_smContextStatusNotification; apiVersion=1"},
  {"POST", "/nsmf-pdusession/v1/sm-contexts/{smContextRef}/retrieve", ""},
  {"POST", "/nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify", ""},
  {"POST", "/nsmf-pdusession/v1/sm-contexts/{smContextRef}/release", ""},
  {"POST", "/nsmf-pdusession/v1/pdu-sessions", ""},
  {"POST", "/nsmf-pdusession/v1/pdu-sessions", "Nsmf_PDUSession_StatusNotify"},
  {"POST", "/nsmf-pdusession/v1/pdu-sessions", "Nsmf_PDUSession_Update"},
  {"POST", "/nsmf-pdusession/v1/pdu-sessions", "Nsmf_PDUSession_statusNotification-ismf"},
  {"POST", "/nsmf-pdusession/v1/pdu-sessions", "Nsmf_PDUSession_update-ismf"},
  {"POST", "/nsmf-pdusession/v1/pdu-sessions", "Nsmf_PDUSession_transferMtData"},
  {"POST", "/nsmf-pdusession/v1/pdu-sessions", "Nsmf_PDUSession_transferMtData-ismf"},
  {"POST", "/nsmf-pdusession/v1/pdu-sessions/{pduSessionRef}/modify", ""},
  {"POST", "/nsmf-pdusession/v1/pdu-sessions/{pduSessionRef}/release", ""},
  {"POST", "/nsmf-pdusession/v1/pdu-sessions/{pduSessionRef}/retrieve", ""},
  {"POST", "/nsmf-pdusession/v1/pdu-sessions/{pduSessionRef}/transfer-mo-data", ""},
  {"POST", "/nudm-ee/v1/anyUE/ee-subscriptions", ""},
  {"POST", "/nudm-ee/v1/anyUE/ee-subscriptions", "Nudm_EE_eventOccurrenceNotification"},
  {"DELETE", "/nudm-ee/v1/anyUE/ee-subscriptions/{subscriptionId}", ""},
  {"PATCH", "/nudm-ee/v1/anyUE/ee-subscriptions/{subscriptionId}", ""},
  {"PUT", "/nudm-sdm/v2/imsi-12345/am-data/cag-ack", ""},
  {"GET", "/nudm-sdm/v2/imsi-12345", ""},
  {"GET", "/nudm-sdm/v2/imsi-12345/nssai", ""},
  {"GET", "/nudm-sdm/v2/imsi-12345/am-data", ""},
  {"GET", "/nudm-sdm/v2/imsi-12345/smf-select-data", ""},
  {"GET", "/nudm-sdm/v2/imsi-12345/ue-context-in-smf-data", ""},
  {"GET", "/nudm-sdm/v2/imsi-12345/ue-context-in-smsf-data", ""},
  {"GET", "/nudm-sdm/v2/imsi-12345/trace-data", ""},
  {"GET", "/nudm-sdm/v2/imsi-12345/sm-data", ""},
  {"GET", "/nudm-sdm/v2/imsi-12345/sms-data", ""},
  {"GET", "/nudm-sdm/v2/imsi-12345/sms-mng-data", ""},
  {"GET", "/nudm-sdm/v2/imsi-12345/lcs-mo-data", ""},
  {"GET", "/nudm-sdm/v2/imsi-12345/lcs-bca-data", ""},
  {"GET", "/nudm-sdm/v2/imsi-12345/v2x-data", ""},
  {"POST", "/nudm-sdm/v2/imsi-12345/sdm-subscriptions", ""},
  {"DELETE", "/nudm-sdm/v2/imsi-12345/sdm-subscriptions/{subscriptionId}", ""},
  {"PATCH", "/nudm-sdm/v2/imsi-12345/sdm-subscriptions/{subscriptionId}", ""},
  {"PUT", "/nudm-sdm/v2/imsi-12345/am-data/sor-ack", ""},
  {"PUT", "/nudm-sdm/v2/imsi-12345/am-data/upu-ack", ""},
  {"PUT", "/nudm-sdm/v2/imsi-12345/am-data/subscribed-snssais-ack", ""},
  {"GET", "/nudm-sdm/v2/shared-data", ""},
  {"POST", "/nudm-sdm/v2/shared-data-subscriptions", ""},
  {"DELETE", "/nudm-sdm/v2/shared-data-subscriptions/{subscriptionId}", ""},
  {"PATCH", "/nudm-sdm/v2/shared-data-subscriptions/{subscriptionId}", ""},
  {"POST", "/nudm-sdm/v2/imsi-12345/am-data/update-sor", ""},
  {"GET", "/nudm-sdm/v2/group-data/group-identifiers", ""},
  {"PUT", "/nudm-uecm/v1/gci-12345/registrations/amf-3gpp-access", ""},
  {"PATCH", "/nudm-uecm/v1/gci-12345/registrations/amf-3gpp-access", ""},
  {"PUT", "/nudm-uecm/v1/gci-12345/registrations/amf-non-3gpp-access", ""},
  {"PATCH", "/nudm-uecm/v1/gci-12345/registrations/amf-non-3gpp-access", ""},
  {"POST", "/nudm-uecm/v1/gci-12345/registrations/amf-3gpp-access", "Nudm_UECM_DeregistrationNotification"},
  {"POST", "/nudm-uecm/v1/gci-12345/registrations/amf-3gpp-access", "Nudm_UECM_PCSCFRestorationNotification"},
  {"POST", "/nudm-uecm/v1/gci-12345/registrations/amf-non-3gpp-access", "Nudm_UECM_DeregistrationNotification"},
  {"POST", "/nudm-uecm/v1/gci-12345/registrations/amf-non-3gpp-access", "Nudm_UECM_PCSCFRestorationNotification"},
  {"POST", "/nudm-uecm/v1/gci-12345/registrations/smf-registrations/12345", "Nudm_UECM_DeregistrationNotification"},
  {"POST", "/nudm-uecm/v1/gci-12345/registrations/smf-registrations/12345", "Nudm_UECM_PCSCFRestorationNotification"},
  {"PUT", "/nudm-uecm/v1/gci-12345/registrations/smf-registrations/12345", ""},
  {"DELETE", "/nudm-uecm/v1/gci-12345/registrations/smf-registrations/12345", ""},
  {"PUT", "/nudm-uecm/v1/gci-12345/registrations/smsf-3gpp-access", ""},
  {"DELETE", "/nudm-uecm/v1/gci-12345/registrations/smsf-3gpp-access", ""},
  {"PUT", "/nudm-uecm/v1/gci-12345/registrations/smsf-non-3gpp-access", ""},
  {"DELETE", "/nudm-uecm/v1/gci-12345/registrations/smsf-non-3gpp-access", ""},
  {"GET", "/nudm-uecm/v1/gci-12345/registrations", ""},
  {"POST", "/nausf-auth/v1/ue-authentications", ""},
  {"PUT", "/nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation", ""},
  {"DELETE", "/nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation", ""},
  {"POST", "/nausf-auth/v1/ue-authentications/{authCtxId}/eap-session", ""},
  {"DELETE", "/nausf-auth/v1/ue-authentications/{authCtxId}/eap-session", ""},
  {"POST", "/nausf-auth/v1/rg-authentications", ""},
  {"POST", "/oauth2/token", ""},
  {"GET", "/bootstrapping", ""},
  {"GET", "/nnrf-disc/v1/nf-instances", ""},
  {"GET", "/nnrf-disc/v1/searches/{searchId}", ""},
  {"GET", "/nnrf-disc/v1/searches/{searchId}/complete", ""},
  {"POST", "/namf-eventexposure/v1/subscriptions", "Namf_EventExposure_Notify"},
  {"POST", "/namf-loc/v1/5g-guti-12345abcdefabcdefab/provide-loc-info", ""},
  {"GET", "/namf-mt/v1/ue-contexts/5g-guti-12345abcdefabcdefab", ""},
  {"GET", "/nnssf-nsselection/v2/network-slice-information", ""},
  {"POST", "/n32f-forward/v1/n32f-process", ""},
  {"OPTIONS", "/n32f-forward/v1/n32f-process", ""},
  {"POST", "/n32c-handshake/v1/exchange-capability", ""},
  {"POST", "/n32c-handshake/v1/exchange-params", ""},
  {"POST", "/n32c-handshake/v1/n32f-terminate", ""},
  {"POST", "/n32c-handshake/v1/n32f-error", ""}
};

const std::vector<std::tuple<std::string, std::string, std::string>> default_denied_requests {
  {"GET", "/nsmf-pdusession/v1/sm-contexts", ""},
  {"POST", "/nsmfpdusession/v1/sm-contexts", ""},
  {"POST", "/nsmf-pdusession/V1/sm-contexts", ""},
  {"POST", "/nsmf-pdusession/v1/sm-context", ""},
  {"POST", "/nsmf-pdusession/v1/SM-contexts", ""},
  {"POST", "/nsmf-pdusession/v1/sm-contexts/xyz", ""},
  {"POST", "/nsmf-pdusession/v1/xyz/sm-contexts", ""},
  {"POST", "", ""},
  {"POST", "/nsmf-pdusession/v1/sm-contexts", "NsmfPDUSessionsmContextStatusNotification"},
  {"POST", "Nsmf_PDUSession_smContextStatusNotification", "/nsmf-pdusession/v1/sm-contexts"},
  {"POST", "/nsmf-pdusession/v1/sm-contexts", "Nsmf_PDUSession_smContextStatusNotification; apiVersion=2"},
  {"POST", "/nsmf-pdusession/v1/sm-context/{smContextRef}/retrieve", ""},
  {"POST", "/nsmf-pdusession/v1/sm-contexts/{smContextRef}/xyz", ""},
  {"POST", "/nudm-ee/v1/{ueIdentity}/ee-subscriptions", ""},
  {"DELETE", "/nudm-ee/v1/anyUE/ee-subscriptions/{subscriptionId}/", ""},
  {"DELETE", "/nudm-ee/v1/anyUE/ee-subscriptions/{subscriptionId}/xyz", ""},
  {"PUT", "/nudm-sdm/v2/{supi}/am-data/cag-ack", ""},
  {"DELETE", "/nudm-sdm/v2/imsi-12345/sdm-subscriptions/{subscriptionId}/xyz", ""},
  {"DELETE", "/nudm-sdm/v2/shared-data-subscriptions/{subscriptionId}/xyz", ""},
  {"PUT", "/nudm-uecm/v1/{ueId}/registrations/amf-3gpp-access", ""},
  {"PUT", "/nudm-uecm/v1/gci-12345/registrations/smf-registrations/{pduSessionId}", ""},
  {"PUT", "/nausf-auth/v1/ue-authentications/{authCtxId}//5g-aka-confirmation", ""},
  {"PUT", "/nausf-auth/v1/ue-authentications/{authCtxId}/xyz/5g-aka-confirmation", ""},
  {"POST", "/nausf-auth/v1/ue-authentications/{authCtxId}/xyz/eap-session", ""},
  {"POST", "/oauth2/token/xyz", ""},
  {"GET", "/bootstrapping/xyz", ""},
  {"GET", "/nnrf-disc/v1/searches/{searchId}/", ""},
  {"GET", "/nnrf-disc/v1/searches/{searchId}/xyz", ""},
  {"GET", "/nnrf-disc/v1/searches/{searchId}/xyz/complete", ""},
  {"POST", "/namf-loc/v1/{ueContextId}/provide-loc-info", ""},
  {"GET", "/namf-mt/v1/ue-contexts/{ueContextId}", ""}
};

Http::TestRequestHeaderMapImpl genHeaders(const std::string& method, const std::string& path,
                                          const std::string& callback) {
  if (!callback.empty()) {
    return Http::TestRequestHeaderMapImpl{
      {":method", method},
      {":path", path},
      {"3gpp-Sbi-Callback", callback}
    };    
  }
  return Http::TestRequestHeaderMapImpl{
    {":method", method},
    {":path", path}
  };
}

void populateTestServiceClassifier(TestServiceClassifier& test_classifier, const Json& service_operation) {
  if (service_operation.contains("api_versions")) {
    test_classifier.setApiVersions(service_operation.at("api_versions"));
  }
  if (service_operation.contains("resource_matchers")) {
    test_classifier.setResourceMatchers(service_operation.at("resource_matchers"));
  }
  if (service_operation.contains("http_methods")) {
    test_classifier.setMethods(service_operation.at("http_methods"));
  }
  if (service_operation.contains("is_notification")) {
    test_classifier.setIsNotification(service_operation.at("is_notification"));
  }
}

bool isAuthorizedServiceOperation(RunContext& run_ctx, const Json& config) {
  for (const auto& service_operation : config.at("default_allowed_service_operations")) {
    if (service_operation.at("api_names").empty()) {
      TestServiceClassifier test_classifier;
      populateTestServiceClassifier(test_classifier, service_operation);
      // ENVOY_LOG_MISC(trace, "Check if request matches: {}", test_classifier.debugString());
      if (test_classifier.eval(&run_ctx)) {
        return true;
      }
    } else {
      for (const auto& api_name : service_operation.at("api_names")) {
        TestServiceClassifier test_classifier;
        test_classifier.setApiName(api_name);
        populateTestServiceClassifier(test_classifier, service_operation);
        // ENVOY_LOG_MISC(trace, "Check if request matches: {}", test_classifier.debugString());
        if (test_classifier.eval(&run_ctx)) {
          return true;
        }
      }
    }
  }
  return false;
}

TEST(EricProxyFilterServiceClassifierTest, TestDefaultAllowedServiceOperations) {
  std::string path = TestEnvironment::substitute("{{ test_rundir }}/test/extensions/filters/http/eric_proxy/test_data/usfw_usoc_config_dump.json");
  std::unique_ptr<Envoy::Api::Api> api = Api::createApiForTest();
  auto file_or_error = api->fileSystem().fileReadToEnd(path);
  THROW_IF_STATUS_NOT_OK(file_or_error, throw);
  const std::string contents = file_or_error.value();
  const Json& config = Json::parse(contents);

  for (const auto& request : default_allowed_requests) {
    RootContext root_ctx;
    RunContext run_ctx = RunContext(&root_ctx);
    Http::TestRequestHeaderMapImpl headers = genHeaders(std::get<0>(request), std::get<1>(request), std::get<2>(request));
    run_ctx.setReqHeaders(&headers);
    EricProxyFilter::populateServiceContext(run_ctx, nullptr);
    EXPECT_TRUE(isAuthorizedServiceOperation(run_ctx, config));
  }

  for (const auto& request : default_denied_requests) {
    RootContext root_ctx;
    RunContext run_ctx = RunContext(&root_ctx);
    Http::TestRequestHeaderMapImpl headers = genHeaders(std::get<0>(request), std::get<1>(request), std::get<2>(request));
    run_ctx.setReqHeaders(&headers);
    EricProxyFilter::populateServiceContext(run_ctx, nullptr);
    EXPECT_FALSE(isAuthorizedServiceOperation(run_ctx, config));
  }
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
