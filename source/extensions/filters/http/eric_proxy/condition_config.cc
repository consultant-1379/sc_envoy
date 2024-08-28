// Given a condition from the decoded protobuf
// configuration and the root-context, create the operator
// tree to evaluate the condition later when a
// request comes in.
// The entrypoint is the last function in this file.

#include "source/common/common/utility.h"
#include "source/extensions/filters/http/eric_proxy/condition.h"
#include "source/extensions/filters/http/eric_proxy/condition_config.h"
#include "source/extensions/filters/http/eric_proxy/contexts.h"
#include "source/extensions/filters/http/eric_proxy/proxy_filter_config.h"
#include <memory>
#include <iostream>
#include <string>

// Some abbreviations to make the code below easier to read:
#define BooleanConstT RootContext::ConditionType::BooleanConstT
#define NumberConstT RootContext::ConditionType::NumberConstT
#define StringConstT RootContext::ConditionType::StringConstT
#define StringReqHeaderT RootContext::ConditionType::StringReqHeaderT
#define StringRespHeaderT RootContext::ConditionType::StringRespHeaderT
#define StringQueryParamT RootContext::ConditionType::StringQueryParamT
#define StringApiContextNameT RootContext::ConditionType::StringApiContextNameT
#define VarT RootContext::ConditionType::VarT

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// Set up an op_equals expression.
std::unique_ptr<Operator> setUpOpEquals(RootContext& root_ctx,
                                        const ConditionProtoConfig& cfg,
                                        std::set<ValueIndex>& var_req,
                                        std::set<ValueIndex>& hdr_req,
                                        std::set<ValueIndex>& query_param_req) {
  ConditionValue arg1;
  ConditionValue arg2;
  Condition condition1;
  Condition condition2;
  if (cfg.op_equals().typed_config1().UnpackTo(&arg1) &&
      cfg.op_equals().typed_config2().UnpackTo(&arg2)) {

    auto [type1, index1] = root_ctx.typeAndIndexForValue(arg1);
    auto [type2, index2] = root_ctx.typeAndIndexForValue(arg2);

    switch (type1) {
    case StringConstT: {
      switch (type2) {
      case StringConstT:
        return std::make_unique<OperatorEqualsStringConstStringConst>(root_ctx, index1, index2);
      case VarT:
        return std::make_unique<OperatorEqualsStringVarStringConst>(root_ctx, index2, index1,
                                                                    var_req, hdr_req);
      case StringReqHeaderT:
        return std::make_unique<OperatorEqualsStringHeaderStringConst>(
            root_ctx, index2, index1, var_req, hdr_req, ReqOrResp::Request);
      case StringRespHeaderT:
        return std::make_unique<OperatorEqualsStringHeaderStringConst>(
            root_ctx, index2, index1, var_req, hdr_req, ReqOrResp::Response);
      case StringQueryParamT:
        return std::make_unique<OperatorEqualsStringQueryParamStringConst>(root_ctx, index2, index1,
                                                                           query_param_req);
      case StringApiContextNameT:
        return std::make_unique<OperatorEqualsStringConstApiContextName>(root_ctx, index1, false);
      default:
        ExceptionUtil::throwEnvoyException("Unknown condition type for op_equals");
      }
    }
    case NumberConstT: {
      switch (type2) {
      case NumberConstT:
        return std::make_unique<OperatorEqualsNumberConstNumberConst>(root_ctx, index1, index2);
      case VarT:
        return std::make_unique<OperatorEqualsStringVarNumberConst>(root_ctx, index2, index1,
                                                                    var_req, hdr_req);
      case StringReqHeaderT:
      case StringRespHeaderT:
      case StringQueryParamT:
      case StringApiContextNameT:
        return std::make_unique<OperatorTermBoolean>(root_ctx,
                                                     false); // always false b/c differnt types
      default:
        ExceptionUtil::throwEnvoyException("Unknown condition type for op_equals");
      }
    }
    case StringReqHeaderT: {
      switch (type2) {
      case StringReqHeaderT:
        return std::make_unique<OperatorEqualsStringHeaderStringHeader>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Request, ReqOrResp::Request);
      case StringRespHeaderT:
        return std::make_unique<OperatorEqualsStringHeaderStringHeader>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Request, ReqOrResp::Response);
      case StringConstT:
        return std::make_unique<OperatorEqualsStringHeaderStringConst>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Request);
      case NumberConstT:
        return std::make_unique<OperatorTermBoolean>(root_ctx,
                                                     false); // always false b/c differnt types
      case VarT:
        return std::make_unique<OperatorEqualsStringVarStringHeader>(
            root_ctx, index2, index1, var_req, hdr_req, ReqOrResp::Request);
      case StringQueryParamT:
        return std::make_unique<OperatorEqualsStringQueryParamStringHeader>(
            root_ctx, index2, index1, hdr_req, query_param_req, ReqOrResp::Request);
      case StringApiContextNameT:
        return std::make_unique<OperatorEqualsStringHeaderApiContextName>(
            root_ctx, index1, hdr_req, ReqOrResp::Request, false);
      default:
        ExceptionUtil::throwEnvoyException("Unknown condition type for op_equals");
      }
    }
    case StringRespHeaderT: {
      switch (type2) {
      case StringReqHeaderT:
        return std::make_unique<OperatorEqualsStringHeaderStringHeader>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Response, ReqOrResp::Request);
      case StringRespHeaderT:
        return std::make_unique<OperatorEqualsStringHeaderStringHeader>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Response, ReqOrResp::Response);
      case VarT:
        return std::make_unique<OperatorEqualsStringVarStringHeader>(
            root_ctx, index2, index1, var_req, hdr_req, ReqOrResp::Response);
      case StringConstT:
        return std::make_unique<OperatorEqualsStringHeaderStringConst>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Response);
      case StringQueryParamT:
        return std::make_unique<OperatorEqualsStringQueryParamStringHeader>(
            root_ctx, index2, index1, hdr_req, query_param_req, ReqOrResp::Response);
      case NumberConstT:
        return std::make_unique<OperatorTermBoolean>(root_ctx,
                                                     false); // always false b/c differnt types
      case StringApiContextNameT:
        return std::make_unique<OperatorEqualsStringHeaderApiContextName>(
            root_ctx, index1, hdr_req, ReqOrResp::Response, false);
      default:
        ExceptionUtil::throwEnvoyException("Unknown condition type for op_equals");
      }
    }
    case VarT: {
      switch (type2) {
      case StringConstT:
        return std::make_unique<OperatorEqualsStringVarStringConst>(root_ctx, index1, index2,
                                                                    var_req, hdr_req);
      case VarT:
        return std::make_unique<OperatorEqualsStringVarStringVar>(root_ctx, index1, index2, var_req,
                                                                  hdr_req);
      case NumberConstT:
        return std::make_unique<OperatorEqualsStringVarNumberConst>(root_ctx, index1, index2,
                                                                    var_req, hdr_req);
      case BooleanConstT:
        return std::make_unique<OperatorEqualsStringVarBooleanConst>(root_ctx, index1, index2,
                                                                     var_req, hdr_req);
      case StringReqHeaderT:
        return std::make_unique<OperatorEqualsStringVarStringHeader>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Request);
      case StringRespHeaderT:
        return std::make_unique<OperatorEqualsStringVarStringHeader>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Response);
      case StringQueryParamT:
        return std::make_unique<OperatorEqualsStringQueryParamStringVar>(root_ctx, index2, index1,
                                                                         var_req, query_param_req);
      case StringApiContextNameT:
        return std::make_unique<OperatorEqualsStringVarApiContextName>(root_ctx, index1, var_req,
                                                                       false);
      default:
        ExceptionUtil::throwEnvoyException("Unknown condition type for op_equals");
      }
    }
    case BooleanConstT: {
      switch (type2) {
      case VarT:
        return std::make_unique<OperatorEqualsStringVarBooleanConst>(root_ctx, index2, index1,
                                                                     var_req, hdr_req);
      // all other comparisons of term_val throw an exception
      default:
        ExceptionUtil::throwEnvoyException("Unknown condition type for op_equals");
      }
    }
    case StringQueryParamT: {
      switch (type2) {
      case StringConstT:
        return std::make_unique<OperatorEqualsStringQueryParamStringConst>(root_ctx, index1, index2,
                                                                           query_param_req);
      case VarT:
        return std::make_unique<OperatorEqualsStringQueryParamStringVar>(root_ctx, index1, index2,
                                                                         var_req, query_param_req);
      case NumberConstT:
        return std::make_unique<OperatorTermBoolean>(root_ctx,
                                                     false); // always false b/c differnt types
      case StringReqHeaderT:
        return std::make_unique<OperatorEqualsStringQueryParamStringHeader>(
            root_ctx, index1, index2, hdr_req, query_param_req, ReqOrResp::Request);
      case StringRespHeaderT:
        return std::make_unique<OperatorEqualsStringQueryParamStringHeader>(
            root_ctx, index1, index2, hdr_req, query_param_req, ReqOrResp::Response);
      case StringQueryParamT:
        return std::make_unique<OperatorEqualsStringQueryParamStringQueryParam>(
            root_ctx, index1, index2, query_param_req);
      case StringApiContextNameT:
        return std::make_unique<OperatorEqualsStringQueryParamApiContextName>(
            root_ctx, index1, query_param_req, false);
      default:
        ExceptionUtil::throwEnvoyException("Unknown condition type for op_equals");
      }
    }
    case StringApiContextNameT: {
      switch (type2) {
      case StringConstT:
        return std::make_unique<OperatorEqualsStringConstApiContextName>(root_ctx, index2, false);
      case VarT:
        return std::make_unique<OperatorEqualsStringVarApiContextName>(root_ctx, index2, var_req,
                                                                       false);
      case StringReqHeaderT:
        return std::make_unique<OperatorEqualsStringHeaderApiContextName>(
            root_ctx, index2, hdr_req, ReqOrResp::Request, false);
      case StringRespHeaderT:
        return std::make_unique<OperatorEqualsStringHeaderApiContextName>(
            root_ctx, index2, hdr_req, ReqOrResp::Response, false);
      case StringQueryParamT:
        return std::make_unique<OperatorEqualsStringQueryParamApiContextName>(
            root_ctx, index2, query_param_req, false);
      case StringApiContextNameT:
        return std::make_unique<OperatorTermBoolean>(
            root_ctx,
            true); // always true as it's comparing the same thing
      case NumberConstT:
      case BooleanConstT:
        return std::make_unique<OperatorTermBoolean>(root_ctx,
                                                     false); // always false b/c differnt types
      }
    }
    }
  } else if (cfg.op_equals().typed_config1().UnpackTo(&condition1) &&
             cfg.op_equals().typed_config2().UnpackTo(&condition2)) {
    return std::make_unique<OperatorEqualsCondition>(
        root_ctx, setUpCondition(root_ctx, condition1, var_req, hdr_req, query_param_req),
        setUpCondition(root_ctx, condition2, var_req, hdr_req, query_param_req));
  } else {
    ExceptionUtil::throwEnvoyException("Illegal argument types or combination for op_equals");
  }
}

// Set up an op_exists expression
std::unique_ptr<Operator> setUpOpExists(RootContext& root_ctx,
                                        const ConditionProtoConfig& cfg,
                                        std::set<ValueIndex>& var_req,
                                        std::set<ValueIndex>& hdr_req,
                                        std::set<ValueIndex>& query_param_req) {
  auto [type, index] = root_ctx.typeAndIndexForValue(cfg.op_exists().arg1());
  switch (type) {
  case BooleanConstT:
  case NumberConstT:
  case StringConstT:
    return std::make_unique<OperatorTrue>(root_ctx);
  case StringReqHeaderT:
    return std::make_unique<OperatorExistsHeader>(root_ctx, index, var_req, hdr_req,
                                                  ReqOrResp::Request);
  case StringRespHeaderT:
    return std::make_unique<OperatorExistsHeader>(root_ctx, index, var_req, hdr_req,
                                                  ReqOrResp::Response);
  case StringQueryParamT:
    return std::make_unique<OperatorExistsQueryParam>(root_ctx, index, query_param_req);
  case VarT:
    return std::make_unique<OperatorExistsStringVar>(root_ctx, index, var_req, hdr_req);
  case StringApiContextNameT:
    return std::make_unique<OperatorExistsApiContextName>(root_ctx);
  default:
    ExceptionUtil::throwEnvoyException("Unknown condition type for op_exists");
  }
}

// Set up an op_isempty expression
std::unique_ptr<Operator> setUpOpIsempty(RootContext& root_ctx,
                                         const ConditionProtoConfig& cfg,
                                         std::set<ValueIndex>& var_req,
                                         std::set<ValueIndex>& hdr_req,
                                         std::set<ValueIndex>& query_param_req) {
  auto [type, index] = root_ctx.typeAndIndexForValue(cfg.op_isempty().arg1());
  switch (type) {
  case BooleanConstT:
  case NumberConstT:
  case StringConstT:
    return std::make_unique<OperatorFalse>(root_ctx);
  case StringReqHeaderT:
    return std::make_unique<OperatorIsemptyHeader>(root_ctx, index, var_req, hdr_req,
                                                   ReqOrResp::Request);
  case StringRespHeaderT:
    return std::make_unique<OperatorIsemptyHeader>(root_ctx, index, var_req, hdr_req,
                                                   ReqOrResp::Response);
  case StringQueryParamT:
    return std::make_unique<OperatorIsemptyQueryParam>(root_ctx, index, query_param_req);
  case VarT:
    return std::make_unique<OperatorIsemptyStringVar>(root_ctx, index, var_req, hdr_req);
  case StringApiContextNameT:
    return std::make_unique<OperatorIsEmptyApiContextName>(root_ctx);
  default:
    ExceptionUtil::throwEnvoyException("Unknown condition type for op_isempty");
  }
}

// Set up an op_isinsubnet expression
std::unique_ptr<Operator> setUpOpIsinsubnet(RootContext& root_ctx,
                                         const ConditionProtoConfig& cfg,
                                         std::set<ValueIndex>& var_req,
                                         std::set<ValueIndex>& hdr_req) {
  auto [addr_type, addr_index] = root_ctx.typeAndIndexForValue(cfg.op_isinsubnet().arg1());
  switch (addr_type) {
  case StringConstT:
    return std::make_unique<OperatorIsinsubnetStringConst>(root_ctx, addr_index,
        cfg.op_isinsubnet().arg2());
       break;
  case StringReqHeaderT:
    return std::make_unique<OperatorIsinsubnetHeader>(root_ctx, addr_index,
        cfg.op_isinsubnet().arg2(), hdr_req, ReqOrResp::Request);
  case StringRespHeaderT:
    return std::make_unique<OperatorIsinsubnetHeader>(root_ctx, addr_index,
        cfg.op_isinsubnet().arg2(), hdr_req, ReqOrResp::Response);
    break;
  case VarT:
    return std::make_unique<OperatorIsinsubnetStringVar>(root_ctx, addr_index,
        cfg.op_isinsubnet().arg2(), var_req);
    break;
  default:
    ExceptionUtil::throwEnvoyException("Unknown condition type for op_isempty");
  }
}

// Set up op_equals_case_insensitive expression
std::unique_ptr<Operator> setUpOpEqualsCaseInsensitive(RootContext& root_ctx,
                                                       const ConditionProtoConfig& cfg,
                                                       std::set<ValueIndex>& var_req,
                                                       std::set<ValueIndex>& hdr_req,
                                                       std::set<ValueIndex>& query_param_req) {
  ConditionValue arg1;
  ConditionValue arg2;
  Condition condition1;
  Condition condition2;

  if (cfg.op_equals_case_insensitive().typed_config1().UnpackTo(&arg1) &&
      cfg.op_equals_case_insensitive().typed_config2().UnpackTo(&arg2)) {

    auto [type1, index1] = root_ctx.typeAndIndexForValue(arg1);
    auto [type2, index2] = root_ctx.typeAndIndexForValue(arg2);

    switch (type1) {
    case StringConstT: {
      switch (type2) {
      case StringConstT:
        return std::make_unique<OperatorEqualsCaseInsStringConstStringConst>(root_ctx, index1,
                                                                             index2);
      case VarT:
        return std::make_unique<OperatorEqualsCaseInsStringVarStringConst>(root_ctx, index2, index1,
                                                                           var_req, hdr_req);
      case StringReqHeaderT:
        return std::make_unique<OperatorEqualsCaseInsStringHeaderStringConst>(
            root_ctx, index2, index1, var_req, hdr_req, ReqOrResp::Request);
      case StringRespHeaderT:
        return std::make_unique<OperatorEqualsCaseInsStringHeaderStringConst>(
            root_ctx, index2, index1, var_req, hdr_req, ReqOrResp::Response);
      case StringQueryParamT:
        return std::make_unique<OperatorEqualsCaseInsStringQueryParamStringConst>(
            root_ctx, index2, index1, query_param_req);
      case StringApiContextNameT:
        return std::make_unique<OperatorEqualsStringConstApiContextName>(root_ctx, index1, false);
      default:
        ExceptionUtil::throwEnvoyException("Unknown condition type for op_equals");
      }
    }
    case NumberConstT: {
      switch (type2) {
      case NumberConstT:
        return std::make_unique<OperatorEqualsNumberConstNumberConst>(root_ctx, index1, index2);
      case VarT:
        return std::make_unique<OperatorEqualsStringVarNumberConst>(root_ctx, index2, index1,
                                                                    var_req, hdr_req);
      case StringReqHeaderT:
      case StringRespHeaderT:
      case StringQueryParamT:
      case StringApiContextNameT:
        return std::make_unique<OperatorTermBoolean>(root_ctx,
                                                     false); // always false b/c differnt types
      default:
        ExceptionUtil::throwEnvoyException("Unknown condition type for op_equals");
      }
    }
    case StringReqHeaderT: {
      switch (type2) {
      case StringReqHeaderT:
        return std::make_unique<OperatorEqualsCaseInsStringHeaderStringHeader>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Request, ReqOrResp::Request);
      case StringRespHeaderT:
        return std::make_unique<OperatorEqualsCaseInsStringHeaderStringHeader>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Request, ReqOrResp::Response);
      case StringConstT:
        return std::make_unique<OperatorEqualsCaseInsStringHeaderStringConst>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Request);
      case NumberConstT:
        return std::make_unique<OperatorTermBoolean>(root_ctx,
                                                     false); // always false b/c differnt types
      case VarT:
        return std::make_unique<OperatorEqualsCaseInsStringVarStringHeader>(
            root_ctx, index2, index1, var_req, hdr_req, ReqOrResp::Request);
      case StringQueryParamT:
        return std::make_unique<OperatorEqualsCaseInsStringQueryParamStringHeader>(
            root_ctx, index2, index1, hdr_req, query_param_req, ReqOrResp::Request);
      case StringApiContextNameT:
        return std::make_unique<OperatorEqualsStringHeaderApiContextName>(
            root_ctx, index1, hdr_req, ReqOrResp::Request, false);
      default:
        ExceptionUtil::throwEnvoyException("Unknown condition type for op_equals");
      }
    }
    case StringRespHeaderT: {
      switch (type2) {
      case StringReqHeaderT:
        return std::make_unique<OperatorEqualsCaseInsStringHeaderStringHeader>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Response, ReqOrResp::Request);
      case StringRespHeaderT:
        return std::make_unique<OperatorEqualsCaseInsStringHeaderStringHeader>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Response, ReqOrResp::Response);
      case VarT:
        return std::make_unique<OperatorEqualsCaseInsStringVarStringHeader>(
            root_ctx, index2, index1, var_req, hdr_req, ReqOrResp::Response);
      case StringConstT:
        return std::make_unique<OperatorEqualsCaseInsStringHeaderStringConst>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Response);
      case StringQueryParamT:
        return std::make_unique<OperatorEqualsCaseInsStringQueryParamStringHeader>(
            root_ctx, index2, index1, hdr_req, query_param_req, ReqOrResp::Response);
      case NumberConstT:
        return std::make_unique<OperatorTermBoolean>(root_ctx,
                                                     false); // always false b/c differnt types
      case StringApiContextNameT:
        return std::make_unique<OperatorEqualsStringHeaderApiContextName>(
            root_ctx, index1, hdr_req, ReqOrResp::Response, false);
      default:
        ExceptionUtil::throwEnvoyException("Unknown condition type for op_equals");
      }
    }
    case VarT: {
      switch (type2) {
      case StringConstT:
        return std::make_unique<OperatorEqualsCaseInsStringVarStringConst>(root_ctx, index1, index2,
                                                                           var_req, hdr_req);
      case VarT:
        return std::make_unique<OperatorEqualsCaseInsStringVarStringVar>(root_ctx, index1, index2,
                                                                         var_req, hdr_req);
      case NumberConstT:
        return std::make_unique<OperatorEqualsStringVarNumberConst>(root_ctx, index1, index2,
                                                                    var_req, hdr_req);
      case BooleanConstT:
        return std::make_unique<OperatorEqualsStringVarBooleanConst>(root_ctx, index1, index2,
                                                                     var_req, hdr_req);
      case StringReqHeaderT:
        return std::make_unique<OperatorEqualsCaseInsStringVarStringHeader>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Request);
      case StringRespHeaderT:
        return std::make_unique<OperatorEqualsCaseInsStringVarStringHeader>(
            root_ctx, index1, index2, var_req, hdr_req, ReqOrResp::Response);
      case StringQueryParamT:
        return std::make_unique<OperatorEqualsCaseInsStringQueryParamStringVar>(
            root_ctx, index2, index1, var_req, query_param_req);
      case StringApiContextNameT:
        return std::make_unique<OperatorEqualsStringVarApiContextName>(root_ctx, index1, var_req,
                                                                       false);
      default:
        ExceptionUtil::throwEnvoyException("Unknown condition type for op_equals");
      }
    }
    case BooleanConstT: {
      switch (type2) {
      case VarT:
        return std::make_unique<OperatorEqualsStringVarBooleanConst>(root_ctx, index2, index1,
                                                                     var_req, hdr_req);
      // all other comparisons of term_val throw an exception
      default:
        ExceptionUtil::throwEnvoyException("Unknown condition type for op_equals");
      }
    }
    case StringQueryParamT: {
      switch (type2) {
      case StringConstT:
        return std::make_unique<OperatorEqualsCaseInsStringQueryParamStringConst>(
            root_ctx, index1, index2, query_param_req);
      case VarT:
        return std::make_unique<OperatorEqualsCaseInsStringQueryParamStringVar>(
            root_ctx, index1, index2, var_req, query_param_req);
      case NumberConstT:
        return std::make_unique<OperatorTermBoolean>(root_ctx,
                                                     false); // always false b/c differnt types
      case StringReqHeaderT:
        return std::make_unique<OperatorEqualsCaseInsStringQueryParamStringHeader>(
            root_ctx, index1, index2, hdr_req, query_param_req, ReqOrResp::Request);
      case StringRespHeaderT:
        return std::make_unique<OperatorEqualsCaseInsStringQueryParamStringHeader>(
            root_ctx, index1, index2, hdr_req, query_param_req, ReqOrResp::Response);
      case StringQueryParamT:
        return std::make_unique<OperatorEqualsCaseInsStringQueryParamStringQueryParam>(
            root_ctx, index1, index2, query_param_req);
      case StringApiContextNameT:
        return std::make_unique<OperatorEqualsStringQueryParamApiContextName>(
            root_ctx, index1, query_param_req, false);
      default:
        ExceptionUtil::throwEnvoyException("Unknown condition type for op_equals");
      }
    }
    case StringApiContextNameT: {
      switch (type2) {
      case StringConstT:
        return std::make_unique<OperatorEqualsStringConstApiContextName>(root_ctx, index2, true);
      case VarT:
        return std::make_unique<OperatorEqualsStringVarApiContextName>(root_ctx, index2, var_req,
                                                                       true);
      case StringReqHeaderT:
        return std::make_unique<OperatorEqualsStringHeaderApiContextName>(root_ctx, index2, hdr_req,
                                                                          ReqOrResp::Request, true);
      case StringRespHeaderT:
        return std::make_unique<OperatorEqualsStringHeaderApiContextName>(
            root_ctx, index2, hdr_req, ReqOrResp::Response, true);
      case StringQueryParamT:
        return std::make_unique<OperatorEqualsStringQueryParamApiContextName>(
            root_ctx, index2, query_param_req, true);
      case StringApiContextNameT:
        return std::make_unique<OperatorTermBoolean>(
            root_ctx,
            true); // always true as it's comparing the same thing
      case NumberConstT:
      case BooleanConstT:
        return std::make_unique<OperatorTermBoolean>(root_ctx,
                                                     false); // always false b/c differnt types
      }
    }
    }
  } else if (cfg.op_equals_case_insensitive().typed_config1().UnpackTo(&condition1) &&
             cfg.op_equals_case_insensitive().typed_config2().UnpackTo(&condition2)) {
    return std::make_unique<OperatorEqualsCondition>(
        root_ctx, setUpCondition(root_ctx, condition1, var_req, hdr_req, query_param_req),
        setUpCondition(root_ctx, condition2, var_req, hdr_req, query_param_req));
  } else {
    ExceptionUtil::throwEnvoyException("Illegal argument types or combination for op_equals_case_insensitive");
  }
}

// Set up an op_isvalidjson expression
std::unique_ptr<Operator> setUpOpIsvalidjson(RootContext& root_ctx,
                                         const ConditionProtoConfig& cfg) {
  if (cfg.op_isvalidjson().has_request_body()) { return std::make_unique<OperatorIsvalidjson>(root_ctx, ReqOrResp::Request); }
  else if (cfg.op_isvalidjson().has_response_body()) { return std::make_unique<OperatorIsvalidjson>(root_ctx, ReqOrResp::Response); }
  else { ExceptionUtil::throwEnvoyException("Unknown source for op_isvalidjson"); }
 }

//-------Entry point ----------------------------------------------------------

// Create the object-tree to later evaluate a condition. This code
// is executed during configuration time (= not in the request path).
std::unique_ptr<Operator> setUpCondition(RootContext& root_ctx,
                                       const ConditionProtoConfig& cfg,
                                       std::set<ValueIndex>& var_req,
                                       std::set<ValueIndex>& hdr_req,
                                       std::set<ValueIndex>& query_param_req) {
  switch (cfg.expr_case()) {
  case envoy::extensions::filters::http::eric_proxy::v3::Condition::kOpEquals:
    return setUpOpEquals(root_ctx, cfg, var_req, hdr_req, query_param_req);
  case envoy::extensions::filters::http::eric_proxy::v3::Condition::kTermBoolean:
    return std::make_unique<OperatorTermBoolean>(root_ctx, cfg.term_boolean());
  case envoy::extensions::filters::http::eric_proxy::v3::Condition::kOpAnd:
    return std::make_unique<OperatorAnd>(
        root_ctx, setUpCondition(root_ctx, cfg.op_and().arg1(), var_req, hdr_req, query_param_req),
        setUpCondition(root_ctx, cfg.op_and().arg2(), var_req, hdr_req, query_param_req));
  case envoy::extensions::filters::http::eric_proxy::v3::Condition::kOpOr:
    return std::make_unique<OperatorOr>(
        root_ctx, setUpCondition(root_ctx, cfg.op_or().arg1(), var_req, hdr_req, query_param_req),
        setUpCondition(root_ctx, cfg.op_or().arg2(), var_req, hdr_req, query_param_req));
  case envoy::extensions::filters::http::eric_proxy::v3::Condition::kOpNot:
    return std::make_unique<OperatorNot>(
        root_ctx, setUpCondition(root_ctx, cfg.op_not().arg1(), var_req, hdr_req, query_param_req));
  case envoy::extensions::filters::http::eric_proxy::v3::Condition::kOpExists:
    return setUpOpExists(root_ctx, cfg, var_req, hdr_req, query_param_req);
  case envoy::extensions::filters::http::eric_proxy::v3::Condition::kOpIsempty:
    return setUpOpIsempty(root_ctx, cfg, var_req, hdr_req, query_param_req);
  case envoy::extensions::filters::http::eric_proxy::v3::Condition::kOpIsinsubnet:
    return setUpOpIsinsubnet(root_ctx, cfg, var_req, hdr_req);
  case envoy::extensions::filters::http::eric_proxy::v3::Condition::kOpIsvalidjson:
    return setUpOpIsvalidjson(root_ctx, cfg);
  case envoy::extensions::filters::http::eric_proxy::v3::Condition::kOpEqualsCaseInsensitive:
    return setUpOpEqualsCaseInsensitive(root_ctx, cfg, var_req, hdr_req, query_param_req);
  default:
    ExceptionUtil::throwEnvoyException(fmt::format("Unknown operator in condition {}", cfg.expr_case()));
  }
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
