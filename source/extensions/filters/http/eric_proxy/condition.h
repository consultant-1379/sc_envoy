#pragma once

#include <algorithm>
#include <string>
#include <cfloat>
#include "absl/strings/string_view.h"
#include "source/extensions/filters/http/eric_proxy/contexts.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/cidr_range.h"
#include "source/common/network/utility.h"
#include "body.h"


namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// TODO(eedala): Change all structs below into classes and make the method public
//               in order to match Envoy's coding standards (structs must not have
//               methods, only data)
//               See op_isinsubnet.

//---------------------------------------------------------------------------------------
// Base-class for all operators. A condition is compiled into a tree of
// specialized operators derived from this class.
class Operator {
public:
  Operator(RootContext& root_ctx) : root_ctx_(root_ctx){};
  Operator(RootContext& root_ctx, ValueIndex index1) : root_ctx_(root_ctx), index1_(index1){};
  Operator(RootContext& root_ctx, ValueIndex index1, ValueIndex index2)
      : root_ctx_(root_ctx), index1_(index1), index2_(index2){};
  Operator(RootContext& root_ctx, std::shared_ptr<Operator> op1)
      : root_ctx_(root_ctx), operator1_(op1){};
  Operator(RootContext& root_ctx, std::shared_ptr<Operator> op1, std::shared_ptr<Operator> op2)
      : root_ctx_(root_ctx), operator1_(op1), operator2_(op2){};
  virtual ~Operator() = default;
  virtual bool eval(RunContext&) = 0;

protected:
  RootContext& root_ctx_;
  ValueIndex index1_;
  ValueIndex index2_;
  std::shared_ptr<Operator> operator1_;
  std::shared_ptr<Operator> operator2_;

  // AlmostEqualRelative from:
  // https://randomascii.wordpress.com/2012/02/25/comparing-floating-point-numbers-2012-edition/
  bool almostEqualRelative(double a, double b,
                         double max_rel_diff = DBL_EPSILON)
{
    // Calculate the difference.
    double diff = fabs(a - b);
    a = fabs(a);
    b = fabs(b);
    // Find the largest
    float largest = (b > a) ? b : a;

    return (diff <= largest * max_rel_diff);
}
};

//--------- true and false ------------------------------------------------------------
// A pseudo-operator that always returns true or false. Used when it's clear at config
// time what the outcome will be.
struct OperatorTrue : Operator {
  OperatorTrue(RootContext& root_ctx) : Operator(root_ctx){};
  bool eval(RunContext&) override { return true; }
};

struct OperatorFalse : Operator {
  OperatorFalse(RootContext& root_ctx) : Operator(root_ctx){};
  bool eval(RunContext&) override { return false; }
};

//--------- op_and --------------------------------------------------------------------
struct OperatorAnd : Operator {
  OperatorAnd(RootContext& root_ctx, std::shared_ptr<Operator> op1, std::shared_ptr<Operator> op2)
      : Operator(root_ctx, op1, op2){};
  bool eval(RunContext& run_ctx) override {
    return operator1_->eval(run_ctx) && operator2_->eval(run_ctx);
  }
};

//--------- op_or --------------------------------------------------------------------
struct OperatorOr : Operator {
  OperatorOr(RootContext& root_ctx, std::shared_ptr<Operator> op1, std::shared_ptr<Operator> op2)
      : Operator(root_ctx, op1, op2){};
  bool eval(RunContext& run_ctx) override {
    return operator1_->eval(run_ctx) || operator2_->eval(run_ctx);
  }
};

//--------- op_not --------------------------------------------------------------------
struct OperatorNot : Operator {
  OperatorNot(RootContext& root_ctx, std::shared_ptr<Operator> op1) : Operator(root_ctx, op1){};
  bool eval(RunContext& run_ctx) override { return !operator1_->eval(run_ctx); }
};

//--------- op_equals -----------------------------------------------------------------
struct OperatorEqualsStringConstStringConst : Operator {
  OperatorEqualsStringConstStringConst(RootContext& root_ctx, ValueIndex const_index1,
                                       ValueIndex const_index2)
      : Operator(root_ctx, const_index1, const_index2){};
  bool eval(RunContext&) override {
    return root_ctx_.constValue(index1_) == root_ctx_.constValue(index2_);
  }
};
struct OperatorEqualsNumberConstNumberConst : Operator {
  OperatorEqualsNumberConstNumberConst(RootContext& root_ctx, ValueIndex const_index1,
                                       ValueIndex const_index2)
      : Operator(root_ctx, const_index1, const_index2){};
  bool eval(RunContext&) override {
    // Since using == for floating point numbers is not working in most cases, use a more
    // clever way:
    return almostEqualRelative(root_ctx_.constValue(index1_).get<double>(),
      root_ctx_.constValue(index2_).get<double>());
  }
};
struct OperatorEqualsStringVarStringConst : Operator {
  OperatorEqualsStringVarStringConst(RootContext& root_ctx, ValueIndex var_index,
                                     ValueIndex const_index, std::set<ValueIndex>& var_req,
                                     std::set<ValueIndex>&)
      : Operator(root_ctx, var_index, const_index) {
    var_req.insert(var_index);
  };
  bool eval(RunContext& run_ctx) override {
    const auto& json_val = run_ctx.varValue(index1_);
    // Since a string const is always of type string, if the variable is not of
    // type string as well, the comparison ends here:
    if(!json_val.is_string()) {
        return false;
    }
    const std::string var_val = run_ctx.varValue(index1_).get<std::string>();
    return var_val == root_ctx_.constValue(index2_);
  }
};
struct OperatorEqualsStringVarNumberConst : Operator {
  OperatorEqualsStringVarNumberConst(RootContext& root_ctx, ValueIndex var_index,
                                     ValueIndex const_index, std::set<ValueIndex>& var_req,
                                     std::set<ValueIndex>&)
      : Operator(root_ctx, var_index, const_index) {
    var_req.insert(var_index);
  };
  bool eval(RunContext& run_ctx) override {
    const auto& json_val = run_ctx.varValue(index1_);
    // If the variable is not of type number, comparison returns false because comparing
    // different types always results in false
    if(!json_val.is_number()) {
        return false;
    }
    const double var_val = run_ctx.varValue(index1_).get<double>();
    return var_val == root_ctx_.constValue(index2_);
  }
};
struct OperatorEqualsStringVarBooleanConst : Operator {
  OperatorEqualsStringVarBooleanConst(RootContext& root_ctx, ValueIndex var_index,
                                     ValueIndex const_index, std::set<ValueIndex>& var_req,
                                     std::set<ValueIndex>&)
      : Operator(root_ctx, var_index, const_index) {
    var_req.insert(var_index);
  };
  bool eval(RunContext& run_ctx) override {
    const auto& json_val = run_ctx.varValue(index1_);
    // If the variable is not of type boolean, comparison returns false because comparing
    // different types always results in false
    if(!json_val.is_boolean()) {
        return false;
    }
    const bool var_val = run_ctx.varValue(index1_).get<bool>();
    return var_val == root_ctx_.constValue(index2_);
  }
};
struct OperatorEqualsStringVarStringVar : Operator {
  OperatorEqualsStringVarStringVar(RootContext& root_ctx, ValueIndex var_index1, ValueIndex var_index2,
                                   std::set<ValueIndex>& var_req, std::set<ValueIndex>&)
      : Operator(root_ctx, var_index1, var_index2) {
    var_req.insert(var_index1);
    var_req.insert(var_index2);
  };
  bool eval(RunContext& run_ctx) override {
    // nlohmann/json states that when comparing json objects with different types,
    // the operator== always returns false
    return run_ctx.varValue(index1_) == run_ctx.varValue(index2_);
  }
};
class OperatorEqualsStringVarStringHeader : public Operator {
public:
  OperatorEqualsStringVarStringHeader(RootContext& root_ctx, ValueIndex var_index,
                                      ValueIndex header_index, std::set<ValueIndex>& var_req,
                                      std::set<ValueIndex>& hdr_req, ReqOrResp ror)
      : Operator(root_ctx, var_index, header_index), ror_(ror) {
    var_req.insert(var_index);
    hdr_req.insert(header_index);
  };
  bool eval(RunContext& run_ctx) override {
    const auto& json_val = run_ctx.varValue(index1_);
    // Since a header is always of type string, if the variable is not of
    // type string as well, the comparison ends here:
    if(!json_val.is_string()) {
        return false;
    }
    // DND-32215 (Anna) For equals only if req header equals all comma separated values
    // should it be considered match else not
    const std::string string_var_val = run_ctx.varValue(index1_).get<std::string>();
    const auto& header_val = absl::StrJoin(run_ctx.headerValue(index2_,ror_),",");
      if(string_var_val == header_val){
        return true;
      }
    return false;
  }
private:
  ReqOrResp ror_;
};
class OperatorEqualsStringHeaderStringHeader : public Operator {
public:
  OperatorEqualsStringHeaderStringHeader(RootContext& root_ctx, ValueIndex header_index1,
                                         ValueIndex header_index2, std::set<ValueIndex>&,
                                         std::set<ValueIndex>& hdr_req, ReqOrResp ror1,
                                         ReqOrResp ror2)
      : Operator(root_ctx, header_index1, header_index2), ror1_(ror1), ror2_(ror2) {
    hdr_req.insert(header_index1);
    hdr_req.insert(header_index2);
  };
  bool eval(RunContext& run_ctx) override {
    return run_ctx.headerValue(index1_, ror1_) == run_ctx.headerValue(index2_, ror2_);
  }
private:
  const ReqOrResp ror1_;
  const ReqOrResp ror2_;
};
class OperatorEqualsStringHeaderStringConst : public Operator {
public:
  OperatorEqualsStringHeaderStringConst(RootContext& root_ctx, ValueIndex header_index,
                                        ValueIndex const_index, std::set<ValueIndex>&,
                                        std::set<ValueIndex>& hdr_req, ReqOrResp ror)
      : Operator(root_ctx, header_index, const_index), ror_(ror) {
    hdr_req.insert(header_index);
  };
  bool eval(RunContext& run_ctx) override {
    // DND-32215 (Anna) For equals only if req header equals all comma separated values
    // should it be considered match else not
    // Since a header is always a string, if the constant is not a string constant,
    // the comparison is always false:
    if(!root_ctx_.constValue(index2_).is_string())
    {
      return false;
    }
    else
    {
      auto hdr_maybe_list = run_ctx.headerValue(index1_, ror_);
      std::string hdr_maybe_list_str = absl::StrJoin(hdr_maybe_list,",");
      if(hdr_maybe_list_str == root_ctx_.constValue(index2_).get<std::string>())
      {
          return true;
      }
      return false;
    }

  }
private:
  const ReqOrResp ror_;
};
class OperatorEqualsStringQueryParamStringQueryParam : public Operator {
public:
  OperatorEqualsStringQueryParamStringQueryParam(RootContext& root_ctx, ValueIndex query_param_index1,
                                                 ValueIndex query_param_index2, std::set<ValueIndex>& query_param_req)
  : Operator(root_ctx, query_param_index1, query_param_index2) {
    query_param_req.insert(query_param_index1);
    query_param_req.insert(query_param_index2);
  };
  bool eval(RunContext& run_ctx) override {
    return run_ctx.queryParamValue(index1_) == run_ctx.queryParamValue(index2_);
  }
};
class OperatorEqualsStringQueryParamStringConst : public Operator {
public:
  OperatorEqualsStringQueryParamStringConst(RootContext& root_ctx, ValueIndex query_param_index,
                                            ValueIndex const_index, std::set<ValueIndex>& query_param_req)
  : Operator(root_ctx, query_param_index, const_index) {
    query_param_req.insert(query_param_index);
  };
  bool eval(RunContext& run_ctx) override {
    if(!root_ctx_.constValue(index2_).is_string()) {
      return false;
    }
    return run_ctx.queryParamValue(index1_) == root_ctx_.constValue(index2_).get<std::string>();
  }
};
class OperatorEqualsStringQueryParamStringVar : public Operator {
public:
  OperatorEqualsStringQueryParamStringVar(RootContext& root_ctx, ValueIndex query_param_index,
                                          ValueIndex var_index, std::set<ValueIndex>& var_req,
                                          std::set<ValueIndex>& query_param_req)
  : Operator(root_ctx, query_param_index, var_index) {
    var_req.insert(var_index);
    query_param_req.insert(query_param_index);
  };
  bool eval(RunContext& run_ctx) override {
    if(!run_ctx.varValue(index2_).is_string()) {
      return false;
    }
    return run_ctx.queryParamValue(index1_) == run_ctx.varValue(index2_).get<std::string>();
  }
};
class OperatorEqualsStringQueryParamStringHeader : public Operator {
public:
  OperatorEqualsStringQueryParamStringHeader(RootContext& root_ctx, ValueIndex query_param_index,
                                             ValueIndex header_index, std::set<ValueIndex>& hdr_req,
                                             std::set<ValueIndex>& query_param_req, ReqOrResp ror)
  : Operator(root_ctx, query_param_index, header_index), ror_(ror) {
    hdr_req.insert(header_index);
    query_param_req.insert(query_param_index);
  };
  bool eval(RunContext& run_ctx) override {
    return run_ctx.queryParamValue(index1_) == absl::StrJoin(run_ctx.headerValue(index2_, ror_), ",");;
  }
private:
  const ReqOrResp ror_;
};

struct OperatorEqualsCondition : Operator {
  OperatorEqualsCondition(RootContext& root_ctx, std::shared_ptr<Operator> op1,
                               std::shared_ptr<Operator> op2)
      : Operator(root_ctx, op1, op2){};
  bool eval(RunContext& run_ctx) override {
    return operator1_->eval(run_ctx) == operator2_->eval(run_ctx);
  }
};

// apicontext equals operators

struct OperatorEqualsStringConstApiContextName : Operator {
  OperatorEqualsStringConstApiContextName(RootContext& root_ctx, ValueIndex const_index1,
                                          bool case_insensitive)
      : Operator(root_ctx, const_index1), case_ins_(case_insensitive){};
  bool eval(RunContext& run_ctx) override {
    if (!root_ctx_.constValue(index1_).is_string()) {
      return false;
    }
    if (case_ins_) {
      return absl::EqualsIgnoreCase(root_ctx_.constValue(index1_).get<std::string>(),
                                    run_ctx.getServiceClassifierCtx().getApiName());
    }
    return root_ctx_.constValue(index1_).get<std::string>() ==
           run_ctx.getServiceClassifierCtx().getApiName();
  }

private:
  const bool case_ins_;
};

struct OperatorEqualsStringHeaderApiContextName : Operator {
  OperatorEqualsStringHeaderApiContextName(RootContext& root_ctx, ValueIndex header_index,
                                           std::set<ValueIndex>& hdr_req, ReqOrResp ror,
                                           bool case_insensitive)
      : Operator(root_ctx, header_index), ror_(ror), case_ins_(case_insensitive) {
    hdr_req.insert(header_index);
  };
  bool eval(RunContext& run_ctx) override {
    auto header_val = absl::StrJoin(run_ctx.headerValue(index1_, ror_), ",");
    if (case_ins_) {
      return absl::EqualsIgnoreCase(header_val, run_ctx.getServiceClassifierCtx().getApiName());
    }
    return header_val == run_ctx.getServiceClassifierCtx().getApiName();
  }

private:
  const ReqOrResp ror_;
  const bool case_ins_;
};

struct OperatorEqualsStringVarApiContextName : Operator {
  OperatorEqualsStringVarApiContextName(RootContext& root_ctx, ValueIndex var_index,
                                        std::set<ValueIndex>& var_req, bool case_insensitive)
      : Operator(root_ctx, var_index), case_ins_(case_insensitive) {
    var_req.insert(var_index);
  };
  bool eval(RunContext& run_ctx) override {
    const auto& json_val = run_ctx.varValue(index1_);

    if (!json_val.is_string()) {
      return false;
    }
    if (case_ins_) {
      return absl::EqualsIgnoreCase(json_val.get<std::string>(),
                                    run_ctx.getServiceClassifierCtx().getApiName());
    }
    return json_val.get<std::string>() == run_ctx.getServiceClassifierCtx().getApiName();
  }

private:
  const bool case_ins_;
};

struct OperatorEqualsStringQueryParamApiContextName : Operator {
  OperatorEqualsStringQueryParamApiContextName(RootContext& root_ctx, ValueIndex query_param_index,
                                               std::set<ValueIndex>& query_param_req,
                                               bool case_insensitive)
      : Operator(root_ctx, query_param_index), case_ins_(case_insensitive) {
    query_param_req.insert(query_param_index);
  };
  bool eval(RunContext& run_ctx) override {
    if (case_ins_) {
      return absl::EqualsIgnoreCase(run_ctx.queryParamValue(index1_),
                                    run_ctx.getServiceClassifierCtx().getApiName());
    }
    return run_ctx.queryParamValue(index1_) == run_ctx.getServiceClassifierCtx().getApiName();
  }

private:
  const bool case_ins_;
};

//--------- op_exists --------------------------------------------------------------------
class OperatorExistsHeader : public Operator {
public:
  OperatorExistsHeader(RootContext& root_ctx, ValueIndex index, std::set<ValueIndex>&,
                       std::set<ValueIndex>& hdr_req, ReqOrResp ror)
      : Operator(root_ctx, index), ror_(ror) {
    hdr_req.insert(index);
  };
  bool eval(RunContext& run_ctx) override { return run_ctx.hasHeaderValue(index1_, ror_); };
private:
  ReqOrResp ror_;
};

class OperatorExistsQueryParam : public Operator {
public:
  OperatorExistsQueryParam(RootContext& root_ctx, ValueIndex index,
                           std::set<ValueIndex>& query_param_req)
  : Operator(root_ctx, index) {
    query_param_req.insert(index);
  };
  bool eval(RunContext& run_ctx) override { return run_ctx.hasQueryParamValue(index1_); };
};

struct OperatorExistsStringVar : Operator {
  OperatorExistsStringVar(RootContext& root_ctx, ValueIndex index,
                          std::set<ValueIndex>& var_req, std::set<ValueIndex>&)
      : Operator(root_ctx, index) {
    var_req.insert(index);
  };
  bool eval(RunContext& run_ctx) override {
    const auto& json_val = run_ctx.varValue(index1_);
    // If the variable is a string variable and empty, then it's considered to not exist:
    if(json_val.is_string()) {
        return !json_val.get<std::string>().empty();
    } else {  // not string
      return run_ctx.hasVarValue(index1_);
    }
  };
};

struct OperatorExistsApiContextName : Operator {
  OperatorExistsApiContextName(RootContext& root_ctx) : Operator(root_ctx){};
  bool eval(RunContext& run_ctx) override {
    return !run_ctx.getServiceClassifierCtx().getApiName().empty();
  }
};

//--------- op_isempty -------------------------------------------------------------------
class OperatorIsemptyHeader : public Operator {
public:
  OperatorIsemptyHeader(RootContext& root_ctx, ValueIndex index, std::set<ValueIndex>&,
                        std::set<ValueIndex>& hdr_req, ReqOrResp ror)
      : Operator(root_ctx, index), ror_(ror) {
    hdr_req.insert(index);
  };
  bool eval(RunContext& run_ctx) override {
    return run_ctx.headerValueIsEmpty(index1_, ror_);
  };
private:
  ReqOrResp ror_;
};

class OperatorIsemptyQueryParam : public Operator {
public:
  OperatorIsemptyQueryParam(RootContext& root_ctx, ValueIndex index,
                           std::set<ValueIndex>& query_param_req)
  : Operator(root_ctx, index) {
    query_param_req.insert(index);
  };
  bool eval(RunContext& run_ctx) override { return run_ctx.queryParamValueIsEmpty(index1_); };
};

struct OperatorIsemptyStringVar : Operator {
  OperatorIsemptyStringVar(RootContext& root_ctx, ValueIndex index,
                           std::set<ValueIndex>& var_req, std::set<ValueIndex>&)
      : Operator(root_ctx, index) {
    var_req.insert(index);
  };
  bool eval(RunContext& run_ctx) override { return run_ctx.varValueIsEmpty(index1_); };
};

struct OperatorIsEmptyApiContextName : Operator {
  OperatorIsEmptyApiContextName(RootContext& root_ctx) : Operator(root_ctx){};
  bool eval(RunContext& run_ctx) override {
    return run_ctx.getServiceClassifierCtx().getApiName().empty();
  }
};

//----------op_isinsubnet ----------------------------------------------------------------
class OperatorIsinsubnetStringConst : public Operator {
private:
  Network::Address::CidrRange subnet_range_;
public:
  OperatorIsinsubnetStringConst(RootContext& root_ctx, ValueIndex addr_index,
                                     const std::string& subnet)
    : Operator(root_ctx, addr_index) {
    // If the subnet range contains slash and mask, then the address parsing can
    // throw an exception if the address is not a valid IP-address. Catch it and
    // create an empty subnet in that case.
    // This happens at configuration time (not during traffic), so an exception is ok.
    try {
      subnet_range_ = Network::Address::CidrRange::create(subnet);
    } catch (...) {
      subnet_range_ = Network::Address::CidrRange::create("");
    }
  };
  bool eval(RunContext&) override {
    // If the subnet range is not valid, always return false:
    if (!subnet_range_.isValid()) {
      return false;
    }
    Network::Address::InstanceConstSharedPtr addr = Network::Utility::parseInternetAddressNoThrow(root_ctx_.constValue(index1_));
    // Address cannot be parsed -> cannot be in subnet
    if (addr == nullptr) {
      return false;
    }
    // IsInRange() takes care of IPv4 vs IPv6 and returns false if address and subnet use
    // different versions:
    return subnet_range_.isInRange(*addr);
  }
};

class OperatorIsinsubnetHeader : public Operator {
public:
  OperatorIsinsubnetHeader(RootContext& root_ctx, ValueIndex addr_index,
                                     const std::string& subnet, std::set<ValueIndex>& hdr_req,
                                     ReqOrResp ror)
    : Operator(root_ctx, addr_index), ror_(ror) {
    // If the subnet range contains slash and mask, then the address parsing can
    // throw an exception if the address is not a valid IP-address. Catch it and
    // create an empty subnet in that case.
    // This happens at configuration time (not during traffic), so an exception is ok.
    try {
      subnet_range_ = Network::Address::CidrRange::create(subnet);
    } catch (...) {
      subnet_range_ = Network::Address::CidrRange::create("");
    }
    hdr_req.insert(addr_index);
  };
  bool eval(RunContext& run_ctx) override {
    // If the subnet range is not valid, always return false:
    if (!subnet_range_.isValid()) {
      return false;
    }

    for(const auto& value: run_ctx.headerValue(index1_, ror_)){
      Network::Address::InstanceConstSharedPtr addr = Network::Utility::parseInternetAddressNoThrow(std::string(value));
      // Address cannot be parsed -> cannot be in subnet
      if (addr == nullptr) {
        continue;
      }
      // IsInRange() takes care of IPv4 vs IPv6 and returns false if address and subnet use
      // different versions:
      if(subnet_range_.isInRange(*addr)){
        return true;
      }
    }
      return false;
  }
private:
  Network::Address::CidrRange subnet_range_;
  ReqOrResp ror_;
};

class OperatorIsinsubnetStringVar : public Operator {
private:
  Network::Address::CidrRange subnet_range_;
public:
  OperatorIsinsubnetStringVar(RootContext& root_ctx, ValueIndex addr_index,
                                     const std::string& subnet, std::set<ValueIndex>& var_req)
    : Operator(root_ctx, addr_index) {
    // If the subnet range contains slash and mask, then the address parsing can
    // throw an exception if the address is not a valid IP-address. Catch it and
    // create an empty subnet in that case.
    // This happens at configuration time (not during traffic), so an exception is ok.
    try {
      subnet_range_ = Network::Address::CidrRange::create(subnet);
    } catch (...) {
      subnet_range_ = Network::Address::CidrRange::create("");
    }
    var_req.insert(addr_index);
  };
  bool eval(RunContext& run_ctx) override {
    // If the subnet range is not valid, always return false:
    if (!subnet_range_.isValid()) {
      return false;
    }
    const auto& json_val = run_ctx.varValue(index1_);
    // Since a string const is always of type string, if the variable is not of
    // type string as well, the comparison ends here:
    if(!json_val.is_string()) {
        return false;
    }
    const std::string string_var_val = run_ctx.varValue(index1_).get<std::string>();
    Network::Address::InstanceConstSharedPtr addr = Network::Utility::parseInternetAddressNoThrow(string_var_val);
    // Address cannot be parsed -> cannot be in subnet
    if (addr == nullptr) {
      return false;
    }
    // IsInRange() takes care of IPv4 vs IPv6 and returns false if address and subnet use
    // different versions:
    return subnet_range_.isInRange(*addr);
  }
};

//----------op_equals_case_insensitive ---------------------------------------------------
struct OperatorEqualsCaseInsStringConstStringConst : Operator {
  OperatorEqualsCaseInsStringConstStringConst(RootContext& root_ctx, ValueIndex const_index1,
                                              ValueIndex const_index2)
      : Operator(root_ctx, const_index1, const_index2){};
  bool eval(RunContext&) override {
    if (root_ctx_.constValue(index1_).is_string() && root_ctx_.constValue(index2_).is_string()) {
      return StringUtil::toUpper(root_ctx_.constValue(index1_).get<std::string>()) ==
             StringUtil::toUpper(root_ctx_.constValue(index2_).get<std::string>());
    } else {
      return root_ctx_.constValue(index1_) == root_ctx_.constValue(index2_);
    }
  }
};

struct OperatorEqualsCaseInsStringVarStringConst : Operator {
  OperatorEqualsCaseInsStringVarStringConst(RootContext& root_ctx, ValueIndex var_index,
                                     ValueIndex const_index, std::set<ValueIndex>& var_req,
                                     std::set<ValueIndex>&)
      : Operator(root_ctx, var_index, const_index) {
    var_req.insert(var_index);
  };
  bool eval(RunContext& run_ctx) override {
    const auto& json_val = run_ctx.varValue(index1_);
    // Since a string const is always of type string, if the variable is not of
    // type string as well, the comparison ends here:
    if(!json_val.is_string()) {
        return false;
    }
    const std::string var_val = StringUtil::toUpper(run_ctx.varValue(index1_).get<std::string>());
    return var_val == StringUtil::toUpper(root_ctx_.constValue(index2_).get<std::string>());
  }
};
struct OperatorEqualsCaseInsStringVarStringVar : Operator {
  OperatorEqualsCaseInsStringVarStringVar(RootContext& root_ctx, ValueIndex var_index1, ValueIndex var_index2,
                                   std::set<ValueIndex>& var_req, std::set<ValueIndex>&)
      : Operator(root_ctx, var_index1, var_index2) {
    var_req.insert(var_index1);
    var_req.insert(var_index2);
  };
  bool eval(RunContext& run_ctx) override {
    if (run_ctx.varValue(index1_).is_string() && run_ctx.varValue(index2_).is_string()) {
      return StringUtil::toUpper(run_ctx.varValue(index1_).get<std::string>()) == StringUtil::toUpper(run_ctx.varValue(index2_).get<std::string>());
    } else {
      return run_ctx.varValue(index1_) == run_ctx.varValue(index2_);
    }
  }
};
class OperatorEqualsCaseInsStringVarStringHeader : public Operator {
public:
  OperatorEqualsCaseInsStringVarStringHeader(RootContext& root_ctx, ValueIndex var_index,
                                      ValueIndex header_index, std::set<ValueIndex>& var_req,
                                      std::set<ValueIndex>& hdr_req, ReqOrResp ror)
      : Operator(root_ctx, var_index, header_index), ror_(ror) {
    var_req.insert(var_index);
    hdr_req.insert(header_index);
  };
  bool eval(RunContext& run_ctx) override {
    const auto& json_val = run_ctx.varValue(index1_);
    // Since a header is always of type string, if the variable is not of
    // type string as well, the comparison ends here:
    if(!json_val.is_string()) {
        return false;
    }
    /* DND-32215 (Anna) For equals only if req header equals all comma separated values should it be considered match else not */
    const std::string string_var_val = run_ctx.varValue(index1_).get<std::string>();
    const auto& header_val = StringUtil::toUpper(absl::StrJoin(run_ctx.headerValue(index2_,ror_),","));
      if(StringUtil::toUpper(string_var_val) == header_val){
        return true;
      }
    return false;
  }
private:
  ReqOrResp ror_;
};
class OperatorEqualsCaseInsStringHeaderStringHeader : public Operator {
public:
  OperatorEqualsCaseInsStringHeaderStringHeader(RootContext& root_ctx, ValueIndex header_index1,
                                                ValueIndex header_index2, std::set<ValueIndex>&,
                                                std::set<ValueIndex>& hdr_req, ReqOrResp ror1,
                                                ReqOrResp ror2)
      : Operator(root_ctx, header_index1, header_index2), ror1_(ror1), ror2_(ror2) {
    hdr_req.insert(header_index1);
    hdr_req.insert(header_index2);
  };
  bool eval(RunContext& run_ctx) override {
    const auto t1 = run_ctx.headerValue(index1_, ror1_);
    const auto t2 = run_ctx.headerValue(index2_, ror2_);

    return std::equal(t1.begin(), t1.end(), t2.begin(), t2.end(),
                      [](auto&& l, auto&& r) { return absl::EqualsIgnoreCase(l, r); });
    ;
  }

private:
  const ReqOrResp ror1_;
  const ReqOrResp ror2_;
};
class OperatorEqualsCaseInsStringHeaderStringConst : public Operator {
public:
  OperatorEqualsCaseInsStringHeaderStringConst(RootContext& root_ctx, ValueIndex header_index,
                                               ValueIndex const_index, std::set<ValueIndex>&,
                                               std::set<ValueIndex>& hdr_req, ReqOrResp ror)
      : Operator(root_ctx, header_index, const_index), ror_(ror) {
    hdr_req.insert(header_index);
  };
  bool eval(RunContext& run_ctx) override {

    /* DND-32215 (Anna) For equals only if req header equals all comma separated values should it be
     * considered match else not */
    // Since a header is always a string, if the constant is not a string constant,
    // the comparison is always false:
    if (!root_ctx_.constValue(index2_).is_string()) {
      return false;
    } else {
      auto hdr_maybe_list = run_ctx.headerValue(index1_, ror_);
      const std::string hdr_maybe_list_str = StringUtil::toUpper(absl::StrJoin(hdr_maybe_list, ","));
      if (hdr_maybe_list_str == StringUtil::toUpper(root_ctx_.constValue(index2_).get<std::string>())) {
        return true;
      }
      return false;
    }
  }

private:
  const ReqOrResp ror_;
};
class OperatorEqualsCaseInsStringQueryParamStringQueryParam : public Operator {
public:
  OperatorEqualsCaseInsStringQueryParamStringQueryParam(RootContext& root_ctx, ValueIndex query_param_index1,
                                                        ValueIndex query_param_index2, std::set<ValueIndex>& query_param_req)
  : Operator(root_ctx, query_param_index1, query_param_index2) {
    query_param_req.insert(query_param_index1);
    query_param_req.insert(query_param_index2);
  };
  bool eval(RunContext& run_ctx) override {
    return StringUtil::toUpper(run_ctx.queryParamValue(index1_)) == StringUtil::toUpper(run_ctx.queryParamValue(index2_));
  }
};
class OperatorEqualsCaseInsStringQueryParamStringConst : public Operator {
public:
  OperatorEqualsCaseInsStringQueryParamStringConst(RootContext& root_ctx, ValueIndex query_param_index,
                                                   ValueIndex const_index, std::set<ValueIndex>& query_param_req)
  : Operator(root_ctx, query_param_index, const_index) {
    query_param_req.insert(query_param_index);
  };
  bool eval(RunContext& run_ctx) override {
    if(!root_ctx_.constValue(index2_).is_string()) {
      return false;
    }
    return StringUtil::toUpper(run_ctx.queryParamValue(index1_)) == StringUtil::toUpper(root_ctx_.constValue(index2_).get<std::string>());
  }
};
class OperatorEqualsCaseInsStringQueryParamStringVar : public Operator {
public:
  OperatorEqualsCaseInsStringQueryParamStringVar(RootContext& root_ctx, ValueIndex query_param_index,
                                                 ValueIndex var_index, std::set<ValueIndex>& var_req,
                                                 std::set<ValueIndex>& query_param_req)
  : Operator(root_ctx, query_param_index, var_index) {
    var_req.insert(var_index);
    query_param_req.insert(query_param_index);
  };
  bool eval(RunContext& run_ctx) override {
    if(!run_ctx.varValue(index2_).is_string()) {
      return false;
    }
    return StringUtil::toUpper(run_ctx.queryParamValue(index1_)) == StringUtil::toUpper(run_ctx.varValue(index2_).get<std::string>());
  }
};
class OperatorEqualsCaseInsStringQueryParamStringHeader : public Operator {
public:
  OperatorEqualsCaseInsStringQueryParamStringHeader(RootContext& root_ctx, ValueIndex query_param_index,
                                                    ValueIndex header_index, std::set<ValueIndex>& hdr_req,
                                                    std::set<ValueIndex>& query_param_req, ReqOrResp ror)
  : Operator(root_ctx, query_param_index, header_index), ror_(ror) {
    hdr_req.insert(header_index);
    query_param_req.insert(query_param_index);
  };
  bool eval(RunContext& run_ctx) override {
    return StringUtil::toUpper(run_ctx.queryParamValue(index1_)) == StringUtil::toUpper(absl::StrJoin(run_ctx.headerValue(index2_, ror_), ","));
  }
private:
  const ReqOrResp ror_;
};

struct OperatorEqualsCaseInsCondition : Operator {
  OperatorEqualsCaseInsCondition(RootContext& root_ctx, std::shared_ptr<Operator> op1,
                               std::shared_ptr<Operator> op2)
      : Operator(root_ctx, op1, op2){};
  bool eval(RunContext& run_ctx) override {
    return operator1_->eval(run_ctx) == operator2_->eval(run_ctx);
  }
};

//--------- op_isvalidjson ---------------------------------------------------------------
class OperatorIsvalidjson : public Operator {
private:
  ReqOrResp ror_;
public:
  OperatorIsvalidjson(RootContext& root_ctx, ReqOrResp ror) : Operator(root_ctx), ror_(ror){};
  bool eval(RunContext& run_ctx) override {
    Body* body;
    switch (ror_) {
    case ReqOrResp::Request:
      body = run_ctx.getRequestBody();
      return body->hasJson();
      break;
    case ReqOrResp::Response:
      body = run_ctx.getResponseBody();
      return body->hasJson();
      break;
    default:
      ExceptionUtil::throwEnvoyException("Unknown value for ReqOrResp");
    }
  };
};

//--------- term_boolean -----------------------------------------------------------------
struct OperatorTermBoolean : Operator {
  OperatorTermBoolean(RootContext& root_ctx, bool value) : Operator(root_ctx), value_(value){};
  bool eval(RunContext&) override { return value_; }

private:
  bool value_;
};

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
