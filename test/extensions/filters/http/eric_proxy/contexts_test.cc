#include "source/extensions/filters/http/eric_proxy/contexts.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {


// Tests constants in the root context
TEST(EricProxyFilterContextsTest, TestConstants) {
  RootContext ctx;
  auto idx1 = ctx.findOrInsertConstValue("abcdefg");
  EXPECT_EQ(idx1, 0);
  auto idx2 = ctx.findOrInsertConstValue("abcdefg");
  EXPECT_EQ(idx2, idx1);
  auto idx3 = ctx.findOrInsertConstValue("klmnop");
  EXPECT_NE(idx3, idx1);
  auto idx4 = ctx.findOrInsertConstValue("abcdefg");
  EXPECT_EQ(idx4, idx1);
}

// Tests constants in the root context, Unicode
TEST(EricProxyFilterContextsTest, TestConstantsUnicode) {
  RootContext ctx;

  auto idx1 = ctx.findOrInsertConstValue(u8"\u24B6\u24B7\u24B8\u24B9\u24BA\u24BB\u24BC\u24BD");
  EXPECT_EQ(idx1, 0);
  auto idx2 = ctx.findOrInsertConstValue(u8"\u24B6\u24B7\u24B8\u24B9\u24BA\u24BB\u24BC\u24BD");
  EXPECT_EQ(idx2, idx1);
  auto idx3 = ctx.findOrInsertConstValue(u8"\u039A\u039B\u039C\u039D\u039E\u039F");
  EXPECT_NE(idx3, idx1);
  auto idx4 = ctx.findOrInsertConstValue(u8"\u24B6\u24B7\u24B8\u24B9\u24BA\u24BB\u24BC\u24BD");
  EXPECT_EQ(idx4, idx1);
}

// Tests headers in the root context
TEST(EricProxyFilterContextsTest, TestHeaders) {
  RootContext ctx;
  auto idx1 = ctx.findOrInsertHeaderName("HIJKL");
  EXPECT_EQ(idx1, 0);
  auto idx2 = ctx.findOrInsertHeaderName("HIJKL");
  EXPECT_EQ(idx2, idx1);
  auto idx3 = ctx.findOrInsertHeaderName("XYZ");
  EXPECT_NE(idx3, idx1);
  auto idx4 = ctx.findOrInsertHeaderName("HIJKL");
  EXPECT_EQ(idx4, idx1);
}

// Tests headers in the root context
TEST(EricProxyFilterContextsTest, TestQueryParams) {
  RootContext ctx;
  auto idx1 = ctx.findOrInsertQueryParamName("ERIC");
  EXPECT_EQ(idx1, 0);
  auto idx2 = ctx.findOrInsertQueryParamName("ERIC");
  EXPECT_EQ(idx2, idx1);
  auto idx3 = ctx.findOrInsertQueryParamName("PROXY");
  EXPECT_NE(idx3, idx1);
  auto idx4 = ctx.findOrInsertQueryParamName("ERIC");
  EXPECT_EQ(idx4, idx1);
}

// Tests vars in the root context
TEST(EricProxyFilterContextsTest, TestVars) {
  RootContext ctx;
  auto idx1 = ctx.findOrInsertVarName("ericsson");
  EXPECT_EQ(idx1, 0);
  auto idx2 = ctx.findOrInsertVarName("ericsson");
  EXPECT_EQ(idx2, idx1);
  auto idx3 = ctx.findOrInsertVarName("eurolab");
  EXPECT_NE(idx3, idx1);
  auto idx4 = ctx.findOrInsertVarName("ericsson");
  EXPECT_EQ(idx4, idx1);
}

// Tests consts, headers, vars in the root context
TEST(EricProxyFilterContextsTest, TestConstsHeadersVars) {
  RootContext ctx;
  auto v1 = ctx.findOrInsertVarName("ericsson");
  auto c1 = ctx.findOrInsertConstValue("abcdefg");
  auto v2 = ctx.findOrInsertVarName("ericsson");
  auto h1 = ctx.findOrInsertHeaderName("HIJKL");
  auto h2 = ctx.findOrInsertHeaderName("HIJKL");
  auto q1 = ctx.findOrInsertQueryParamName("ERIC");
  auto c2 = ctx.findOrInsertConstValue("abcdefg");
  auto c3 = ctx.findOrInsertConstValue("klmnop");
  auto q2 = ctx.findOrInsertQueryParamName("ERIC");
  auto q3 = ctx.findOrInsertQueryParamName("PROXY");
  auto v3 = ctx.findOrInsertVarName("eurolab");
  auto h3 = ctx.findOrInsertHeaderName("XYZ");
  auto c4 = ctx.findOrInsertConstValue("abcdefg");
  auto h4 = ctx.findOrInsertHeaderName("HIJKL");
  auto v4 = ctx.findOrInsertVarName("ericsson");
  auto q4 = ctx.findOrInsertQueryParamName("ERIC");
  EXPECT_EQ(v1, 0);
  EXPECT_EQ(v2, v1);
  EXPECT_NE(v3, v1);
  EXPECT_EQ(v4, v1);
  EXPECT_EQ(h1, 0);
  EXPECT_EQ(h2, h1);
  EXPECT_NE(h3, h1);
  EXPECT_EQ(h4, h1);
  EXPECT_EQ(q1, 0);
  EXPECT_EQ(q2, q1);
  EXPECT_NE(q3, q1);
  EXPECT_EQ(q4, q1);
  EXPECT_EQ(c1, 0);
  EXPECT_EQ(c2, c1);
  EXPECT_NE(c3, c1);
  EXPECT_EQ(c4, c1);
}

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
