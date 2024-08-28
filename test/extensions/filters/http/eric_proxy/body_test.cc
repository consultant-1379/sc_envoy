#include "source/extensions/filters/http/eric_proxy/body.h"
#include "test/test_common/utility.h"
#include "test/mocks/http/mocks.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <iostream>
#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

// Tests for content-type parsing

// Single-part body
TEST(ContentType, TestSinglePart1) {
  Body body;
  body.setBodyFromString(R"({"a": "b"})", std::string{"application/json"});
  EXPECT_FALSE(body.isMultipart());
}

// Although there is a multipart/related content-type, it is not multipart
// because there is no boundary
TEST(ContentType, TestNoMultiPart1) {
  Body body;
  body.setBodyFromString(R"({"a": "b"})", std::string{"multipart/related"});
  EXPECT_FALSE(body.isMultipart());
}

// Although there is a multipart/related content-type, it is not multipart
// because the boundary is not terminated correctly (closing double-quote missing)
TEST(ContentType, TestNoMultiPart2) {
  Body body;
  body.setBodyFromString(R"({"a": "b"})", std::string{"multipart/related; boundary=\"ASDF"});
  EXPECT_FALSE(body.isMultipart());
}

// Although there is a multipart/related content-type, it is not multipart
// because the boundary is empty
TEST(ContentType, TestNoMultiPart3) {
  Body body;
  body.setBodyFromString(R"({"a": "b"})", std::string{"multipart/related; boundary="});
  EXPECT_FALSE(body.isMultipart());
}

// Although there is a multipart/related content-type, it is not multipart
// because the boundary is empty
TEST(ContentType, TestNoMultiPart3b) {
  Body body;
  body.setBodyFromString(R"({"a": "b"})", std::string{"multipart/related; boundary  =    "});
  EXPECT_FALSE(body.isMultipart());
}

// Although there is a multipart/related content-type, it is not multipart
// because the boundary is empty
TEST(ContentType, TestNoMultiPart3c) {
  Body body;
  body.setBodyFromString(R"({"a": "b"})", std::string{"multipart/related; boundary     "});
  EXPECT_FALSE(body.isMultipart());
}

// Although there is a multipart/related content-type, it is not multipart
// because the boundary is empty
TEST(ContentType, TestNoMultiPart3d) {
  Body body;
  body.setBodyFromString(R"({"a": "b"})", std::string{"multipart/related; boundary"});
  EXPECT_FALSE(body.isMultipart());
}

// Although there is a multipart/related content-type, it is not multipart
// because the boundary only consists of the starting double quote
TEST(ContentType, TestNoMultiPart4) {
  Body body;
  body.setBodyFromString(R"({"a": "b"})", std::string{"multipart/related; boundary=\""});
  EXPECT_FALSE(body.isMultipart());
}

// Multi-part
TEST(ContentType, TestMultiPart1) {
  std::string content_type{"multipart/related; boundary=ASDF"};
  std::string mp_body_str{"--ASDF\r\nContent-type: ApplIcAtIOn/JSoN\r\n\r\n{\"subscriberIdentifier\": \"imsi-460001357924610\"}\r\n--ASDF--)"};
  Body body;
  body.setBodyFromString(mp_body_str, content_type);
  EXPECT_TRUE(body.isMultipart());
  EXPECT_EQ(body.mpBoundary(), "ASDF");
}

// Multi-part, space after the boundary
TEST(ContentType, TestMultiPart2) {
  std::string mp_body_str{"--ASDF\r\nContent-type: ApplIcAtIOn/JSoN\r\n\r\n{\"subscriberIdentifier\": \"imsi-460001357924610\"}\r\n--ASDF--)"};
  Body body;
  body.setBodyFromString(mp_body_str, std::string{"multipart/related; boundary=ASDF  "});
  EXPECT_TRUE(body.isMultipart());
  EXPECT_EQ(body.mpBoundary(), "ASDF");
}

// Multi-part, quoted boundary
TEST(ContentType, TestMultiPart3) {
  std::string mp_body_str{"--ASDF hjkl\r\nContent-type: ApplIcAtIOn/JSoN\r\n\r\n{\"subscriberIdentifier\": \"imsi-460001357924610\"}\r\n--ASDF hjkl--)"};
  Body body;
  body.setBodyFromString(mp_body_str, std::string{"multipart/related; boundary=\"ASDF hjkl\" "});
  EXPECT_TRUE(body.isMultipart());
  EXPECT_EQ(body.mpBoundary(), "ASDF hjkl");
}

// Multi-part, quoted boundary, start
TEST(ContentType, TestMultiPart4) {
  std::string mp_body_str{"--ASDF hjkl\r\nContent-type: ApplIcAtIOn/JSoN\r\n\r\n{\"subscriberIdentifier\": \"imsi-460001357924610\"}\r\n--ASDF hjkl--)"};
  Body body;
  body.setBodyFromString(mp_body_str, std::string{"multipart/related; boundary=\"ASDF hjkl\" ; start=ContentIdPart1 "});
  EXPECT_TRUE(body.isMultipart());
  EXPECT_EQ(body.mpBoundary(), "ASDF hjkl");
  EXPECT_EQ(body.mpStart(), "ContentIdPart1");
}

// Multi-part, start, boundary
TEST(ContentType, TestMultiPart5) {
  std::string mp_body_str{"--ASdf\r\nContent-type: ApplIcAtIOn/JSoN\r\n\r\n{\"subscriberIdentifier\": \"imsi-460001357924610\"}\r\n--ASdf--)"};
  Body body;
  body.setBodyFromString(mp_body_str, std::string{"multipart/related;start=ContentIdPart2;boundary=ASdf  "});
  EXPECT_TRUE(body.isMultipart());
  EXPECT_EQ(body.mpBoundary(), "ASdf");
  EXPECT_EQ(body.mpStart(), "ContentIdPart2");
}

//------------------------------------------------------------------------------
// Tests for BodyPart

// BodyPart: simple data-only body-part, no headers
TEST(BodyPartTest, TestBodyPartParseWithOutHeaders) {
  std::string str_body{R"({
"subscriberIdentifier": "imsi-460001357924610",
nfConsumerIdentification": {
    "nFName": "123e-e8b-1d3-a46-421",
    "nFIPv4Address": "192.168.0.1",
    "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
    "nFPLMNID": {
        "mcc": "311",
        "mnc": "280"
    },
    "nodeFunctionality": "SMF"
}
)"};
  BodyPart bp(str_body);
  EXPECT_EQ(bp.whole_part_, str_body);
  EXPECT_TRUE(bp.header_part_.empty());
  EXPECT_EQ(bp.data_part_, str_body);
}


// BodyPart: 3 headers and a body part
TEST(BodyPartTest, TestBodyPartParseWithHeaders) {
  std::string str_headers{"Content-type: application/json\r\ncontent-ignored :asdf\r\ncontent-id : asdf"};

  std::string str_data{R"({
"subscriberIdentifier": "imsi-460001357924610",
nfConsumerIdentification": {
    "nFName": "123e-e8b-1d3-a46-421",
    "nFIPv4Address": "192.168.0.1",
    "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
    "nFPLMNID": {
        "mcc": "311",
        "mnc": "280"
    },
    "nodeFunctionality": "SMF"
})"};
  auto everything = absl::StrCat(str_headers, std::string{"\r\n\r\n"}, str_data);
  BodyPart bp(everything);
  EXPECT_EQ(bp.whole_part_, everything);
  EXPECT_EQ(bp.header_part_, str_headers);
  EXPECT_EQ(bp.data_part_, str_data);
  EXPECT_EQ(bp.content_id_, "asdf");
  EXPECT_EQ(bp.content_type_lc_, Http::LowerCaseString("application/json"));
}

//-------------------------------------------------------------------------------------
// Tests for Body

// Body: application/json, no multipart
TEST(BodyTest, TestBodyParseWithoutHeaders) {
  std::string str_body{R"({
"subscriberIdentifier": "imsi-460001357924610",
nfConsumerIdentification": {
    "nFName": "123e-e8b-1d3-a46-421",
    "nFIPv4Address": "192.168.0.1",
    "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
    "nFPLMNID": {
        "mcc": "311",
        "mnc": "280"
    },
    "nodeFunctionality": "SMF"
})"};
  Body body;
  body.setBodyFromString(str_body, std::string{"application/json"});
  EXPECT_FALSE(body.isMultipart());
  EXPECT_EQ(body.getBodyAsString(), str_body);
  EXPECT_FALSE(body.mpStartIndex().has_value());
}


// Body: multipart/related and 1 body parts (only the JSON part)
// Quoted-boundary string
// No preamble or epilogue, no "start" parameter (JSON is the first and only part)
TEST(BodyTest, TestMutlipartBodyParseOnePart) {
  std::string multipart_related{"multipart/related"};
  std::string boundary{"BouNDaRY bOUndAry"};
  std::string content_type{absl::StrCat(multipart_related, "; Boundary=\"", boundary, "\"")};

  std::string mp_json_headers{"Content-type: ApplIcAtIOn/JSoN\r\ncontent-ignored :asdf\r\ncontent-id : asdf"};

  std::string mp_json_part{R"({
"subscriberIdentifier": "imsi-460001357924610",
nfConsumerIdentification": {
    "nFName": "123e-e8b-1d3-a46-421",
    "nFIPv4Address": "192.168.0.1",
    "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
    "nFPLMNID": {
        "mcc": "311",
        "mnc": "280"
    },
    "nodeFunctionality": "SMF"
})"};

  auto everything = absl::StrCat(
    "--", boundary, "\r\n", 
    mp_json_headers, "\r\n\r\n",
    mp_json_part, "\r\n",
    "--", boundary, "--" );
  std::cout << "Everything: |" << everything << "|" << std::endl;
  Body body;
  body.setBodyFromString(everything, content_type);
  EXPECT_TRUE(body.isMultipart());
  EXPECT_EQ(body.getBodyAsString(), everything);
  EXPECT_EQ(body.mpBoundary(), boundary);
  EXPECT_TRUE(body.mpStart().empty());
  EXPECT_TRUE(body.mpPreamble().empty());
  EXPECT_TRUE(body.mpEpilogue().empty());
  EXPECT_EQ(body.mpBodyParts().size(), 1);
  EXPECT_EQ(body.mpBodyParts().at(0).content_type_lc_, Http::LowerCaseString("application/json"));
  EXPECT_EQ(body.mpStartIndex(), 0);
}

// Body: multipart/related and 2 body parts.
// Quoted-boundary string
// No preamble or epilogue, no "start" parameter, JSON is the first part
TEST(BodyTest, TestBodyParseWithHeaders) {
  std::string multipart_related{"multipart/related"};
  std::string boundary{"a;lsdkfjas;lkjrfpaosiej"};
  std::string content_type{absl::StrCat(multipart_related, "; Boundary=\"", boundary, "\"")};

  std::string mp_json_headers{"Content-type: application/json\r\ncontent-ignored :asdf\r\ncontent-id : asdf"};

  std::string mp_json_part{R"({
"subscriberIdentifier": "imsi-460001357924610",
nfConsumerIdentification": {
    "nFName": "123e-e8b-1d3-a46-421",
    "nFIPv4Address": "192.168.0.1",
    "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
    "nFPLMNID": {
        "mcc": "311",
        "mnc": "280"
    },
    "nodeFunctionality": "SMF"
})"};

  std::string mp_binary_headers{"Content-type: application/vnd.3gpp.5gnas\r\ncontent-id: binpart01"};
  std::string str_binary_part("ABCDEFabcdef\0GHIJ", 17);

  auto everything = absl::StrCat(
    "--", boundary, "\r\n", 
    mp_json_headers, "\r\n\r\n",
    mp_json_part, "\r\n",
    "--", boundary, "\r\n",
    mp_binary_headers, "\r\n\r\n",
    str_binary_part, "\r\n",
    "--", boundary, "--" );
  std::cout << "Everything: |" << everything << "|" << std::endl;
  Body body;
  body.setBodyFromString(everything, content_type);
  EXPECT_TRUE(body.isMultipart());
  EXPECT_EQ(body.getBodyAsString(), everything);
  EXPECT_EQ(body.mpBoundary(), boundary);
  EXPECT_TRUE(body.mpStart().empty());
  EXPECT_TRUE(body.mpPreamble().empty());
  EXPECT_TRUE(body.mpEpilogue().empty());
  EXPECT_EQ(body.mpBodyParts().size(), 2);
  EXPECT_EQ(body.mpBodyParts().at(0).content_type_lc_, Http::LowerCaseString("application/json"));
  EXPECT_EQ(body.mpStartIndex(), 0);
}

// Body: multipart/related and 2 body parts, both with
// the same content-id which is not allowed, but should not matter.
// Quoted-boundary string
// No preamble or epilogue, no "start" parameter, JSON is the first part
TEST(BodyTest, TestBodyParseWithHeadersSameContentId) {
  std::string multipart_related{"multipart/related"};
  std::string boundary{"a;lsdkfjas;lkjrfpaosiej"};
  std::string content_type{absl::StrCat(multipart_related, "; Boundary=\"", boundary, "\"")};

  std::string mp_json_headers{"Content-type: application/json\r\ncontent-ignored :asdf\r\ncontent-id : asdf"};

  std::string mp_json_part{R"({
"subscriberIdentifier": "imsi-460001357924610",
nfConsumerIdentification": {
    "nFName": "123e-e8b-1d3-a46-421",
    "nFIPv4Address": "192.168.0.1",
    "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
    "nFPLMNID": {
        "mcc": "311",
        "mnc": "280"
    },
    "nodeFunctionality": "SMF"
})"};

  std::string mp_binary_headers{"Content-type: application/vnd.3gpp.5gnas\r\ncontent-id: asdf"};
  std::string str_binary_part("ABCDEFabcdef\0GHIJ", 17);

  auto everything = absl::StrCat(
    "--", boundary, "\r\n", 
    mp_json_headers, "\r\n\r\n",
    mp_json_part, "\r\n",
    "--", boundary, "\r\n",
    mp_binary_headers, "\r\n\r\n",
    str_binary_part, "\r\n",
    "--", boundary, "--" );
  std::cout << "Everything: |" << everything << "|" << std::endl;
  Body body;
  body.setBodyFromString(everything, content_type);
  EXPECT_TRUE(body.isMultipart());
  EXPECT_EQ(body.getBodyAsString(), everything);
  EXPECT_EQ(body.mpBoundary(), boundary);
  EXPECT_TRUE(body.mpStart().empty());
  EXPECT_TRUE(body.mpPreamble().empty());
  EXPECT_TRUE(body.mpEpilogue().empty());
  EXPECT_EQ(body.mpBodyParts().size(), 2);
  EXPECT_EQ(body.mpBodyParts().at(0).content_type_lc_, Http::LowerCaseString("application/json"));
  EXPECT_EQ(body.mpStartIndex(), 0);
  EXPECT_EQ(body.mpBodyParts().at(0).data_part_, mp_json_part);
  EXPECT_EQ(body.mpBodyParts().at(1).data_part_, str_binary_part);
}

// Body: multipart/related and 3 body parts.
// Un-quoted boundary.
// With preamble or epilogue
TEST(BodyTest, TestBodyParseWithHeaders2) {
  std::string multipart_related{"multipart/related"};
  std::string boundary{"boundary"};
  std::string content_type{absl::StrCat(multipart_related, "; Boundary=", boundary)};
  std::string preamble{"asdfasdfas\r\nasfsadafasd\r\n\r\nasfsds\r\n"};
  std::string epilogue{"lkjlkjlkjlkjlkjlkjlkj\r\nlkjlkjlkjlkjlkj"};

  std::string mp_json_headers{"Content-type: application/json\r\ncontent-ignored :asdf\r\ncontent-id : asdf"};

  std::string mp_json_part{R"({
"subscriberIdentifier": "imsi-460001357924610",
nfConsumerIdentification": {
    "nFName": "123e-e8b-1d3-a46-421",
    "nFIPv4Address": "192.168.0.1",
    "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
    "nFPLMNID": {
        "mcc": "311",
        "mnc": "280"
    },
    "nodeFunctionality": "SMF"
})"};

  std::string mp_binary_headers1{"Content-type: application/vnd.3gpp.5gnas\r\ncontent-id: binpart01"};
  std::string str_binary_part1("ABCDEFabcdef\0GHIJ", 17);

  std::string mp_binary_headers2{"Content-type: application/vnd.3gpp.5gtrock\r\ncontent-id: binpart02"};
  std::string str_binary_part2("XYZxyzXYZxyz\0xyz\0", 17);

  auto everything = absl::StrCat(
    preamble, "\r\n",
    "--", boundary, "\r\n", 
    mp_json_headers, "\r\n\r\n",
    mp_json_part, "\r\n",
    "--", boundary, "\r\n",
    mp_binary_headers1, "\r\n\r\n",
    str_binary_part1, "\r\n",
    "--", boundary, "\r\n",
    mp_binary_headers2, "\r\n\r\n",
    str_binary_part2, "\r\n",
    "--", boundary, "--", "\r\n",
    epilogue);
  std::cout << "Everything: |" << everything << "|" << std::endl;
  Body body;
  body.setBodyFromString(everything, content_type);
  EXPECT_TRUE(body.isMultipart());
  EXPECT_EQ(body.getBodyAsString(), everything);
  EXPECT_EQ(body.mpBoundary(), boundary);
  EXPECT_TRUE(body.mpStart().empty());
  EXPECT_EQ(body.mpPreamble(), preamble);
  EXPECT_EQ(body.mpEpilogue(), epilogue);
  EXPECT_EQ(body.mpBodyParts().size(), 3);
  EXPECT_EQ(body.mpBodyParts().at(0).content_type_lc_, Http::LowerCaseString("application/json"));
  EXPECT_EQ(body.mpBodyParts().at(1).content_type_lc_, Http::LowerCaseString("application/vnd.3gpp.5gnas"));
  EXPECT_EQ(body.mpBodyParts().at(2).content_type_lc_, Http::LowerCaseString("application/vnd.3gpp.5gtrock"));
  EXPECT_EQ(body.mpStartIndex(), 0);
  EXPECT_EQ(body.mpBodyParts().at(0).data_part_, mp_json_part);
  EXPECT_EQ(body.mpBodyParts().at(1).data_part_, str_binary_part1);
  EXPECT_EQ(body.mpBodyParts().at(2).data_part_, str_binary_part2);
}

// Body: multipart/related and 3 body parts. The two binary parts have
// the same content-id which should not matter.
// Un-quoted boundary.
// With preamble or epilogue
TEST(BodyTest, TestBodyParseWithHeaders2sameContentIdvs) {
  std::string multipart_related{"multipart/related"};
  std::string boundary{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
  std::string content_type{absl::StrCat(multipart_related, "; Boundary=\"", boundary, "\"")};
  std::string preamble{"asdfasdfas\r\nasfsadafasd\r\n\r\nasfsds\r\n"};
  std::string epilogue{"lkjlkjlkjlkjlkjlkjlkj\r\nlkjlkjlkjlkjlkj"};

  std::string mp_json_headers{"Content-type: application/json\r\ncontent-ignored :asdf\r\ncontent-id : asdf"};

  std::string mp_json_part{R"({
"subscriberIdentifier": "imsi-460001357924610",
nfConsumerIdentification": {
    "nFName": "123e-e8b-1d3-a46-421",
    "nFIPv4Address": "192.168.0.1",
    "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
    "nFPLMNID": {
        "mcc": "311",
        "mnc": "280"
    },
    "nodeFunctionality": "SMF"
})"};

  std::string mp_binary_headers1{"Content-type: application/vnd.3gpp.5gnas\r\ncontent-id: binpart01"};
  std::string str_binary_part1("ABCDEFabcdef\0GHIJ", 17);

  std::string mp_binary_headers2{"Content-type: application/vnd.3gpp.5gtrock\r\ncontent-id: binpart01"};
  std::string str_binary_part2("XYZxyzXYZxyz\0xyz\0", 17);

  auto everything = absl::StrCat(
    preamble, "\r\n",
    "--", boundary, "\r\n", 
    mp_json_headers, "\r\n\r\n",
    mp_json_part, "\r\n",
    "--", boundary, "\r\n",
    mp_binary_headers1, "\r\n\r\n",
    str_binary_part1, "\r\n",
    "--", boundary, "\r\n",
    mp_binary_headers2, "\r\n\r\n",
    str_binary_part2, "\r\n",
    "--", boundary, "--", "\r\n",
    epilogue);
  std::cout << "Everything: |" << everything << "|" << std::endl;
  Body body;
  body.setBodyFromString(everything, content_type);
  EXPECT_TRUE(body.isMultipart());
  EXPECT_EQ(body.getBodyAsString(), everything);
  EXPECT_EQ(body.mpBoundary(), boundary);
  EXPECT_TRUE(body.mpStart().empty());
  EXPECT_EQ(body.mpPreamble(), preamble);
  EXPECT_EQ(body.mpEpilogue(), epilogue);
  EXPECT_EQ(body.mpBodyParts().size(), 3);
  EXPECT_EQ(body.mpBodyParts().at(0).content_type_lc_, Http::LowerCaseString("application/json"));
  EXPECT_EQ(body.mpBodyParts().at(1).content_type_lc_, Http::LowerCaseString("application/vnd.3gpp.5gnas"));
  EXPECT_EQ(body.mpBodyParts().at(2).content_type_lc_, Http::LowerCaseString("application/vnd.3gpp.5gtrock"));
  EXPECT_EQ(body.mpStartIndex(), 0);
  EXPECT_EQ(body.mpBodyParts().at(0).data_part_, mp_json_part);
  EXPECT_EQ(body.mpBodyParts().at(1).data_part_, str_binary_part1);
  EXPECT_EQ(body.mpBodyParts().at(2).data_part_, str_binary_part2);
}


}
}
}
}
