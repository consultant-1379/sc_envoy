#include "include/nlohmann/json.hpp"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <iostream>
#include <stdexcept>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

using json = nlohmann::json;

TEST(EricProxyJsonTest, TestJsonPatch) {


    // the original document
    //json doc = R"(
    //    {
    //      "baz": "qux",
    //      "foo": "bar"
    //    }
    //)"_json;


    json doc = R"(
      {
        "subscriberIdentifier": "imsi-460001357924610",
        "nfConsumerIdentification": {
            "nFName": "123e-e8b-1d3-a46-421",
            "nFIPv4Address": "192.168.0.1",
            "nFIPv6Address": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
            "nFPLMNID": {
                "mcc": "311",
                "mnc": 280
            },
            "nodeFunctionality": "SMF"
        }
      }
    )"_json;

    json patch = R"([{ "op": "default_op", "path": "default_path", "value": "default_value"}])"_json;

    std::cout << "Testing patch >" << patch.dump() << std::endl;

    std::string input_value = "\"supi-replaced\"";
    //std::string input_value = "11.11";
    //std::string input_value = "{ \"js_object\" : { \"a\":\"b\" } }";
     

    json json_input_value = json::parse(input_value);

    patch.at(0).at("op") = "replace";
    patch.at(0).at("path") = "/subscriberIdentifier";
    patch.at(0).at("value") = json_input_value;

    std::cout << "Testing patches >" << patch.dump() << std::endl;


    // apply the patch
    json patched_doc = doc.patch(patch);

    // output original and patched document
    std::cout << std::setw(4) << doc << "\n\n"
              << std::setw(4) << patched_doc << std::endl;

    // depth of json object
    std::cout << std::setw(4) << doc.size() << "\n\n"
              << std::setw(4) << doc.max_size() << std::endl;
}


TEST(EricProxyJsonTest, TestJsonSize) {

  json doc = R"(
      {
        "L1": "V1",
        "L2": {
            "L21": "V21",
            "L22": "V22",
            "L23": "V23",
            "L24": {
                "L241": "V241",
                "L242": true
            },
            "L25": "V25"
        }
      }
  )"_json;

    // depth of json object
    std::cout << std::setw(4) << doc.size() << "\n\n"
              << std::setw(4) << doc.max_size() << std::endl;

    // depth of json object
    std::cout << std::setw(4) << doc["L2"].size() << "\n\n"
              << std::setw(4) << doc.max_size() << std::endl;
}

TEST(EricProxyJsonTest, TestJsonParseCb_depthLimit) {

  json doc = R"(
      {
        "L1": "V1",
        "L2": {
            "L21": "V21",
            "L22": "V22",
            "L23": "V23",
            "L24": {
                "L241": "V241",
                "L242": true,
                "L243": {
                  "L2431":"V2431"
                } 
            },
            "L25": "V25"
        }
      }
  )"_json;

  // define parser callback
  json::parser_callback_t cb = [](int depth, json::parse_event_t event, json & parsed)
  {
      if (event == json::parse_event_t::object_start){
        std::cout << std::setw(4) << "event:parse_event_t::object_start" << "\n\n" << std::endl; 
      }
      if (event == json::parse_event_t::key){
        std::cout << std::setw(4) << "event:parse_event_t::key" << "\n\n" << std::endl; 
      }      
      if (event == json::parse_event_t::object_end){
        std::cout << std::setw(4) << "event:parse_event_t::object_end" << "\n\n" << std::endl; 
      }      
      if (event == json::parse_event_t::array_start){
        std::cout << std::setw(4) << "event:parse_event_t::array_start" << "\n\n" << std::endl; 
      }
      if (event == json::parse_event_t::array_end){
        std::cout << std::setw(4) << "event:parse_event_t::array_end" << "\n\n" << std::endl; 
      }
      if (event == json::parse_event_t::value){
        std::cout << std::setw(4) << "event:parse_event_t::value" << "\n\n" << std::endl; 
      }
      std::cout << std::setw(4) << "parsed:"<< parsed << "\n\n" << std::endl; 
      std::cout << std::setw(4) << "depth:" << depth << "\n\n" << std::endl; 

      if (depth > 3) {
        std::cout << std::setw(4)  << "max. depth reached, depth:"  << depth << "\n\n" << std::endl;
        return false;
      } 
//    if (depth > 3) throw std::invalid_argument("maximum json depth reached"); 
      return true;
  
  };

   json j_filtered = json::parse(doc.dump(), cb);
    std::cout << std::setw(4) << j_filtered << '\n';

    // depth of json object
    std::cout << std::setw(4) << doc.size() << "\n\n"
              << std::setw(4) << doc.max_size() << std::endl;

    // depth of json object
    std::cout << std::setw(4) << doc["L2"].size() << "\n\n"
              << std::setw(4) << doc.max_size() << std::endl;
}


TEST(EricProxyJsonTest, TestJsonParseCb_leafLimit) {

  json doc = R"(
      {
        "L1": "V1",
        "L2": {
            "L21": "V21",
            "L22": {},
            "L23": "V23",
            "L24": {
                "L241": "V241",
                "L242": true,
                "L243": {
                  "L2431":"V2431"
                } 
            },
            "L25": "V25",
            "L26": [0,1,2,3,4,5],
            "L27": ["A",true, null,{"k0": "v0"}],
            "L28": [{"k1": "v1"}, {"k2": {"k21": "v21", "k22": "v22"}}],
            "L29": [0,1,2,[0,1],[2,3]]
        }
      }
  )"_json;

  static int leaves = 0;
  static int in_array_level = 0;
  static bool is_simple_array = true;

  // define parser callback
  json::parser_callback_t cb = [](int depth, json::parse_event_t event, json & parsed)
  {
      switch (event) {
      case json::parse_event_t::object_start:
        std::cout << std::setw(4) << "event:parse_event_t::object_start" << "\n\n" << std::endl; 
        if (in_array_level > 0) {
          is_simple_array = false;
        }
        break;

      case json::parse_event_t::key:
        std::cout << std::setw(4) << "event:parse_event_t::key" << "\n\n" << std::endl; 
        break;

      case json::parse_event_t::object_end:
        // an empty array should be counted as leaf
        if (parsed.empty()){
          leaves ++;
        }
        std::cout << std::setw(4) << "event:parse_event_t::object_end" << "\n\n" << std::endl; 
        break;

      case json::parse_event_t::array_start:
        std::cout << std::setw(4) << "event:parse_event_t::array_start" << "\n\n" << std::endl; 
        if (in_array_level > 0) {
          is_simple_array = false;
        }
        in_array_level ++;
        break;
      case json::parse_event_t::array_end:
        std::cout << std::setw(4) << "event:parse_event_t::array_end" << "\n\n" << std::endl;
        // If a leaf IE is an array of a simple data type, 
        // then the whole array shall count as one leaf.
        //
        // ... correct the leaves counter (stepped on "value" event) 
        if (is_simple_array){
          leaves = leaves - parsed.size() +1;
        }
        
        in_array_level --;
        if (in_array_level == 0){
          is_simple_array = true; // reset flag 
        }
        break;

      case json::parse_event_t::value:
        std::cout << std::setw(4) << "event:parse_event_t::value" << "\n\n" << std::endl;
        leaves++;
        break; 
      }

      std::cout << std::setw(4) << "in_array_level:"<< in_array_level << "\n\n" << std::endl;
      std::cout << std::setw(4) << "is_simple_array:"<< is_simple_array << "\n\n" << std::endl;
      std::cout << std::setw(4) << "parsed:"<< parsed << "\n\n" << std::endl; 
      std::cout << std::setw(4) << "depth:" << depth << "\n\n" << std::endl; 
      std::cout << std::setw(4) << "leaves:"  << leaves << '\n';

//      if (depth > 3) {
//        std::cout << std::setw(4)  << "max. depth reached, depth:"  << depth << "\n\n" << std::endl;
//        return false;
//      } 
//    if (depth > 3) throw std::invalid_argument("maximum json depth reached"); 
      return true;
  
  };

   json j_filtered = json::parse(doc.dump(), cb);

   std::cout << std::setw(4) << " ---JSON PARSING FINISHED ---"  << '\n';
   std::cout << std::setw(4) << j_filtered << '\n';
   std::cout << std::setw(4) << "leaves:"  << leaves << '\n';
    
}


} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
