#include "envoy/http/codes.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/eric_proxy/filter.h"
#include "base_integration_test.h"
#include "test/integration/http_integration.h"
#include "test/integration/utility.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {
namespace {

  // Configuration 1 (equality tests)
  const std::string config_1 = R"(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 80
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: r1
        condition:
          op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'hdr'},
                      typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'a,b,c,d'}}
        actions:
        - action_route_to_pool: {pool_name: {term_string: pool_c}}
      - name: r2
        condition:
          op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'hdr'},
                      typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'a,b,c,c'}}
        actions:
        - action_route_to_pool: {pool_name: {term_string: pool_c}}
      - name: r3
        condition:
          op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'hdr'},
                      typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'b'}}
        actions:
        - action_route_to_pool: {pool_name: {term_string: pool_b}}
      - name: r4
        condition:
          op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'hdr'},
                      typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'a'}}
        actions:
        - action_route_to_pool: {pool_name: {term_string: pool_a}}
      - name: r5
        condition:
          op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'set-cookie'},
                      typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'a'}}
        actions:
        - action_route_to_pool: {pool_name: {term_string: wrong_pool_2}}
      - name: r6
        condition:
          op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'set-cookie'},
                      typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'a,b,c,d'}}
        actions:
        - action_route_to_pool: {pool_name: {term_string: pool_abcd}}
      - name: r7
        condition:
          op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'left'},
                      typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'right'}}
        actions:
        - action_route_to_pool: {pool_name: {term_string: pool_hdr_hdr}}
      - name: r8
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool: {pool_name: {term_string: not_found}}
  )";

    // Configuration 2 ('exists' tests)
  const std::string config_2 = R"(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 80
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: r1
        condition:
          op_exists: {arg1: {term_reqheader: 'hdr'}}
        actions:
        - action_route_to_pool: {pool_name: {term_string: pool_hdr}}
      - name: r2
        condition:
          op_exists: {arg1: {term_reqheader: 'set-cookie'}}
        actions:
        - action_route_to_pool: {pool_name: {term_string: pool_cookie}}
      - name: r3
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool: {pool_name: {term_string: not_found}}
  )";

    // Configuration 3 (isEmtpy tests)
    const std::string config_3 = R"(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 80
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: r1
        condition:
          op_isempty: {arg1: {term_reqheader: 'hdr'}}
        actions:
        - action_route_to_pool: {pool_name: {term_string: pool_hdr_empty}}
      - name: r2
        condition:
          op_exists: {arg1: {term_reqheader: 'hdr'}}
        actions:
        - action_route_to_pool: {pool_name: {term_string: pool_hdr_not_empty}}
      - name: r3
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool: {pool_name: {term_string: not_found}}
  )";

      // Configuration 4 (isInSubnet tests)
    const std::string config_4 = R"(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 80
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: r1
        condition:
          op_isinsubnet: {arg1: {term_reqheader: 'addr'}, arg2: '10.0.0.0/24'}
        actions:
        - action_route_to_pool: {pool_name: {term_string: in_subnet_v4}}
      - name: r2
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool: {pool_name: {term_string: not_in_subnet}}
  )";

    // Configuration 5 (addHeader tests)
  const std::string config_5 = R"(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 80
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: r1
        condition:
          op_exists: {arg1: {term_reqheader: 'from'}}
        actions:
        - action_add_header:
            name: to
            value:
              term_header: from
            if_exists: ADD
        - action_route_to_pool: {pool_name: {term_string: done_1}}
      - name: r2
        condition:
          op_exists: {arg1: {term_reqheader: 'replacement'}}
        actions:
        - action_add_header:
            name: to
            value:
              term_header: replacement
            if_exists: REPLACE
        - action_route_to_pool: {pool_name: {term_string: done_2}}
      - name: r3
        condition:
          op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'hdr'},
                      typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'a'}}
        actions:
        - action_add_header:
            name: hdr
            value:
              term_string: b
            if_exists: ADD
      - name: r4
        condition:
          op_equals: {typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_reqheader: 'hdr'},
                      typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value', term_string: 'a,b'}}
        actions:
        - action_route_to_pool: {pool_name: {term_string: done_3}}
  )";  

    // Configuration 6 (modifyHeader tests)
  const std::string config_6 = R"(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 80
  filter_cases:
    - name: default_routing
      filter_rules:
      - name: r1
        condition:
          op_exists: {arg1: {term_reqheader: 'hdr'}}
        actions:
        - action_modify_header:
            name: hdr
            replace_value:
              term_string: x
      - name: r2
        condition:
          op_exists: {arg1: {term_reqheader: 'replacement'}}
        actions:
        - action_modify_header:
            name: to
            replace_value:
              term_header: replacement
  )";

  // Configuration multi-header + variable (Alexandros' question)
  const std::string config_multi_h_v = R"(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 80
  filter_cases: [
                {
                 "name": "default_routing",
                 "filter_data": [
                  {
                   "name": "multiple_values_data",
                   "header": "dummy-header-1",
                   "variable_name": "variableValue"
                  }
                 ],
                 "filter_rules": [
                  {
                   "name": "rule_1",
                   "condition": {
                    "op_equals": {
                     "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "variableValue"
                     },
                     "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "dummy-header-value-1,dummy-header-value-2"
                     }
                    }
                   },
                   "actions": [
                    {
                     "action_add_header": {
                      "name": "dummy-header-1",
                      "value": {
                       "term_string": "dummy-header-value-3"
                      },
                      "if_exists": "ADD"
                     }
                    }
                   ]
                  },
                  {
                   "name": "rule_2",
                   "condition": {
                    "op_equals": {
                     "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "variableValue"
                     },
                     "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "dummy-header-value-1,dummy-header-value-2,dummy-header-value-3"
                     }
                    }
                   },
                   "actions": [
                    {
                     "action_add_header": {
                      "name": "dummy-header-1",
                      "value": {
                       "term_string": "dummy-header-value-4"
                      },
                      "if_exists": "ADD"
                     }
                    }
                   ]
                  }
                 ]
                }
               ]
  )";

        // Configuration multi-header + variable (Alexandros' question 2, Variable not updated)
  const std::string config_multi_h_v_2 = R"(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  response_filter_cases:
    out_response_screening:
      own_nw:
        name: own_network
        start_fc_list:
        - default_response
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 80
  "filter_cases": [
                {
                 "name": "default_routing",
                 "filter_data": [
                  {
                   "name": "multiple_values_data",
                   "header": "dummy-header-1",
                   "variable_name": "variableValue"
                  }
                 ],
                 "filter_rules": [
                  {
                   "name": "rule_1",
                   "condition": {
                    "op_equals": {
                     "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "variableValue"
                     },
                     "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "dummy-header-value-1,dummy-header-value-2"
                     }
                    }
                   },
                   "actions": [
                    {
                     "action_add_header": {
                      "name": "dummy-header-1",
                      "value": {
                       "term_string": "dummy-header-value-3"
                      },
                      "if_exists": "ADD"
                     }
                    },
                    {
                     "action_add_header": {
                      "name": "dummy-header-1",
                      "value": {
                       "term_string": "dummy-header-value-5"
                      },
                      "if_exists": "ADD"
                     }
                    }
                   ]
                  },
                  {
                   "name": "rule_2",
                   "condition": {
                    "op_equals": {
                     "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "variableValue"
                     },
                     "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "dummy-header-value-1,dummy-header-value-2,dummy-header-value-3,dummy-header-value-5"
                     }
                    }
                   },
                   "actions": [
                    {
                     "action_add_header": {
                      "name": "dummy-header-1",
                      "value": {
                       "term_string": "dummy-header-value-4"
                      },
                      "if_exists": "ADD"
                     }
                    },
                    {
                     "action_exit_filter_case": true
                    }
                   ]
                  },
                 ]
                },
                {
                 "name": "default_response",
                 "filter_data": [
                  {
                   "name": "apiRoot_data",
                   "header": "3gpp-Sbi-target-apiRoot",
                   "extractor_regex": "^(http(s?)://)?(?P\u003cnf\u003e.+?)\\..+?\\.(?P\u003cmnc\u003e.+?)\\..+?\\.(?P\u003cmcc\u003e.+?)\\..*"
                  }
                 ],
                 "filter_rules": [
                  {
                   "name": "rule_1",
                   "condition": {
                    "op_equals": {
                     "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "variableValue"
                     },
                     "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "dummy-header-value-1,dummy-header-value-2,dummy-header-value-3,dummy-header-value-5,dummy-header-value-4"
                     }
                    }
                   },
                   "actions": [
                    {
                     "action_add_header": {
                      "name": "dummy-header-1",
                      "value": {
                       "term_string": "dummy-header-value-5"
                      },
                      "if_exists": "ADD"
                     }
                    }
                   ]
                  }
                 ]
                }
               ]
  )";

         // Configuration multi-header + variable (Alexandros' question 3, Variable not updated in go-to action)
  const std::string config_multi_h_v_3 = R"(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 80
  "filter_cases": [
                {
                 "name": "default_routing",
                 "filter_data": [
                  {
                   "name": "multiple_values_data",
                   "header": "dummy-header-1",
                   "variable_name": "variableValue"
                  }
                 ],
                 "filter_rules": [
                  {
                   "name": "rule_1",
                   "condition": {
                    "op_equals": {
                     "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "variableValue"
                     },
                     "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "dummy-header-value-1,dummy-header-value-2"
                     }
                    }
                   },
                   "actions": [
                    {
                     "action_add_header": {
                      "name": "dummy-header-1",
                      "value": {
                       "term_string": "dummy-header-value-3"
                      },
                      "if_exists": "ADD"
                     }
                    },
                    {
                     "action_goto_filter_case": "caseReq_2"
                    }
                   ]
                  }
                 ]
                },
                {
                 "name": "caseReq_2",
                 "filter_data": [
                  {
                   "name": "multi_data",
                   "header": "dummy-header-1",
                   "variable_name": "variableValue2"
                  }
                 ],
                 "filter_rules": [
                  {
                   "name": "rule_2",
                   "condition": {
                    "op_equals": {
                     "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "variableValue2"
                     },
                     "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "dummy-header-value-1,dummy-header-value-2,dummy-header-value-3"
                     }
                    }
                   },
                   "actions": [
                    {
                     "action_add_header": {
                      "name": "dummy-header-1",
                      "value": {
                       "term_string": "dummy-header-value-4"
                      },
                      "if_exists": "ADD"
                     }
                    },
                    {
                     "action_goto_filter_case": "caseReq_3"
                    }
                   ]
                  }
                 ]
                },
                {
                 "name": "caseReq_3",
                 "filter_rules": [
                  {
                   "name": "rule_1",
                   "condition": {
                    "op_equals": {
                     "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "variableValue"
                     },
                     "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "dummy-header-value-1,dummy-header-value-2,dummy-header-value-3"
                     }
                    }
                   },
                   "actions": [
                    {
                     "action_add_header": {
                      "name": "dummy-header-1",
                      "value": {
                       "term_string": "dummy-header-value-5"
                      },
                      "if_exists": "ADD"
                     }
                    },
                    {
                     "action_goto_filter_case": "caseReq_4"
                    }
                   ]
                  }
                 ]
                },
                {
                 "name": "caseReq_4",
                 "filter_rules": [
                  {
                   "name": "rule_1",
                   "condition": {
                    "op_equals": {
                     "typed_config1": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_var": "variableValue"
                     },
                     "typed_config2": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value",
                      "term_string": "dummy-header-value-1,dummy-header-value-2,dummy-header-value-3,dummy-header-value-5"
                     }
                    }
                   },
                   "actions": [
                    {
                     "action_add_header": {
                      "name": "dummy-header-1",
                      "value": {
                       "term_string": "dummy-header-value-6"
                      },
                      "if_exists": "ADD"
                     }
                    }
                   ]
                  }
                 ]
                }
               ]
  )";

//
    const std::string config_var_ordering_1_ = R"(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 80
  filter_cases:
    - name: default_routing
      filter_data:
      - name: MD1
        path: true
        extractor_regex: '/nudm-sdm/v1/udm-\d+-mcc-(?P<mcc>\d+).+'
      - name: MD2
        path: true
        extractor_regex: '/nudm-sdm/v1/udm-(?P<udm>\d+).+-mnc-(?P<mcc>\d+)'
      filter_rules:
      - name: r1
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '787' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: udm }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_route_to_pool: {pool_name: {term_string: pool_md1_md2}}
      - name: r2
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool: {pool_name: {term_string: wrong_pool}}
  )";

     const std::string config_var_ordering_2_ = R"(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 80
  filter_cases:
    - name: default_routing
      filter_data:
      - name: MD1
        path: true
        extractor_regex: '/nudm-sdm/v1/udm-\d+-mcc-(?P<mcc>\d+).+'
      - name: MD2
        path: true
        extractor_regex: '/nudm-sdm/v1/udm-(?P<udm>\d+).+-mnc-(?P<mcc>\d+)'
      filter_rules:
      - name: r1
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: udm }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '787' }}
        actions:
        - action_route_to_pool: {pool_name: {term_string: pool_md2_md1}}
      - name: r2
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool: {pool_name: {term_string: wrong_pool}}
  )";

  const std::string config_var_ordering_3_ = R"(
name: envoy.filters.http.eric_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.EricProxyConfig
  name: sepp_router
  node_type: SEPP
  request_filter_cases:
    routing:
      own_nw:
        name: own_network
        start_fc_list:
        - default_routing
  own_fqdn: sepp.own_plmn.com
  own_internal_port: 80
  filter_cases:
    - name: default_routing
      filter_data:
      - name: MD1
        path: true
        extractor_regex: '/nudm-sdm/v1/udm-\d+-mcc-(?P<mcc>\d+).+'
      - name: MD2
        path: true
        extractor_regex: '/nudm-sdm/v1/udm-(?P<udm>\d+).+-mnc-(?P<mcc>\d+)'
      filter_rules:
      - name: r1
        condition:
          op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: udm }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
        actions:
        - action_log:
            max_log_message_length: 500
            log_values:
              - term_string: "rule1"
            log_level: INFO
      - name: r2
        condition:
          op_and:
            arg1:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: udm }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '123' }}
            arg2:
              op_equals: { typed_config1: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_var: mcc }, typed_config2: {'@type': 'type.googleapis.com/envoy.extensions.filters.http.eric_proxy.v3.Value',  term_string: '787' }}
        actions:
        - action_route_to_pool: {pool_name: {term_string: pool_md2_md1}}
      - name: r3
        condition:
          term_boolean: true
        actions:
        - action_route_to_pool: {pool_name: {term_string: wrong_pool}}
  )";

  //------------------------------------------------------------------------
  class EricProxyFilterMultiHeaderIntegrationTest : public EricProxyIntegrationTestBase,
                                        public testing::TestWithParam<Network::Address::IpVersion> {
public:
  EricProxyFilterMultiHeaderIntegrationTest()
      : EricProxyIntegrationTestBase(Http::CodecClient::Type::HTTP1, GetParam(), EricProxyFilterMultiHeaderIntegrationTest::ericProxyHttpProxyConfig()) {
      }
  void SetUp() override { }
  void TearDown() override { cleanupUpstreamAndDownstream(); }

  // Initialize the filter with the given configuration
  void initializeFilter(const std::string& config) {
    config_helper_.addFilter(config);

    HttpIntegrationTest::initialize();
  }

  void runTest(std::string config, Http::TestRequestHeaderMapImpl req_headers, std::map<std::string, std::vector<std::string>> expected_req_headers, std::map<std::string, std::vector<std::string>> expected_res_headers){
    config_helper_.addFilter(config);
    HttpIntegrationTest::initialize();


    IntegrationCodecClientPtr codec_client;
    FakeHttpConnectionPtr fake_upstream_connection;
    FakeStreamPtr request_stream;

    codec_client = makeHttpConnection(lookupPort("http"));
    auto response = codec_client->makeHeaderOnlyRequest(req_headers);
    ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
    ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
    ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
    ASSERT_TRUE(fake_upstream_connection->close());
    ASSERT_TRUE(response->waitForEndStream());

    EXPECT_THAT(request_stream->headers(), Http::HeaderValueOf("x-eric-proxy", "///"));

    for(std::map<std::string, std::vector<std::string>>::const_iterator it = expected_req_headers.begin(); it != expected_req_headers.end(); ++it )
    {
      std::string header_name = it->first;
      auto req_header = request_stream->headers().get(Http::LowerCaseString(header_name));

      EXPECT_THAT(req_header.size(), it->second.size());

      if(req_header.size() == it->second.size()){
        for(size_t i = 0; i < it->second.size(); i++){

          EXPECT_THAT(req_header[i]
                    ->value()
                    .getStringView(), it->second.at(i));
        }
      }
    }

    for(std::map<std::string, std::vector<std::string>>::const_iterator it = expected_res_headers.begin(); it != expected_res_headers.end(); ++it )
    {
      std::string header_name = it->first;
      auto res_header = response->headers().get(Http::LowerCaseString(header_name));

      EXPECT_THAT(res_header.size(), it->second.size());

      if(res_header.size() == it->second.size()){
        for(size_t i = 0; i < it->second.size(); i++){

          EXPECT_THAT(res_header[i]
                    ->value()
                    .getStringView(), it->second.at(i));
        }
      }
    }

    codec_client->close();
  }

  // Common configuration that sets the start-routingcase
  std::string ericProxyHttpProxyConfig() {
    return absl::StrCat(ConfigHelper::baseConfig(), fmt::format(R"EOF(
    filter_chains:
      filters:
        name: http
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: config_test
          delayed_close_timeout:
            nanos: 100
          http_filters:
            name: envoy.filters.http.router
          codec_type: HTTP1
          access_log:
            name: accesslog
            filter:
              not_health_check_filter:  {{}}
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
              path: {}
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - name: route2
                match:
                  prefix: "/"
                  headers:
                    - name: x-eric-proxy
                route:
                  cluster: cluster_0
              - name: route1
                match:
                  prefix: "/"
                route:
                  cluster: cluster_0
  )EOF", Platform::null_device_path));
  }
  };

//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(IpVersions, EricProxyFilterMultiHeaderIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

//------------------------------------------------------------------------
//-------------------------EQUALITY TESTS---------------------------------
//------------------------------------------------------------------------

// Single header, condition tests for equality
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEq1) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"hdr", "a"},
  };

  runTest(config_1, req_headers, {{"x-cluster",{"pool_a"}}}, {});
}

// Four headers, out of which two are identical, order is reverse 
// compared to the conditions, condition tests for equality
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEq2) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"hdr", "a"},
    {"hdr", "b"},
    {"hdr", "c"},
    {"hdr", "c"},
  };

  runTest(config_1, req_headers, {{"x-cluster",{"pool_c"}}}, {});
}

// Two headers, one of them is a combined header with two values, 
// condition tests for equality
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEq3) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"hdr", "a"},
    {"hdr", "b,c,c"},
  };

  runTest(config_1, req_headers, {{"x-cluster",{"pool_c"}}}, {});
}

// One header, combined of four values, condition tests for equality
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEq4) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"hdr", "a,b,c,d"},
  };

  runTest(config_1, req_headers, {{"x-cluster",{"pool_c"}}}, {});
}

// One set-cookie header with comma that is a single value as per the 
// exception in RFC 7230 3.2.2, condition tests for equality
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEq5) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"set-cookie", "a,b,c,d"},
  };

  runTest(config_1, req_headers, {{"x-cluster",{"pool_abcd"}}}, {});
}

// Compare two headers, same values, same order, condition tests for 
// equality
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEq6) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"left", "a"},
    {"left", "b"},
    {"left", "c"},
    {"right", "a"},
    {"right", "b"},
    {"right", "c"},
  };

  runTest(config_1, req_headers, {{"x-cluster",{"pool_hdr_hdr"}}}, {});
}

// Compare two headers, same values in different order, condition tests 
// for equality
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEq7) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"left", "a"},
    {"left", "b"},
    {"left", "c"},
    {"right", "c"},
    {"right", "b"},
    {"right", "a"},
  };

  runTest(config_1, req_headers, {{"x-cluster",{"not_found"}}}, {});
}

// Compare two different headers,  condition tests for equality
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEq8) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"left", "a"},
    {"left", "b"},
    {"right", "a"},
  };

  runTest(config_1, req_headers, {{"x-cluster",{"not_found"}}}, {});
}

// Compare two headers, combined values are the same, condition tests 
// for equality
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEq9) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"left", "a,b"},
    {"left", "c"},
    {"right", "a"},
    {"right", "b"},
    {"right", "c"},
  };

  runTest(config_1, req_headers, {{"x-cluster",{"pool_hdr_hdr"}}}, {});
}

//------------------------------------------------------------------------
//---------------------------EXISTS TESTS---------------------------------
//------------------------------------------------------------------------

// One header, condition tests for existence
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEx1) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"hdr", "a"},
  };

  runTest(config_2, req_headers, {{"x-cluster",{"pool_hdr"}}}, {});
}

// Three headers, condition tests for existence
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEx2) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"hdr", "a"},
    {"hdr", "b"},
    {"hdr", "c"},
  };

  runTest(config_2, req_headers, {{"x-cluster",{"pool_hdr"}}}, {});
}

// One set-cookie-header with comma, condition tests for existence
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEx3) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"set-cookie", "mmmh,cookies"},
  };

  runTest(config_2, req_headers, {{"x-cluster",{"pool_cookie"}}}, {});
}

//------------------------------------------------------------------------
//---------------------------IS EMPTY TESTS-------------------------------
//------------------------------------------------------------------------

// One empty header, condition tests for empty header
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEmpty1) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"hdr", ""},
    {"hdr2", "not empty"},
  };

  runTest(config_3, req_headers, {{"x-cluster",{"pool_hdr_empty"}}}, {});
}

// Two empty headers, condition tests for empty header
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEmpty2) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"hdr", ""},
    {"hdr", ""},
    {"hdr2", "not empty"},
  };

  runTest(config_3, req_headers, {{"x-cluster",{"pool_hdr_empty"}}}, {});
}

// One empty, one non-empty header, condition tests for empty header
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEmpty3) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"hdr", ""},
    {"hdr", "a"},
  };

  runTest(config_3, req_headers, {{"x-cluster",{"pool_hdr_not_empty"}}}, {});
}

// One empty, one non-empty header (different order than MulitHdrEmpy3), 
// condition tests for empty header
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEmpty4) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"hdr", "a"},
    {"hdr", ""},
  };

  runTest(config_3, req_headers, {{"x-cluster",{"pool_hdr_not_empty"}}}, {});
}

// Two empty, one non-empty header that is not at either end of the list, 
// condition tests for empty header
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrEmpty5) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"hdr", ""},
    {"hdr", "a"},
    {"hdr", ""},
  };

  runTest(config_3, req_headers, {{"x-cluster",{"pool_hdr_not_empty"}}}, {});
}

//------------------------------------------------------------------------
//---------------------------IS IN SUBNET TESTS---------------------------
//------------------------------------------------------------------------

// One header, is inside the subnet 10.0.0.0/24
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrSubnet1) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"addr", "10.0.0.2"},
  };

  runTest(config_4, req_headers, {{"x-cluster",{"in_subnet_v4"}}}, {});
}

// Two headers, both inside the subnet 10.0.0.0/24
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrSubnet2) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"addr", "10.0.0.253"},
    {"addr", "10.0.0.2"},
  };

  runTest(config_4, req_headers, {{"x-cluster",{"in_subnet_v4"}}}, {});
}

// Two headers, one inside the subnet 10.0.0.0/24
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrSubnet3) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"addr", "10.10.10.10"},
    {"addr", "10.0.0.10"},
  };

  runTest(config_4, req_headers, {{"x-cluster",{"in_subnet_v4"}}}, {});
}

// Two headers, none inside the subnet 10.0.0.0/24
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrSubnet4) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"addr", "10.1.0.252"},
    {"addr", "10.2.2.2"},
  };

  runTest(config_4, req_headers, {{"x-cluster",{"not_in_subnet"}}}, {});
}

// Two empty headers
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrSubnet5) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"addr", ""},
    {"addr", ""},
  };

  runTest(config_4, req_headers, {{"x-cluster",{"not_in_subnet"}}}, {});
}

// Two headers, one not an IP address, one in subnet 10.0.0.0/24
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrSubnet6) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"addr", "abcd"},
    {"addr", "10.0.0.20"},
  };

  runTest(config_4, req_headers, {{"x-cluster",{"in_subnet_v4"}}}, {});
}

//------------------------------------------------------------------------
//---------------------------ADD HEADER TESTS-----------------------------
//------------------------------------------------------------------------

// Add one multi-header to another single header, if-exist=add
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrAdd1) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"from", "a"},
    {"from", "b"},
    {"to", "x"},
  };

  runTest(config_5, req_headers, {{"x-cluster",{"done_1"}}, {"to", {"x", "a", "b"}}}, {});
}

// Add one multi-header to another multi-header, if-exist=add
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrAdd2) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"from", "a"},
    {"from", "b"},
    {"to", "x"},
    {"to", "y"},
  };

  runTest(config_5, req_headers, {{"x-cluster",{"done_1"}}, {"to", {"x", "y", "a", "b"}}}, {});
}

// Add a single combined header to another single header, if-exist=add. 
// The combined header does not neet to be transferred in full 
// (as the combined header value "a,b") but can be set as two new headers 
// (a and b) because RFC7230 states that the representation is equal 
// (combined or separate).
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrAdd3) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"from", "a,b"},
    {"to", "x"},
  };

  runTest(config_5, req_headers, {{"x-cluster",{"done_1"}}, {"to", {"x", "a", "b"}}}, {});
}

// Add a multi-header to another multi-header, if-exist=replace. 
// The replacement header has more values than the to header (the destination). 
// This has the same effect as "action modify header" (MultiHdrMod2)
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrAdd4) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"replacement", "a"},
    {"replacement", "b"},
    {"replacement", "c"},
    {"to", "x"},
    {"to", "y"},
  };

  runTest(config_5, req_headers, {{"x-cluster",{"done_2"}}, {"to", {"a", "b", "c"}}}, {});
}

// Add a multi-header to a non-existing header ("to" doesn't exist)
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrAdd5) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"from", "a"},
    {"from", "b"},
  };

  runTest(config_5, req_headers, {{"x-cluster",{"done_1"}}, {"to", {"a", "b"}}}, {});
}

// Add a header to an existing header, then check that newly added 
// header value in the next filter-rule condition.
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrAdd6) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"hdr", "a"},
  };

  runTest(config_5, req_headers, {{"x-cluster",{"done_3"}}, {"hdr", {"a", "b"}}}, {});
}

//------------------------------------------------------------------------
//---------------------------MODIFY HEADER TESTS--------------------------
//------------------------------------------------------------------------

// Modify a multi-header: replace with single value "x"
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrMod1) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"hdr", "a"},
    {"hdr", "b"},
    {"hdr", "c"},
  };

  runTest(config_6, req_headers, {{"hdr",{"x"}}}, {});
}

//Modify a multi-header: replace with another multi-header. 
// This has the same effect as "action add header + if-exists=replace" (MultiHdrAdd4).
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrMod2) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"replacement", "a"},
    {"replacement", "b"},
    {"replacement", "c"},
    {"to", "x"},
    {"to", "y"},
  };

  runTest(config_6, req_headers, {{"to",{"a", "b", "c"}}}, {});
}

//------------------------------------------------------------------------
//-----------------------MULTIPLE HEADERS AND VARIABLES-------------------
//------------------------------------------------------------------------

// Test to check that a variable that is set by a message-data rule gets
// updated when a header value is added to an already multi-header.
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrVar1) {
  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"dummy-header-1", "dummy-header-value-1"},
    {"dummy-header-1", "dummy-header-value-2"},
  };

  runTest(config_multi_h_v, req_headers, {{"dummy-header-1",
      {"dummy-header-value-1", "dummy-header-value-2", "dummy-header-value-3", "dummy-header-value-4"}}}, {});

}

// Test to check that a variable that is set by a message-data rule gets
// updated when a header value is added to an already multi-header.
// In the end, the variable is evaluated in the RESPONSE path and 
// a header is added in the RESPONSE
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrVar2) {
  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/test_api_name_1/v1"},
    {"dummy-header-1", "dummy-header-value-1"},
    {"dummy-header-1", "dummy-header-value-2"},
  };

  runTest(config_multi_h_v_2, req_headers, {{"dummy-header-1",{"dummy-header-value-1", "dummy-header-value-2", "dummy-header-value-3","dummy-header-value-5","dummy-header-value-4"}}}, {{"dummy-header-1", {"dummy-header-value-5"}}});

}

//// Multiple variables.
//// Test to check that a variable that is set by a message-data rule gets
//// updated when a header value is added to an already multi-header.
//// Fails due to a bug regarding updating variables, will be handled in a US
//
// TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiHdrVar3) {
//   Http::TestRequestHeaderMapImpl req_headers {
//     {":method", "GET"},
//     {":authority", "host"},
//     {":path", "/test_api_name_1/v1"},
//     {"dummy-header-1", "dummy-header-value-1"},
//     {"dummy-header-1", "dummy-header-value-2"},
//   };

//   runTest(config_multi_h_v_3, req_headers, {{"dummy-header-1",{"dummy-header-value-1", "dummy-header-value-2", "dummy-header-value-3", "dummy-header-value-4", "dummy-header-value-5", "dummy-header-value-6"}}}, {});

// }

//------------------------------------------------------------------------
//---------------------------VARIABLE ORDERING----------------------------
//------------------------------------------------------------------------

// Check if variables have the same order as in the config.
// Order in config: MD1, MD2
// First evaluate mcc, then udm
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiVar1) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/nudm-sdm/v1/udm-123-mcc-262-mnc-787"},
  };

  runTest(config_var_ordering_1_, req_headers, {{"x-cluster",{"pool_md1_md2"}}}, {});
}

// Check if variables have the same order as in the config.
// Order in config: MD1, MD2
// First evaluate udm, then mcc
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiVar2) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/nudm-sdm/v1/udm-123-mcc-262-mnc-787"},
  };

  runTest(config_var_ordering_2_, req_headers, {{"x-cluster",{"pool_md2_md1"}}}, {});
}

// Check if variables have the same order as in the config.
// Order in config: MD1, MD2
// Evaluation in multiple rules
// First evaluate udm in rule 1, then mcc in rule 2
TEST_P(EricProxyFilterMultiHeaderIntegrationTest, TestMultiVar3) {

  Http::TestRequestHeaderMapImpl req_headers {
    {":method", "GET"},
    {":authority", "host"},
    {":path", "/nudm-sdm/v1/udm-123-mcc-262-mnc-787"},
  };

  runTest(config_var_ordering_3_, req_headers, {{"x-cluster",{"pool_md2_md1"}}}, {});
}

} // namespace
} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
