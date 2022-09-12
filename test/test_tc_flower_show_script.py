"""test_tc_flower_show_script.py

Test the tc-filter-show script.
"""

import unittest
import logging

from petunia.ShowApp import dump_tc_rules

import json

logger = None
def setUpModule():
    global logger
    logging.basicConfig()
    logger = logging.getLogger("unittest")
    logger.setLevel(logging.DEBUG)

class TcFilterShowTest(unittest.TestCase):
    def setUp(self):
        self.log = logger.getChild(self.id())

    def tearDown(self):
        pass

    def testDefault(self):
        dump_tc_rules([], [], False, None)
        dump_tc_rules(json.loads("[{}]"), [], False, None)
        rules = json.loads("""
[
 {
        "chain" : 0,
        "protocol" : "ip",
        "kind" : "flower",
      "pref" : 33239
        },
   {
        "chain" : 0,
      "options" : {
         "actions" : [
            {
               "bind" : 1,
               "stats" : {
                  "requeues" : 0,
                  "overlimits" : 0,
                  "backlog" : 0,
                  "packets" : 0,
                  "drops" : 0,
                  "bytes" : 0,
                  "qlen" : 0
               },
               "control_action" : {
                  "type" : "drop"
               },
               "installed" : 20587080,
               "ref" : 1,
               "index" : 945,
               "order" : 1,
               "kind" : "gact",
               "prob" : {
                  "control_action" : {
                     "type" : "pass"
                  },
                  "random_type" : "none",
                  "val" : 0
               }
            }
         ],
         "in_hw" : true,
         "in_hw_count" : 1,
         "indev" : "swp52",
         "handle" : 472,
         "keys" : {
            "eth_type" : "ipv4"
         }
        },
        "protocol" : "ip",
        "kind" : "flower",
      "pref" : 33239
   }
]        """)
        dump_tc_rules(rules, [], False, None)
        data = dump_tc_rules(rules, ["swp+"], False, None)
        data = dump_tc_rules(rules, ["swp+"], False, data)

if __name__ == "__main__":
    unittest.main()
