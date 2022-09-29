"""test_json.py

"""

import os, sys
import unittest
import logging
import pprint

import path_config

import json
from petunia.JsonUtils import (
    LazyParser,
    LazyFilterParser,
)

logger = None
def setUpModule():
    global logger
    logging.basicConfig()
    logger = logging.getLogger("unittest")
    logger.setLevel(logging.DEBUG)

class JsonTest(unittest.TestCase):

    def setUp(self):
        self.log = logger.getChild(self.id())

    def tearDown(self):
        pass

    def testValue(self):

        buf = """[{"protocol":"ip","pref":49152,"kind":"flower","chain":0},{"protocol":"ip","pref":49152,"kind":"flower","chain":0,"options":{"handle":1,"keys":{"eth_type":"ipv4"},"not_in_hw":true,"actions":[{"order":1, "kind" : "police", "rate" : "8Kbit", "burst" : "100b", "mtu" : "2Kb" ,"control_action":{"type":"drop"}, "overhead" : "0b", "ref" : 1, "bind" : 1
},{"order":2,"kind":"gact","control_action":{"type":"trap"},"prob":{"random_type":"none","control_action":{"type":"pass"},"val":0},"index":1,"ref":1,"bind":1}]}}]"""

        sys.stdout.write(buf)

        p = LazyFilterParser(log=self.log.getChild("json"))
        try:
            data = p.loads(buf)
        except json.JSONDecodeError as ex:
            self.log.error("error at pos %d: %s",
                           ex.pos, str(ex))
            raise

        pprint.pprint(data, sys.stdout)

    def testInvalid(self):

        buf = """[{"protocol":"ip","pref":49152,"kind":"flower","chain":0},{"protocol":"ip","pref":49152,"kind":"flower","chain":0,"options":{"handle":1,"keys":{"eth_type":"ipv4"},"not_in_hw":true,"actions":[{"order":1 police 0x1 rate 8Kbit burst 100b mtu 2Kb ,"control_action":{"type":"drop"} overhead 0b
	ref 1 bind 1
},{"order":2,"kind":"gact","control_action":{"type":"trap"},"prob":{"random_type":"none","control_action":{"type":"pass"},"val":0},"index":1,"ref":1,"bind":1}]}}]"""

        sys.stdout.write(buf)

        p = LazyFilterParser(log=self.log.getChild("json"))
        try:
            data = p.loads(buf)
        except json.JSONDecodeError as ex:
            self.log.error("error at pos %d: %s",
                           ex.pos, str(ex))
            raise

        pprint.pprint(data, sys.stdout)

    def testInvalidStats(self):
        """Test with the addition of 'stats' output."""

        buf = """[{"protocol":"ip","pref":32769,"kind":"flower","chain":0},{"protocol":"ip","pref":32769,"kind":"flower","chain":0,"options":{"handle":2,"keys":{"eth_type":"ipv4","src_ip":"240.0.0.0/4"},"skip_sw":true,"in_hw":true,"in_hw_count":1,"actions":[{"order":1 police 0x1 rate 8Kbit burst 100b mtu 2Kb ,"control_action":{"type":"drop"} overhead 0b 
	ref 1 bind 1,"installed":165686
,"stats":{"bytes":0,"packets":0,"drops":0,"overlimits":0,"requeues":0,"backlog":0,"qlen":0}},{"order":2,"kind":"gact","control_action":{"type":"trap"},"prob":{"random_type":"none","control_action":{"type":"pass"},"val":0},"index":2,"ref":1,"bind":1,"installed":165686,"stats":{"bytes":0,"packets":0,"drops":0,"overlimits":0,"requeues":0,"backlog":0,"qlen":0}}]}}]"""

        sys.stdout.write(buf)

        p = LazyFilterParser(log=self.log.getChild("json"))
        try:
            data = p.loads(buf)
        except json.JSONDecodeError as ex:
            self.log.error("error at pos %d: %s",
                           ex.pos, str(ex))
            raise

        pprint.pprint(data, sys.stdout)

    @unittest.skipIf(True, "this test needs local test content")
    def testInvalidFull(self):
        with open("tc-police-stats.json", 'rt') as fd:
            buf = fd.read()
        p = LazyFilterParser(log=self.log.getChild("json"))
        try:
            data = p.loads(buf)
        except json.JSONDecodeError as ex:
            self.log.error("error at pos %d: %s",
                           ex.pos, str(ex))
            raise

if __name__ == "__main__":
    unittest.main()
