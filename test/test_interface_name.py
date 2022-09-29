"""test_interface_name.py

Test interface name enumeration.
"""

import os
import path_config
import logging
import json

import unittest

from petunia.Topology import (
    Topology,
)

import TcSaveTestUtils

logger = None
def setUpModule():
    global logger
    logging.basicConfig()
    logger = logging.getLogger("unittest")
    logger.setLevel(logging.DEBUG)

class OfflineInterfaceTest(unittest.TestCase):
    """Test the interface name API in offline mode."""

    def setUpLinks(self, ifNames):
        os.environ['TEST_IFNAMES'] = " ".join(ifNames)
        linkMap = dict((x, ['port',]) for x in ifNames)
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        self.topo.update()

    def setUp(self):
        self.log = logger.getChild(self.id())

        os.environ['TEST_IFNAMES'] = "dummy3 dummy4"
        os.environ['TEST_LINKS_JSON'] = json.dumps({})
        os.environ['TEST_VLANS_JSON'] = json.dumps({})
        os.environ['TEST_SVIS_JSON'] = json.dumps({})

        self.topo = Topology(log=self.log)

        self.setUpLinks(['dummy3', 'dummy4',])

    def tearDown(self):
        os.environ.pop('TEST_IFNAMES', None)
        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def assertPorts(self, ports):
        self.assertEqual(ports, self.topo.getPorts())

    def assertMatchLinks(self, links, pat, allLinks=None):
        if allLinks is not None:
            self.setUpLinks(allLinks)
        self.assertEqual(links, self.topo.matchLinks(pat))

    def testSimple(self):
        """Enumerate the default interface list."""
        self.assertPorts(['dummy3', 'dummy4',])

    def testExpandDefault(self):
        self.assertMatchLinks(['dummy3'], 'dummy3')
        self.assertMatchLinks(['dummy4'], 'dummy4')

    def testExpand(self):
        self.assertMatchLinks(['dummy5'], 'dummy5',
                              allLinks=['dummy5', 'dummy6',])
        self.assertMatchLinks(['dummy6'], 'dummy6',
                              allLinks=['dummy5', 'dummy6',])

    def testPrefix(self):

        self.assertMatchLinks(['dummy3', 'dummy4',], 'dummy+')

        self.assertMatchLinks(['dummy5', 'dummy6',], 'dummy+',
                              allLinks=['dummy5', 'dummy6',])

        self.assertMatchLinks(['dummy5', 'dummy6',], 'dummy+',
                              allLinks=['dummy5', 'dummy6', 'other',])

    def testNegate(self):

        self.assertMatchLinks(['dummy3', 'dummy4',], '!other')
        self.assertMatchLinks(['dummy3', 'dummy4',], '!other+')

        self.assertMatchLinks(['dummy3',], '!dummy4')
        self.assertMatchLinks(['dummy4',], '!dummy3')

        self.assertMatchLinks([], '!dummy+')

    def testInvalid(self):

        self.assertMatchLinks([], 'other')

    def testInvalidPattern(self):

        self.assertMatchLinks([], 'other+')

def isVirtualDut():
    if not TcSaveTestUtils.isDut(): return False
    if (not TcSaveTestUtils.isVbox()
        and not TcSaveTestUtils.isKvm()): return False
    return True

@unittest.skipUnless(isVirtualDut(), "this test runs on a virtual DUT")
class OnlineInterfaceTest(unittest.TestCase):
    """Test the interface name API using a VM DUT."""

    def setUp(self):
        TcSaveTestUtils.setUpModule()
        self.log = logger.getChild(self.id())
        os.environ['TEST_DUMMY'] = '1'

    def tearDown(self):
        TcSaveTestUtils.tearDownModule()
        os.environ.pop('TEST_DUMMY')

    def testSimple(self):
        """Enumerate the default interface list."""
        self.topo = Topology(log=self.log)
        ifNames = self.topo.getPorts()
        self.assertIn('dummy0', ifNames)
        self.assertIn('dummy1', ifNames)

if __name__ == "__main__":
    unittest.main()
