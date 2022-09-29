"""test_iptables_slice.py

Test IPTABLES slicing API
"""

import os
import path_config

import unittest
import logging
import json

logger = None
def setUpModule():
    global logger
    logging.basicConfig()
    logger = logging.getLogger("unittest")
    logger.setLevel(logging.DEBUG)

from petunia.Iptables import (
    FilterTable,
)

import petunia.Slicer
from petunia.Slicer import (
    Slicer,
    SliceTable,
)

from petunia.Topology import (
    Topology,
)

import TcSaveTestUtils

@unittest.skipUnless(TcSaveTestUtils.isDut(),
                     "run this test on a virtual or physical DUT")
class NativeSliceTest(TcSaveTestUtils.IptablesTestMixin,
                      unittest.TestCase):
    """Test slice function with implicit interfaces."""

    def setUp(self):
        self.log = logger.getChild(self.id())

        TcSaveTestUtils.setUpModule()

        self.topo = Topology(log=self.log)
        ifNames = self.topo.getPorts()
        self.log.info("interfaces are %s", ifNames)
        self.assertIn('dummy0', ifNames)
        self.assertIn('dummy1', ifNames)

    def tearDown(self):
        TcSaveTestUtils.tearDownModule()

    def testImplicit(self):

        rules = ["-A INPUT -i dummy0 -p tcp -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()
        print(table_.toSave())

        chains_ = ['INPUT', 'OUTPUT', 'FORWARD', 'INPUT_dummy0',]
        self.assertEqual(set(chains_), set(table_.chains.keys()))

class SliceTest(TcSaveTestUtils.IptablesTestMixin,
                unittest.TestCase):

    def setUp(self):
        self.log = logger.getChild(self.id())

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        os.environ['TEST_VLANS_JSON'] = json.dumps({})
        os.environ['TEST_SVIS_JSON'] = json.dumps({})
        # default set of interfaces, may adjust this depending
        # on the stress parameter

    def tearDown(self):
        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def testDefault(self):

        rules = []
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)
        chain = table.chains['INPUT']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(0, len(chain.rules))

        self.log.info("ready to slice")

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()
        print(table_.toSave())

        chains_ = ['INPUT', 'OUTPUT', 'FORWARD',]
        self.assertEqual(set(chains_), set(table_.chains.keys()))

    def testImplicit(self):

        rules = ["-A INPUT -i dummy0 -p tcp -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()
        print(table_.toSave())

        chains_ = ['INPUT', 'OUTPUT', 'FORWARD', 'INPUT_dummy0',]
        self.assertEqual(set(chains_), set(table_.chains.keys()))

        chain = table_.chains['INPUT']
        self.assertEqual(1, len(chain))
        self.assertEqual('dummy0', chain.rules[0].in_interface)
        self.assertEqual([], chain.rules[0].args)
        self.assertEqual('INPUT_dummy0', chain.rules[0].target)

        chain = table_.chains['INPUT_dummy0']
        self.assertEqual(1, len(chain))
        self.assertIsNone(chain.rules[0].in_interface)
        self.assertEqual(['-p', 'tcp',], chain.rules[0].args)

    def testExplicit(self):

        rules = ["-A INPUT -i dummy0 -p tcp -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        # generate rules suitable for two explicit interfaces

        slicer = Slicer(table,
                        onlyInterfaces=['dummy0', 'dummy1',],
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()
        print(table_.toSave())

        chains_ = ['INPUT', 'OUTPUT', 'FORWARD', 'INPUT_dummy0', 'INPUT_dummy1',]
        self.assertEqual(set(chains_), set(table_.chains.keys()))

        chain = table_.chains['INPUT']
        self.assertEqual(2, len(chain))

        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual([], rule.args)
        self.assertEqual('INPUT_dummy0', rule.target)

        rule = chain.rules[1]
        self.assertEqual('dummy1', rule.in_interface)
        self.assertEqual([], rule.args)
        self.assertEqual('INPUT_dummy1', rule.target)

        chain = table_.chains['INPUT_dummy0']

        self.assertEqual(1, len(chain))
        rule = chain.rules[0]
        self.assertIsNone(rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

        chain = table_.chains['INPUT_dummy1']

        self.assertEqual(0, len(chain))

    def testExplicitSingle(self):

        rules = ["-A INPUT -i dummy0 -p tcp -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        # generate rules suitable for a single interface

        slicer = Slicer(table,
                        onlyInterfaces=['dummy0',],
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()
        print(table_.toSave())

        chains_ = ['INPUT', 'OUTPUT', 'FORWARD', 'INPUT_dummy0',]
        self.assertEqual(set(chains_), set(table_.chains.keys()))

        chain = table_.chains['INPUT']
        self.assertEqual(1, len(chain))

        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual([], rule.args)
        self.assertEqual('INPUT_dummy0', rule.target)

        chain = table_.chains['INPUT_dummy0']

        self.assertEqual(1, len(chain))
        rule = chain.rules[0]
        self.assertIsNone(rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

    def testExplicitSingleInvalid(self):

        rules = ["-A INPUT -i dummy0 -p tcp -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        # generate rules suitable for a single interface

        slicer = Slicer(table,
                        onlyInterfaces=['dummy1',],
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()

        chain = table_.chains['INPUT']
        self.assertEqual(1, len(chain))
        rule = chain.rules[0]
        self.assertEqual('INPUT_dummy1', rule.target)
        chain = table_.chains['INPUT_dummy1']
        self.assertEqual(0, len(chain))

    def testNonOverlapping(self):

        rules = ["-A INPUT -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
                 "-A INPUT -i dummy1 -p tcp -m comment --comment 'rule 2' -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()
        print(table_.toSave())

        chains_ = ['INPUT', 'OUTPUT', 'FORWARD', 'INPUT_dummy0', 'INPUT_dummy1',]
        self.assertEqual(set(chains_), set(table_.chains.keys()))

        chain = table_.chains['INPUT']
        self.assertEqual(2, len(chain))

        chain = table_.chains['INPUT_dummy0']

        self.assertEqual(1, len(chain))
        rule = chain.rules[0]
        self.assertEqual('rule 1', rule.comment)

        chain = table_.chains['INPUT_dummy1']

        self.assertEqual(1, len(chain))
        rule = chain.rules[0]
        self.assertEqual('rule 2', rule.comment)

    def testOverlapping(self):

        rules = ["-A INPUT -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
                 "-A INPUT -i dummy1 -p tcp -m comment --comment 'rule 2' -j ACCEPT",
                 "-A INPUT -p tcp -m comment --comment 'rule 3' -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()
        print(table_.toSave())

        chains_ = ['INPUT', 'OUTPUT', 'FORWARD', 'INPUT_dummy0', 'INPUT_dummy1',]
        self.assertEqual(set(chains_), set(table_.chains.keys()))

        chain = table_.chains['INPUT']
        self.assertEqual(2, len(chain))

        chain = table_.chains['INPUT_dummy0']

        self.assertEqual(2, len(chain))
        rule = chain.rules[0]
        self.assertEqual('rule 1', rule.comment)
        rule = chain.rules[1]
        self.assertEqual('rule 3', rule.comment)

        chain = table_.chains['INPUT_dummy1']

        self.assertEqual(2, len(chain))
        rule = chain.rules[0]
        self.assertEqual('rule 2', rule.comment)
        rule = chain.rules[1]
        self.assertEqual('rule 3', rule.comment)

    def testPrefix(self):

        rules = ["-A INPUT -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
                 "-A INPUT -i eth0 -p tcp -m comment --comment 'rule 2' -j ACCEPT",
                 "-A INPUT -i dummy+ -p tcp -m comment --comment 'rule 3' -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))
        with self.assertRaises(ValueError):
            slicer.slice()
        # 'eth0' is not a valid interface

        slicer = Slicer(table,
                        strict=False,
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()
        # allow/ignore 'eth0'

        print(table_.toSave())

        chains_ = ['INPUT', 'OUTPUT', 'FORWARD', 'INPUT_dummy0', 'INPUT_dummy1',]
        self.assertEqual(set(chains_), set(table_.chains.keys()))

        chain = table_.chains['INPUT']
        self.assertEqual(2, len(chain))

        chain = table_.chains['INPUT_dummy0']

        self.assertEqual(2, len(chain))
        rule = chain.rules[0]
        self.assertEqual('rule 1', rule.comment)
        rule = chain.rules[1]
        self.assertEqual('rule 3', rule.comment)

        chain = table_.chains['INPUT_dummy1']

        self.assertEqual(1, len(chain))
        rule = chain.rules[0]
        self.assertEqual('rule 3', rule.comment)

    def testExclude(self):

        rules = ["-A INPUT -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
                 "-A INPUT -i eth0 -p tcp -m comment --comment 'rule 2' -j ACCEPT",
                 "-A INPUT -i !eth0 -p tcp -m comment --comment 'rule 3' -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        strict=True,
                        log=self.log.getChild("slice"))
        with self.assertRaises(ValueError):
            slicer.slice()
        # accept '!eth0' but not 'eth0'

        slicer = Slicer(table,
                        strict=False,
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()
        # accept '!eth0' as 'dummy0 dummy1'

        print(table_.toSave())

        chains_ = ['INPUT', 'OUTPUT', 'FORWARD', 'INPUT_dummy0', 'INPUT_dummy1',]
        self.assertEqual(set(chains_), set(table_.chains.keys()))

        chain = table_.chains['INPUT']
        self.assertEqual(2, len(chain))

        chain = table_.chains['INPUT_dummy0']

        self.assertEqual(2, len(chain))
        rule = chain.rules[0]
        self.assertEqual('rule 1', rule.comment)
        rule = chain.rules[1]
        self.assertEqual('rule 3', rule.comment)

        chain = table_.chains['INPUT_dummy1']

        self.assertEqual(1, len(chain))
        rule = chain.rules[0]
        self.assertEqual('rule 3', rule.comment)

    def testExcludePrefix(self):

        rules = ["-A INPUT -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
                 "-A INPUT -i eth0 -p tcp -m comment --comment 'rule 2' -j ACCEPT",
                 "-A INPUT -i !eth+ -p tcp -m comment --comment 'rule 3' -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))
        with self.assertRaises(ValueError):
            slicer.slice()
        slicer = Slicer(table,
                        strict=False,
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()
        print(table_.toSave())

        chains_ = ['INPUT', 'OUTPUT', 'FORWARD', 'INPUT_dummy0', 'INPUT_dummy1',]
        self.assertEqual(set(chains_), set(table_.chains.keys()))

        chain = table_.chains['INPUT']
        self.assertEqual(2, len(chain))

        chain = table_.chains['INPUT_dummy0']

        self.assertEqual(2, len(chain))
        rule = chain.rules[0]
        self.assertEqual('rule 1', rule.comment)
        rule = chain.rules[1]
        self.assertEqual('rule 3', rule.comment)

        chain = table_.chains['INPUT_dummy1']

        self.assertEqual(1, len(chain))
        rule = chain.rules[0]
        self.assertEqual('rule 3', rule.comment)

    def testNoInterfaces(self):

        rules = ["-A INPUT -p tcp -m comment --comment 'rule 1' -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)
        chain = table.chains['INPUT']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(1, len(chain.rules))

        self.log.info("ready to slice")

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()

        chain = table_.chains['INPUT_dummy0']

        self.assertEqual(1, len(chain))
        rule = chain.rules[0]
        self.assertEqual('rule 1', rule.comment)

        chain = table_.chains['INPUT_dummy1']

        self.assertEqual(1, len(chain))
        rule = chain.rules[0]
        self.assertEqual('rule 1', rule.comment)

    def testAllInterfaces(self):

        # dummy0, dummy1 are ports
        # dummy2, dummy3, dummy4 are links
        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'dummy2' : ['link',],
                   'dummy3' : ['link',],
                   'dummy4' : ['link',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)

        rules = ["-A INPUT -p tcp -m comment --comment 'rule 1' -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)
        chain = table.chains['INPUT']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(1, len(chain.rules))

        slicer = Slicer(table,
                        allInterfaces=['dummy0',],
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()

        self.assertEqual(set(['INPUT', 'OUTPUT', 'FORWARD', 'INPUT_dummy0',]),
                         set(table_.chains.keys()))

        slicer = Slicer(table,
                        allInterfaces=['dummy1',],
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()

        self.assertEqual(set(['INPUT', 'OUTPUT', 'FORWARD', 'INPUT_dummy1',]),
                         set(table_.chains.keys()))

        # pick a set of interfaces that is not native

        slicer = Slicer(table,
                        allInterfaces=['dummy3', 'dummy4',],
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()

        self.assertEqual(set(['INPUT', 'OUTPUT', 'FORWARD', 'INPUT_dummy3', 'INPUT_dummy4',]),
                         set(table_.chains.keys()))

class SliceVirtualTest(TcSaveTestUtils.IptablesTestMixin,
                       unittest.TestCase):

    def setUp(self):
        self.log = logger.getChild(self.id())

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        os.environ['TEST_VLANS_JSON'] = json.dumps({})
        os.environ['TEST_SVIS_JSON'] = json.dumps({})
        # default set of interfaces, may adjust this depending
        # on the stress parameter

    def tearDown(self):
        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def assertComments(self, ifMap, table):
        for chainName in table.chains.keys():
            if chainName.startswith('INPUT_'):
                chain = chainName[6:]
                if chain not in ifMap:
                    raise AssertionError("extra chain %s" % chainName)
        for ifName, comments in ifMap.items():
            tag = 'INPUT_' + ifName
            if tag not in table.chains:
                self.log.error("found chains %s", table.chains.keys())
                raise AssertionError("missing chain %s" % tag)
            chain = table.chains[tag]
            comments_ = [x.comment for x in chain.rules]
            self.assertEqual(comments, comments_)

    def assertVlans(self, ifMap, table):
        for chainName in table.chains.keys():
            if chainName.startswith('INPUT_'):
                chain = chainName[6:]
                if chain not in ifMap:
                    raise AssertionError("extra chain %s" % chainName)
        for ifName, vids in ifMap.items():
            tag = 'INPUT_' + ifName
            if tag not in table.chains:
                self.log.error("found chains %s", table.chains.keys())
                raise AssertionError("missing chain %s" % tag)
            chain = table.chains[tag]
            vids_ = []
            for rule in chain.rules:
                if 'vlan' not in rule.args:
                    vids_.append(None)
                else:
                    idx = rule.args.index('--vlan-tag')
                    vids_.append(int(rule.args[idx+1], 10))
            self.assertEqual(vids, vids_)

    def testPhysical(self):

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy1 -m comment --comment comment2 -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))
        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1',],
                     'dummy1' : ['comment2',],}
        self.assertComments(comments_, table_)

    def testBridge(self):

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i br0 -m comment --comment comment2 -j ACCEPT", ]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))

        # br0 not defined
        with self.assertRaises(ValueError):
            table_ = slicer.slice()

        # map br0 to a dummy0

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'br0' : ['bridge', 'dummy0',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        slicer.topo.update()

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1',
                                 'comment2',],}

        self.assertComments(comments_, table_)

        # map br0 to dummy1

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'br0' : ['bridge', 'dummy1',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        slicer.topo.update()

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1',],
                     'dummy1' : ['comment2',],}

        self.assertComments(comments_, table_)

        # map br0 to both interfaces

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'br0' : ['bridge', 'dummy0', 'dummy1',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        slicer.topo.update()

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1', 'comment2',],
                     'dummy1' : ['comment2',],}

        self.assertComments(comments_, table_)

    def testBridgeExtra(self):
        """Test a bridge that spans an extra interface."""

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i br0 -m comment --comment comment2 -j ACCEPT", ]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))

        # br0 not defined
        with self.assertRaises(ValueError):
            slicer.slice()

        # map br0 to an unsupported interface
        # ma1 is not a supported interface, not a proper port

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'ma1' : ['link',],
                   'br0' : ['bridge', 'dummy0', 'ma1',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        slicer.topo.update()

        with self.assertRaises(ValueError):
            slicer.slice()

        # add this interface manually

        slicer = Slicer(table,
                        allInterfaces=['dummy0', 'dummy1', 'ma1',],
                        log=self.log.getChild("slice"))

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1', 'comment2',],
                     'ma1' : ['comment2',],}

        self.assertComments(comments_, table_)

        slicer = Slicer(table,
                        onlyInterfaces=['dummy0', 'dummy1', 'ma1',],
                        log=self.log.getChild("slice"))

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1', 'comment2',],
                     'dummy1' : [],
                     'ma1' : ['comment2',],}

        self.assertComments(comments_, table_)

    def testVlan(self):
        """Test VLAN support."""

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i vlan100 -m comment --comment comment2 -j ACCEPT", ]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        strictVlan=True,
                        log=self.log.getChild("slice"))

        # vlan100 not defined
        with self.assertRaises(ValueError):
            slicer.slice()

        # vlan100 is untagged on dummy0
        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'br0' : ['bridge', 'dummy0',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        vlanMap = {100 : {'dummy0' : False,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)
        slicer.topo.update()

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1', 'comment2',],}
        vids_ = {'dummy0' : [None, None,],}

        self.assertComments(comments_, table_)
        self.assertVlans(vids_, table_)

        # vlan100 is now untagged on dummy0

        vlanMap = {100 : {'dummy0' : True,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)
        slicer.topo.update()

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1', 'comment2',],}
        vids_ = {'dummy0' : [None, 100,],}

        self.assertComments(comments_, table_)
        self.assertVlans(vids_, table_)

        # make sure the vlan rule is tagged
        chain = table_.chains['INPUT_dummy0']
        self.assertIn('vlan', chain.rules[1].args)

        # dummy0 is tagged, dummy1 is untagged

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'br0' : ['bridge', 'dummy0', 'dummy1',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        vlanMap = {100 : {'dummy0' : True,
                          'dummy1' : False,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)
        slicer.topo.update()

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1', 'comment2',],
                     'dummy1' : ['comment2',],}
        vids_ = {'dummy0' : [None, 100,],
                 'dummy1' : [None,],}

        self.assertComments(comments_, table_)
        self.assertVlans(vids_, table_)

        # dummy0 is untagged, dummy1 is tagged

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'br0' : ['bridge', 'dummy0', 'dummy1',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        vlanMap = {100 : {'dummy0' : False,
                          'dummy1' : True,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)
        slicer.topo.update()

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1', 'comment2',],
                     'dummy1' : ['comment2',],}
        vids_ = {'dummy0' : [None, None,],
                 'dummy1' : [100,],}

        self.assertComments(comments_, table_)
        self.assertVlans(vids_, table_)

    def testVlanImplicit(self):
        """Test with vlans and implicit rules."""

        # first rule does not specify an ingress port

        rules = ["-A INPUT -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i vlan100 -m comment --comment comment2 -j ACCEPT", ]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))

        # dummy0 is untagged, dummy1 is tagged

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'br0' : ['bridge', 'dummy0', 'dummy1',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        vlanMap = {100 : {'dummy0' : False,
                          'dummy1' : True,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)
        slicer.topo.update()

        table_ = slicer.slice()
        print(table_.toSave())

        # first rule applies to dummy0, dummy1, vlan100 -->
        # --> dummy0, dummy1 (untagged), dummy1 (tagged)

        # second rule applies to dummy0 (untagged), dummy1 (tagged)

        comments_ = {'dummy0' : ['comment1', 'comment2',],
                     'dummy1' : ['comment1', 'comment1', 'comment2',],}
        vids_ = {'dummy0' : [None, None,],
                 'dummy1' : [None, 100, 100,],}

        self.assertComments(comments_, table_)
        self.assertVlans(vids_, table_)

        # switch the tags around

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'br0' : ['bridge', 'dummy0', 'dummy1',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        vlanMap = {100 : {'dummy0' : True,
                          'dummy1' : False,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)
        slicer.topo.update()

        table_ = slicer.slice()
        print(table_.toSave())

        # first rule applies to only dummy0, dummy1, vlan100
        # but dummy0.100 is tagged so this is not an an overlap

        # second rule applies to dummy0 (tagged), dummy1 (untagged)

        comments_ = {'dummy0' : ['comment1', 'comment1', 'comment2',],
                     'dummy1' : ['comment1', 'comment2',],}
        vids_ = {'dummy0' : [None, 100, 100,],
                 'dummy1' : [None, None,],}
        self.assertComments(comments_, table_)
        self.assertVlans(vids_, table_)

        # now both vlans are tagged

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'br0' : ['bridge', 'dummy0', 'dummy1',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        vlanMap = {100 : {'dummy0' : True,
                          'dummy1' : True,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)
        slicer.topo.update()

        table_ = slicer.slice()
        print(table_.toSave())

        # first rule applies to only dummy0, dummy1, vlan100
        # but dummy0.100 is tagged so this is not an an overlap

        # second rule applies to dummy0 (tagged), dummy1 (untagged)

        comments_ = {'dummy0' : ['comment1', 'comment1', 'comment2',],
                     'dummy1' : ['comment1', 'comment1', 'comment2',],}
        vids_ = {'dummy0' : [None, 100, 100,],
                 'dummy1' : [None, 100, 100,],}
        self.assertComments(comments_, table_)
        self.assertVlans(vids_, table_)

        # no tags, handle duplicate rules

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'br0' : ['bridge', 'dummy0', 'dummy1',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        vlanMap = {100 : {'dummy0' : False,
                          'dummy1' : False,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)
        slicer.topo.update()

        table_ = slicer.slice()
        print(table_.toSave())

        # first rule applies to only dummy0, dummy1, vlan100
        # but dummy0.100 is tagged so this is not an an overlap

        # second rule applies to dummy0 (tagged), dummy1 (untagged)

        comments_ = {'dummy0' : ['comment1', 'comment2',],
                     'dummy1' : ['comment1', 'comment2',],}
        vids_ = {'dummy0' : [None, None,],
                 'dummy1' : [None, None,],}
        self.assertComments(comments_, table_)
        self.assertVlans(vids_, table_)

    def testVlanOnly(self):
        """Test support if there are only vlans."""

        rules = ["-A INPUT -i vlan100 -m comment --comment comment1 -j ACCEPT", ]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))

        # vlan100 not defined
        with self.assertRaises(ValueError):
            slicer.slice()

        # vlan100 is untagged on dummy0

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'br0' : ['bridge', 'dummy0',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        vlanMap = {100 : {'dummy0' : False,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)
        slicer.topo.update()

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1',],}
        vids_ = {'dummy0' : [None,],}

        self.assertComments(comments_, table_)
        self.assertVlans(vids_, table_)

        # vlan100 is tagged on dummy0

        vlanMap = {100 : {'dummy0' : True,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)
        slicer.topo.update()

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1',],}
        vids_ = {'dummy0' : [100,],}

        self.assertComments(comments_, table_)
        self.assertVlans(vids_, table_)

    def testVlanOverlap(self):
        """Test vlan matching with overlapping port memberships."""

        # vlan100 is untagged on dummy0
        # vlan101 is untagged on dummy0, tagged on dummy1
        # vlan102 is tagged on dummy1

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'br0' : ['bridge', 'dummy0',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        vlanMap = {100 : {'dummy0' : False,},
                   101 : {'dummy0' : False,
                          'dummy1' : True,},
                   102: {'dummy1' : True,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)

        rules = ["-A INPUT -i vlan100 -m comment --comment comment1 -j ACCEPT", ]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1',],}
        vids_ = {'dummy0' : [None,],}

        self.assertComments(comments_, table_)
        self.assertVlans(vids_, table_)

        # vlan101 should emit rules for both interfaces

        rules = ["-A INPUT -i vlan101 -m comment --comment comment1 -j ACCEPT", ]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1',],
                     'dummy1' : ['comment1',],}
        vids_ = {'dummy0' : [None,],
                 'dummy1' : [101,],}

        self.assertComments(comments_, table_)
        self.assertVlans(vids_, table_)

        # vlan102 should only emit rules for dummy1

        rules = ["-A INPUT -i vlan102 -m comment --comment comment1 -j ACCEPT", ]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy1' : ['comment1',],}
        vids_ = {'dummy1' : [102,],}

        self.assertComments(comments_, table_)
        self.assertVlans(vids_, table_)

    def testVlanExtra(self):
        """Handle extra vlans with no member ports."""

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i vlan100 -m comment --comment comment2 -j ACCEPT", ]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))

        # vlan100 is untagged on dummy0
        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'br0' : ['bridge', 'dummy0',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        vlanMap = {100 : {'dummy0' : False,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)
        slicer.topo.update()

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1', 'comment2',],}
        vids_ = {'dummy0' : [None, None,],}

        self.assertComments(comments_, table_)
        self.assertVlans(vids_, table_)

        # add an extra vlan with no front-panel ports

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i vlan100 -m comment --comment comment2 -j ACCEPT",
                 "-A INPUT -i vlan101 -m comment --comment comment2 -j ACCEPT",
        ]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        slicer = Slicer(table,
                        log=self.log.getChild("slice"))

        table_ = slicer.slice()
        print(table_.toSave())

        comments_ = {'dummy0' : ['comment1', 'comment2',],}
        vids_ = {'dummy0' : [None, None,],}

        self.assertComments(comments_, table_)
        self.assertVlans(vids_, table_)

class SliceTableTest(unittest.TestCase):
    """Test the 'SliceTable' data structure."""

    def setUp(self):
        self.log = logger.getChild(self.id())

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        os.environ['TEST_VLANS_JSON'] = json.dumps({})
        os.environ['TEST_SVIS_JSON'] = json.dumps({})
        # default set of interfaces, may adjust this depending
        # on the stress parameter

    def tearDown(self):
        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def testSimple(self):

        t = FilterTable({}, log=self.log.getChild("iptables"))
        t.chains['INPUT'] = t.chain_klass([], 'ACCEPT')
        t.chains['OUTPUT'] = t.chain_klass([], 'ACCEPT')

        t.chains['FORWARD'] = t.chain_klass([], 'ACCEPT')
        t.chains['FORWARD'].rules.append(t.rule_klass(['-i', 'dummy0',],
                                                      target='FORWARD_dummy0'))

        t.chains['FORWARD_dummy0'] = t.chain_klass([], 'RETURN')
        t.chains['FORWARD_dummy0'].rules.append(t.rule_klass(['-p', 'tcp',], target='ACCEPT'))

        t_ = SliceTable.fromSlice(t, log=self.log.getChild("slice"))

        self.assertEqual(2, len(t_.chains))
        self.assertEqual('ACCEPT', t_.policy)

        self.assertEqual(1, len(t_.chains['dummy0']))
        self.assertEqual(['-p', 'tcp',], t_.chains['dummy0'].rules[0].args)
        self.assertEqual('ACCEPT', t_.chains['dummy0'].rules[0].target)
        self.assertEqual('RETURN', t_.chains['dummy0'].policy)

        self.assertEqual(0, len(t_.chains['dummy1']))
        self.assertEqual('RETURN', t_.chains['dummy1'].policy)

        # restrict the interfaces

        t_ = SliceTable.fromSlice(t,
                                  allInterfaces=['dummy0'],
                                  log=self.log.getChild("slice"))

        self.assertEqual(1, len(t_.chains))
        self.assertEqual(1, len(t_.chains['dummy0']))

        t_ = SliceTable.fromSlice(t,
                                  onlyInterfaces=['dummy0'],
                                  log=self.log.getChild("slice"))

        self.assertEqual(1, len(t_.chains))
        self.assertEqual(1, len(t_.chains['dummy0']))

        t_ = SliceTable.fromSlice(t,
                                  onlyInterfaces=['dummy1'],
                                  log=self.log.getChild("slice"))

        self.assertEqual(1, len(t_.chains))
        self.assertEqual(0, len(t_.chains['dummy1']))

        # interfaces must match the front panel

        with self.assertRaises(ValueError):
            t_ = SliceTable.fromSlice(t,
                                      allInterfaces=['dummy3', 'dummy4',],
                                      log=self.log.getChild("slice"))

        with self.assertRaises(ValueError):
            t_ = SliceTable.fromSlice(t,
                                      onlyInterfaces=['dummy3', 'dummy4',],
                                      allInterfaces=['dummy5', 'dummy6'],
                                      log=self.log.getChild("slice"))

        # make sure onlyInterfaces is a subset of allInterfaces

        t_ = SliceTable.fromSlice(t,
                                  onlyInterfaces=['dummy3', 'dummy4',],
                                  allInterfaces=['dummy3', 'dummy4', 'dummy5',],
                                  log=self.log.getChild("slice"))
        self.assertEqual(2, len(t_.chains))
        self.assertEqual(0, len(t_.chains['dummy3']))
        self.assertEqual(0, len(t_.chains['dummy4']))

if __name__ == "__main__":
    unittest.main()
