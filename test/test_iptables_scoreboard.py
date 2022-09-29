"""test_iptables_scoreboard.py

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

from petunia.Scoreboard import Scoreboard

from petunia.Topology import (
    Topology,
)

import TcSaveTestUtils

class ScoreboardTestMixin(object):

    def assertScoreboard(self, scoreboard, rules,
                         onlyInterfaces=None, allInterfaces=None):

        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)
        sb = Scoreboard(table,
                        onlyInterfaces=onlyInterfaces,
                        allInterfaces=allInterfaces,
                        log=self.log.getChild("scoreboard"))
        table_ = sb.scoreboard()
        print(table_.toSave())

        rules_ = []
        for rule_ in table_.chains['INPUT'].rules:
            rules_.append(rule_.toSave(chain='INPUT'))

        if scoreboard != rules_:
            self.log.error("expected rules:")
            for rule in scoreboard:
                self.log.error("<<< %s", rule)
            self.log.error("actual rules:")
            for rule in rules_:
                self.log.error(">>> %s", rule)
            raise AssertionError("scoreboard mismatch")

class ScoreboardTest(ScoreboardTestMixin,
                     TcSaveTestUtils.IptablesTestMixin,
                     unittest.TestCase):

    def setUp(self):
        self.log = logger.getChild(self.id())

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'dummy2' : ['port',],}
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
        rules_ = []
        self.assertScoreboard(rules_, rules)

    def testSimpleNoOverlap(self):

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy1 -m comment --comment comment2 -j ACCEPT",]

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment2 -j ACCEPT",]

        self.assertScoreboard(rules_, rules)

    def testSimpleAlmostOverlap(self):

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy2 -m comment --comment comment2 -j ACCEPT",]

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy2 -m comment --comment comment2 -j ACCEPT",]

        self.assertScoreboard(rules_, rules)

        # interfaces may be re-ordered

        rules = ["-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy2 -m comment --comment comment2 -j ACCEPT",]

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy2 -m comment --comment comment2 -j ACCEPT",]

        self.assertScoreboard(rules_, rules)

    def testSimpleDuplicate(self):
        """A side-effect of scoreboarding is that duplicate rules are suppressed."""

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",]

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",]

        self.assertScoreboard(rules_, rules)

    def testSimpleDuplicate2(self):
        """Duplicate rules do not need to be adjacent."""

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",]

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",]

        self.assertScoreboard(rules_, rules)

    def testSimpleOverlap(self):

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy2 -m comment --comment comment1 -j ACCEPT",]

        rules_ = ["-A INPUT -m comment --comment comment1 -j ACCEPT",]

        self.assertScoreboard(rules_, rules)

        # emit interfaces in order

        rules = ["-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy2 -m comment --comment comment1 -j ACCEPT",]

        rules_ = ["-A INPUT -m comment --comment comment1 -j ACCEPT",]

        self.assertScoreboard(rules_, rules)

    def testSplitOverlap(self):
        """Test overlap boundaries."""

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy2 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy0 -m comment --comment comment2 -j ACCEPT",]

        rules_ = ["-A INPUT -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy0 -m comment --comment comment2 -j ACCEPT",]

        self.assertScoreboard(rules_, rules)

        rules = ["-A INPUT -i dummy0 -m comment --comment comment2 -j ACCEPT",
                 "-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy2 -m comment --comment comment1 -j ACCEPT",
        ]

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment2 -j ACCEPT",
                  "-A INPUT -m comment --comment comment1 -j ACCEPT",
        ]

    def testOverlapNarrow(self):
        """Verify that narrowing works."""

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy2 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy0 -m comment --comment comment2 -j ACCEPT",
                 "-A INPUT -i dummy1 -m comment --comment comment3 -j ACCEPT",
                 "-A INPUT -i dummy2 -m comment --comment comment4 -j ACCEPT",
        ]

        rules_ = ["-A INPUT -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy0 -m comment --comment comment2 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment3 -j ACCEPT",
                  "-A INPUT -i dummy2 -m comment --comment comment4 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

        # default is all interfaces

        rules_ = ["-A INPUT -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy0 -m comment --comment comment2 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment3 -j ACCEPT",
                  "-A INPUT -i dummy2 -m comment --comment comment4 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules,
                              allInterfaces=['dummy0', 'dummy1', 'dummy2',])

        # since dummy2 is still a port, we can't collapse rules that include it

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy0 -m comment --comment comment2 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment3 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules,
                              onlyInterfaces=['dummy0', 'dummy1',])

    def testOverlapNarrow2(self):
        """Verify that narrowing works."""

        # dummy2 is still a front-panel port, no collapsing

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy0 -m comment --comment comment2 -j ACCEPT",]

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy0 -m comment --comment comment2 -j ACCEPT",]

        self.assertScoreboard(rules_, rules)

        # restrict onlyInterfaces, still no collapsing possible

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy0 -m comment --comment comment2 -j ACCEPT",]

        self.assertScoreboard(rules_, rules,
                              onlyInterfaces=['dummy0', 'dummy1',])

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy0 -m comment --comment comment2 -j ACCEPT",]

        self.assertScoreboard(rules_, rules,
                              onlyInterfaces=['dummy0',])

        # restrict using allInterfaces (port demotion)

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy0 -m comment --comment comment2 -j ACCEPT",]

        self.assertScoreboard(rules_, rules,
                              allInterfaces=['dummy0', 'dummy1', 'dummy2'])

        # dummy2 is no longer a port, so collapsing is possible

        rules_ = ["-A INPUT -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy0 -m comment --comment comment2 -j ACCEPT",]

        self.assertScoreboard(rules_, rules,
                              allInterfaces=['dummy0', 'dummy1',])

    def testWildcard(self):
        """Test interface wildcarding."""

        rules = ["-A INPUT -i dummy+ -m comment --comment comment1 -j ACCEPT",
        ]

        rules_ = ["-A INPUT -m comment --comment comment1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

    def testOnlyAll(self):
        """Test interaction of onlyInterfaces and allInterfaces."""

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy1 -m comment --comment comment2 -j ACCEPT",
                 "-A INPUT -i dummy2 -m comment --comment comment3 -j ACCEPT",

                 "-A INPUT -i dummy0 -m comment --comment commentN -j ACCEPT",
                 "-A INPUT -i dummy1 -m comment --comment commentN -j ACCEPT",
                 "-A INPUT -i dummy2 -m comment --comment commentN -j ACCEPT",
        ]

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment2 -j ACCEPT",
                  "-A INPUT -i dummy2 -m comment --comment comment3 -j ACCEPT",
                  "-A INPUT -m comment --comment commentN -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules,
                              allInterfaces=['dummy0', 'dummy1', 'dummy2',])

        # dummy2 is used for overlap calculation, but only dummy0, dummy1
        # rules are emitted...
        # the any-interface rules are not permitted here since that
        # implies dummy2.

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment2 -j ACCEPT",
                  "-A INPUT -i dummy0 -m comment --comment commentN -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment commentN -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules,
                              onlyInterfaces=['dummy0', 'dummy1',],
                              allInterfaces=['dummy0', 'dummy1', 'dummy2',])

class VlanScoreboardTest(ScoreboardTestMixin,
                         TcSaveTestUtils.IptablesTestMixin,
                         unittest.TestCase):

    def setUp(self):
        self.log = logger.getChild(self.id())

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'dummy2' : ['port',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)

        # vlan100 --> dummy0 (untagged), dummy1 (untagged)
        # vlan101 --> dummy1 (untagged), dummy2 (tagged)
        # vlan102 --> dummy1 (tagged)

        vlanMap = {100 : {'dummy0' : False,
                          'dummy1' : True,},
                   101 : {'dummy1' : False,
                          'dummy2' : True,},
                   102 : {'dummy1' : True,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)

        os.environ['TEST_SVIS_JSON'] = json.dumps({})
        # default set of interfaces, may adjust this depending
        # on the stress parameter

    def tearDown(self):
        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def testDefault(self):

        rules = []
        rules_ = []
        self.assertScoreboard(rules_, rules)

    def testSingle(self):
        """Test single rules."""

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
        ]
        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

        rules = ["-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
        ]
        rules_ = ["-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

        rules = ["-A INPUT -i dummy2 -m comment --comment comment1 -j ACCEPT",
        ]
        rules_ = ["-A INPUT -i dummy2 -m comment --comment comment1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

    def testSingleVlan(self):
        """Test single rules."""

        rules = ["-A INPUT -i vlan100 -m comment --comment comment1 -j ACCEPT",
        ]

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -m vlan --vlan-tag 100 -m comment --comment comment1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

        rules = ["-A INPUT -i vlan101 -m comment --comment comment1 -j ACCEPT",
        ]
        rules_ = ["-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -m vlan --vlan-tag 101 -m comment --comment comment1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

        rules = ["-A INPUT -i vlan102 -m comment --comment comment1 -j ACCEPT",
        ]

        rules_ = ["-A INPUT -m vlan --vlan-tag 102 -m comment --comment comment1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

    def testSimpleNoOverlap(self):

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy1 -m comment --comment comment2 -j ACCEPT",
                 "-A INPUT -i vlan100 -m comment --comment comment3 -j ACCEPT",
                 "-A INPUT -i vlan101 -m comment --comment comment4 -j ACCEPT",]

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment2 -j ACCEPT",

                  "-A INPUT -i dummy0 -m comment --comment comment3 -j ACCEPT",
                  "-A INPUT -m vlan --vlan-tag 100 -m comment --comment comment3 -j ACCEPT",

                  "-A INPUT -i dummy1 -m comment --comment comment4 -j ACCEPT",
                  "-A INPUT -m vlan --vlan-tag 101 -m comment --comment comment4 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

    def testOverlapUntagged(self):
        """Test overlap with untagged ports."""

        # dummy0 overlaps with vlan100 (dummy0 untagged)

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i vlan100 -m comment --comment comment1 -j ACCEPT",
        ]

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -m vlan --vlan-tag 100 -m comment --comment comment1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

        # dummy1 overlaps with vlan101 (dummy1 untagged)

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i vlan100 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i vlan101 -m comment --comment comment1 -j ACCEPT",
        ]

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -m vlan --vlan-tag 100 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -m vlan --vlan-tag 101 -m comment --comment comment1 -j ACCEPT",
        ]
        self.assertScoreboard(rules_, rules)

        # widen the rule to include dummy2
        # the untagged rule is collapsed, but not the tagged rule

        rules = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i dummy2 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i vlan100 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i vlan101 -m comment --comment comment1 -j ACCEPT",
        ]

        rules_ = ["-A INPUT -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -m vlan --vlan-tag 100 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -m vlan --vlan-tag 101 -m comment --comment comment1 -j ACCEPT",
        ]
        self.assertScoreboard(rules_, rules)

    def testOverlapTagged(self):
        """Collapse vlan tags."""

        rules = ["-A INPUT -i vlan100 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i vlan101 -m comment --comment comment1 -j ACCEPT",
        ]

        # matches all vlan tags

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -m vlan --vlan-tag 100 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -m vlan --vlan-tag 101 -m comment --comment comment1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

        rules = ["-A INPUT -i vlan100 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i vlan101 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i vlan102 -m comment --comment comment1 -j ACCEPT",
        ]

        # matches all vlan tags

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -m vlan --vlan-tag any -m comment --comment comment1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

class VlanTagOverlapTest(ScoreboardTestMixin,
                         TcSaveTestUtils.IptablesTestMixin,
                         unittest.TestCase):

    def setUp(self):
        self.log = logger.getChild(self.id())

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'dummy2' : ['port',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)

        # vlan100 --> dummy0 (untagged), dummy1 (untagged)
        # vlan101 --> dummy1 (untagged), dummy2 (tagged)
        # vlan102 --> dummy0 (tagged), dummy2 (tagged)

        # all vlans together cover all interfaces (both tagged and untagged)

        vlanMap = {100 : {'dummy0' : False,
                          'dummy1' : True,},
                   101 : {'dummy1' : False,
                          'dummy2' : True,},
                   102 : {'dummy2' : False,
                          'dummy0' : True,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)

        os.environ['TEST_SVIS_JSON'] = json.dumps({})
        # default set of interfaces, may adjust this depending
        # on the stress parameter

    def tearDown(self):
        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def testNoOverlap(self):

        rules = ["-A INPUT -i vlan100 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i vlan101 -m comment --comment comment1 -j ACCEPT",
        ]

        rules_ = ["-A INPUT -i dummy0 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -i dummy1 -m comment --comment comment1 -j ACCEPT",

                  "-A INPUT -m vlan --vlan-tag 100 -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -m vlan --vlan-tag 101 -m comment --comment comment1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

    def testOverlap(self):

        rules = ["-A INPUT -i vlan100 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i vlan101 -m comment --comment comment1 -j ACCEPT",
                 "-A INPUT -i vlan102 -m comment --comment comment1 -j ACCEPT",
        ]

        # all ports are covered as untagged
        # all ports are covered as tagged
        # but collapsing across vids is not supported

        rules_ = ["-A INPUT -m comment --comment comment1 -j ACCEPT",

                  "-A INPUT -m vlan --vlan-tag any -m comment --comment comment1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

    def testWildcard(self):
        """Test interface wildcarding."""

        rules = ["-A INPUT -i vlan+ -m comment --comment comment1 -j ACCEPT",
        ]

        rules_ = ["-A INPUT -m comment --comment comment1 -j ACCEPT",
                  "-A INPUT -m vlan --vlan-tag any -m comment --comment comment1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

if __name__ == "__main__":
    unittest.main()
