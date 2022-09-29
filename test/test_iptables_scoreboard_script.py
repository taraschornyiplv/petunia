"""test_iptables_scoreboard_script.py

Test the scoreboard script.
"""

import os, sys

import unittest
import logging
import path_config
import subprocess
import json

import TcSaveTestUtils
from TcSaveTestUtils import (
    ScriptTestMixin,
    isDut,
)

global logger

def setUpModule():
    global logger

    if TcSaveTestUtils.isDut():
        TcSaveTestUtils.setUpModule()
        logger = TcSaveTestUtils.logger
    else:
        logging.basicConfig()
        logger = logging.getLogger("unittest")
        logger.setLevel(logging.DEBUG)

def tearDownModule():

    if TcSaveTestUtils.isDut():
        TcSaveTestUtils.tearDownModule()

class ScoreboardTestMixin(object):

    def saveRules(self, p, rules):

        with open(p, 'wt') as fd:
            fd.write("*filter\n")
            fd.write(":INPUT ACCEPT [0:0]\n")
            fd.write(":OUTPUT ACCEPT [0:0]\n")
            fd.write(":FORWARD ACCEPT [0:0]\n")

            for rule in rules:
                fd.write("-A FORWARD " + rule + "\n")

            fd.write("COMMIT\n")

    def assertSavedRules(self, rules, p):

        with open(p, 'rt') as fd:
            buf = fd.read()

        lines = buf.splitlines(False)
        p = lines.index("*filter")
        q = lines.index("COMMIT", p)
        lines = lines[p+1:q]
        lines = [x for x in lines if not x.startswith(':')]
        lines = [x[11:] for x in lines if x.startswith('-A FORWARD')]

        if rules != lines:
            self.log.error("expected rules:")
            for line in rules:
                self.log.error("<<< %s", line)
            self.log.error("actual rules:")
            for line in lines:
                self.log.error(">>> %s", line)
            raise AssertionError("saved rule mismatch")

    def assertScoreboard(self, scoreboardRules, rules,
                         opts=[], interfaces=[]):

        src = os.path.join(self.workdir, 'iptables-unroll')
        dst = os.path.join(self.workdir, 'iptables-scoreboard')

        self.saveRules(src, rules)

        cmd = (['iptables-scoreboard',]
               + list(opts)
               + [src, dst,]
               + ['FORWARD',]
               + list(interfaces))
        subprocess.check_call(cmd)
        self.assertSavedRules(scoreboardRules, dst)

class ScoreboardTest(ScoreboardTestMixin,
                     ScriptTestMixin,
                     unittest.TestCase):

    def setUp(self):
        self.setUpWorkdir()

        self.log = logger.getChild(self.id())

        if not path_config.isBrazil():
            self.setUpScripts()

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'dummy2' : ['port',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        os.environ['TEST_VLANS_JSON'] = json.dumps({})
        os.environ['TEST_SVIS_JSON'] = json.dumps({})

    def tearDown(self):
        self.tearDownWorkdir()

        if not path_config.isBrazil():
            self.tearDownScripts()

        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def testDefault(self):

        cmd = ('iptables-scoreboard',)
        with self.assertRaises(subprocess.CalledProcessError) as ex:
            out = subprocess.check_output(cmd,
                                          universal_newlines=True,
                                          stderr=subprocess.STDOUT)
        sys.stderr.write(ex.exception.output)
        self.assertIn("Usage", ex.exception.output)

    def testEmpty(self):

        rules = []
        rules_ = []
        self.assertScoreboard(rules_, rules)

    def testSimple(self):

        rules = ["-i dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-i dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                  "-i dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

    def testOverlap(self):

        rules = ["-i dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i dummy2 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

    def testPattern(self):

        rules = ["-i dummy+ -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

class BridgeScoreboardTest(ScoreboardTestMixin,
                           ScriptTestMixin,
                           unittest.TestCase):

    def setUp(self):
        self.setUpWorkdir()

        self.log = logger.getChild(self.id())

        if not path_config.isBrazil():
            self.setUpScripts()

        linkMap = {'dummy0' : ['link',],
                   'swp1' : ['port',],
                   'eth0' : ['port',],
                   'br0' : ['bridge', 'dummy0', 'eth0', 'swp1',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        os.environ['TEST_VLANS_JSON'] = json.dumps({})
        os.environ['TEST_SVIS_JSON'] = json.dumps({})

    def tearDown(self):
        self.tearDownWorkdir()

        if not path_config.isBrazil():
            self.tearDownScripts()

        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def testEmpty(self):

        rules = []
        rules_ = []
        self.assertScoreboard(rules_, rules)

    def testDummy(self):

        rules = ["-i dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        # dummy0 is not a front-panel port, no other valid interface rules

        with self.assertRaises(subprocess.CalledProcessError):
            self.assertScoreboard(rules_, rules)

        # now it is

        self.assertScoreboard(rules_, rules,
                              interfaces=['dummy+'])

    def testSwp(self):

        # (implicit) eth0 is demoted to a link

        rules = ["-i swp1 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules,
                              interfaces=['swp+',])

        # still ignore other front-panel ports

        rules = ["-i swp1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i eth0 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules,
                              interfaces=['swp+',])

        # eth0 is still implicit, include a non-front-panel port

        rules = ["-i swp1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        # cannot collapse since (implicit) eth0 is not included

        rules_ = ["-i swp1 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        # ignore the implicit front-panel port

        rules = ["-i swp1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        # able to collapse

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules,
                              interfaces=['swp+',])

        # now include eth0 with an overlapping rule

        rules = ["-i swp1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i eth0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

    def testBridge(self):

        rules = ["-i br0 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        # includes eth0, swp1, but excludes dummy0

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)
        self.assertScoreboard(rules_, rules, interfaces=['swp+',])

        # overlapping rule on one of br0's members

        rules = ["-i br0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i swp1 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        # includes eth0, swp1, but excludes dummy0

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

class VlanScoreboardTest(ScoreboardTestMixin,
                         ScriptTestMixin,
                         unittest.TestCase):

    def setUp(self):
        self.setUpWorkdir()

        self.log = logger.getChild(self.id())

        if not path_config.isBrazil():
            self.setUpScripts()

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'dummy2' : ['port',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        vlanMap = {100 : {'dummy0' : False,
                          'dummy1' : True,},
                   101 : {'dummy1' : False,
                          'dummy2' : True,},
                   102 : {'dummy2' : False,
                          'dummy0' : True,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)
        os.environ['TEST_SVIS_JSON'] = json.dumps({})

    def tearDown(self):
        self.tearDownWorkdir()

        if not path_config.isBrazil():
            self.tearDownScripts()

        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def testDefault(self):

        cmd = ('iptables-scoreboard',)
        with self.assertRaises(subprocess.CalledProcessError) as ex:
            out = subprocess.check_output(cmd,
                                          universal_newlines=True,
                                          stderr=subprocess.STDOUT)
        sys.stderr.write(ex.exception.output)
        self.assertIn("Usage", ex.exception.output)

    def testEmpty(self):

        rules = []
        rules_ = []
        self.assertScoreboard(rules_, rules)

    def testSimple(self):

        rules = ["-i vlan100 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-i dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                  "-m vlan --vlan-tag 100 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

        rules = ["-i vlan100 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i vlan101 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-i dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                  "-i dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                  "-m vlan --vlan-tag 100 -p tcp -s 10.0.0.1 -j ACCEPT",
                  "-m vlan --vlan-tag 101 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

    def testCollapse(self):

        rules = ["-i vlan100 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i vlan101 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i vlan102 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
                  "-m vlan --vlan-tag any -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

class VlanLinkScoreboardTest(ScoreboardTestMixin,
                             ScriptTestMixin,
                             unittest.TestCase):

    def setUp(self):
        self.setUpWorkdir()

        self.log = logger.getChild(self.id())

        if not path_config.isBrazil():
            self.setUpScripts()

        linkMap = {'eth0' : ['port',],
                   'swp1' : ['port',],
                   'dummy0' : ['link',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        vlanMap = {100 : {'eth0' : False,
                          'swp1' : False,
                          'dummy0' : False,},
                   101 : {'eth0' : True,
                          'swp1' : True,
                          'dummy0' : True,},}
        os.environ['TEST_VLANS_JSON'] = json.dumps(vlanMap)
        os.environ['TEST_SVIS_JSON'] = json.dumps({})

    def tearDown(self):
        self.tearDownWorkdir()

        if not path_config.isBrazil():
            self.tearDownScripts()

        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def testEmpty(self):

        rules = []
        rules_ = []
        self.assertScoreboard(rules_, rules)

    def testUntagged(self):

        rules = ["-i vlan100 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

        # extra rule on dummy0 should be ignored

        rules = ["-i vlan100 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i dummy0 -p tcp -s 10.0.0.2 -j ACCEPT",
        ]

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

        # overlapping rule on swp1 should be collapsed

        rules = ["-i vlan100 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i swp1 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)
        self.assertScoreboard(rules_, rules, interfaces=['swp+',])

        # ignore eth1

        rules = ["-i vlan100 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i eth1 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)
        self.assertScoreboard(rules_, rules, interfaces=['swp+',])

        # ignore eth0 even if non-overlapping

        rules = ["-i vlan100 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i eth0 -p tcp -s 10.0.0.2 -j ACCEPT",
        ]

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules, interfaces=['swp+',])

        rules_ = ["-p tcp -s 10.0.0.1 -j ACCEPT",
                  "-i eth0 -p tcp -s 10.0.0.2 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

    def testTagged(self):

        rules = ["-i vlan101 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-m vlan --vlan-tag any -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

        # ignore dummy0

        rules = ["-i vlan101 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i dummy0 -p tcp -s 10.0.0.2 -j ACCEPT",
        ]

        rules_ = ["-m vlan --vlan-tag any -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules)

        # ignore eth1

        rules = ["-i vlan101 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-i eth0 -p tcp -s 10.0.0.2 -j ACCEPT",
        ]

        rules_ = ["-m vlan --vlan-tag any -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        self.assertScoreboard(rules_, rules, interfaces=['swp+',])

if __name__ == "__main__":
    unittest.main()
