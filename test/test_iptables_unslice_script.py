"""test_iptables_unslice_script.py

Verify that iptables-unslice works.
"""

import os, sys

import unittest

import path_config
import subprocess
import json
import logging

from TcSaveTestUtils import ScriptTestMixin

logger = None
def setUpModule():
    global logger
    logging.basicConfig()
    logger = logging.getLogger("unittest")

class UnsliceTestMixin(object):

    def saveRules(self, p, dummy0rules, dummy1rules, dummy2rules):

        with open(p, 'wt') as fd:
            fd.write("*filter\n")
            fd.write(":INPUT ACCEPT [0:0]\n")
            fd.write(":OUTPUT ACCEPT [0:0]\n")
            fd.write(":FORWARD ACCEPT [0:0]\n")
            fd.write(":FORWARD_dummy0 - [0:0]\n")
            fd.write(":FORWARD_dummy1 - [0:0]\n")
            fd.write(":FORWARD_dummy2 - [0:0]\n")

            fd.write("-A FORWARD -i dummy0 -j FORWARD_dummy0\n")
            fd.write("-A FORWARD -i dummy1 -j FORWARD_dummy1\n")
            fd.write("-A FORWARD -i dummy2 -j FORWARD_dummy2\n")

            for rule in dummy0rules:
                fd.write("-A FORWARD_dummy0 " + rule + "\n")

            for rule in dummy1rules:
                fd.write("-A FORWARD_dummy1 " + rule + "\n")

            for rule in dummy2rules:
                fd.write("-A FORWARD_dummy2 " + rule + "\n")

            fd.write("COMMIT\n")

    def assertSavedRules(self, rules, p):

        with open(p, 'rt') as fd:
            buf = fd.read()

        lines = buf.splitlines(False)
        p = lines.index("*filter")
        q = lines.index("COMMIT", p)
        lines = lines[p+1:q]
        lines = [x for x in lines if not x.startswith(':')]

        if rules != lines:
            self.log.error("expected rules:")
            for line in rules:
                self.log.error("<<< %s", line)
            self.log.error("actual rules:")
            for line in lines:
                self.log.error(">>> %s", line)
            raise AssertionError("saved rule mismatch")

    def assertUnslice(self,
                      unslicedRules,
                      dummy0rules, dummy1rules, dummy2rules,
                      opts=[], interfaces=[]):

        src = os.path.join(self.workdir, 'iptables-slice')
        dst = os.path.join(self.workdir, 'iptables-unslice')

        self.saveRules(src, dummy0rules, dummy1rules, dummy2rules)

        if interfaces:
            cmd = (['iptables-unslice',]
                   + list(opts)
                   + [src, dst,]
                   + ['FORWARD',]
                   + list(interfaces))
        else:
            cmd = ['iptables-unslice',] + list(opts) + [src, dst,]
        subprocess.check_call(cmd)
        self.assertSavedRules(unslicedRules, dst)

class UnsliceTest(UnsliceTestMixin,
                  ScriptTestMixin,
                  unittest.TestCase):

    def setUp(self):
        self.setUpWorkdir()

        if not path_config.isBrazil():
            self.setUpScripts()

        self.log = logger.getChild(self.id())

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

        cmd = ('iptables-unslice',)
        with self.assertRaises(subprocess.CalledProcessError) as ex:
            out = subprocess.check_output(cmd,
                                          universal_newlines=True,
                                          stderr=subprocess.STDOUT)
        sys.stderr.write(ex.exception.output)
        self.assertIn("Usage", ex.exception.output)

    def testEmptyNoMerge(self):
        """Verify basic functionality of an sliced filter table."""

        rules0 = []
        rules1 = []
        rules2 = []

        rules_ = [
            "-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
            "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",
            "-A FORWARD -i dummy2 -j SKIP --skip-rules 2",

            "-A FORWARD -j SKIP --skip-rules 2",
            "-A FORWARD -j SKIP --skip-rules 1",
            "-A FORWARD -j SKIP --skip-rules 0",
        ]

        self.assertUnslice(rules_,
                           rules0, rules1, rules2,
                           ['--no-merge',])

    def testEmptyMerge(self):
        """Merge empty rule sets."""

        rules0 = []
        rules1 = []
        rules2 = []

        # in all cases the three chains get merged by 'exact'

        rules_ = [
            "-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
            "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",
            "-A FORWARD -i dummy2 -j SKIP --skip-rules 0",

            "-A FORWARD -j SKIP --skip-rules 0",
        ]

        # test different strategies

        self.assertUnslice(rules_, rules0, rules1, rules2,
                           ['--merge', 'exact',])
        self.assertUnslice(rules_, rules0, rules1, rules2,
                           ['--merge', 'suffix',])
        self.assertUnslice(rules_, rules0, rules1, rules2,
                           ['--merge', 'prefix',])
        self.assertUnslice(rules_, rules0, rules1, rules2,
                           ['--merge', 'all',])
        self.assertUnslice(rules_, rules0, rules1, rules2,
                           ['--merge', 'default',])
        self.assertUnslice(rules_, rules0, rules1, rules2,
                           ['--merge',])

    def testMerge(self):
        """Merge empty rule sets."""

        rules0 = [
            "-p tcp -s 10.0.0.1 -j ACCEPT",
            "-p tcp -s 10.0.0.2 -j ACCEPT",
            "-p tcp -s 10.0.0.3 -j ACCEPT",
        ]
        rules1 = [
            "-p tcp -s 10.0.0.1 -j ACCEPT",
            "-p tcp -s 10.0.0.2 -j ACCEPT",
            "-p tcp -s 10.0.0.3 -j ACCEPT",
            "-p tcp -s 10.0.0.4 -j ACCEPT",
            "-p tcp -s 10.0.0.5 -j ACCEPT",
        ]
        rules2 = [
            "-p tcp -s 10.0.0.3 -j ACCEPT",
            "-p tcp -s 10.0.0.4 -j ACCEPT",
            "-p tcp -s 10.0.0.5 -j ACCEPT",
        ]

        rules_ = [
            "-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
            "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",
            "-A FORWARD -i dummy2 -j SKIP --skip-rules 2",

            # dummy0,dummy1
            "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",
            "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",

            # dummy0,dummy1,dummy2
            "-A FORWARD -p tcp -s 10.0.0.3 -j ACCEPT",

            "-A FORWARD -i dummy0 -j SKIP --skip-rules 2",

            # dummy1,dummy2
            "-A FORWARD -p tcp -s 10.0.0.4 -j ACCEPT",
            "-A FORWARD -p tcp -s 10.0.0.5 -j ACCEPT",

            "-A FORWARD -j SKIP --skip-rules 0",
        ]

        # test different strategies

        self.assertUnslice(rules_, rules0, rules1, rules2,
                           ['--merge',])

    def testMergeSubset(self):
        """Verify we can control which interfaces get merged."""

        rules0 = [
            "-p tcp -s 10.0.0.1 -j ACCEPT",
            "-p tcp -s 10.0.0.2 -j ACCEPT",
            "-p tcp -s 10.0.0.3 -j ACCEPT",
        ]
        rules1 = [
            "-p tcp -s 10.0.0.1 -j ACCEPT",
            "-p tcp -s 10.0.0.2 -j ACCEPT",
            "-p tcp -s 10.0.0.3 -j ACCEPT",
        ]
        rules2 = [
            "-p tcp -s 10.0.0.1 -j ACCEPT",
            "-p tcp -s 10.0.0.2 -j ACCEPT",
            "-p tcp -s 10.0.0.3 -j ACCEPT",
        ]

        rules_ = [
            "-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
            "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",
            "-A FORWARD -i dummy2 -j SKIP --skip-rules 0",

            # dummy0,dummy1,dummy2
            "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",
            "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",
            "-A FORWARD -p tcp -s 10.0.0.3 -j ACCEPT",

            "-A FORWARD -j SKIP --skip-rules 0",
        ]

        # default, merge all interfaces

        self.assertUnslice(rules_, rules0, rules1, rules2,
                           opts=['--merge',])

        # merge by subset

        self.assertUnslice(rules_, rules0, rules1, rules2,
                           opts=['--merge',],
                           interfaces=['dummy+',])

        # restrict to a single interface

        rules_ = [
            "-A FORWARD -i dummy1 -j SKIP --skip-rules 0",

            # dummy1
            "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",
            "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",
            "-A FORWARD -p tcp -s 10.0.0.3 -j ACCEPT",

            "-A FORWARD -j SKIP --skip-rules 0",
        ]

        # merge by subset

        self.assertUnslice(rules_, rules0, rules1, rules2,
                           opts=['--merge',],
                           interfaces=['dummy1',])

class BridgeUnsliceTest(UnsliceTestMixin,
                        ScriptTestMixin,
                        unittest.TestCase):

    def setUp(self):
        self.setUpWorkdir()

        if not path_config.isBrazil():
            self.setUpScripts()

        self.log = logger.getChild(self.id())

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'dummy2' : ['link',],
                   'br0' : ['bridge', 'dummy0', 'dummy1', 'dummy2',],}
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

    def testPort(self):

        rules0 = [
            "-p tcp -s 10.0.0.1 -j ACCEPT",
            "-p tcp -s 10.0.0.2 -j ACCEPT",
            "-p tcp -s 10.0.0.3 -j ACCEPT",
        ]
        rules1 = [
            "-p tcp -s 10.0.0.1 -j ACCEPT",
            "-p tcp -s 10.0.0.2 -j ACCEPT",
            "-p tcp -s 10.0.0.3 -j ACCEPT",
        ]
        rules2 = [
            "-p tcp -s 10.0.0.1 -j ACCEPT",
            "-p tcp -s 10.0.0.2 -j ACCEPT",
            "-p tcp -s 10.0.0.3 -j ACCEPT",
        ]

        rules_ = [
            "-A FORWARD -i dummy0 -j SKIP --skip-rules 1",
            "-A FORWARD -i dummy1 -j SKIP --skip-rules 0",

            # dummy0,dummy1
            "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",
            "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",
            "-A FORWARD -p tcp -s 10.0.0.3 -j ACCEPT",

            "-A FORWARD -j SKIP --skip-rules 0",
        ]

        # dummy2 is not a front panel port

        with self.assertRaises(subprocess.CalledProcessError):
            self.assertUnslice(rules_, rules0, rules1, rules2,
                               opts=['--merge',])

        # specify the front panel ports

        self.assertUnslice(rules_, rules0, rules1, rules2,
                           opts=['--merge', 'default',],
                           interfaces=['dummy0', 'dummy1',])

        # mix and match

        rules_ = [
            "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",
            "-A FORWARD -i dummy2 -j SKIP --skip-rules 0",

            # dummy1,dummy2
            "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",
            "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",
            "-A FORWARD -p tcp -s 10.0.0.3 -j ACCEPT",

            "-A FORWARD -j SKIP --skip-rules 0",
        ]

        self.assertUnslice(rules_, rules0, rules1, rules2,
                           opts=['--merge', 'default',],
                           interfaces=['dummy1', 'dummy2',])

    def testBridge(self):
        """Test bridge ports."""

        # I'm too lazy to refactor this so let's re-arrange
        # the three dummy ports

        linkMap = {'dummy0' : ['port',],                        # front-panel
                   'dummy1' : ['link',],                        # not front-panel
                   'dummy2' : ['bridge', 'dummy0', 'dummy1'],}  # aggregate
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        os.environ['TEST_VLANS_JSON'] = json.dumps({})
        os.environ['TEST_SVIS_JSON'] = json.dumps({})

        rules0 = []
        rules1 = []
        rules2 = [
            "-p tcp -s 10.0.0.1 -j ACCEPT",
            "-p tcp -s 10.0.0.2 -j ACCEPT",
            "-p tcp -s 10.0.0.3 -j ACCEPT",
        ]

        rules_ = [
            "-A FORWARD -i dummy0 -j SKIP --skip-rules 1",
            "-A FORWARD -i dummy1 -j SKIP --skip-rules 0",

            # dummy0,dummy1 (br0)
            "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",
            "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",
            "-A FORWARD -p tcp -s 10.0.0.3 -j ACCEPT",

            "-A FORWARD -j SKIP --skip-rules 0",
        ]

        # This is not valid for unslicing since br0 should have
        # been broken out during slicing

        with self.assertRaises(subprocess.CalledProcessError):
            self.assertUnslice(rules_, rules0, rules1, rules2,
                               opts=['--merge', 'default',])

if __name__ == "__main__":
    unittest.main()
