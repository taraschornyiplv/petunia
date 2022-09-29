"""test_iptables_slice_script.py

Test the slicing script.
"""

import os, sys

import unittest

import path_config
import subprocess
import json

import TcSaveTestUtils
from TcSaveTestUtils import (
    ScriptTestMixin,
    isDut,
)

def setUpModule():

    if TcSaveTestUtils.isDut():
        TcSaveTestUtils.setUpModule()

def tearDownModule():

    if TcSaveTestUtils.isDut():
        TcSaveTestUtils.tearDownModule()

class SliceTestMixin(object):

    def saveRules(self, p, rules, otherChains=[]):

        with open(p, 'wt') as fd:
            fd.write("*filter\n")
            fd.write(":INPUT ACCEPT [0:0]\n")
            fd.write(":OUTPUT ACCEPT [0:0]\n")
            fd.write(":FORWARD ACCEPT [0:0]\n")
            for chain in otherChains:
                fd.write(":%s - [0:0]\n" % chain)
            for rule in rules:
                fd.write(rule + "\n")
            fd.write("COMMIT\n")

    def assertSavedRules(self, rules, p):

        with open(p, 'rt') as fd:
            buf = fd.read()

        lines = buf.splitlines(False)
        p = lines.index("*filter")
        q = lines.index("COMMIT", p)
        lines = lines[p+1:q]
        lines = [x for x in lines if not x.startswith(':')]
        self.assertEqual(rules, lines)

class SliceTest(SliceTestMixin,
                ScriptTestMixin,
                unittest.TestCase):

    def setUp(self):
        self.setUpWorkdir()

        if not path_config.isBrazil():
            self.setUpScripts()

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],}
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

        cmd = ('iptables-slice',)
        with self.assertRaises(subprocess.CalledProcessError) as ex:
            out = subprocess.check_output(cmd,
                                          universal_newlines=True,
                                          stderr=subprocess.STDOUT)
        sys.stderr.write(ex.exception.output)
        self.assertIn("Usage", ex.exception.output)

    def testEmpty(self):

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, [])

        dst = os.path.join(self.workdir, 'iptables-slice')

        cmd = ('iptables-slice', src, dst,)
        subprocess.check_call(cmd)

        self.assertSavedRules([], dst)

    def testSimple(self):

        rules = [
            "-A FORWARD -i dummy0 -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        cmd = ('iptables-slice', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD_dummy0 -p tcp -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

        cmd = ('iptables-slice', src, dst)
        subprocess.check_call(cmd)

        self.assertSavedRules(rules_, dst)

        rules = [
            "-A INPUT -i dummy0 -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        cmd = ('iptables-slice', src, dst)
        subprocess.check_call(cmd)

        self.assertSavedRules(rules, dst)

        cmd = ('iptables-slice', src, dst, 'INPUT')
        subprocess.check_call(cmd)

        rules_ = [
            "-A INPUT -i dummy0 -m comment --comment 'TOC entry' -j INPUT_dummy0",
            "-A INPUT_dummy0 -p tcp -j ACCEPT",
        ]

        self.assertSavedRules(rules_, dst)

    def testSliceImplicit(self):
        """Implicit interfaces are not valid."""

        src = os.path.join(self.workdir, "iptables-save")
        dst = os.path.join(self.workdir, 'iptables-slice')

        rules = [
            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD -i dummy1 -p tcp -m comment --comment 'rule 2' -j OTHER",
            "-A FORWARD -i eth0 -p tcp -m comment --comment 'rule 3' -j ACCEPT",
        ]

        self.saveRules(src, rules, otherChains=["OTHER",])

        cmd = ('iptables-slice', src, dst, 'FORWARD')

        with self.assertRaises(subprocess.CalledProcessError):
            subprocess.check_call(cmd)
        # interface 'eth0' is not valid

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'dummy0', 'dummy1', 'eth0')

        with self.assertRaises(subprocess.CalledProcessError):
            subprocess.check_call(cmd)
        # interface 'eth0' is not valid even if explicitly specified

    def testSlicePattern(self):

        src = os.path.join(self.workdir, "iptables-save")
        dst = os.path.join(self.workdir, 'iptables-slice')

        rules = [
            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD -i dummy+ -p tcp -m comment --comment 'rule 2' -j OTHER",
        ]

        self.saveRules(src, rules, otherChains=["OTHER",])

        cmd = ('iptables-slice', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD -i dummy1 -m comment --comment 'TOC entry' -j FORWARD_dummy1",

            "-A FORWARD_dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD_dummy0 -p tcp -m comment --comment 'rule 2' -j OTHER",
            "-A FORWARD_dummy1 -p tcp -m comment --comment 'rule 2' -j OTHER",
        ]

        with open(dst, 'rt') as fd:
            buf = fd.read()
        sys.stdout.write(buf)

        self.assertSavedRules(rules_, dst)

        # specifying dummy1 hides the dummy0 rules

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'dummy1',)
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -i dummy1 -m comment --comment 'TOC entry' -j FORWARD_dummy1",

            "-A FORWARD_dummy1 -p tcp -m comment --comment 'rule 2' -j OTHER",
        ]

        self.assertSavedRules(rules_, dst)

        # specifying dummy0 and dummy1 is OK

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'dummy0', 'dummy1',)
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD -i dummy1 -m comment --comment 'TOC entry' -j FORWARD_dummy1",

            "-A FORWARD_dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD_dummy0 -p tcp -m comment --comment 'rule 2' -j OTHER",
            "-A FORWARD_dummy1 -p tcp -m comment --comment 'rule 2' -j OTHER",
        ]

        with open(dst, 'rt') as fd:
            buf = fd.read()
        sys.stdout.write(buf)

        self.assertSavedRules(rules_, dst)

        # specifying dummy0 only

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'dummy0',)
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",

            "-A FORWARD_dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD_dummy0 -p tcp -m comment --comment 'rule 2' -j OTHER",
        ]

        with open(dst, 'rt') as fd:
            buf = fd.read()
        sys.stdout.write(buf)

        self.assertSavedRules(rules_, dst)

        # interface patterns are also valid on the command line

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'dummy+',)
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD -i dummy1 -m comment --comment 'TOC entry' -j FORWARD_dummy1",

            "-A FORWARD_dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD_dummy0 -p tcp -m comment --comment 'rule 2' -j OTHER",
            "-A FORWARD_dummy1 -p tcp -m comment --comment 'rule 2' -j OTHER",
        ]

        with open(dst, 'rt') as fd:
            buf = fd.read()
        sys.stdout.write(buf)

        self.assertSavedRules(rules_, dst)

    def testSliceExclude(self):

        src = os.path.join(self.workdir, "iptables-save")
        dst = os.path.join(self.workdir, 'iptables-slice')

        rules = [
            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD -i !dummy0 -p tcp -m comment --comment 'rule 2' -j ACCEPT",
        ]

        self.saveRules(src, rules, otherChains=["OTHER",])

        cmd = ('iptables-slice', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD -i dummy1 -m comment --comment 'TOC entry' -j FORWARD_dummy1",

            "-A FORWARD_dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD_dummy1 -p tcp -m comment --comment 'rule 2' -j ACCEPT",
        ]

        with open(dst, 'rt') as fd:
            buf = fd.read()
        sys.stdout.write(buf)

        self.assertSavedRules(rules_, dst)

        # suppress dummy0

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'dummy1',)
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -i dummy1 -m comment --comment 'TOC entry' -j FORWARD_dummy1",

            "-A FORWARD_dummy1 -p tcp -m comment --comment 'rule 2' -j ACCEPT",
        ]

        with open(dst, 'rt') as fd:
            buf = fd.read()
        sys.stdout.write(buf)

        self.assertSavedRules(rules_, dst)

        # !dummy0 is valid but we are not including it

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'dummy0',)
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",

            "-A FORWARD_dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
        ]

        with open(dst, 'rt') as fd:
            buf = fd.read()
        sys.stdout.write(buf)

        self.assertSavedRules(rules_, dst)

    def testSliceExcludePattern(self):

        src = os.path.join(self.workdir, "iptables-save")
        dst = os.path.join(self.workdir, 'iptables-slice')

        rules = [
            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD -i !dummy+ -p tcp -m comment --comment 'rule 2' -j ACCEPT",
        ]

        self.saveRules(src, rules, otherChains=["OTHER",])

        cmd = ('iptables-slice', src, dst, 'FORWARD')

        # !dummy+ does not match anything
        with self.assertRaises(subprocess.CalledProcessError):
            subprocess.check_call(cmd)

        rules = [
            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD -i !other+ -p tcp -m comment --comment 'rule 2' -j ACCEPT",
        ]

        self.saveRules(src, rules, otherChains=["OTHER",])

        # match dummy0 only

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'dummy0')

        # !other+ matches dummy0 etc.
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",

            "-A FORWARD_dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD_dummy0 -p tcp -m comment --comment 'rule 2' -j ACCEPT",
        ]

        with open(dst, 'rt') as fd:
            buf = fd.read()
        sys.stdout.write(buf)

        self.assertSavedRules(rules_, dst)

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'dummy0', 'dummy1')
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD -i dummy1 -m comment --comment 'TOC entry' -j FORWARD_dummy1",

            "-A FORWARD_dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD_dummy0 -p tcp -m comment --comment 'rule 2' -j ACCEPT",
            "-A FORWARD_dummy1 -p tcp -m comment --comment 'rule 2' -j ACCEPT",
        ]

        with open(dst, 'rt') as fd:
            buf = fd.read()
        sys.stdout.write(buf)

        self.assertSavedRules(rules_, dst)

class BridgeSliceTest(SliceTestMixin,
                      ScriptTestMixin,
                      unittest.TestCase):

    def setUp(self):
        self.setUpWorkdir()

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

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, [])

        dst = os.path.join(self.workdir, 'iptables-slice')

        cmd = ('iptables-slice', src, dst,)
        subprocess.check_call(cmd)

        self.assertSavedRules([], dst)

    def testDummy(self):

        rules = [
            "-A FORWARD -i dummy0 -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        # dummy0 is not a front-panel interface, no rules left

        with self.assertRaises(subprocess.CalledProcessError):
            cmd = ('iptables-slice', src, dst, 'FORWARD')
            subprocess.check_call(cmd)

        # make dummy0 be a valid interface
        cmd = ('iptables-slice', src, dst, 'FORWARD', 'dummy+',)
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD_dummy0 -p tcp -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

    def testSwp(self):

        rules = [
            "-A FORWARD -i swp1 -p tcp -j ACCEPT",
            "-A FORWARD -i dummy0 -p tcp -j ACCEPT",
            "-A FORWARD -i eth0 -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        # slice should fail, dummy0 is not a valid port

        with self.assertRaises(subprocess.CalledProcessError):
            cmd = ('iptables-slice', src, dst, 'FORWARD',)
            subprocess.check_call(cmd)

        # ignore dummy0 but emit eth0 and swp1
        cmd = ('iptables-slice', src, dst, 'FORWARD', 'eth0', 'swp1',)
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i eth0 -m comment --comment 'TOC entry' -j FORWARD_eth0",
            "-A FORWARD -i swp1 -m comment --comment 'TOC entry' -j FORWARD_swp1",
            "-A FORWARD_eth0 -p tcp -j ACCEPT",
            "-A FORWARD_swp1 -p tcp -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

        # ignore eth0

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'swp+',)
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i swp1 -m comment --comment 'TOC entry' -j FORWARD_swp1",
            "-A FORWARD_swp1 -p tcp -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

        # demote all front panel ports

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'dummy+',)
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD_dummy0 -p tcp -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

    def testBridge(self):

        rules = [
            "-A FORWARD -i br0 -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        # dummy0 is invalid

        with self.assertRaises(subprocess.CalledProcessError):
            cmd = ('iptables-slice', src, dst, 'FORWARD',)
            subprocess.check_call(cmd)

        # allow front-panel ports only

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'eth+', 'swp+',)
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i eth0 -m comment --comment 'TOC entry' -j FORWARD_eth0",
            "-A FORWARD -i swp1 -m comment --comment 'TOC entry' -j FORWARD_swp1",
            "-A FORWARD_eth0 -p tcp -j ACCEPT",
            "-A FORWARD_swp1 -p tcp -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'swp+',)
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i swp1 -m comment --comment 'TOC entry' -j FORWARD_swp1",
            "-A FORWARD_swp1 -p tcp -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

        # allow dummy0

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'dummy+',)
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD_dummy0 -p tcp -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

class VlanLinkSliceTest(SliceTestMixin,
                        ScriptTestMixin,
                        unittest.TestCase):

    def setUp(self):
        self.setUpWorkdir()

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

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, [])

        dst = os.path.join(self.workdir, 'iptables-slice')

        cmd = ('iptables-slice', src, dst,)
        subprocess.check_call(cmd)

        self.assertSavedRules([], dst)

    def testUntagged(self):

        rules = [
            "-A FORWARD -i vlan100 -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        # dummy0 is not a front-panel interface, no rules left

        with self.assertRaises(subprocess.CalledProcessError):
            cmd = ('iptables-slice', src, dst, 'FORWARD')
            subprocess.check_call(cmd)

        # make dummy0 be a valid interface

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'dummy+',)
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD_dummy0 -p tcp -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

        # allow the other interfaces

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'eth+', 'swp+')
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i eth0 -m comment --comment 'TOC entry' -j FORWARD_eth0",
            "-A FORWARD -i swp1 -m comment --comment 'TOC entry' -j FORWARD_swp1",
            "-A FORWARD_eth0 -p tcp -j ACCEPT",
            "-A FORWARD_swp1 -p tcp -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

    def testTagged(self):

        rules = [
            "-A FORWARD -i vlan101 -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        # dummy0 is not a front-panel interface, no rules left

        with self.assertRaises(subprocess.CalledProcessError):
            cmd = ('iptables-slice', src, dst, 'FORWARD')
            subprocess.check_call(cmd)

        # make dummy0 be a valid interface

        cmd = ('iptables-slice', src, dst, 'FORWARD', 'dummy+',)
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD_dummy0 -p tcp -m vlan --vlan-tag 101 -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

@unittest.skipUnless(isDut(),
                     "this test requires a DUT")
class PhysicalPortSliceTest(SliceTestMixin,
                            ScriptTestMixin,
                            unittest.TestCase):

    def setUp(self):
        self.setUpWorkdir()

        if not path_config.isBrazil():
            self.setUpScripts()

        os.environ['TEST_DUMMY'] = '1'
        os.environ.pop('TEST_IFNAME_PREFIX', None)
        # allow dummy interfaces as front-panel ports

    def tearDown(self):
        self.tearDownWorkdir()

        if not path_config.isBrazil():
            self.tearDownScripts()

        os.environ.pop('TEST_DUMMY', None)
        os.environ['TEST_IFNAME_PREFIX'] = 'dummy'

    def testSimple(self):

        rules = [
            "-A FORWARD -i dummy0 -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        cmd = ('iptables-slice', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD_dummy0 -p tcp -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

    def doTestBridge(self):

        rules = [
            "-A FORWARD -i br0 -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        cmd = ('iptables-slice', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD -i dummy1 -m comment --comment 'TOC entry' -j FORWARD_dummy1",
            "-A FORWARD_dummy0 -p tcp -j ACCEPT",
            "-A FORWARD_dummy1 -p tcp -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

    def doPortTest(self, fn, cmds, finalCmds):

        with self.assertRaises(subprocess.CalledProcessError):
            fn()

        for cmd in finalCmds:
            try:
                subprocess.check_call(cmd)
            except subprocess.CalledProcessError:
                pass
        try:
            for cmd in cmds:
                subprocess.check_call(cmd)
            fn()
        finally:
            for cmd in finalCmds:
                try:
                    subprocess.check_call(cmd)
                except subprocess.CalledProcessError:
                    pass

    def testBridge(self):

        with self.assertRaises(subprocess.CalledProcessError):
            self.doTestBridge()

        cmds = [['ip', 'link', 'add', 'name', 'br0', 'type', 'bridge',],
                ['ip', 'link', 'set', 'br0', 'up',],
                ['ip', 'link', 'set', 'dummy0', 'master', 'br0'],
                ['ip', 'link', 'set', 'dummy1', 'master', 'br0'],
                ['ip', 'link', 'set', 'br0', 'up',],]
        finalCmds = [['ip', 'link', 'del', 'br0',],]

        self.doPortTest(self.doTestBridge, cmds, finalCmds)

    def doTestBond(self):

        rules = [
            "-A FORWARD -i bond0 -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        cmd = ('iptables-slice', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD -i dummy1 -m comment --comment 'TOC entry' -j FORWARD_dummy1",
            "-A FORWARD_dummy0 -p tcp -j ACCEPT",
            "-A FORWARD_dummy1 -p tcp -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

    def testBond(self):

        cmds = [['ip', 'link', 'add', 'dev', 'bond0', 'type', 'bond',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'down',],
                ['ip', 'link', 'set', 'dev', 'dummy1', 'down',],
                ['ip', 'link', 'set', 'dev', 'bond0', 'down',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'master', 'bond0',],
                ['ip', 'link', 'set', 'dev', 'dummy1', 'master', 'bond0',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'up',],
                ['ip', 'link', 'set', 'dev', 'dummy1', 'up',],
                ['ip', 'link', 'set', 'dev', 'bond0', 'up',],
        ]
        finalCmds = [['ip', 'link', 'del', 'bond0',],]

        self.doPortTest(self.doTestBond, cmds, finalCmds)

    def doTestSvi(self):

        rules = [
            "-A FORWARD -i vlan100 -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        cmd = ('iptables-slice', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD_dummy0 -p tcp -m vlan --vlan-tag 100 -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

    def testSvi(self):
        """Simple SVI test with a single trunk port"""

        cmds = [['ip', 'link', 'add',
                 'link', 'dummy0',
                 'name', 'dummy0.100',
                 'type', 'vlan', 'id', '100',],
        ]
        finalCmds = [['ip', 'link', 'del', 'dummy0.100',],]

        self.doPortTest(self.doTestSvi, cmds, finalCmds)

    def doTestSviBridge(self):

        rules = [
            "-A FORWARD -i vlan100 -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        cmd = ('iptables-slice', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD -i dummy1 -m comment --comment 'TOC entry' -j FORWARD_dummy1",
            "-A FORWARD_dummy0 -p tcp -m vlan --vlan-tag 100 -j ACCEPT",
            "-A FORWARD_dummy1 -p tcp -m vlan --vlan-tag 100 -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

    def testSviBridge(self):
        """Simple SVI test with a bridge."""

        cmds = [['ip', 'link', 'add',
                 'link', 'dummy0',
                 'name', 'dummy0.100',
                 'type', 'vlan', 'id', '100',],
                ['ip', 'link', 'add',
                 'link', 'dummy1',
                 'name', 'dummy1.100',
                 'type', 'vlan', 'id', '100',],

                ['ip', 'link', 'add', 'name', 'br0', 'type', 'bridge',],
                ['ip', 'link', 'set', 'br0', 'up',],

                ['ip', 'link', 'set', 'dummy0', 'up',],
                ['ip', 'link', 'set', 'dummy0.100', 'up',],
                ['ip', 'link', 'set', 'dummy0.100', 'master', 'br0',],

                ['ip', 'link', 'set', 'dummy1', 'up',],
                ['ip', 'link', 'set', 'dummy1.100', 'up',],
                ['ip', 'link', 'set', 'dummy1.100', 'master', 'br0',],
        ]
        finalCmds = [['ip', 'link', 'del', 'br0',],
                     ['ip', 'link', 'del', 'dummy0.100',],
                     ['ip', 'link', 'del', 'dummy1.100',],]

        self.doPortTest(self.doTestSviBridge, cmds, finalCmds)

    def doTestVlan(self):

        rules = [
            "-A FORWARD -i vlan100 -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        cmd = ('iptables-slice', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        with open(dst, 'rt') as fd:
            sys.stdout.write(fd.read())

        rules_ = [
            "-A FORWARD -i dummy0 -m comment --comment 'TOC entry' -j FORWARD_dummy0",
            "-A FORWARD -i dummy1 -m comment --comment 'TOC entry' -j FORWARD_dummy1",
            "-A FORWARD_dummy0 -p tcp -j ACCEPT",
            "-A FORWARD_dummy1 -p tcp -m vlan --vlan-tag 100 -j ACCEPT",
        ]
        self.assertSavedRules(rules_, dst)

    def testVlan(self):
        """Test a vlan-aware bridge."""

        cmds = [['ip', 'link', 'add', 'name', 'br0',
                 'type', 'bridge',
                 'vlan_filtering', '1', 'vlan_default_pvid', '1',],
                ['ip', 'link', 'set', 'br0', 'up',],

                ['ip', 'link', 'set', 'dummy0', 'master', 'br0',],
                ['ip', 'link', 'set', 'dummy0', 'up',],

                ['ip', 'link', 'set', 'dummy1', 'master', 'br0',],
                ['ip', 'link', 'set', 'dummy1', 'up',],

                ['bridge', 'vlan', 'add', 'vid', '100', 'dev', 'dummy0', 'pvid',],
                ['bridge', 'vlan', 'add', 'vid', '100', 'dev', 'dummy1',],
        ]
        finalCmds = [['ip', 'link', 'del', 'br0',],]
        self.doPortTest(self.doTestVlan, cmds, finalCmds)

if __name__ == "__main__":
    unittest.main()
