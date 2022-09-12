"""test_iptables_unroll_script.py

Test the iptables-unroll script.
"""

import os, sys

import unittest

import path_config
import subprocess
import tempfile
import shutil

from TcSaveTestUtils import ScriptTestMixin

class UnrollTest(ScriptTestMixin,
                 unittest.TestCase):

    def setUp(self):
        self.setUpWorkdir()
        if not path_config.isBrazil():
            self.setUpScripts()

    def tearDown(self):
        if not path_config.isBrazil():
            self.tearDownScripts()
        self.tearDownWorkdir()

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

    def testDefault(self):

        cmd = ('iptables-unroll',)
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            out = subprocess.check_output(cmd,
                                          universal_newlines=True,
                                          stderr=subprocess.STDOUT)
        sys.stderr.write(cm.exception.output)
        self.assertIn("Usage", cm.exception.output)

    def testEmpty(self):

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, [])

        dst = os.path.join(self.workdir, 'iptables-unroll')

        cmd = ('iptables-unroll', src, dst,)
        subprocess.check_call(cmd)

        self.assertSavedRules([], dst)

    def testSimple(self):

        rules = [
            "-A FORWARD -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        cmd = ('iptables-unroll', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        self.assertSavedRules(rules, dst)

        cmd = ('iptables-unroll', src, dst)
        subprocess.check_call(cmd)

        self.assertSavedRules(rules, dst)

        rules = [
            "-A INPUT -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        cmd = ('iptables-unroll', src, dst, 'INPUT')
        subprocess.check_call(cmd)

        self.assertSavedRules(rules, dst)

    def testUnroll(self):

        rules = [
            "-A FORWARD -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD -p tcp -m comment --comment 'rule 2' -j OTHER",
            "-A FORWARD -p tcp -m comment --comment 'rule 3' -j ACCEPT",
            "-A OTHER -p tcp -m comment --comment 'rule 1.1' -j ACCEPT",
            "-A OTHER -p tcp -m comment --comment 'rule 1.2' -j RETURN",
            "-A OTHER -p tcp -m comment --comment 'rule 1.3' -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules, otherChains=["OTHER",])

        dst = os.path.join(self.workdir, 'iptables-unroll')

        cmd = ('iptables-unroll', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -p tcp -m comment --comment 'rule 1' -j ACCEPT",

            "-A FORWARD -p tcp -m comment --comment 'rule 2' -j SKIP --skip-rules 1",
            "-A FORWARD -m comment --comment 'rule 2 (FORWARD --> OTHER false branch)' -j SKIP --skip-rules 3",

            "-A FORWARD -p tcp -m comment --comment 'rule 1.1' -j ACCEPT",

            "-A FORWARD -p tcp -m comment --comment 'rule 1.2 -- return 1 frame(s)' -j SKIP --skip-rules 1",

            "-A FORWARD -p tcp -m comment --comment 'rule 1.3' -j ACCEPT",

            "-A FORWARD -p tcp -m comment --comment 'rule 3' -j ACCEPT",
        ]

        with open(dst, 'rt') as fd:
            buf = fd.read()
        sys.stdout.write(buf)

        self.assertSavedRules(rules_, dst)

    def testMultiChain(self):
        """Test unrolling with multi-rule support."""

        rules = [
            "-A INPUT,FORWARD -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        # initially this fails
        cmd = ('iptables-unroll', src, dst, 'FORWARD')
        with self.assertRaises(subprocess.CalledProcessError):
            subprocess.check_call(cmd)

        # if we give the correct options it works, dropping INPUT

        cmd = ('iptables-unroll', '--multi-chain', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -p tcp -j ACCEPT",
        ]

        self.assertSavedRules(rules_, dst)

        # preserve INPUT but not FORWARD

        cmd = ('iptables-unroll', '--multi-chain', src, dst, 'INPUT')
        subprocess.check_call(cmd)

        rules_ = [
            "-A INPUT -p tcp -j ACCEPT",
        ]

        self.assertSavedRules(rules_, dst)

    def testMultiInput(self):
        """Test unrolling with multi-input support."""

        rules = [
            "-A FORWARD -i dummy0,dummy1 -p tcp -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules)

        dst = os.path.join(self.workdir, 'iptables-unroll')

        # initially this fails
        cmd = ('iptables-unroll', src, dst, 'FORWARD')
        with self.assertRaises(subprocess.CalledProcessError):
            subprocess.check_call(cmd)

        # if we give the correct options it works, dropping INPUT

        cmd = ('iptables-unroll', '--multi-interface', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -i dummy0 -p tcp -j ACCEPT",
            "-A FORWARD -i dummy1 -p tcp -j ACCEPT",
        ]

        self.assertSavedRules(rules_, dst)

    def testUnrollNoOverride(self):
        """Test interface-specific jumps without trigger override checks.

        Here there are no interface specifiers in either the parent
        or child chains.
        """

        rules = [
            "-A FORWARD -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD -p tcp -m comment --comment 'rule 2' -j OTHER",
            "-A OTHER -p tcp -m comment --comment 'rule 1.1' -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules, otherChains=["OTHER",])

        dst = os.path.join(self.workdir, 'iptables-unroll')

        cmd = ('iptables-unroll', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -p tcp -m comment --comment 'rule 1' -j ACCEPT",

            "-A FORWARD -p tcp -m comment --comment 'rule 2' -j SKIP --skip-rules 1",
            "-A FORWARD -m comment --comment 'rule 2 (FORWARD --> OTHER false branch)' -j SKIP --skip-rules 1",

            "-A FORWARD -p tcp -m comment --comment 'rule 1.1' -j ACCEPT",

        ]

        with open(dst, 'rt') as fd:
            buf = fd.read()
        sys.stdout.write(buf)

        self.assertSavedRules(rules_, dst)

    def testUnrollNoOverride2(self):
        """Test interface-specific jumps without trigger override checks.

        Here the parent chain is interface-specific,
        but the child chain has no interface specifier."""

        rules = [
            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 2' -j OTHER",
            "-A OTHER -p tcp -m comment --comment 'rule 1.1' -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules, otherChains=["OTHER",])

        dst = os.path.join(self.workdir, 'iptables-unroll')

        cmd = ('iptables-unroll', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",

            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 2' -j SKIP --skip-rules 1",
            "-A FORWARD -i dummy0 -m comment --comment 'rule 2 (FORWARD --> OTHER false branch)' -j SKIP --skip-rules 1",

            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 1.1' -j ACCEPT",

        ]

        with open(dst, 'rt') as fd:
            buf = fd.read()
        sys.stdout.write(buf)

        self.assertSavedRules(rules_, dst)

    def testUnrollNoOverride3(self):
        """Test interface-specific jumps without trigger override checks.

        Here the parent and child chains have interface specifiers,
        but they are overlapping.
        """

        rules = [
            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 2' -j OTHER",
            "-A OTHER -i dummy0 -p tcp -m comment --comment 'rule 1.1' -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules, otherChains=["OTHER",])

        dst = os.path.join(self.workdir, 'iptables-unroll')

        cmd = ('iptables-unroll', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",

            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 2' -j SKIP --skip-rules 1",
            "-A FORWARD -i dummy0 -m comment --comment 'rule 2 (FORWARD --> OTHER false branch)' -j SKIP --skip-rules 1",

            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 1.1' -j ACCEPT",

        ]

        with open(dst, 'rt') as fd:
            buf = fd.read()
        sys.stdout.write(buf)

        self.assertSavedRules(rules_, dst)

    def testUnrollNoOverride4(self):
        """Test interface-specific jumps without trigger override checks.

        Here the parent and child chains have interface specifiers,
        and they disagree.
        """

        rules = [
            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",
            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 2' -j OTHER",
            "-A OTHER -i dummy1 -p tcp -m comment --comment 'rule 1.1' -j ACCEPT",
        ]

        src = os.path.join(self.workdir, "iptables-save")
        self.saveRules(src, rules, otherChains=["OTHER",])

        dst = os.path.join(self.workdir, 'iptables-unroll')

        # this fails, since interface overrides are forbidden by default

        with self.assertRaises(subprocess.CalledProcessError):
            cmd = ('iptables-unroll', src, dst, 'FORWARD')
            subprocess.check_call(cmd)

        # allow this (with caveats)
        cmd = ('iptables-unroll', '--override-interface', src, dst, 'FORWARD')
        subprocess.check_call(cmd)

        rules_ = [
            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 1' -j ACCEPT",

            "-A FORWARD -i dummy0 -p tcp -m comment --comment 'rule 2' -j SKIP --skip-rules 1",
            "-A FORWARD -i dummy0 -m comment --comment 'rule 2 (FORWARD --> OTHER false branch)' -j SKIP --skip-rules 1",

            "-A FORWARD -i dummy1 -p tcp -m comment --comment 'rule 1.1 (parent --in-interface dummy0)' -j ACCEPT",

        ]

        with open(dst, 'rt') as fd:
            buf = fd.read()
        sys.stdout.write(buf)

        self.assertSavedRules(rules_, dst)

if __name__ == "__main__":
    unittest.main()
