"""test_iptables_save.py

Unit tests for the iptables-save parser.
"""

import os, sys
import path_config
import subprocess
import tempfile
import socket
import json

import unittest

from TcSaveTestUtils import (
    isLinux,
    isRoot,
)

if isLinux() and isRoot():
    from TcSaveTestUtils import (
        setUpModule,
        tearDownModule,
    )

from petunia.Iptables import (
    FilterTable,
)

@unittest.skipIf(not isLinux() or not isRoot(),
                 "this test only runs on Linux as root")
class IptablesKernelTest(unittest.TestCase):
    """Test parsing iptables-save from kernel-generated rules."""

    def clearIptables(self):
        """Clear all iptables rules."""

        fno, p = tempfile.mkstemp(prefix='iptables-',
                                  suffix='.rules')
        with os.fdopen(fno, 'wt') as fd:
            fd.write("*filter\n"
                     ":INPUT ACCEPT [0:0]\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":OUTPUT ACCEPT [0:0]\n"
                     "COMMIT\n")
        subprocess.check_call(('iptables-restore', p,))
        subprocess.check_call(('ip6tables-restore', p,))

    def assertIptablesEmpty(self):

        table = FilterTable.fromKernel()

        self.assertEqual(3, len(table.chains))

        for chainName in ('INPUT', 'OUTPUT', 'FORWARD',):
            chain = table.chains[chainName]
            self.assertEqual('ACCEPT', chain.policy)
            self.assertEqual(0, len(chain.rules))

        table = FilterTable.fromKernel(version=socket.AF_INET6)

        self.assertEqual(3, len(table.chains))

        for chainName in ('INPUT', 'OUTPUT', 'FORWARD',):
            chain = table.chains[chainName]
            self.assertEqual('ACCEPT', chain.policy)
            self.assertEqual(0, len(chain.rules))

    def setUp(self):
        self.clearIptables()

    def tearDown(self):
        self.clearIptables()

    def testDefault(self):
        """Test the default state of the chains at boot."""
        self.assertIptablesEmpty()

    def testIgnored(self):
        """Verify that sample rules are persisted."""

        for cmd in (('iptables', '-A', 'FORWARD', '-i', 'dummy0', '-p', 'tcp', '-j', 'ACCEPT',),
                    ('ip6tables', '-A', 'OUTPUT', '-o', 'dummy0', '-p', 'tcp', '-j', 'ACCEPT',),):
            subprocess.check_call(cmd)

        table = FilterTable.fromKernel()
        chain = table.chains['FORWARD']
        self.assertEqual(1, len(chain.rules))
        rule = chain.rules[0]
        self.assertEqual('ACCEPT', rule.target)
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

        table = FilterTable.fromKernel(version=socket.AF_INET6)
        chain = table.chains['OUTPUT']
        self.assertEqual(1, len(chain.rules))
        rule = chain.rules[0]
        self.assertEqual('ACCEPT', rule.target)
        self.assertEqual('dummy0', rule.out_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

    def testComment(self):
        """Verify the positioning of comments."""

        cmd = ('iptables', '-A', 'FORWARD', '-i', 'dummy0', '-p', 'tcp', '-j', 'ACCEPT',)
        subprocess.check_call(cmd)

        table = FilterTable.fromKernel()
        chain = table.chains['FORWARD']
        self.assertEqual(1, len(chain.rules))
        rule = chain.rules[0]
        self.assertEqual('ACCEPT', rule.target)
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

        self.clearIptables()

        cmd = ['iptables', '-A', 'FORWARD',
               '-i', 'dummy0', '-p', 'tcp', '-j', 'ACCEPT',
               '-m', 'comment', '--comment', 'some-rule',]
        subprocess.check_call(cmd)

        table = FilterTable.fromKernel()
        chain = table.chains['FORWARD']
        self.assertEqual(1, len(chain.rules))
        rule = chain.rules[0]
        self.assertEqual('ACCEPT', rule.target)
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual('some-rule', rule.comment)
        self.assertEqual(['-p', 'tcp',],
                         rule.args)

if __name__ == "__main__":
    unittest.main()
