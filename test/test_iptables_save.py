"""test_iptables_save.py

Unit tests for the iptables-save parser.
"""

import path_config

import unittest

from petunia.Iptables import (
    FilterTable,
)

class IptablesTestMixin(object):

    def saveFromLines(self, ruleLines):
        """Generate an abbreviated ruleset.

        Assume the default targets for the root chains (ACCEPT).
        """

        buf = ""
        buf += "*filter\n"

        chains = {}
        chains.setdefault('INPUT', None)
        chains.setdefault('OUTPUT', None)
        chains.setdefault('FORWARD', None)
        for line in ruleLines:
            chain = line.split()[1]
            chains.setdefault(chain, None)

        for chain in chains:
            if chain in ('INPUT', 'OUTPUT', 'FORWARD',):
                buf += ":%s ACCEPT [0:]\n" % chain
            else:
                buf += ":%s - [0:]\n" % chain

        if ruleLines:
            buf += "\n".join(ruleLines) + "\n"

        buf += "COMMIT\n"
        return buf

class IptablesFormatTest(IptablesTestMixin,
                         unittest.TestCase):
    """Test various rule formats."""

    def testDefault(self):
        """Test the startup defaults."""

        table = FilterTable.fromString(self.saveFromLines([]))
        chain = table.chains['INPUT']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(0, len(chain.rules))

    def testSimpleLines(self):
        """Test some simple IPTABLES rules."""

        ruleLines = ["-A INPUT -p tcp -i dummy0 -j ACCEPT",
                     "-A OUTPUT -p tcp -o dummy0 -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(ruleLines))

        chain = table.chains['INPUT']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(1, len(chain.rules))
        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

        chain = table.chains['OUTPUT']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(1, len(chain.rules))
        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.out_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

    def testSimpleTable(self):
        """Test parsing a simple table."""

        table = FilterTable()
        table.chains['INPUT'] = table.chain_klass([], 'ACCEPT')
        table.chains['OUTPUT'] = table.chain_klass([], 'ACCEPT')
        table.chains['FORWARD'] = table.chain_klass([], 'ACCEPT')

        table_ = FilterTable.fromString(table.toSave())
        chain = table_.chains['INPUT']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(0, len(chain.rules))

        rule = table.rule_klass(['-i', 'dummy0', '-p', 'tcp',], 'ACCEPT')
        table.chains['INPUT'].rules.append(rule)

        table_ = FilterTable.fromString(table.toSave())
        chain = table_.chains['INPUT']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(1, len(chain.rules))
        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

    def testSimpleTableDrop(self):
        """Test non-default chain policies."""

        table = FilterTable()
        table.chains['INPUT'] = table.chain_klass([], 'DROP')
        table.chains['OUTPUT'] = table.chain_klass([], 'ACCEPT')
        table.chains['FORWARD'] = table.chain_klass([], 'ACCEPT')

        table_ = FilterTable.fromString(table.toSave())
        chain = table_.chains['INPUT']
        self.assertEqual('DROP', chain.policy)
        self.assertEqual(0, len(chain.rules))

        rule = table.rule_klass(['-i', 'dummy0', '-p', 'tcp',], 'ACCEPT')
        table.chains['INPUT'].rules.append(rule)

        table_ = FilterTable.fromString(table.toSave())
        chain = table_.chains['INPUT']
        self.assertEqual('DROP', chain.policy)
        self.assertEqual(1, len(chain.rules))
        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

    def testComment(self):
        """Test handling of comments."""

        ruleLines = [
            "-A INPUT -p tcp -i dummy0 -m comment --comment c1 -j ACCEPT",
            "-A OUTPUT -p tcp -o dummy0 -m comment --comment c2 -j ACCEPT",
        ]
        table = FilterTable.fromString(self.saveFromLines(ruleLines))

        chain = table.chains['INPUT']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(1, len(chain.rules))
        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)
        self.assertEqual('c1', rule.comment)
        self.assertEqual([], rule.tc_args)

        chain = table.chains['OUTPUT']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(1, len(chain.rules))
        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.out_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)
        self.assertEqual('c2', rule.comment)
        self.assertEqual([], rule.tc_args)

    def testTcComment(self):
        """Test handling of comments with embedded attributes."""

        ruleLines = [
            "-A INPUT -i dummy0 -p tcp -m comment --comment c1 -j ACCEPT",
            "-A INPUT -i dummy0 -p tcp -m comment --comment TC:foo -j ACCEPT",
            "-A INPUT -i dummy0 -p tcp -m comment --comment 'TC:foo TC:bar' -j ACCEPT",
            "-A INPUT -i dummy0 -p tcp -m comment --comment 'c4 TC:foo' -j ACCEPT",
            "-A INPUT -i dummy0 -p tcp -m comment --comment 'TC:foo c5' -j ACCEPT",
            "-A INPUT -i dummy0 -p tcp -m comment --comment 'c6 TC:foo TC:bar' -j ACCEPT",
            "-A INPUT -i dummy0 -p tcp -m comment --comment 'TC:foo c7 TC:bar' -j ACCEPT",
        ]
        table = FilterTable.fromString(self.saveFromLines(ruleLines))

        chain = table.chains['INPUT']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(7, len(chain.rules))

        rule = chain.rules[0]
        self.assertEqual('c1', rule.comment)
        self.assertEqual([], rule.tc_args)
        self.assertEqual(ruleLines[0], rule.toSave())

        rule = chain.rules[1]
        self.assertIsNone(rule.comment)
        self.assertEqual(['foo',], rule.tc_args)
        self.assertEqual(ruleLines[1], rule.toSave())

        rule = chain.rules[2]
        self.assertIsNone(rule.comment)
        self.assertEqual(['foo', 'bar',], rule.tc_args)
        self.assertEqual(ruleLines[2], rule.toSave())

        rule = chain.rules[3]
        self.assertEqual('c4', rule.comment)
        self.assertEqual(['foo',], rule.tc_args)
        self.assertEqual(ruleLines[3], rule.toSave())

        rule = chain.rules[4]
        self.assertEqual('c5', rule.comment)
        self.assertEqual(['foo',], rule.tc_args)

        # comment is re-ordered
        self.assertNotEqual(ruleLines[4], rule.toSave())
        ruleLine = "-A INPUT -i dummy0 -p tcp -m comment --comment 'c5 TC:foo' -j ACCEPT"
        self.assertEqual(ruleLine, rule.toSave())

        rule = chain.rules[5]
        self.assertEqual('c6', rule.comment)
        self.assertEqual(['foo', 'bar',], rule.tc_args)
        self.assertEqual(ruleLines[5], rule.toSave())

        rule = chain.rules[6]
        self.assertEqual('c7', rule.comment)
        self.assertEqual(['foo', 'bar',], rule.tc_args)
        ruleLine = "-A INPUT -i dummy0 -p tcp -m comment --comment 'c7 TC:foo TC:bar' -j ACCEPT"
        self.assertNotEqual(ruleLines[6], rule.toSave())
        self.assertEqual(ruleLine, rule.toSave())

if __name__ == "__main__":
    unittest.main()
