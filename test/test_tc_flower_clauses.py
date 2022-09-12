"""test_tc_flow_clauses.py

Test the or- and and-clause support.
"""

import path_config

import os
import unittest
import socket
import logging
import copy
import json

from petunia.Iptables import (
    IptablesRule,
    IptablesChain,
    FilterTable,
)

from petunia.TcStatement import (
    LiteralClause,
    LineNumberClause,
    OrClause,
    AndClause,
    ImmutableAndClause,
    NotClause,
    StatementList,
    IpProtoClause,
    SrcIpClause,
    DstIpClause,
    MultiSrcIpClause,
    MultiDstIpClause,
    SrcPortClause,
    DstPortClause,
    MultiSrcPortClause,
    MultiDstPortClause,
    SrcMacClause,
    IpFlagsClause,
    IcmpTypeCodeClause,
    IcmpV6TypeCodeClause,
    GactClause,
    SkipClause,
    LogClause,
    IndevClause,
    AddrTypeClause,
    VlanTagClause,
    Translator,
)

from petunia.TcFlowerLoader import Loader

logger = None
def setUpModule():
    global logger
    logging.basicConfig()
    logger = logging.getLogger("unittest")
    logger.setLevel(logging.DEBUG)

class ClauseTest(unittest.TestCase):

    def setUp(self):
        self.log = logger.getChild(self.id())

    def assertExpand(self, statements, clause, action=None):

        # default action applied to every TC statement
        # (inherited from the root IPTABLES chain policy)
        if action is not None:
            stmts = StatementList(clause, action=action,
                                  log=self.log)
        else:
            stmts = StatementList(clause,
                                  log=self.log)

        stmts.reduce()
        # iteratively reduce the AST to its canonical form

        statements_ = stmts.expand()
        # generate an OR-tree of AND-trees
        # that can be represented as a sequence of TC statements

        self.assertEqual(statements, statements_)

    def testLiteral(self):
        """Single literal clause translates to a single statement."""
        clause = LiteralClause("foo")
        stmt_ = ['foo', 'action', 'default',]
        self.assertExpand([stmt_,], clause)

    def testSimpleAnd(self):
        """Two-clause AND tree creates a single statement."""

        _ = LiteralClause
        a = AndClause

        clause = a(_("one"),
                   _("two"))
        stmt_ = ['one', 'two', 'action', 'default',]
        self.assertExpand([stmt_,], clause)

    def testNestedAnd(self):
        """Three-clause AND tree creates a single statement."""

        _ = LiteralClause
        a = AndClause

        clause = a(_("one"),
                   a(_("two"),
                     _("three")))
        stmt_ = ['one', 'two', 'three', 'action', 'default']
        self.assertExpand([stmt_,], clause)

        clause = a(a(_("one"),
                     _("two")),
                   _("three"))
        self.assertExpand([stmt_,], clause)

    def testSimpleOr(self):
        """Two-clause OR tree creates two statements."""

        _ = LiteralClause
        O = OrClause

        clause = O(_("one"),
                   _("two"))
        stmts_ = [['one', 'action', 'default',],
                  ['two', 'action', 'default',],]
        self.assertExpand(stmts_, clause)

    def testNestedOr(self):
        """Three-clause OR tree creates three statements."""

        _ = LiteralClause
        O = OrClause

        clause = O(_("one"),
                   O(_("two"),
                     _("three")))
        stmts_ = [['one', 'action', 'default',],
                  ['two', 'action', 'default',],
                  ['three', 'action', 'default',],]

        self.assertExpand(stmts_, clause)

        clause = O(O(_("one"),
                                   _("two")),
                          _("three"))
        stmts_ = [['one', 'action', 'default',],
                  ['two', 'action', 'default',],
                  ['three', 'action', 'default',],]
        self.assertExpand(stmts_, clause)

    def testAndOr(self):
        """Refactor OR-trees within an AND clause."""

        _ = LiteralClause
        a = AndClause
        O = OrClause

        clause = a(O(_("one"),
                     _("two")),
                   O(_("three"),
                     _("four")))
        stmts_ = [['one', 'three', 'action', 'default',],
                  ['one', 'four', 'action', 'default',],
                  ['two', 'three', 'action', 'default',],
                  ['two', 'four', 'action', 'default',],]
        self.assertExpand(stmts_, clause)

    def testOrAnd(self):
        """Nest an 'and' within an 'or'"""

        _ = LiteralClause
        a = AndClause
        O = OrClause

        clause = O(a(_("one"),
                     _("two")),
                   a(_("three"),
                     _("four")))
        stmts_ = [['one', 'two', 'action', 'default',],
                  ['three', 'four', 'action', 'default',],]
        self.assertExpand(stmts_, clause)

    def testAndOrAnd(self):
        """Multiple nesting test, and-or-and."""

        a = AndClause
        O = OrClause
        _ = LiteralClause

        clause = a(O(a(_("one"),
                       _("two")),
                     a(_("three"),
                       _("four"))),
                   O(a(_("five"),
                       _("six")),
                     a(_("seven"),
                       _("eight"))))
        stmts_ = [['one', 'two', 'five', 'six', 'action', 'default',],
                  ['one', 'two', 'seven', 'eight', 'action', 'default',],
                  ['three', 'four', 'five', 'six', 'action', 'default',],
                  ['three', 'four', 'seven', 'eight', 'action', 'default',],]
        self.assertExpand(stmts_, clause)

    def testOrAndOr(self):
        """Multiple nesting test, or-and-or."""

        a = AndClause
        O = OrClause
        _ = LiteralClause

        clause = O(a(O(_("one"),
                       _("two")),
                     O(_("three"),
                       _("four"))),
                   a(O(_("five"),
                       _("six")),
                     O(_("seven"),
                       _("eight"))))
        stmts_ = [['one', 'three', 'action', 'default',],
                  ['one', 'four', 'action', 'default',],
                  ['two', 'three', 'action', 'default',],
                  ['two', 'four', 'action', 'default',],
                  ['five', 'seven', 'action', 'default',],
                  ['five', 'eight', 'action', 'default',],
                  ['six', 'seven', 'action', 'default',],
                  ['six', 'eight', 'action', 'default',],]
        self.assertExpand(stmts_, clause)

    def testNot(self):
        """NOT clause refactors into an OR with a skip past the else-clause."""

        _ = LiteralClause
        N = NotClause

        clause = N(_("one"))
        stmts_ = [['one', 'action', 'jump', '1',],
                   ['action', 'default',],]
        self.assertExpand(stmts_, clause)

    def testNotOr(self):
        """Two independent statements with 'NOT' clauses."""

        _ = LiteralClause
        N = NotClause
        O = OrClause

        clause = O(N(_("one")),
                   N(_("two")))
        stmts_ = [['one', 'action', 'jump', '1',],
                  ['action', 'default',],
                  ['two', 'action', 'jump', '1',],
                  ['action', 'default',],]

        # does not account for follow-on statements
        self.assertExpand(stmts_, clause)

        clause = O(_("one"),
                   N(_("two")))
        stmts_ = [['one', 'action', 'default',],
                  ['two', 'action', 'jump', '1',],
                  ['action', 'default',],]

        # does not account for follow-on statements
        self.assertExpand(stmts_, clause)

        clause = O(N(_("one")),
                   _("two"))

        stmts_ = [['one', 'action', 'jump', '1',],
                  ['action', 'default',],
                  ['two', 'action', 'default',],]

        # does not account for follow-on statements
        self.assertExpand(stmts_, clause)

    def testNotAnd(self):
        """Two dependent (AND) statements with 'NOT' clauses."""

        _ = LiteralClause
        N = NotClause
        a = AndClause

        clause = a(_("one"),
                   N(_("two")))
        stmts_ = [['one', 'two', 'action', 'jump', '1',],
                  ['one', 'action', 'default',],]

        # does not account for follow-on statements
        self.assertExpand(stmts_, clause)

        clause = a(N(_("one")),
                   _("two"))
        stmts_ = [['one', 'two', 'action', 'jump', '1',],
                  ['two', 'action', 'default',],]

        # does not account for follow-on statements
        self.assertExpand(stmts_, clause)

        clause = a(N(_("one")),
                   N(_("two")))
        stmts_ = [['one', 'action', 'jump', '2',],
                  ['two', 'action', 'jump', '1',],
                  ['action', 'default',],]

        # does not account for follow-on statements
        self.assertExpand(stmts_, clause)

    def testNotAndIntersperse(self):
        """Try to intersperse positive and negative terms."""

        _ = LiteralClause
        N = NotClause
        a = AndClause

        # one ! two three ! four five
        clause = a(_("one"),
                   a(N(_("two")),
                     a(_("three"),
                       a(N(_("four")),
                         _("five")))))

        stmts_ = [['one', 'two', 'three', 'five', 'action', 'jump', '2',],
                  ['one', 'three', 'four', 'five', 'action', 'jump', '1',],
                  ['one', 'three', 'five', 'action', 'default',],]
        self.assertExpand(stmts_, clause)

    def testAction(self):
        """Test non-default action."""

        _ = LiteralClause
        N = NotClause

        clause = N(_("foo"))
        stmts_ = [['foo', 'action', 'jump', '1',],
                  ['action', 'pass',],]
        self.assertExpand(stmts_, clause, action='pass')

    def testImmutableAnd(self):
        """Test immutable AND clauses."""

        _ = LiteralClause
        N = NotClause
        O = OrClause
        a = AndClause
        A = ImmutableAndClause

        clause = a(_("one"),
                   _("two"))
        stmts_ = [['one', 'two', 'action', 'default',],]
        self.assertExpand(stmts_, clause)

        clause = A(_("one"),
                   _("two"))
        stmts_ = [['one', 'two', 'action', 'default',],]
        self.assertExpand(stmts_, clause)

        clause = A(_("one"),
                   A(_("two"),
                     _("three")))
        stmts_ = [['one', 'two', 'three', 'action', 'default',],]
        self.assertExpand(stmts_, clause)

        clause = O(_("one"),
                   A(_("two"),
                     _("three")))
        stmts_ = [['one', 'action', 'default',],
                  ['two', 'three', 'action', 'default',],]
        self.assertExpand(stmts_, clause)

        # inverting an AND is subject to refactor

        clause = N(a(_("one"),
                     _("two")))
        stmts_ = [['one', 'action', 'jump', '1',],
                  ['action', 'default',],
                  ['two', 'action', 'jump', '1',],
                  ['action', 'default',],]
        self.assertExpand(stmts_, clause)

        # inverting an immutable AND is not subject to refactor

        clause = N(A(_("one"),
                     _("two")))
        stmts_ = [['one', 'two', 'action', 'jump', '1',],
                  ['action', 'default',],]
        self.assertExpand(stmts_, clause)

        # handle interspersed arguments

        clause = N(a(a(_("one"),
                       _("two")),
                     _("three")))
        stmts_ = [['one', 'action', 'jump', '1',],
                  ['action', 'default',],
                  ['two', 'action', 'jump', '1',],
                  ['action', 'default',],
                  ['three', 'action', 'jump', '1',],
                  ['action', 'default',],]
        self.assertExpand(stmts_, clause)

        clause = N(A(A(_("one"),
                       _("two")),
                     _("three")))
        stmts_ = [['one', 'two', 'three', 'action', 'jump', '1',],
                  ['action', 'default',],]
        self.assertExpand(stmts_, clause)

        # tricky -- 'three' is not immutable,
        # but occurs after 'one two', which is immutable

        clause = N(a(A(_("one"),
                       _("two")),
                     _("three")))
        stmts_ = [['one', 'two', 'action', 'jump', '1',],
                  ['action', 'default',],
                  ['three', 'action', 'jump', '1',],
                  ['action', 'default',],]
        self.assertExpand(stmts_, clause)

    def testFromClauses(self):
        """Test the list-based clause constructors."""

        _ = LiteralClause
        a = AndClause
        A = ImmutableAndClause
        O = OrClause

        c1 = _("one")
        c2 = _("two")
        c3 = _("three")

        # zero clauses, not OK

        with self.assertRaises(ValueError):
            clause = a.fromClauses()

        with self.assertRaises(ValueError):
            clause = O.fromClauses()

        # one clause retains the singleton

        clause = a.fromClauses(c1)
        self.assertIsInstance(clause, _)
        self.assertEqual("one", clause.s)

        clause = O.fromClauses(c1)
        self.assertIsInstance(clause, _)
        self.assertEqual("one", clause.s)

        # two clauses creates a simple binary

        clause = a.fromClauses(c1, c2)
        self.assertIsInstance(clause, a)
        self.assertIsInstance(clause.c1, _)
        self.assertEqual("one", clause.c1.s)
        self.assertIsInstance(clause.c2, _)
        self.assertEqual("two", clause.c2.s)

        clause = O.fromClauses(c1, c2)
        self.assertIsInstance(clause, O)
        self.assertIsInstance(clause.c1, _)
        self.assertEqual("one", clause.c1.s)
        self.assertIsInstance(clause.c2, _)
        self.assertEqual("two", clause.c2.s)

        # three clauses makes a tree
        # NOTE that this isn't balanced

        # in thise case it is
        #
        #                   AND
        #                   | |
        #             .-----. .-----.
        #             |             |
        #           AND            three
        #           | |
        #       .---. .---.
        #       |         |
        #       |         |
        #      one       two
        #


        clause = a.fromClauses(c1, c2, c3)

        self.assertIsInstance(clause, a)
        self.assertIsInstance(clause.c1, a)
        self.assertIsInstance(clause.c2, _)
        self.assertEqual("three", clause.c2.s)

        self.assertIsInstance(clause.c1.c1, _)
        self.assertEqual("one", clause.c1.c1.s)
        self.assertIsInstance(clause.c1.c2, _)
        self.assertEqual("two", clause.c1.c2.s)

        # similar algorithm implemented for OR

        clause = O.fromClauses(c1, c2, c3)

        self.assertIsInstance(clause, O)
        self.assertIsInstance(clause.c1, O)
        self.assertIsInstance(clause.c2, _)
        self.assertEqual("three", clause.c2.s)

        self.assertIsInstance(clause.c1.c1, _)
        self.assertEqual("one", clause.c1.c1.s)
        self.assertIsInstance(clause.c1.c2, _)
        self.assertEqual("two", clause.c1.c2.s)

    def testLineNumber(self):
        """Test the line number clause (a meta clause)."""

        _ = LiteralClause
        l = LineNumberClause
        a = AndClause
        o = OrClause

        clause = l(42)
        stmt_ = ['action', 'default',]
        self.assertExpand([stmt_,], clause)

        clause = a(l(42),
                   _("foo"))
        stmt_ = ['foo', 'action', 'default',]
        self.assertExpand([stmt_,], clause)

        clause = a(_("foo"),
                   l(42))
        stmt_ = ['foo', 'action', 'default',]
        self.assertExpand([stmt_,], clause)

        clause = a(l(42),
                   o(_("foo"),
                     _("bar")))
        stmts_ = [['foo', 'action', 'default',],
                  ['bar', 'action', 'default',],]
        self.assertExpand(stmts_, clause)

class StatementTest(unittest.TestCase):
    """Test TC statement generation from IPTABLES statement clauses."""

    def setUp(self):
        self.log = logger.getChild(self.id())

    def assertParse(self, statements, clause, action=None):
        """A single clause generates a single TC statement with an implicit action."""

        statements_ = StatementList(clause, log=self.log)
        statements_.reduce()
        statements_.annotate()
        statements_ = statements_.expand()

        statements = copy.deepcopy(statements)
        action_ = action if action is not None else 'default'
        [x.extend(['action', action_]) for x in statements]

        if statements != statements_:

            self.log.error("expected statements:")
            for stmt in statements:
                self.log.error("<<< %s", stmt)

            self.log.error("actual statements:")
            for stmt in statements_:
                self.log.error(">>> %s", stmt)

            raise AssertionError("parse mismatch")

    def assertParsePolicy(self, statements, clause):
        """A clause expands to multiple TC statements, each with an explicit action."""

        statements_ = StatementList(clause, log=self.log)
        statements_.reduce()
        statements_.annotate()
        statements_ = statements_.expand()

        if statements != statements_:

            self.log.error("expected statements:")
            for stmt in statements:
                self.log.error("<<< %s", stmt)

            self.log.error("actual statements:")
            for stmt in statements_:
                self.log.error(">>> %s", stmt)

            raise AssertionError("parse mismatch")

    def testIpProto(self):
        """Translate IPTABLES protocol version to TC protocol."""

        stmt = IpProtoClause.fromIptables('tcp', log=self.log)
        stmts = [['ip_proto', 'tcp',]]
        self.assertParse(stmts, stmt)

        stmt = IpProtoClause.fromIptables('udp', log=self.log)
        stmts = [['ip_proto', 'udp',]]
        self.assertParse(stmts, stmt)

        stmt = IpProtoClause.fromIptables('132', log=self.log)
        stmts = [['ip_proto', '84',]]
        self.assertParse(stmts, stmt)

        stmt = IpProtoClause.fromIptables('all', log=self.log)
        stmts = [['ip_proto', 'tcp',],
                 ['ip_proto', 'udp',],
                 ['ip_proto', 'sctp',],
                 ['ip_proto', 'icmp',],]
        self.assertParse(stmts, stmt)

        stmt = IpProtoClause.fromIptables('all',
                                          version=socket.AF_INET6,
                                          log=self.log)
        stmts = [['ip_proto', 'tcp',],
                 ['ip_proto', 'udp',],
                 ['ip_proto', 'sctp',],
                 ['ip_proto', 'icmpv6',],]
        self.assertParse(stmts, stmt)

        stmt = IpProtoClause.fromIptables('tcp',
                                          invert=True,
                                          log=self.log)
        stmts = [['ip_proto', 'udp',],
                 ['ip_proto', 'sctp',],
                 ['ip_proto', 'icmp',],]
        self.assertParse(stmts, stmt)

        stmt = IpProtoClause.fromIptables('tcp',
                                          invert=True, version=socket.AF_INET6,
                                          log=self.log)
        stmts = [['ip_proto', 'udp',],
                 ['ip_proto', 'sctp',],
                 ['ip_proto', 'icmpv6',],]
        self.assertParse(stmts, stmt)

        with self.assertRaises(ValueError):
            stmt = IpProtoClause.fromIptables('other', log=self.log)
            stmt.parse()

        with self.assertRaises(ValueError):
            stmt = IpProtoClause.fromIptables('other', invert=True, log=self.log)
            stmt.parse()

        with self.assertRaises(ValueError):
            stmt = IpProtoClause.fromIptables('132', invert=True, log=self.log)
            stmt.parse()

    def testIpAction(self):
        """Translate IPTABLES polciy to TC gact action."""

        stmt = GactClause.fromIptables('ACCEPT')
        stmts = [['action', 'ok',]]
        self.assertParsePolicy(stmts, stmt)

        stmt = GactClause.fromIptables('DROP')
        stmts = [['action', 'drop',]]
        self.assertParsePolicy(stmts, stmt)

        with self.assertRaises(ValueError):
            stmt = GactClause.fromIptables('SKIP',
                                           target_args=['--skip-rules', '2',])
        with self.assertRaises(ValueError):
            stmt = GactClause.fromIptables('QUEUE')
        with self.assertRaises(ValueError):
            stmt = GactClause.fromIptables('RETURN')

    def testSkipAction(self):
        """Translate IPTABLES polciy to TC gact action."""

        a = AndClause
        l = LineNumberClause

        with self.assertRaises(ValueError):
            stmt = SkipClause.fromIptables('ACCEPT', log=self.log)

        with self.assertRaises(ValueError):
            stmt = SkipClause.fromIptables('DROP', log=self.log)

        stmt = SkipClause.fromIptables('SKIP',
                                       target_args=['--skip-rules', '2',],
                                       log=self.log)
        stmts = []

        # initial parse fails because we have not supplied a line number
        with self.assertRaises(ValueError):
            self.assertParsePolicy(stmts, stmt)

        # let's supply an IPTABLES line number
        stmt = a(l(42), stmt)
        stmts = [['action', 'skip_until', '45',]]
        self.assertParsePolicy(stmts, stmt)

        # handle skipping over zero rules (no-op)

        stmt = SkipClause.fromIptables('SKIP',
                                       target_args=['--skip-rules', '0',],
                                       log=self.log)

        with self.assertRaises(ValueError):
            self.assertParsePolicy(stmts, stmt)

        stmt = a(l(42),stmt)
        stmts = [['action', 'skip_until', '43',]]
        self.assertParsePolicy(stmts, stmt)

    def testLogAction(self):
        """Handle logging targets (not directly supported in TC)."""

        stmt = LogClause.fromIptables('LOG',
                                      ['--log-prefix', "foo",])
        with self.assertRaises(ValueError):
            self.assertParsePolicy([], stmt)

        stmt = LogClause.fromIptables('LOG',
                                      ['--log-prefix', "foo",],
                                      ignore=True)
        stmts = [['action', 'continue',],]
        self.assertParsePolicy(stmts, stmt)

    def testSrcIp(self):
        """Handle source ip address."""

        stmt = SrcIpClause.fromIptables('1.1.1.1')
        stmts = [['src_ip', '1.1.1.1',],]
        self.assertParse(stmts, stmt)

        stmt = SrcIpClause.fromIptables('0.0.0.0')
        stmts = [['src_ip', '0.0.0.0',],]
        self.assertParse(stmts, stmt)

        stmt = SrcIpClause.fromIptables('1.1.1.1/32')
        stmts = [['src_ip', '1.1.1.1/32',],]
        self.assertParse(stmts, stmt)

        stmt = SrcIpClause.fromIptables('0.0.0.0/0')
        stmts = [['src_ip', '0.0.0.0/0',],]
        self.assertParse(stmts, stmt)

        stmt = SrcIpClause.fromIptables('0.0.0.0/0', ipOnly=True)
        stmts = [[],]
        self.assertParse(stmts, stmt)

        stmt = SrcIpClause.fromIptables('1.1.1.1/255.255.255.255')
        stmts = [['src_ip', '1.1.1.1/32',],]
        self.assertParse(stmts, stmt)

        stmt = SrcIpClause.fromIptables('2001::dead:beef', version=socket.AF_INET6)
        stmts = [['src_ip', '2001::dead:beef',],]
        self.assertParse(stmts, stmt)

        stmt = SrcIpClause.fromIptables('::', version=socket.AF_INET6)
        stmts = [['src_ip', '::',],]
        self.assertParse(stmts, stmt)

        stmt = SrcIpClause.fromIptables('2001::dead:beef/128', version=socket.AF_INET6)
        stmts = [['src_ip', '2001::dead:beef/128',],]
        self.assertParse(stmts, stmt)

        stmt = SrcIpClause.fromIptables('::/0', version=socket.AF_INET6)
        stmts = [['src_ip', '::/0',],]
        self.assertParse(stmts, stmt)

        stmt = SrcIpClause.fromIptables('::/0', ipOnly=True, version=socket.AF_INET6)
        stmts = [[],]
        self.assertParse(stmts, stmt)

        # test negated addresses

        stmt = SrcIpClause.fromIptables('1.1.1.1', invert=True)
        stmts = [['src_ip', '1.1.1.1', 'action', 'jump', '1'],
                 ['action', 'default',],]
        self.assertParsePolicy(stmts, stmt)

    def testSrcIpMulti(self):
        """Handle multiple source ip address."""

        with self.assertRaises(ValueError):
            stmt = SrcIpClause.fromIptables('1.1.1.1,1.1.1.2')

        stmt = MultiSrcIpClause.fromIptables('1.1.1.1,1.1.1.2')
        stmts = [['src_ip', '1.1.1.1',],
                 ['src_ip', '1.1.1.2',],]
        self.assertParse(stmts, stmt)

        # here we define '! -s 1.1.1.1,1.1.1.2 -j accept'
        # as 'accept' if the packet matches none of the addresses

        stmt = MultiSrcIpClause.fromIptables('1.1.1.1,1.1.1.2',
                                             invert=True)
        stmts = [['src_ip', '1.1.1.1', 'action', 'jump', '2',],
                 ['src_ip', '1.1.1.2', 'action', 'jump', '1',],
                 ['action', 'default',],]
        self.assertParsePolicy(stmts, stmt)

        stmt = MultiSrcIpClause.fromIptables('2001::1,2001::2',
                                             invert=True,
                                             version=socket.AF_INET6)
        stmts = [['src_ip', '2001::1', 'action', 'jump', '2',],
                 ['src_ip', '2001::2', 'action', 'jump', '1',],
                 ['action', 'default',],]
        self.assertParsePolicy(stmts, stmt)

    def testDstIp(self):
        """Handle destination ip address."""

        stmt = DstIpClause.fromIptables('1.1.1.1')
        stmts = [['dst_ip', '1.1.1.1',],]
        self.assertParse(stmts, stmt)

    def testSrcPort(self):
        """Handle source port."""

        stmt = SrcPortClause.fromIptables('80')
        stmts = [['src_port', '80',],]
        self.assertParse(stmts, stmt)

        stmt = SrcPortClause.fromIptables('80:81')
        stmts = [['src_port', '80-81',],]
        self.assertParse(stmts, stmt)

        stmt = SrcPortClause.fromIptables(':1023')
        stmts = [['src_port', '1-1023',],]
        self.assertParse(stmts, stmt)

        stmt = SrcPortClause.fromIptables('1024:')
        stmts = [['src_port', '1024-65535',],]
        self.assertParse(stmts, stmt)

        # test port by name
        stmt = SrcPortClause.fromIptables('bootps')
        stmts = [['src_port', '67',],]
        self.assertParse(stmts, stmt)

        stmt = SrcPortClause.fromIptables('bootps:bootpc')
        stmts = [['src_port', '67-68',],]
        self.assertParse(stmts, stmt)

        # test port inversion

        stmt = SrcPortClause.fromIptables('80', invert=True)
        stmts = [['src_port', '80', 'action', 'jump', '1',],
                 ['action', 'default',],]
        self.assertParsePolicy(stmts, stmt)

    def testSrcPortInvert(self):
        """Handle source port inversion."""

        stmt = SrcPortClause.fromIptables('80')
        stmts = [['src_port', '80',],]
        self.assertParse(stmts, stmt)

        stmt = SrcPortClause.fromIptables('80', invert=True)
        stmts = [['src_port', '80', 'action', 'jump', '1',],
                 ['action', 'default',],
        ]
        self.assertParsePolicy(stmts, stmt)

        stmt = SrcPortClause.fromIptables('80:81', invert=True)
        stmts = [['src_port', '80-81', 'action', 'jump', '1',],
                 ['action', 'default',],
        ]
        self.assertParsePolicy(stmts, stmt)

    def testSrcPortUnroll(self):
        """Test port range unrolling."""

        stmt = SrcPortClause.fromIptables('80:81')
        stmts = [['src_port', '80-81',],]
        self.assertParse(stmts, stmt)

        stmt = SrcPortClause.fromIptables('80:81', unroll=None)
        stmts = [['src_port', '80-81',],]
        self.assertParse(stmts, stmt)

        stmt = SrcPortClause.fromIptables('80:81', unroll=10)
        stmts = [['src_port', '80',],
                 ['src_port', '81',],
        ]
        self.assertParse(stmts, stmt)

        # maximum unroll range
        with self.assertRaises(ValueError):
            SrcPortClause.fromIptables('80:85', unroll=3)
        with self.assertRaises(ValueError):
            SrcPortClause.fromIptables('80:85', unroll=5)

        stmt = SrcPortClause.fromIptables('80:85', unroll=6)
        stmts = [['src_port', '80',],
                 ['src_port', '81',],
                 ['src_port', '82',],
                 ['src_port', '83',],
                 ['src_port', '84',],
                 ['src_port', '85',],
        ]
        self.assertParse(stmts, stmt)

        stmt = SrcPortClause.fromIptables('80:81', unroll=5, invert=True)
        stmts = [['src_port', '80', 'action', 'jump', '2',],
                 ['src_port', '81', 'action', 'jump', '1',],
                 ['action', 'default',],
        ]
        self.assertParsePolicy(stmts, stmt)

    def testSrcPortMulti(self):

        with self.assertRaises(ValueError):
            stmt = SrcPortClause.fromIptables('80,81')

        stmt = MultiSrcPortClause.fromIptables('80,81')
        stmts = [['src_port', '80',],
                 ['src_port', '81',],]
        self.assertParse(stmts, stmt)

        stmt = MultiSrcPortClause.fromIptables('80,81', invert=True)
        stmts = [['src_port', '80', 'action', 'jump', '2',],
                 ['src_port', '81', 'action', 'jump', '1',],
                 ['action', 'default',],]
        self.assertParsePolicy(stmts, stmt)

    def testDstPort(self):
        """Handle destination port."""

        stmt = DstPortClause.fromIptables('80')
        stmts = [['dst_port', '80',],]
        self.assertParse(stmts, stmt)

    def testSrcMac(self):
        """Handle source mac address."""

        stmt = SrcMacClause.fromIptables('00:11:22:33:44:55')
        stmts = [['src_mac', '00:11:22:33:44:55',],]
        self.assertParse(stmts, stmt)

        stmt = SrcMacClause.fromIptables('00:11:22:33:44:55', invert=True)
        stmts = [['src_mac', '00:11:22:33:44:55', 'action', 'jump', '1',],
                 ['action', 'default',],]
        self.assertParsePolicy(stmts, stmt)

    def testIpFlags(self):
        """Handle IP flags (such as 'fragment')."""

        stmt = IpFlagsClause.fromIptables(fragment=True)
        stmts = [['ip_flags', 'frag',],]
        self.assertParse(stmts, stmt)

        stmt = IpFlagsClause.fromIptables(fragment=True, invert=True)
        stmts = [['ip_flags', 'nofrag',],]
        self.assertParse(stmts, stmt)

    def testIcmpType(self):
        """Handle icmp type and code."""

        stmt = IcmpTypeCodeClause.fromIptables('destination-unreachable')
        stmts = [['type', '3',]]
        self.assertParse(stmts, stmt)

        stmt = IcmpTypeCodeClause.fromIptables('network-unreachable')
        stmts = [['type', '3', 'code', '0',]]
        self.assertParse(stmts, stmt)

        stmt = IcmpTypeCodeClause.fromIptables('network-unreachable', invert=True)
        stmts = [['type', '3', 'code', '0', 'action', 'jump', '1',],
                 ['action', 'default',],]
        self.assertParsePolicy(stmts, stmt)

    def testIcmpV6Type(self):
        """Handle icmpv6 type and code."""

        stmt = IcmpV6TypeCodeClause.fromIptables('destination-unreachable')
        stmts = [['type', '1',]]
        self.assertParse(stmts, stmt)

        stmt = IcmpV6TypeCodeClause.fromIptables('no-route')
        stmts = [['type', '1', 'code', '0',]]
        self.assertParse(stmts, stmt)

        stmt = IcmpV6TypeCodeClause.fromIptables('no-route', invert=True)
        stmts = [['type', '1', 'code', '0', 'action', 'jump', '1',],
                 ['action', 'default',],]
        self.assertParsePolicy(stmts, stmt)

    def testIndevType(self):
        """Handle indev specifiers."""

        stmt = IndevClause.fromIptables('dummy0')
        stmts = [['indev', 'dummy0',]]
        self.assertParse(stmts, stmt)

    def testAddrType(self):
        """Handle policer targets (not directly supported in TC)."""

        # no args --> not supported

        with self.assertRaises(ValueError):
            AddrTypeClause.fromIptables()
        with self.assertRaises(ValueError):
            AddrTypeClause.fromIptables(match=True)
        with self.assertRaises(ValueError):
            AddrTypeClause.fromIptables(match=False)

        # invalid address type --> not supported

        with self.assertRaises(ValueError):
            AddrTypeClause.fromIptables(src_type='not-a-type')
        with self.assertRaises(ValueError):
            AddrTypeClause.fromIptables(src_type='not-a-type', match=True)
        with self.assertRaises(ValueError):
            AddrTypeClause.fromIptables(src_type='not-a-type', match=False)

        # valid address type

        stmt = AddrTypeClause.fromIptables(src_type='LOCAL')
        stmts = [['action', 'default',],]
        with self.assertRaises(ValueError):
            self.assertParsePolicy(stmts, stmt)

        stmt = AddrTypeClause.fromIptables(src_type='LOCAL', match=True)
        self.assertParsePolicy(stmts, stmt)

        # handle match=False --> drops the filter entirely

        stmts = []
        stmt = AddrTypeClause.fromIptables(src_type='LOCAL', match=False)
        self.assertParsePolicy(stmts, stmt)

    def testVlanTag(self):
        """Handle vlan tag specifiers."""

        stmt = VlanTagClause.fromIptables('42')
        stmts = [['vlan_ethtype', 'ipv4', 'vlan_id', '42',]]
        self.assertParse(stmts, stmt)

        stmt = VlanTagClause.fromIptables('42', version=socket.AF_INET6)
        stmts = [['vlan_ethtype', 'ipv6', 'vlan_id', '42',]]
        self.assertParse(stmts, stmt)

        stmt = VlanTagClause.fromIptables('any')
        stmts = [['vlan_ethtype', 'ipv4',]]
        self.assertParse(stmts, stmt)

class TranslateTestBase(object):

    def assertTranslate(self, tcRules, aclArgs,
                        action=None, action_args=[],
                        lineno=None, commit=True):

        iptTarget = {'ok' : 'ACCEPT',
                     'pass' : 'ACCEPT',
                     'drop' : 'DROP',
                     'skip' : 'SKIP'}.get(action, 'ACCEPT')
        iptTargetArgs = action_args

        iptRule = IptablesRule(aclArgs, iptTarget, target_args=iptTargetArgs)

        try:
            self.translator.feed(iptRule, lineno=lineno)
            if commit:
                self.translator.commit()
        except ValueError as ex:
            raise AssertionError("parse error: %s" % str(ex))

        tcRules_ = [ x.stmts for x in self.translator.stmts]
        self.translator.clear()

        if action is None:
            tcRules = copy.deepcopy(tcRules)
            [x.extend(['action', 'ok',]) for x in tcRules]


        self.assertEqual(tcRules, tcRules_)

class TranslateTest(TranslateTestBase,
                    unittest.TestCase):
    """Test TC statement translation from parsing IPTABLES rules."""

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.translator = Translator(log=self.log.getChild("translate"))

    def tearDown(self):
        self.translator.clear()

    def testProtocol(self):
        self.assertTranslate([['ip_proto', 'tcp',]], ('-p', 'tcp',))

    def testProtocolDrop(self):
        aclArgs = ('-p', 'tcp',)
        tcRules = [['ip_proto', 'tcp', 'action', 'drop',]]
        self.assertTranslate(tcRules, aclArgs, action='drop')

    def testProtocolInvert(self):
        aclArgs = ('!', '-p', 'tcp',)
        tcRules = [['ip_proto', 'udp',],
                   ['ip_proto', 'sctp',],
                   ['ip_proto', 'icmp',]]
        self.assertTranslate(tcRules, aclArgs)

    def testSourceIpTcp(self):
        aclArgs = ('-p', 'tcp', '-s', '1.1.1.1/32',)
        tcRules = [['ip_proto', 'tcp', 'src_ip', '1.1.1.1/32',]]
        self.assertTranslate(tcRules, aclArgs)

    def testSourceIpUdp(self):
        aclArgs = ('-p', 'udp', '-s', '1.1.1.1/32',)
        tcRules = [['ip_proto', 'udp', 'src_ip', '1.1.1.1/32',]]
        self.assertTranslate(tcRules, aclArgs)

    def testSourceIpTcpInvert(self):
        aclArgs = ('-p', 'tcp', '!', '-s', '1.1.1.1/32',)
        tcRules = [['ip_proto', 'tcp', 'src_ip', '1.1.1.1/32', 'action', 'jump', '1',],
                   ['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertTranslate(tcRules, aclArgs, action='ok')

    def testDestIpTcp(self):
        aclArgs = ('-p', 'tcp', '-d', '1.1.1.1/32',)
        tcRules = [['ip_proto', 'tcp', 'dst_ip', '1.1.1.1/32',]]
        self.assertTranslate(tcRules, aclArgs)

    def testMultiSourceIpTcp(self):
        self.translator = Translator(match_multi=True,
                                     log=self.log.getChild("translate"))

        aclArgs = ('-p', 'tcp', '-s', '1.1.1.1/32',)
        tcRules = [['ip_proto', 'tcp', 'src_ip', '1.1.1.1/32',]]
        self.assertTranslate(tcRules, aclArgs)

        aclArgs = ('-p', 'tcp', '-s', '1.1.1.1/32,1.1.1.2/32',)
        tcRules = [['ip_proto', 'tcp', 'src_ip', '1.1.1.1/32',],
                   ['ip_proto', 'tcp', 'src_ip', '1.1.1.2/32',],
        ]
        self.assertTranslate(tcRules, aclArgs)

    def testMultiSourceIpTcpInvert(self):
        self.translator = Translator(match_multi=True,
                                     log=self.log.getChild("translate"))

        aclArgs = ('-p', 'tcp', '!', '-s', '1.1.1.1/32',)
        tcRules = [['ip_proto', 'tcp', 'src_ip', '1.1.1.1/32', 'action', 'jump', '1',],
                   ['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertTranslate(tcRules, aclArgs, action='ok')

        aclArgs = ('-p', 'tcp', '!', '-s', '1.1.1.1/32,1.1.1.2/32',)
        tcRules = [['ip_proto', 'tcp', 'src_ip', '1.1.1.1/32', 'action', 'jump', '2',],
                   ['ip_proto', 'tcp', 'src_ip', '1.1.1.2/32', 'action', 'jump', '1',],
                   ['ip_proto', 'tcp', 'action', 'ok',],
        ]
        self.assertTranslate(tcRules, aclArgs, action='ok')

    def testSourcePortTcp(self):

        aclArgs = ('-p', 'tcp', '-m', 'tcp', '--sport', '80',)
        tcRules = [['ip_proto', 'tcp', 'src_port', '80',]]
        self.assertTranslate(tcRules, aclArgs)

        aclArgs = ('-p', 'tcp', '-m', 'tcp', '--sport', '80:81',)
        tcRules = [['ip_proto', 'tcp', 'src_port', '80-81',]]
        self.assertTranslate(tcRules, aclArgs)

        self.translator = Translator(match_multi=True,
                                     port_unroll=5,
                                     log=self.log.getChild("translate"))

        aclArgs = ('-p', 'tcp', '-m', 'tcp', '--sport', '80:81',)
        tcRules = [['ip_proto', 'tcp', 'src_port', '80',],
                   ['ip_proto', 'tcp', 'src_port', '81',],
        ]
        self.assertTranslate(tcRules, aclArgs)

        aclArgs = ('-p', 'tcp', '-m', 'tcp', '!', '--sport', '80:81',)
        tcRules = [['ip_proto', 'tcp', 'src_port', '80', 'action', 'jump', '2',],
                   ['ip_proto', 'tcp', 'src_port', '81', 'action', 'jump', '1',],
                   ['ip_proto', 'tcp', 'action', 'ok',],
        ]
        self.assertTranslate(tcRules, aclArgs, action='ok')

        # too many to unroll
        aclArgs = ('-p', 'tcp', '-m', 'tcp', '--sport', '80:90',)
        tcRules = []
        with self.assertRaises(AssertionError) as ex:
            self.assertTranslate(tcRules, aclArgs, action='ok')
        self.assertIn("parse error", str(ex.exception))

    def testSourcePortInvertTcp(self):
        aclArgs = ('-p', 'tcp', '-m', 'tcp', '!', '--sport', '80',)
        tcRules = [['ip_proto', 'tcp', 'src_port', '80', 'action', 'jump', '1',],
                   ['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertTranslate(tcRules, aclArgs, action='ok')

    def testSourcePortUdp(self):
        aclArgs = ('-p', 'udp', '-m', 'udp', '--sport', '80',)
        tcRules = [['ip_proto', 'udp', 'src_port', '80',]]
        self.assertTranslate(tcRules, aclArgs)

    def testDestPortTcp(self):
        aclArgs = ('-p', 'tcp', '-m', 'tcp', '--dport', '80',)
        tcRules = [['ip_proto', 'tcp', 'dst_port', '80',]]
        self.assertTranslate(tcRules, aclArgs)

    def testMultiSourcePortTcp(self):
        self.translator = Translator(match_multi=True,
                                     log=self.log.getChild("translate"))

        aclArgs = ('-p', 'tcp', '-m', 'tcp', '--sport', '80',)
        tcRules = [['ip_proto', 'tcp', 'src_port', '80',]]
        self.assertTranslate(tcRules, aclArgs)

        aclArgs = ('-p', 'tcp', '-m', 'tcp', '--sport', '80,82',)
        tcRules = [['ip_proto', 'tcp', 'src_port', '80',],
                   ['ip_proto', 'tcp', 'src_port', '82',],]
        self.assertTranslate(tcRules, aclArgs)

    def testMultiSourcePortInvertTcp(self):
        self.translator = Translator(match_multi=True,
                                     log=self.log.getChild("translate"))

        aclArgs = ('-p', 'tcp', '-m', 'tcp', '!', '--sport', '80',)
        tcRules = [['ip_proto', 'tcp', 'src_port', '80', 'action', 'jump', '1',],
                   ['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertTranslate(tcRules, aclArgs, action='ok')

        aclArgs = ('-p', 'tcp', '-m', 'tcp', '!', '--sport', '80,82',)
        tcRules = [['ip_proto', 'tcp', 'src_port', '80', 'action', 'jump', '2',],
                   ['ip_proto', 'tcp', 'src_port', '82', 'action', 'jump', '1',],
                   ['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertTranslate(tcRules, aclArgs, action='ok')

    def testMacSource(self):
        """Test mac-source (outside of ebtables)"""
        aclArgs = ('-m', 'mac', '--mac-source', '00:11:22:33:44:55',)
        tcRules = [['src_mac', '00:11:22:33:44:55',],]
        self.assertTranslate(tcRules, aclArgs)

    def testFragment(self):
        aclArgs = ('--fragment',)
        tcRules = [['ip_flags', 'frag',],]
        self.assertTranslate(tcRules, aclArgs)

    def testFragmentInvert(self):
        aclArgs = ('!', '--fragment',)
        tcRules = [['ip_flags', 'nofrag',],]
        self.assertTranslate(tcRules, aclArgs)

    def testIcmpTypeWord(self):
        aclArgs = ('-m', 'icmp', '--icmp-type', 'destination-unreachable',)
        tcRules = [['type', '3',],]
        self.assertTranslate(tcRules, aclArgs)

    def testIcmpTypeWordInvert(self):
        aclArgs = ('-m', 'icmp', '!', '--icmp-type', 'destination-unreachable',)
        tcRules = [['type', '3', 'action', 'jump', '1',],
                   ['action', 'ok',],]
        self.assertTranslate(tcRules, aclArgs, action='ok')

    def testIcmpTypeCodeWord(self):
        aclArgs = ('-m', 'icmp', '--icmp-type', 'host-unreachable',)
        tcRules = [['type', '3', 'code', '1',],]
        self.assertTranslate(tcRules, aclArgs)

    def testIcmpTypeCodeWordInvert(self):
        aclArgs = ('-m', 'icmp', '!', '--icmp-type', 'host-unreachable',)
        tcRules = [['type', '3', 'code', '1', 'action', 'jump', '1'],
                   ['action', 'ok',],]
        self.assertTranslate(tcRules, aclArgs, action='ok')

    def testIcmpTypeNum(self):
        aclArgs = ('-m', 'icmp', '--icmp-type', '5',)
        tcRules = [['type', '5',],]
        self.assertTranslate(tcRules, aclArgs)

    def testIcmpTypeCodeNum(self):
        aclArgs = ('-m', 'icmp', '--icmp-type', '3/1',)
        tcRules = [['type', '3', 'code', '1',],]
        self.assertTranslate(tcRules, aclArgs)

    def testIcmpTypeNumInvert(self):
        aclArgs = ('-m', 'icmp', '!', '--icmp-type', '5',)
        tcRules = [['type', '5', 'action', 'jump', '1',],
                   ['action', 'ok',],]
        self.assertTranslate(tcRules, aclArgs, action='ok')

    def testIcmpTypeCodeNumInvert(self):
        aclArgs = ('-m', 'icmp', '!', '--icmp-type', '3/1',)
        tcRules = [['type', '3', 'code', '1', 'action', 'jump', '1',],
                   ['action', 'ok',],]
        self.assertTranslate(tcRules, aclArgs, action='ok')

    def testLineNumber(self):
        """Test parsing with line numbers."""

        # simple rule, line number is ignored

        self.assertTranslate([['ip_proto', 'tcp',]], ('-p', 'tcp',),
                             lineno=42)

        # still ignored

        acl = ('-m', 'tcp', '-s', '1.1.1.1/32',)
        rules = [['src_ip', '1.1.1.1/32', 'action', 'ok',]]
        self.assertTranslate(rules, acl,
                             action='ok', lineno=42)

        # still ignored

        acl = ('-m', 'tcp', '!', '-s', '1.1.1.1/32',)
        rules = [['src_ip', '1.1.1.1/32', 'action', 'jump', '1',],
                 ['action', 'ok',],]
        self.assertTranslate(rules, acl,
                             action='ok', lineno=42)

        # include a skip rule that needs fixup

        acl = ('-p', 'tcp',)
        rules = [['ip_proto', 'tcp', 'action', 'skip_until', '53',],]
        self.assertTranslate(rules, acl,
                             action='skip', action_args=['--skip-rules', '10',],
                             lineno=42,
                             commit=False)

        # inversion is supported, but still requires global fixup

        acl = ('-p', 'tcp', '!', '-s', '1.1.1.1/32',)
        rules = [['ip_proto', 'tcp', 'src_ip', '1.1.1.1/32', 'action', 'jump', '1',],
                 ['ip_proto', 'tcp', 'action', 'skip_until', '53',],]
        self.assertTranslate(rules, acl,
                             action='skip', action_args=['--skip-rules', '10',],
                             lineno=42,
                             commit=False)

    def testIndev(self):

        # in_interface is usually suppressed

        self.assertFalse(self.translator.shared)

        aclArgs = ('-i', 'dummy0',)
        tcRules = [[],]
        self.assertTranslate(tcRules, aclArgs)

        # in_interface is usually suppressed

        aclArgs = ('-i', 'dummy0',)
        tcRules = [[],]
        self.assertTranslate(tcRules, aclArgs)

    def testAddrType(self):
        """Parse the addrtype fields."""
        aclArgs = ('-m', 'addrtype', '--dst-type', 'LOCAL',)

        # default, addrtype is not supported
        with self.assertRaises(AssertionError):
            self.assertTranslate([], aclArgs)

        # create a new translator that ignores addrtype
        tcRules = [[],]
        self.translator = Translator(addrtype=True,
                                     log=self.log.getChild("translate"))
        self.assertTranslate(tcRules, aclArgs)

        # this one always fails (generates zero statements)
        self.translator = Translator(addrtype=False,
                                     log=self.log.getChild("translate"))
        tcRules = []
        self.assertTranslate(tcRules, aclArgs)

    def testVlanTag(self):

        aclArgs = ('-m', 'vlan', '--vlan-tag', '42',)
        tcRules = [['vlan_ethtype', 'ipv4', 'vlan_id', '42',],]
        self.assertTranslate(tcRules, aclArgs)

        aclArgs = ('-m', 'vlan', '--vlan-tag', 'any',)
        tcRules = [['vlan_ethtype', 'ipv4',],]
        self.assertTranslate(tcRules, aclArgs)

    def testVlanTagEncoded(self):
        """Decode VLAN arguments from an IPTABLES comment."""

        aclArgs = ('-m', 'vlan', '--vlan-tag', '42',)
        commArgs = [('TC:' + x) for x in aclArgs]
        aclArgs_ = ('-m', 'comment', '--comment', " ".join(commArgs),)
        tcRules = [['vlan_ethtype', 'ipv4', 'vlan_id', '42',],]
        self.assertTranslate(tcRules, aclArgs_)

        aclArgs = ('-m', 'vlan', '--vlan-tag', 'any',)
        commArgs = [('TC:' + x) for x in aclArgs]
        aclArgs_ = ('-m', 'comment', '--comment', " ".join(commArgs),)
        tcRules = [['vlan_ethtype', 'ipv4',],]
        self.assertTranslate(tcRules, aclArgs_)

    def testProtocolDropPolice(self):

        aclArgs = ('-p', 'tcp',)
        tcRules = [['ip_proto', 'tcp', 'action', 'drop',],]
        self.assertTranslate(tcRules, aclArgs, action='drop')

        police = "8KBit"
        burst = "100"
        trap = True
        mode = (police, burst, trap,)

        self.translator = Translator(addrtype=True,
                                     drop_mode=mode,
                                     log=self.log.getChild("translate"))

        tcRules = [['ip_proto', 'tcp',
                    'action', 'police',
                    'rate', '8KBit', 'burst', '100',
                    'conform-exceed', 'drop',
                    'action', 'trap',],]
        self.assertTranslate(tcRules, aclArgs, action='drop')

        police = "8KBit"
        burst = "100"
        trap = False
        mode = (police, burst, trap,)

        self.translator = Translator(addrtype=True,
                                     drop_mode=mode,
                                     log=self.log.getChild("translate"))

        tcRules = [['ip_proto', 'tcp',
                    'action', 'police',
                    'rate', '8KBit', 'burst', '100',
                    'conform-exceed', 'drop',],]
        self.assertTranslate(tcRules, aclArgs, action='drop')

        police = None
        burst = None
        trap = True
        mode = (police, burst, trap,)

        self.translator = Translator(addrtype=True,
                                     drop_mode=mode,
                                     log=self.log.getChild("translate"))

        tcRules = [['ip_proto', 'tcp',
                    'action', 'trap',],]
        self.assertTranslate(tcRules, aclArgs, action='drop')

    def testArpHack(self):
        ipt_opts = ('-p', 'tcp',)
        stmts = [['ip_proto', 'tcp', 'action', 'drop',]]
        self.assertTranslate(stmts, ipt_opts, action='drop')

        self.translator = Translator(hack_vlan_arp=True,
                                     log=self.log.getChild("translate"))

        stmts = [['vlan_ethtype', 'arp', 'action', 'ok',],
                 ['ip_proto', 'tcp', 'action', 'drop',],
        ]
        self.assertTranslate(stmts, ipt_opts, action='drop')

class TranslateSharedTest(TranslateTestBase,
                          unittest.TestCase):
    """Test TC statement translation from parsing IPTABLES rules."""

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.translator = Translator(shared=True,
                                     log=self.log.getChild("translate"))

    def tearDown(self):
        self.translator.clear()

    def testIndev(self):

        # in_interface is usually suppressed

        self.assertTrue(self.translator.shared)

        aclArgs = ('-i', 'dummy0',)
        tcRules = [['indev', 'dummy0',],]
        self.assertTranslate(tcRules, aclArgs)

class TranslateV6Test(TranslateTestBase,
                      unittest.TestCase):
    """Test TC statement generation from parsing IPTABLES rules."""

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.translator = Translator(version=socket.AF_INET6,
                                     log=self.log.getChild("translate"))

    def tearDown(self):
        self.translator.clear()

    def testProtocolInvert(self):
        aclArgs = ('!', '-p', 'tcp',)
        tcRules = [['ip_proto', 'udp',],
                   ['ip_proto', 'sctp',],
                   ['ip_proto', 'icmpv6',]]
        self.assertTranslate(tcRules, aclArgs)

    def testSourceIpTcp(self):
        aclArgs = ('-p', 'tcp', '-s', '2001::dead:beef/128',)
        tcRules = [['ip_proto', 'tcp', 'src_ip', '2001::dead:beef/128',]]
        self.assertTranslate(tcRules, aclArgs)

    def testMultiSourceIpTcp(self):
        self.translator = Translator(version=socket.AF_INET6,
                                     match_multi=True,
                                     log=self.log.getChild("translate"))

        aclArgs = ('-p', 'tcp', '-s', '2001::dead:beef/128',)
        tcRules = [['ip_proto', 'tcp', 'src_ip', '2001::dead:beef/128',]]
        self.assertTranslate(tcRules, aclArgs)

        aclArgs = ('-p', 'tcp', '-s', '2001::1/128,2001::2/128',)
        tcRules = [['ip_proto', 'tcp', 'src_ip', '2001::1/128',],
                   ['ip_proto', 'tcp', 'src_ip', '2001::2/128',],
        ]
        self.assertTranslate(tcRules, aclArgs)

    def testIcmpv6TypeWord(self):
        aclArgs = ('-m', 'icmpv6', '--icmpv6-type', 'destination-unreachable',)
        tcRules = [['type', '1',],]
        self.assertTranslate(tcRules, aclArgs)

    def testIcmpv6TypeWordInvert(self):
        aclArgs = ('-m', 'icmpv6', '!', '--icmpv6-type', 'destination-unreachable',)
        tcRules = [['type', '1', 'action', 'jump', '1'],
                   ['action', 'ok',],]
        self.assertTranslate(tcRules, aclArgs, action='ok')

    def testIcmpv6TypeCodeWord(self):
        aclArgs = ('-m', 'icmpv6', '--icmpv6-type', 'communication-prohibited',)
        tcRules = [['type', '1', 'code', '1',],]
        self.assertTranslate(tcRules, aclArgs)

    def testIcmpv6TypeCodeWordInvert(self):
        aclArgs = ('-m', 'icmpv6', '!', '--icmpv6-type', 'communication-prohibited',)
        tcRules = [['type', '1', 'code', '1', 'action', 'jump', '1',],
                   ['action', 'ok',],]
        self.assertTranslate(tcRules, aclArgs, action='ok')

    def testIcmpv6TypeNum(self):
        aclArgs = ('-m', 'icmpv6', '--icmpv6-type', '128',)
        tcRules = [['type', '128',],]
        self.assertTranslate(tcRules, aclArgs)

    def testIcmpv6TypeNumInvert(self):
        aclArgs = ('-m', 'icmpv6', '!', '--icmpv6-type', '128',)
        tcRules = [['type', '128', 'action', 'jump', '1',],
                   ['action', 'ok',],]
        self.assertTranslate(tcRules, aclArgs, action='ok')

    def testIcmpv6TypeCodeNum(self):
        aclArgs = ('-m', 'icmpv6', '--icmpv6-type', '1/3',)
        tcRules = [['type', '1', 'code', '3',],]
        self.assertTranslate(tcRules, aclArgs)

    def testIcmpv6TypeCodeNumInvert(self):
        aclArgs = ('-m', 'icmpv6', '!', '--icmpv6-type', '1/3',)
        tcRules = [['type', '1', 'code', '3', 'action', 'jump', '1'],
                   ['action', 'ok',],]
        self.assertTranslate(tcRules, aclArgs, action='ok')

    def testVlanTag(self):

        aclArgs = ('-m', 'vlan', '--vlan-tag', '42',)
        tcRules = [['vlan_ethtype', 'ipv6', 'vlan_id', '42',],]
        self.assertTranslate(tcRules, aclArgs)

        aclArgs = ('-m', 'vlan', '--vlan-tag', 'any',)
        tcRules = [['vlan_ethtype', 'ipv6',],]
        self.assertTranslate(tcRules, aclArgs)

class PolicyTest(unittest.TestCase):
    """Test global fixups for chain policy."""

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.translator = Translator(log=self.log.getChild("translate"))

    def tearDown(self):
        self.translator.clear()

    def assertRules(self, stmts, acls, policy=None):

        iptChain = IptablesChain(acls, 'ACCEPT')

        [self.translator.feed(r, lineno=True) for r in iptChain.rules]
        if policy is None:
            self.translator.commit(lineno=True)
        else:
            self.translator.commit(policy=policy,
                                   lineno=True)
        stmts_ = [ x.stmts for x in self.translator.stmts]
        self.translator.clear()

        if stmts != stmts_:
            self.log.error("expected statments:")
            for stmt in stmts:
                self.log.error("<<< %s", stmt)
            self.log.error("actual statments:")
            for stmt in stmts_:
                self.log.error("<<< %s", stmt)
            raise AssertionError("mismatch in rules")

    def testPolicy(self):

        A = lambda args: IptablesRule(args, target='ACCEPT')
        D = lambda args: IptablesRule(args, target='DROP')

        acls = [A(['-p', 'tcp',]),]
        rules = [['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertRules(rules, acls)

        acls = [A(['-p', 'tcp',]),]
        rules = [['ip_proto', 'tcp', 'action', 'ok',],
                 ['action', 'drop',],]
        self.assertRules(rules, acls, policy='DROP')

        acls = [A(['-p', 'tcp',]),]
        rules = [['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertRules(rules, acls, policy='ACCEPT')

    def testRejectTarget(self):
        """Handle REJECT with a special flag."""
        args = ['-p', 'tcp',]
        acls = [IptablesRule(['-p', 'tcp',], 'REJECT'),]
        rules = [['ip_proto', 'tcp', 'action', 'drop',],
        ]

        self.translator = Translator(reject_drop=False,
                                     log=self.log.getChild("translate"))
        with self.assertRaises(ValueError):
            self.assertRules(rules, acls)

        self.translator = Translator(log=self.log.getChild("translate"))
        self.assertRules(rules, acls)

    def testLogTarget(self):

        args = ['-p', 'tcp',]
        acls = [IptablesRule(args, target='LOG')]
        rules = [['ip_proto', 'tcp', 'action', 'continue',],]

        # default, don't accept log actions
        with self.assertRaises(ValueError):
            self.assertRules(rules, acls)

        # need to explicitly handle LOG targets
        self.translator = Translator(log_ignore=True,
                                     log=self.log.getChild("translate"))
        self.assertRules(rules, acls)

        # suppress the ignore
        self.translator = Translator(log_ignore=True,
                                     continue_suppress=True,
                                     log=self.log.getChild("translate"))
        self.assertRules([], acls)

class SkipTest(unittest.TestCase):
    """Test global fixups for skip_until."""

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.translator = Translator(log=self.log.getChild("translate"))

    def tearDown(self):
        self.translator.clear()

    def assertRules(self, stmts, acls):

        iptChain = IptablesChain(acls, 'ACCEPT')

        [self.translator.feed(r, lineno=True) for r in iptChain.rules]
        self.translator.commit(lineno=True)
        stmts_ = [ x.stmts for x in self.translator.stmts]

        self.translator.clear()

        if stmts != stmts_:
            self.log.error("expected statments:")
            for stmt in stmts:
                self.log.error("<<< %s", stmt)
            self.log.error("actual statments:")
            for stmt in stmts_:
                self.log.error("<<< %s", stmt)
            raise AssertionError("mismatch in mkRules")

    def testNoSkip(self):
        """Test simple rule generation with no skipping."""

        A = lambda args: IptablesRule(args, target='ACCEPT')

        acls = [A(['-p', 'tcp',]),]
        rules = [['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertRules(rules, acls)

        acls = [A(['-p', 'tcp']),
                A(['-p', 'udp']),]
        rules = [['ip_proto', 'tcp', 'action', 'ok',],
                 ['ip_proto', 'udp', 'action', 'ok',],]
        self.assertRules(rules, acls)

    def testNoSkipInvert(self):
        """Verify that inversion does not break the line numbering."""

        A = lambda args: IptablesRule(args, target='ACCEPT')

        acls = [A(['-p', 'tcp', '!', '-s', '1.1.1.1/32',]),
                A(['-p', 'udp',]),]
        rules = [['ip_proto', 'tcp', 'src_ip', '1.1.1.1/32', 'action', 'jump', '1',],
                 ['ip_proto', 'tcp', 'action', 'ok',],
                 ['ip_proto', 'udp', 'action', 'ok',],]
        self.assertRules(rules, acls)

    def testSkip(self):
        """Test skipping across simple rules."""

        A = lambda args: IptablesRule(args, target='ACCEPT')
        S = lambda args, stride: IptablesRule(args,
                                              target='SKIP',
                                              target_args=['--skip-rules', str(stride),])

        # simple skip, no added rules

        acls = [A(['-p', 'tcp',]),     # line 1
                S(['-p', 'udp',], 1),  # line 2
                                       # skip 1 rule --> 1 TC filter
                A(['-p', 'tcp',])]     # line 3
        rules = [['ip_proto', 'tcp', 'action', 'ok',],
                 ['ip_proto', 'udp', 'action', 'jump', '1',],
                 ['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertRules(rules, acls)

        # a bit more complex, an added rule

        acls = [A(['-p', 'tcp',]),     # line 1
                S(['-p', 'udp',], 1),  # line 2
                                       # skip 1 rule --> 2 TC filters
                A(['-p', 'udp', '!', '--source-port', '5000',]),
                                       # line 3 --> expands to 2 TC filters
                A(['-p', 'tcp',])]     # line 4
        rules = [['ip_proto', 'tcp', 'action', 'ok',],
                 ['ip_proto', 'udp', 'action', 'jump', '2',],
                 ['ip_proto', 'udp', 'src_port', '5000', 'action', 'jump', '1',],
                 ['ip_proto', 'udp', 'action', 'ok',],
                 ['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertRules(rules, acls)

        # a bit more complex, two added rules

        acls = [A(['-p', 'tcp',]),     # line 1
                S(['-p', 'udp',], 1),  # line 2
                                       # skip 1 rule --> 3 TC filters
                A(['-p', 'udp',
                   '!', '--source-port', '5000',
                   '!', '--destination-port', '5000',]),
                                       # line 2
                                       # expands from 1 to 3 rules
                A(['-p', 'tcp',])]     # line 3
        rules = [['ip_proto', 'tcp', 'action', 'ok',],
                 ['ip_proto', 'udp', 'action', 'jump', '3',],
                 ['ip_proto', 'udp', 'src_port', '5000', 'action', 'jump', '2'],
                 ['ip_proto', 'udp', 'dst_port', '5000', 'action', 'jump', '1'],
                 ['ip_proto', 'udp', 'action', 'ok',],
                 ['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertRules(rules, acls)

    def testSkipOr(self):
        """Test skipping across from an OR-rule, with multiple source jumps."""

        A = lambda args: IptablesRule(args, target='ACCEPT')
        S = lambda args, stride: IptablesRule(args,
                                              target='SKIP',
                                              target_args=['--skip-rules', str(stride),])

        # simple proto match

        acls = [A(['-p', 'tcp',]),     # line 1
                S(['-p', 'udp',], 1),  # line 2
                                       # skip 1 rule --> 1 TC filter
                A(['-p', 'tcp',])]     # line 3
        rules = [['ip_proto', 'tcp', 'action', 'ok',],
                 ['ip_proto', 'udp', 'action', 'jump', '1',],
                 ['ip_proto', 'tcp', 'action', 'ok',],]
        ##self.assertRules(rules, acls)

        # negated proto results in an or-clause

        acls = [A(['-p', 'tcp',]),     # line 1
                S(['!', '-p', 'udp',], 1),
                                       # line 2
                                       # skip 1 rule --> 3 TC filter(s)
                A(['-p', 'tcp',])]     # line 3
        rules = [['ip_proto', 'tcp', 'action', 'ok',],
                 ['ip_proto', 'tcp', 'action', 'jump', '3',],
                 ['ip_proto', 'sctp', 'action', 'jump', '2',],
                 ['ip_proto', 'icmp', 'action', 'jump', '1',],
                 ['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertRules(rules, acls)

        # try again with a longer stride

        acls = [A(['-p', 'tcp',]),     # line 1
                S(['!', '-p', 'udp',], 1),
                                       # line 2
                                       # skip 1 rule --> 4 TC filter(s)
                A(['-p', 'tcp', '!', '-s', '1.1.1.1/32',])]
                                       # line 3 --> 2 rules
        rules = [['ip_proto', 'tcp', 'action', 'ok',],
                 ['ip_proto', 'tcp', 'action', 'jump', '4',],
                 ['ip_proto', 'sctp', 'action', 'jump', '3',],
                 ['ip_proto', 'icmp', 'action', 'jump', '2',],
                 ['ip_proto', 'tcp', 'src_ip', '1.1.1.1/32', 'action', 'jump', '1',],
                 ['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertRules(rules, acls)

    def testSkipNoop(self):
        """Test with a zero-length skip.

        XXX rothcar -- is the actually a no-op, or do was skip to the end
        of the IPTABLES rule?

        I'll make the claim here that 'skip 0' means "skip to the end of the rule".
        """

        A = lambda args: IptablesRule(args, target='ACCEPT')
        S = lambda args, stride: IptablesRule(args,
                                              target='SKIP',
                                              target_args=['--skip-rules', str(stride),])

        acls = [A(['-p', 'tcp',]),     # line 1
                S(['-p', 'udp',], 0),  # line 2
                                       # skip 0 rule --> 0 TC filters
                A(['-p', 'tcp',])]     # line 3
        rules = [['ip_proto', 'tcp', 'action', 'ok',],
                 ['ip_proto', 'udp', 'action', 'jump', '0',],
                 ['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertRules(rules, acls)

        # add an implicit TC rule, but it's a tail expansion so still a zero jump

        acls = [A(['-p', 'tcp',]),     # line 1
                S(['-p', 'udp', '!', '-s', '1.1.1.1/32',], 0),
                                       # line 2
                                       # skip 0 rules --> 1 TC filters
                A(['-p', 'tcp',]),]
                                       # line 3 --> 0 TC filters
        rules = [['ip_proto', 'tcp', 'action', 'ok',],
                 ['ip_proto', 'udp', 'src_ip', '1.1.1.1/32', 'action', 'jump', '1',],
                 ['ip_proto', 'udp', 'action', 'jump', '0',],
                 ['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertRules(rules, acls)

        # two negated terms, still a zero jump

        acls = [A(['-p', 'tcp',]),     # line 1
                S(['-p', 'udp',
                   '!', '-s', '1.1.1.1/32',
                   '!', '-d', '1.1.1.1/32'], 0),
                                       # line 2
                                       # skip 0 rules --> 1 TC filters
                A(['-p', 'tcp',]),]
                                       # line 3 --> 0 TC filters
        rules = [['ip_proto', 'tcp', 'action', 'ok',],
                 ['ip_proto', 'udp', 'src_ip', '1.1.1.1/32', 'action', 'jump', '2',],
                 ['ip_proto', 'udp', 'dst_ip', '1.1.1.1/32', 'action', 'jump', '1',],
                 ['ip_proto', 'udp', 'action', 'jump', '0',],
                 ['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertRules(rules, acls)

    def testSkipOrNoop(self):
        """Test a no-op skip from an or-clause."""

        A = lambda args: IptablesRule(args, target='ACCEPT')
        S = lambda args, stride: IptablesRule(args,
                                              target='SKIP',
                                              target_args=['--skip-rules', str(stride),])

        # negated proto results in an or-clause

        acls = [A(['-p', 'tcp',]),     # line 1
                S(['!', '-p', 'udp',], 0),
                                       # line 2
                                       # skip 1 rule --> 2 TC filter(s)
                A(['-p', 'tcp',])]     # line 3
        rules = [['ip_proto', 'tcp', 'action', 'ok',],
                 ['ip_proto', 'tcp', 'action', 'jump', '2',],
                 ['ip_proto', 'sctp', 'action', 'jump', '1',],
                 ['ip_proto', 'icmp', 'action', 'jump', '0',],
                 ['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertRules(rules, acls)

        # try again with a longer stride

        acls = [A(['-p', 'tcp',]),     # line 1
                S(['!', '-p', 'udp',], 0),
                                       # line 2
                                       # skip 1 rule --> 3 TC filter(s)
                A(['-p', 'tcp', '!', '-s', '1.1.1.1/32',])]
                                       # line 3 --> 2 rules
        rules = [['ip_proto', 'tcp', 'action', 'ok',],
                 ['ip_proto', 'tcp', 'action', 'jump', '2',],
                 ['ip_proto', 'sctp', 'action', 'jump', '1',],
                 ['ip_proto', 'icmp', 'action', 'jump', '0',],
                 ['ip_proto', 'tcp', 'src_ip', '1.1.1.1/32', 'action', 'jump', '1',],
                 ['ip_proto', 'tcp', 'action', 'ok',],]
        self.assertRules(rules, acls)

class LoaderTest(unittest.TestCase):
    """Test the TC statement generation in TcFlowerLoader."""

    def setUp(self):
        self.log = logger.getChild(self.id())

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],
                   'dummy2' : ['port',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        os.environ['TEST_VLANS_JSON'] = json.dumps({})
        os.environ['TEST_SVIS_JSON'] = json.dumps({})

    def tearDown(self):
        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def assertAclFilters(self, filterSpecs, acl,
                         version=socket.AF_INET,
                         interfaces=None,
                         match_multi=False, port_unroll=None, hack_vlan_arp=False):
        r0 = IptablesRule(acl, 'ACCEPT')
        chain = IptablesChain([r0,], 'RETURN')
        table = FilterTable({}, log=self.log)
        loader = Loader(table, 'FORWARD',
                        interfaces=interfaces,
                        version=version,
                        match_multi=match_multi,
                        port_unroll=port_unroll,
                        hack_vlan_arp=hack_vlan_arp,
                        log=self.log)
        recs = list(loader.mkRules(chain, dev='dummy0', policy='ACCEPT'))

        recs_ = []
        hnd = 1
        pref = 32768
        for filterSpec in filterSpecs:
            proto, filterArgs, action = filterSpec
            args = ['tc', 'filter', 'add', 'dev', 'dummy0',]
            args.extend(['protocol', proto,])
            args.append('ingress')
            args.extend(['handle', str(hnd),])
            args.extend(['pref', str(pref),])
            args.append('flower')
            args.append('verbose')
            args.extend(filterArgs)
            args.extend(['action', action,])

            recs_.append((hnd, pref, args,))

            hnd += 1
            pref += 1

        self.assertEqual(recs_, recs)

    def testSimple(self):

        acl = []
        recs = [['ip', [], 'ok',],]
        self.assertAclFilters(recs, acl)

        acl = ['-p', 'tcp',]
        recs = [['ip', ['ip_proto', 'tcp',], 'ok',],]
        self.assertAclFilters(recs, acl)

    def testSimpleMulti(self):

        acl = ['-s', '1.1.1.1,1.1.1.2',]
        recs = [['ip', ['src_ip', '1.1.1.1',], 'ok',],
                ['ip', ['src_ip', '1.1.1.2',], 'ok',],
        ]
        self.assertAclFilters(recs, acl,
                              match_multi=True)

    def testSimpleUnroll(self):

        acl = ['-p', 'tcp', '--sport', '80:81',]
        recs = [['ip', ['ip_proto', 'tcp', 'src_port', '80-81',], 'ok',],
        ]
        self.assertAclFilters(recs, acl)

        acl = ['-p', 'tcp', '--sport', '80:81',]
        recs = [['ip', ['ip_proto', 'tcp', 'src_port', '80',], 'ok',],
                ['ip', ['ip_proto', 'tcp', 'src_port', '81',], 'ok',],
        ]
        self.assertAclFilters(recs, acl,
                              port_unroll=5)

    def testSimpleIpv6(self):

        acl = []
        recs = [['ipv6', [], 'ok',],]
        self.assertAclFilters(recs, acl, version=socket.AF_INET6)

        acl = ['-p', 'tcp',]
        recs = [['ipv6', ['ip_proto', 'tcp',], 'ok',],]
        self.assertAclFilters(recs, acl, version=socket.AF_INET6)

    def testSimpleIpv6Multi(self):

        acl = ['-s', '2001::1/128,2001::2/128',]
        recs = [['ipv6', ['src_ip', '2001::1/128',], 'ok',],
                ['ipv6', ['src_ip', '2001::2/128',], 'ok',],
        ]
        self.assertAclFilters(recs, acl,
                              version=socket.AF_INET6, match_multi=True)

    def testVlan(self):

        acl = ['-m', 'vlan', '--vlan-tag', '42',]
        args = ['vlan_ethtype', 'ipv4', 'vlan_id', '42',]
        recs = [['802.1q', args, 'ok',],]
        self.assertAclFilters(recs, acl)

        acl = ['-m', 'vlan', '--vlan-tag', '42',
               '-p', 'tcp',]
        args = ['vlan_ethtype', 'ipv4', 'vlan_id', '42', 'ip_proto', 'tcp',]
        recs = [['802.1q', args, 'ok',],]
        self.assertAclFilters(recs, acl)

        acl = ['-m', 'vlan', '--vlan-tag', 'any',
               '-p', 'tcp',]
        args = ['vlan_ethtype', 'ipv4', 'ip_proto', 'tcp',]
        recs = [['802.1q', args, 'ok',],]
        self.assertAclFilters(recs, acl)

    def testVlanIpv6(self):

        acl = ['-m', 'vlan', '--vlan-tag', '42',]
        args = ['vlan_ethtype', 'ipv6', 'vlan_id', '42',]
        recs = [['802.1q', args, 'ok',],]
        self.assertAclFilters(recs, acl, version=socket.AF_INET6)

        acl = ['-m', 'vlan', '--vlan-tag', '42',
               '-p', 'tcp',]
        args = ['vlan_ethtype', 'ipv6', 'vlan_id', '42', 'ip_proto', 'tcp',]
        recs = [['802.1q', args, 'ok',],]
        self.assertAclFilters(recs, acl, version=socket.AF_INET6)

        acl = ['-m', 'vlan', '--vlan-tag', 'any',
               '-p', 'tcp',]
        args = ['vlan_ethtype', 'ipv6', 'ip_proto', 'tcp',]
        recs = [['802.1q', args, 'ok',],]
        self.assertAclFilters(recs, acl, version=socket.AF_INET6)

    def testArpHack(self):

        acl = ['-p', 'tcp',]
        args = ['ip_proto', 'tcp',]
        recs = [['ip', args, 'ok',],]
        self.assertAclFilters(recs, acl)

        recs = [['802.1q', ['vlan_ethtype', 'arp',], 'ok',],
                ['ip', args, 'ok',],
        ]

        self.assertAclFilters(recs, acl,
                              hack_vlan_arp=True)

if __name__ == "__main__":
    unittest.main()
