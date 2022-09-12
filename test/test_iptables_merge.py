"""test_iptable_merge.py

Test different unslicer/merge algorithms.
"""

import sys, os

import logging
import unittest
import json

import path_config

logger = None
def setUpModule():
    global logger
    logging.basicConfig()
    logger = logging.getLogger("unittest")
    logger.setLevel(logging.DEBUG)

import TcSaveTestUtils

from petunia.Iptables import (
    FilterTable,
    IptablesRule,
    IptablesChain,
)
from petunia.Unslicer import (
    Unslicer,
    UuidChain,
    simpleMerge,
    simpleSuffixMerge,
    simplePrefixMerge,
)
from petunia.Slicer import SliceTable

class HashTest(TcSaveTestUtils.IptablesTestMixin,
               unittest.TestCase):
    """Test rule hashing."""

    def setUp(self):
        self.log = logger.getChild(self.id())

    def testRuleHash(self):

        def R(spec):
            return list(IptablesRule.fromIptablesSave(spec))[0]

        r0 = R("-p tcp -s 10.0.0.1 -j ACCEPT")
        r1 = R("-p tcp -s 10.0.1.1 -j ACCEPT")

        self.assertNotEqual(hash(r0), hash(r1))

        r0 = R("-p tcp -s 10.0.0.1 -j ACCEPT")
        r1 = R("-p tcp -s 10.0.0.1 -j DROP")

        self.assertNotEqual(hash(r0), hash(r1))

        r0 = R("-p tcp -s 10.0.0.1 -j ACCEPT")
        r1 = R("-p tcp -s 10.0.0.1 -g ACCEPT")

        self.assertNotEqual(hash(r0), hash(r1))

        r0 = R("-p tcp -s 10.0.0.1 -m comment --comment \"comment 1\" -j ACCEPT")
        r1 = R("-p tcp -s 10.0.0.1 -m comment --comment \"comment 2\" -j ACCEPT")

        self.assertNotEqual(hash(r0), hash(r1))

        r0 = R("-p tcp -s 10.0.0.1 -j ACCEPT")
        r1 = R("-p tcp -s 10.0.0.1 -j ACCEPT")

        self.assertEqual(hash(r0), hash(r1))

        r0 = R("-p tcp -s 10.0.0.1 -m comment --comment \"comment 1\" -j ACCEPT")
        r1 = R("-p tcp -s 10.0.0.1 -m comment --comment \"comment 1\" -j ACCEPT")

        self.assertEqual(hash(r0), hash(r1))

        r0 = R("-p tcp -s 10.0.0.1 -j SKIP --skip-rules 1")
        r1 = R("-p tcp -s 10.0.0.1 -j SKIP --skip-rules 2")

        self.assertNotEqual(hash(r0), hash(r1))

        r0 = R("-p tcp -s 10.0.0.1 -j SKIP --skip-rules 1")
        r1 = R("-p tcp -s 10.0.0.1 -j SKIP --skip-rules 1")

        self.assertEqual(hash(r0), hash(r1))

    def testChainHash(self):

        def C(specs):
            rules = []
            [rules.extend(IptablesRule.fromIptablesSave(x)) for x in specs]
            return IptablesChain(rules, 'RETURN')

        c0 = C(["-p tcp -s 10.0.0.1 -j ACCEPT",])
        c1 = C(["-p tcp -s 10.0.0.1 -j ACCEPT",])
        self.assertEqual(hash(c0), hash(c1))

        c0 = C(["-p tcp -s 10.0.0.1 -j ACCEPT",])
        c1 = C(["-p tcp -s 10.0.1.1 -j ACCEPT",])
        self.assertNotEqual(hash(c0), hash(c1))

        c0 = C(["-p tcp -s 10.0.0.1 -j ACCEPT",
                "-p tcp -s 10.0.0.2 -j ACCEPT",])
        c1 = C(["-p tcp -s 10.0.0.1 -j ACCEPT",
                "-p tcp -s 10.0.0.2 -j ACCEPT",])
        self.assertEqual(hash(c0), hash(c1))

        c0 = C(["-p tcp -s 10.0.0.2 -j ACCEPT",
                "-p tcp -s 10.0.0.1 -j ACCEPT",])
        c1 = C(["-p tcp -s 10.0.0.1 -j ACCEPT",
                "-p tcp -s 10.0.0.2 -j ACCEPT",])
        self.assertNotEqual(hash(c0), hash(c1))

        c0 = C(["-p tcp -s 10.0.0.1 -j ACCEPT",
                "-p tcp -s 10.0.0.2 -j ACCEPT",])
        c1 = C(["-p tcp -s 10.0.0.1 -j ACCEPT",
                "-p tcp -s 10.0.0.2 -j ACCEPT",
                "-p tcp -s 10.0.0.3 -j ACCEPT",])
        self.assertNotEqual(hash(c0), hash(c1))

        c0 = C(["-p tcp -s 10.0.0.2 -j ACCEPT",
                "-p tcp -s 10.0.0.3 -j ACCEPT",])
        c1 = C(["-p tcp -s 10.0.0.1 -j ACCEPT",
                "-p tcp -s 10.0.0.2 -j ACCEPT",
                "-p tcp -s 10.0.0.3 -j ACCEPT",])
        self.assertNotEqual(hash(c0), hash(c1))

class UuidTestBase(object):

    def assertUuidChain(self, chain, uuidChain):
        self.assertEqual(1+len(chain.rules), len(uuidChain.rules))
        uuidChain_ = uuidChain.toIptablesChain()
        if hash(chain) != hash(uuidChain_):
            self.log.error("UUID chain:")
            for rule in uuidChain.rules:
                buf = rule.toSave('FORWARD')
                sys.stderr.write("%s # UUID %s\n"
                                 % (buf, rule.uuid,))
            sys.stderr.write(uuidChain.toSave('FORWARD') + "\n")
            self.log.error("UUID chain, after conversion:")
            sys.stderr.write(uuidChain_.toSave('FORWARD') + "\n")
            self.log.error("expected chain:")
            sys.stderr.write(chain.toSave('FORWARD') + "\n")
            raise AssertionError("UUID chain did not convert correctly")
        self.assertEqual(hash(chain), hash(uuidChain_))

class UuidInsertTest(UuidTestBase,
                     unittest.TestCase):
    """Test the UUID-based IPTABLES chain and rules."""

    def setUp(self):
        self.log = logger.getChild(self.id())

    def testChainNoInsert(self):

        def R(line):
            return next(iter(IptablesRule.fromIptablesSave(line)))

        r = IptablesRule
        c = IptablesChain
        C = UuidChain

        # simple rule translate to and fro

        r0 = R("-p tcp -s 10.0.0.1 -j ACCEPT")

        chain = c([r0,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)

        self.assertUuidChain(chain, chain_)

        # simple skip to and fro

        r0 = R("-j SKIP --skip-rules 0")

        chain = c([r0,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)

        self.assertUuidChain(chain, chain_)

        # skip, not to the end

        r0 = R("-j SKIP --skip-rules 1")
        r1 = R("-p tcp -s 10.0.0.1 -j ACCEPT")
        r2 = R("-p tcp -s 10.0.0.2 -j ACCEPT")

        chain = c([r0, r1, r2,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)

        self.assertUuidChain(chain, chain_)

        # skip to the end

        r0 = R("-j SKIP --skip-rules 1")
        r1 = R("-p tcp -s 10.0.0.1 -j ACCEPT")

        chain = c([r0, r1,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)

        self.assertUuidChain(chain, chain_)

    def testChainInsertNoSkip(self):
        """Test the UUID chains in the presence of insert."""

        def R(line):
            return next(iter(IptablesRule.fromIptablesSave(line)))

        r = IptablesRule
        c = IptablesChain
        C = UuidChain

        # simple inserts with no SKIP

        r0 = R("-p tcp -s 10.0.0.1 -j ACCEPT")
        r1 = R("-p tcp -s 10.0.0.2 -j ACCEPT")
        r2 = R("-p tcp -s 10.0.0.3 -j ACCEPT")

        r4 = R("-p tcp -s 10.0.0.4 -j ACCEPT")

        # insert at the beginning

        chain = c([r0, r1, r2,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.insertRule(0, r4)

        chain = c([r4, r0, r1, r2,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # insert in the middle

        chain = c([r0, r1, r2,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.insertRule(1, r4)

        chain = c([r0, r4, r1, r2,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # append

        chain = c([r0, r1, r2,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)

        # not allowed with overrideTarget=True
        with self.assertRaises(ValueError):
            chain_.insertRule(3, r4)
            chain = c([r0, r1, r2, r4,], 'RETURN')
            self.assertUuidChain(chain, chain_)

    def testChainInsertSkipNoSkip(self):
        """Insert a non-skip into a chain that includes skips."""

        def R(line):
            return next(iter(IptablesRule.fromIptablesSave(line)))

        r = IptablesRule
        c = IptablesChain
        C = UuidChain

        # chain with a bunch of skips

        r0 = R("-j SKIP --skip-rules 0")
        r1 = R("-p tcp -s 10.0.0.1 -j ACCEPT")
        r2 = R("-j SKIP --skip-rules 1")
        r3 = R("-p tcp -s 10.0.0.2 -j ACCEPT")
        r4 = R("-p tcp -s 10.0.0.3 -j ACCEPT")
        r5 = R("-j SKIP --skip-rules 1")
        r6 = R("-p tcp -s 10.0.0.4 -j ACCEPT")

        r7 = R("-p tcp -s 10.0.0.5 -j ACCEPT")

        # let's make sure the original chain translates correctly

        chain = c([r0, r1, r2, r3, r4, r5, r6,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)

        self.assertUuidChain(chain, chain_)

        # insert on both sides of the first skip

        chain = c([r0, r1, r2, r3, r4, r5, r6,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.insertRule(0, r7)

        chain = c([r7, r0, r1, r2, r3, r4, r5, r6,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # insert a rule directly at a jump target
        # here, r0's SKIP target should be updated to point to r7

        chain = c([r0, r1, r2, r3, r4, r5, r6,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.insertRule(1, r7)

        chain = c([r0, r7, r1, r2, r3, r4, r5, r6,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # insert a rule after the 2nd skip
        # it's not a skip target, but the other SKIPs
        # that stride it should be updated

        chain = c([r0, r1, r2, r3, r4, r5, r6,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.insertRule(3, r7)

        r2_ = R("-j SKIP --skip-rules 2")
        chain = c([r0, r1, r2_, r7, r3, r4, r5, r6,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # insert a rule at the target of the 2nd skip

        chain = c([r0, r1, r2, r3, r4, r5, r6,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.insertRule(4, r7)

        chain = c([r0, r1, r2, r3, r7, r4, r5, r6,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # we are not allowed to insert a rule at the end

        chain = c([r0, r1, r2, r3, r4, r5, r6,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        with self.assertRaises(ValueError):
            chain_.insertRule(7, r7)

    def testChainInsertNoSkipSkip(self):
        """Insert a skip into a chain that does not include skips."""

        def R(line):
            return next(iter(IptablesRule.fromIptablesSave(line)))

        r = IptablesRule
        c = IptablesChain
        C = UuidChain

        # simple insert of a zero-skip rule

        r0 = R("-p tcp -s 10.0.0.1 -j ACCEPT")
        r1 = R("-p tcp -s 10.0.0.2 -j ACCEPT")

        r2 = R("-j SKIP --skip-rules 0")

        chain = c([r0, r1,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.insertRule(0, r2)

        chain = c([r2, r0, r1,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # insert into the middle

        chain = c([r0, r1,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.insertRule(1, r2)

        chain = c([r0, r2, r1,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # insert at the end

        chain = c([r0, r1,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)

        with self.assertRaises(ValueError):
            chain_.insertRule(2, r2)
            chain = c([r0, r1, r2,], 'RETURN')
            self.assertUuidChain(chain, chain_)

        # insert a non-zero length skip

        r0 = R("-p tcp -s 10.0.0.1 -j ACCEPT")
        r1 = R("-p tcp -s 10.0.0.2 -j ACCEPT")

        r2 = R("-j SKIP --skip-rules 1")
        r3 = R("-p tcp -s 10.0.0.3 -j ACCEPT")

        chain = c([r0, r1,], 'RETURN')

        # insert in reverse order to not adjust r2's stride
        chain_ = C.fromIptablesChain(chain)
        chain_.insertRule(0, r3)
        chain_.insertRule(0, r2)

        chain = c([r2, r3, r0, r1,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # insert a non-zero length skip in the middle

        chain = c([r0, r1,], 'RETURN')

        # insert in reverse order to not adjust r2's stride
        chain_ = C.fromIptablesChain(chain)
        chain_.insertRule(1, r3)
        chain_.insertRule(1, r2)

        chain = c([r0, r2, r3, r1,], 'RETURN')

        self.assertUuidChain(chain, chain_)

    def testChainExit(self):
        """Verify we can insert exit rules."""

        def R(line):
            return next(iter(IptablesRule.fromIptablesSave(line)))

        r = IptablesRule
        c = IptablesChain
        C = UuidChain

        # insert at the start

        r0 = R("-p tcp -s 10.0.0.1 -j ACCEPT")
        r1 = R("-p tcp -s 10.0.0.2 -j ACCEPT")

        r2 = R("-j SKIP --skip-rules 2")

        chain = c([r0, r1,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.insertRule(0, r2)

        chain = c([r2, r0, r1,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # insert in the middle

        r2 = R("-j SKIP --skip-rules 1")

        chain = c([r0, r1,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.insertRule(1, r2)

        chain = c([r0, r2, r1,], 'RETURN')

        self.assertUuidChain(chain, chain_)

class UuidAppendTest(UuidTestBase,
                     unittest.TestCase):
    """Test the UUID-based IPTABLES chain and rules."""

    def setUp(self):
        self.log = logger.getChild(self.id())

    def testSimpleAppend(self):

        def R(line):
            return next(iter(IptablesRule.fromIptablesSave(line)))

        r0 = R("-p tcp -s 10.0.0.1 -j ACCEPT")
        r1 = R("-p tcp -s 10.0.0.2 -j ACCEPT")
        r2 = R("-p tcp -s 10.0.0.3 -j ACCEPT")

        r = IptablesRule
        c = IptablesChain
        C = UuidChain

        # beginning

        chain = c([r0, r1,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.appendRule(0, r2)

        chain = c([r2, r0, r1,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # middle

        chain = c([r0, r1,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.appendRule(1, r2)

        chain = c([r0, r2, r1,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # end
        # this is OK for append but not for insert

        chain = c([r0, r1,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.appendRule(2, r2)

        chain = c([r0, r1, r2,], 'RETURN')

        self.assertUuidChain(chain, chain_)

    def testZeroSkipTarget(self):

        def R(line):
            return next(iter(IptablesRule.fromIptablesSave(line)))

        r0 = R("-j SKIP --skip-rules 0")

        r1 = R("-p tcp -s 10.0.0.2 -j ACCEPT")

        r = IptablesRule
        c = IptablesChain
        C = UuidChain

        # ok to append at position zero

        chain = c([r0,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.appendRule(0, r1)

        chain = c([r1, r0,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # position 1 adjusts the skip

        chain = c([r0,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.appendRule(1, r1)

        r0_ = R("-j SKIP --skip-rules 1")

        chain = c([r0_, r1], 'RETURN')

        self.assertUuidChain(chain, chain_)

    def testNonZeroSkipTarget(self):

        def R(line):
            return next(iter(IptablesRule.fromIptablesSave(line)))

        r0 = R("-j SKIP --skip-rules 1")
        r1 = R("-p tcp -s 10.0.0.1 -j ACCEPT")
        r2 = R("-p tcp -s 10.0.0.2 -j ACCEPT")

        r = IptablesRule
        c = IptablesChain
        C = UuidChain

        # append after the skip, it should extend the skip

        chain = c([r0, r1,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.appendRule(1, r2)

        r0_ = R("-j SKIP --skip-rules 2")
        chain = c([r0_, r2, r1,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # at the skip target also extends the skip

        chain = c([r0, r1,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.appendRule(2, r2)

        r0_ = R("-j SKIP --skip-rules 2")
        chain = c([r0_, r1, r2,], 'RETURN')

        self.assertUuidChain(chain, chain_)

    def testSkipInsert(self):
        """Insert rules with skips."""

        def R(line):
            return next(iter(IptablesRule.fromIptablesSave(line)))

        r = IptablesRule
        c = IptablesChain
        C = UuidChain

        r0 = R("-p tcp -s 10.0.0.1 -j ACCEPT")
        r1 = R("-p tcp -s 10.0.0.2 -j ACCEPT")
        r2 = R("-j SKIP --skip-rules 0")

        # append at beginning

        chain = c([r0, r1,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.appendRule(0, r2)

        chain = c([r2, r0, r1,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # append at ene

        chain = c([r0, r1,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.appendRule(2, r2)

        chain = c([r0, r1, r2,], 'RETURN')

        self.assertUuidChain(chain, chain_)

    def testSkipExit(self):
        """Insert rules that exit."""

        def R(line):
            return next(iter(IptablesRule.fromIptablesSave(line)))

        r = IptablesRule
        c = IptablesChain
        C = UuidChain

        r0 = R("-p tcp -s 10.0.0.1 -j ACCEPT")
        r1 = R("-p tcp -s 10.0.0.2 -j ACCEPT")

        r2 = R("-j SKIP --skip-rules 2")

        # append at beginning

        chain = c([r0, r1,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.appendRule(0, r2)

        chain = c([r2, r0, r1,], 'RETURN')

        self.assertUuidChain(chain, chain_)

        # append at middle

        r2 = R("-j SKIP --skip-rules 1")

        chain = c([r0, r1,], 'RETURN')

        chain_ = C.fromIptablesChain(chain)
        chain_.appendRule(1, r2)

        chain = c([r0, r2, r1,], 'RETURN')

        self.assertUuidChain(chain, chain_)

class MergeTestMixin(object):

    def assertSimpleMerge(self, addresses, rules):
        """Verify that the merge results are correct."""

        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        sys.stdout.write(table.toSave())

        unslicer = Unslicer(table, 'FORWARD',
                            log=self.log.getChild("slice"))
        table_ = unslicer.unslice(merge_fn=simpleMerge)

        sys.stdout.write(table_.toSave())

        self.assertAddresses(addresses, table_)

    def assertAnyMerge(self, mergedRules, rules, merge_fn):

        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        sys.stdout.write(table.toSave())

        unslicer = Unslicer(table, 'FORWARD',
                            log=self.log.getChild("slice"))
        table_ = unslicer.unslice(merge_fn=merge_fn)

        sys.stdout.write(table_.toSave())

        chain = table_.chains['FORWARD']
        mergedRules_ = []
        for rule in chain.rules:
            args = ['-A', 'FORWARD',]
            if rule.in_interface:
                args.append('-i')
                args.append(rule.in_interface)
            args.extend(rule.args)
            args.append('-j')
            args.append(rule.target)
            args.extend(rule.target_args)
            mergedRules_.append(" ".join(args))

        self.assertEqual(mergedRules, mergedRules_)

    def assertSimpleSuffixMerge(self, mergedRules, rules):
        """Verify that the merge results are correct."""
        self.assertAnyMerge(mergedRules, rules,
                            merge_fn=simpleSuffixMerge)

    def assertSimpleSuffixGroupMerge(self, mergedRules, rules):
        """Verify that the suffix merge results are correct with ifGroups.."""

        def _fn(table):
            table.log.info("merging whole chains")
            table = simpleMerge(table)
            table.log.info("merging suffixes")
            table = simpleSuffixMerge(table)
            return table

        self.assertAnyMerge(mergedRules, rules,
                            merge_fn=_fn)

    def assertSimplePrefixMerge(self, mergedRules, rules):
        """Verify that the merge results are correct."""
        self.assertAnyMerge(mergedRules, rules,
                            merge_fn=simplePrefixMerge)

    def assertSimplePrefixGroupMerge(self, mergedRules, rules):
        """Verify that the prefix merge results are correct with ifGroups.."""

        def _fn(table):
            table.log.info("merging whole chains")
            table = simpleMerge(table)
            table.log.info("merging prefixes")
            table = simplePrefixMerge(table)
            return table

        self.assertAnyMerge(mergedRules, rules,
                            merge_fn=_fn)

    def assertSimplePrefixSuffixMerge(self, mergedRules, rules, prefixOnly=True):
        """Verify that the prefix/suffix merge works."""

        def _fn(table):
            table.log.info("merging suffixes")
            table = simpleSuffixMerge(table)
            self.log.info("here is the suffix-merged table:")
            table.log.info("merging prefixes")
            table = simplePrefixMerge(table,
                                      prefixOnly=prefixOnly)
            return table

        self.assertAnyMerge(mergedRules, rules,
                            merge_fn=_fn)

class SimpleMergeTest(MergeTestMixin,
                      TcSaveTestUtils.IptablesTestMixin,
                      unittest.TestCase):
    """Test chain merges using the simpleMerge algorithm."""

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

    def assertAddresses(self, addresses, table):
        """Slice out the --source-address matches."""

        rules = table.chains['FORWARD'].rules
        rules = [x for x in rules if '-s' in x.args]
        addresses_ = [x.args[3] for x in rules]
        self.assertEqual(addresses, addresses_)

    def testNoMerge(self):
        """Verify that non-mergeable chains are not merged."""

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",]

        # create three distinct chains
        idx0 = len(rules)
        rules.append("-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT")
        idx1 = len(rules)
        rules.append("-A FORWARD_dummy1 -p tcp -s 10.0.1.1 -j ACCEPT")
        idx2 = len(rules)
        rules.append("-A FORWARD_dummy2 -p tcp -s 10.0.2.1 -j ACCEPT")

        addrs = ['10.0.0.1',
                 '10.0.1.1',
                 '10.0.2.1',]

        self.assertSimpleMerge(addrs, rules)

    def testSingleMerge(self):
        """Try to merge single rules."""

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",]

        # create three distinct chains
        idx0 = len(rules)
        rules.append("-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT")
        idx1 = len(rules)
        rules.append("-A FORWARD_dummy1 -p tcp -s 10.0.1.1 -j ACCEPT")
        idx2 = len(rules)
        rules.append("-A FORWARD_dummy2 -p tcp -s 10.0.2.1 -j ACCEPT")

        addrs = ['10.0.0.1',
                 '10.0.1.1',
                 '10.0.2.1',]

        self.assertSimpleMerge(addrs, rules)

        # dummy1 is mergeable with dummy0

        rule_ = rules[idx1]
        rules[idx1] = "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT"

        addrs = ['10.0.0.1',
                 '10.0.2.1',]

        self.assertSimpleMerge(addrs, rules)

        rules[idx1] = rule_

        # dummy2 is mergeable with dummy0

        rule_ = rules[idx2]
        rules[idx2] = "-A FORWARD_dummy2 -p tcp -s 10.0.0.1 -j ACCEPT"

        addrs = ['10.0.0.1',
                 '10.0.1.1',]

        self.assertSimpleMerge(addrs, rules)

        rules[idx2] = rule_

        # dummy2 is mergeable with dummy1

        rule_ = rules[idx2]
        rules[idx2] = "-A FORWARD_dummy2 -p tcp -s 10.0.1.1 -j ACCEPT"

        addrs = ['10.0.0.1',
                 '10.0.1.1',]

        self.assertSimpleMerge(addrs, rules)

        rules[idx2] = rule_

        # all mergeable

        rules[idx1] = "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT"
        rules[idx2] = "-A FORWARD_dummy2 -p tcp -s 10.0.0.1 -j ACCEPT"

        addrs = ['10.0.0.1',]

        self.assertSimpleMerge(addrs, rules)

    def testDoubleMerge(self):
        """Verify that the merge can be accomplished with longer chains."""

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",]

        idx0 = len(rules)
        rules.append("-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT")
        rules.append("-A FORWARD_dummy0 -p tcp -s 10.0.0.2 -j ACCEPT")

        idx1 = len(rules)
        rules.append("-A FORWARD_dummy1 -p tcp -s 10.0.1.1 -j ACCEPT")
        rules.append("-A FORWARD_dummy1 -p tcp -s 10.0.1.2 -j ACCEPT")

        idx2 = len(rules)
        rules.append("-A FORWARD_dummy2 -p tcp -s 10.0.2.1 -j ACCEPT")
        rules.append("-A FORWARD_dummy2 -p tcp -s 10.0.2.2 -j ACCEPT")

        addrs = ['10.0.0.1',
                 '10.0.0.2',
                 '10.0.1.1',
                 '10.0.1.2',
                 '10.0.2.1',
                 '10.0.2.2',]

        self.assertSimpleMerge(addrs, rules)

        # dummy1 is almost mergeable with dummy0

        rules[idx1] = "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT"

        addrs = ['10.0.0.1',
                 '10.0.0.2',
                 '10.0.0.1',
                 '10.0.1.2',
                 '10.0.2.1',
                 '10.0.2.2',]

        self.assertSimpleMerge(addrs, rules)

        # dummy1 is fully mergeable with dummy0

        rules[idx1+1] = "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT"

        addrs = ['10.0.0.1',
                 '10.0.0.2',
                 '10.0.2.1',
                 '10.0.2.2',]

        self.assertSimpleMerge(addrs, rules)

        # dummy1 includes the same rules, but in the reverse order -- not merged

        rules[idx1] = "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT"
        rules[idx1+1] = "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT"

        addrs = ['10.0.0.1',
                 '10.0.0.2',
                 '10.0.0.2',
                 '10.0.0.1',
                 '10.0.2.1',
                 '10.0.2.2',]

        self.assertSimpleMerge(addrs, rules)

class SimpleSuffixMergeTest(MergeTestMixin,
                            TcSaveTestUtils.IptablesTestMixin,
                            unittest.TestCase):
    """Test chain merges using the simpleSuffixMerge algorithm."""

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

    def testNoMerge(self):
        """Verify that non-mergeable chains are not merged."""

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 2",
                  "-A FORWARD -j SKIP --skip-rules 2",
                  "-A FORWARD -j SKIP --skip-rules 1",
                  "-A FORWARD -j SKIP --skip-rules 0",
        ]

        self.assertSimpleSuffixMerge(rules_, rules)

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.1.1 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.2.1 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",    # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 3",    # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 4",    # 3.
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",        # 4.
                  "-A FORWARD -j SKIP --skip-rules 4",              # 5.
                  "-A FORWARD -p tcp -s 10.0.1.1 -j ACCEPT",        # 6.
                  "-A FORWARD -j SKIP --skip-rules 2",              # 7.
                  "-A FORWARD -p tcp -s 10.0.2.1 -j ACCEPT",        # 8.
                  "-A FORWARD -j SKIP --skip-rules 0",              # 9.
        ]

        self.assertSimpleSuffixMerge(rules_, rules)

    def testMergeFail(self):

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        # this causes the suffix algorithm to fail (dummy0 and dummy1
        # are 100% overlapping)

        with self.assertRaises(ValueError):
            self.assertSimpleSuffixMerge([], rules)

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        # dummy1 and dummy2 are empty,
        # which is technically a subset of dummy0...

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 3",
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 3",

                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",
                  "-A FORWARD -j SKIP --skip-rules 2",
                  "-A FORWARD -j SKIP --skip-rules 1",
                  "-A FORWARD -j SKIP --skip-rules 0",
        ]

        self.assertSimpleSuffixMerge(rules_, rules)

    def testMerge(self):

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.100.0.1 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",   # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 3",   # 3.

                  # dummy0
                  "-A FORWARD -p tcp -s 10.100.0.1 -j ACCEPT",     # 4.

                  # dummy0, dummy1
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",       # 5.
                  "-A FORWARD -j SKIP --skip-rules 1",             # 6.

                  # dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",             # 7.
        ]

        self.assertSimpleSuffixMerge(rules_, rules)

        # merge in the other direction

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.100.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 3",   # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",   # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 3",   # 3.

                  # dummy1
                  "-A FORWARD -p tcp -s 10.100.0.1 -j ACCEPT",     # 4.

                  # dummy0, dummy1
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",       # 5.
                  "-A FORWARD -j SKIP --skip-rules 1",             # 6.

                  # dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",             # 7.
        ]

        self.assertSimpleSuffixMerge(rules_, rules)

        # slightly longer example

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.100.0.1 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.100.0.2 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 3",   # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 5",   # 3.

                  # dummy0
                  "-A FORWARD -p tcp -s 10.100.0.1 -j ACCEPT",     # 4.
                  "-A FORWARD -p tcp -s 10.100.0.2 -j ACCEPT",     # 5.

                  # dummy0, dummy1
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",       # 6.
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",       # 7.
                  "-A FORWARD -j SKIP --skip-rules 1",             # 8.

                  # dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",             # 9.
        ]

        self.assertSimpleSuffixMerge(rules_, rules)

    def testMergeMulti(self):
        """Collapse multiple chains onto a parent chain"""

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.100 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.101 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.2 -j ACCEPT",

        ]

        # dummy1, dummy2 both are subsets of dummy0

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 3",   # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 2",   # 3.

                  # dummy0
                  "-A FORWARD -p tcp -s 10.0.0.100 -j ACCEPT",     # 4.
                  "-A FORWARD -p tcp -s 10.0.0.101 -j ACCEPT",     # 5.

                  # dummy1, dummy2
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",       # 6.
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",       # 7.
                  "-A FORWARD -j SKIP --skip-rules 0",             # 8.
        ]

        # however, dummy1, dummy2 are identical
        with self.assertRaises(ValueError):
            self.assertSimpleSuffixMerge(rules_, rules)

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.100 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.101 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.101 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.2 -j ACCEPT",

        ]

        # dummy0 is a parent of dummy1, dummy2, but not at the same offsets

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",   # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 2",   # 3.

                  # dummy0
                  "-A FORWARD -p tcp -s 10.0.0.100 -j ACCEPT",     # 4.

                  # dummy0,dummy1
                  "-A FORWARD -p tcp -s 10.0.0.101 -j ACCEPT",     # 5.

                  # dummy0, dummy1, dummy2
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",       # 6.
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",       # 7.
                  "-A FORWARD -j SKIP --skip-rules 0",             # 8.
        ]

        self.assertSimpleSuffixMerge(rules_, rules)

        # merge in the opposite order

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.101 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.100 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.101 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.2 -j ACCEPT",

        ]

        # dummy2 is a parent of dummy0, dummy1, but not at the same offsets

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 4",   # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",   # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 0",   # 3.

                  # dummy2
                  "-A FORWARD -p tcp -s 10.0.0.100 -j ACCEPT",     # 4.

                  # dummy1, dummy2
                  "-A FORWARD -p tcp -s 10.0.0.101 -j ACCEPT",     # 5.

                  # dummy0, dummy1, dummy2
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",       # 6.
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",       # 7.
                  "-A FORWARD -j SKIP --skip-rules 0",             # 8.
        ]

        self.assertSimpleSuffixMerge(rules_, rules)

    def testMergeGroup(self):
        """Collapse multiple chains onto a parent chain"""

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.100 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.101 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.2 -j ACCEPT",

        ]

        # dummy1, dummy2 both are subsets of dummy0

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 3",   # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 2",   # 3.

                  # dummy0
                  "-A FORWARD -p tcp -s 10.0.0.100 -j ACCEPT",     # 4.
                  "-A FORWARD -p tcp -s 10.0.0.101 -j ACCEPT",     # 5.

                  # dummy1, dummy2
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",       # 6.
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",       # 7.
                  "-A FORWARD -j SKIP --skip-rules 0",             # 8.
        ]

        # however, dummy1, dummy2 are identical
        self.assertSimpleSuffixGroupMerge(rules_, rules)

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.100 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.101 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.100 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.101 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.2 -j ACCEPT",

        ]

        # dummy2 is a subset of dummy0,dummy1

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",   # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 2",   # 3.

                  # dummy0,dummy1
                  "-A FORWARD -p tcp -s 10.0.0.100 -j ACCEPT",     # 4.
                  "-A FORWARD -p tcp -s 10.0.0.101 -j ACCEPT",     # 5.

                  # dummy2
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",       # 6.
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",       # 7.
                  "-A FORWARD -j SKIP --skip-rules 0",             # 8.
        ]

        # however, dummy1, dummy2 are identical
        self.assertSimpleSuffixGroupMerge(rules_, rules)

    def testMergeSkip(self):
        """Merge suffixes in the presence of skip rules."""

        # parent rule has a SKIP in it

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -j SKIP --skip-rules 1",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",   # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 4",   # 3.

                  # dummy0
                  "-A FORWARD -j SKIP --skip-rules 1",             # 4.

                  # dummy0,dummy1
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",       # 5.
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",       # 6.
                  "-A FORWARD -j SKIP --skip-rules 1",             # 7.

                  # dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",             # 8.
        ]

        self.assertSimpleSuffixMerge(rules_, rules)

        # child rule has a SKIP in it

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy0 -j SKIP --skip-rules 1",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.2 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.3 -j ACCEPT",

                 "-A FORWARD_dummy1 -j SKIP --skip-rules 1",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.3 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",   # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 5",   # 3.

                  # dummy0
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",       # 4.

                  # dummy0,dummy1

                  "-A FORWARD -j SKIP --skip-rules 1",             # 5.

                  # skip straddle is OK here (no rules inserted)

                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",       # 6.
                  "-A FORWARD -p tcp -s 10.0.0.3 -j ACCEPT",       # 7.
                  "-A FORWARD -j SKIP --skip-rules 1",             # 8.

                  # dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",             # 9.
        ]

        self.assertSimpleSuffixMerge(rules_, rules)

class SimplePrefixMergeTest(MergeTestMixin,
                            TcSaveTestUtils.IptablesTestMixin,
                            unittest.TestCase):
    """Test chain merges using the simplePrefixMerge algorithm."""

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

    def testNoMerge(self):
        """Verify that non-mergeable chains are not merged."""

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 2",
                  "-A FORWARD -j SKIP --skip-rules 2",
                  "-A FORWARD -j SKIP --skip-rules 1",
                  "-A FORWARD -j SKIP --skip-rules 0",
        ]

        self.assertSimplePrefixMerge(rules_, rules)

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.1.1 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.2.1 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",    # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 3",    # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 4",    # 3.
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",        # 4.
                  "-A FORWARD -j SKIP --skip-rules 4",              # 5.
                  "-A FORWARD -p tcp -s 10.0.1.1 -j ACCEPT",        # 6.
                  "-A FORWARD -j SKIP --skip-rules 2",              # 7.
                  "-A FORWARD -p tcp -s 10.0.2.1 -j ACCEPT",        # 8.
                  "-A FORWARD -j SKIP --skip-rules 0",              # 9.
        ]

        self.assertSimplePrefixMerge(rules_, rules)

    def testMergeFail(self):

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        with self.assertRaises(ValueError):
            self.assertSimplePrefixMerge([], rules)

    def testMergeSingle(self):
        """Merge simple chains."""

        # dummy0 is a prefix of dummy1

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",      # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",      # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 4",      # 3.

                  # dummy0,dummy1
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",          # 4.

                  # done with dummy0
                  "-A FORWARD -i dummy0 -j SKIP --skip-rules 1",      # 5.
                  # skip to the end of dummy0,dummy1 (double-jump)

                  # dummy1
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",          # 6.
                  "-A FORWARD -j SKIP --skip-rules 1",                # 7.

                  # dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",                # 8.
        ]

        self.assertSimplePrefixMerge(rules_, rules)

        # dummy1 is a prefix of dummy0

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",      # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",      # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 4",      # 3.

                  # dummy0,dummy1
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",          # 4.

                  # done with dummy1
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",      # 5.
                  # skip to the end of dummy0,dummy1 (double-jump)

                  # dummy0
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",          # 6.
                  "-A FORWARD -j SKIP --skip-rules 1",                # 7.

                  # dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",                # 8.
        ]

        self.assertSimplePrefixMerge(rules_, rules)

    def testMergeDouble(self):
        """Test overlapping prefixes."""

        # dummy0 is a prefix of dummy1, dummy2
        # dummy1 is a prefix of dummy2

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.2 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.3 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",      # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",      # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 0",      # 3.

                  # dummy0,dummy1,dummy2
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",          # 4.

                  # done with dummy0
                  "-A FORWARD -i dummy0 -j SKIP --skip-rules 3",      # 5.

                  # dummy1,dummy2
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",          # 6.

                  # done with dummy1
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",      # 7.

                  # dummy2
                  "-A FORWARD -p tcp -s 10.0.0.3 -j ACCEPT",          # 8.

                  # done with dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",                # 9.
        ]

        self.assertSimplePrefixMerge(rules_, rules)

        # dummy2 is a prefix of dummy0, dummy2
        # dummy1 is a prefix of dummy0

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.2 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.3 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",      # 1.
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",      # 2.
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 0",      # 3.

                  # dummy0,dummy1,dummy2
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",          # 4.

                  # done with dummy2
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 3",      # 5.

                  # dummy0,dummy1
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",          # 6.

                  # done with dummy1
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",      # 7.

                  # dummy0
                  "-A FORWARD -p tcp -s 10.0.0.3 -j ACCEPT",          # 8.

                  # done with dummy0
                  "-A FORWARD -j SKIP --skip-rules 0",                # 9.
        ]

        self.assertSimplePrefixMerge(rules_, rules)

    def testMergeGroup(self):
        """Merge prefixes with interface groups."""

        # dummy0 is a prefix of dummy1,dummy2

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.2 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 0",

                  # dummy0,dummy1,dummy2
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",

                  # done with dummy0
                  "-A FORWARD -i dummy0 -j SKIP --skip-rules 1",

                  # dummy1,dummy2
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",

                  # done with dummy1, dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",
        ]

        self.assertSimplePrefixGroupMerge(rules_, rules)

        # dummy2 is a prefix for dummy0,dummy1

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 0",

                  # dummy0,dummy1,dummy2
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",

                  # done with dummy2
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 1",

                  # dummy2
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",

                  # done with dummy0,dummy1
                  "-A FORWARD -j SKIP --skip-rules 0",
        ]

        self.assertSimplePrefixGroupMerge(rules_, rules)

    def testMergeGroupMultiExit(self):
        """Merge prefixes with interface groups.

        Make sure we can generate exit statements for interface groups.
        """

        # dummy0,dummy1 is a prefix of dummy2

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",

                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.2 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 0",

                  # dummy0,dummy1,dummy2
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",

                  # done with dummy0,dummy1
                  # NOTE two exit rules!
                  "-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",

                  # dummy2
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",

                  # done with dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",
        ]

        self.assertSimplePrefixGroupMerge(rules_, rules)

        # dummy1,dummy2 is a prefix of dummy0

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",

                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.1 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 0",

                  # dummy0,dummy1,dummy2
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",

                  # done with dummy1,dummy2
                  # NOTE two exit rules!
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 1",

                  # dummy0
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",

                  # done with dummy0
                  "-A FORWARD -j SKIP --skip-rules 0",
        ]

        self.assertSimplePrefixGroupMerge(rules_, rules)

    def testMergeSkip(self):
        """Merge prefixes in the presence of skip rules."""

        # dummy0 is a prefix of dummy1
        # this should be fine, the skip stride is fully enclosed in the prefix

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -j SKIP --skip-rules 1",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",

                 "-A FORWARD_dummy1 -j SKIP --skip-rules 1",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 5",

                  # dummy0,dummy1
                  "-A FORWARD -j SKIP --skip-rules 1",
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",

                  # done with dummy0 (skip past all dummy1 rules)
                  "-A FORWARD -i dummy0 -j SKIP --skip-rules 1",

                  # dummy1
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",

                  # done with dummy1
                  "-A FORWARD -j SKIP --skip-rules 1",

                  # dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",
        ]

        self.assertSimplePrefixMerge(rules_, rules)

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -j SKIP --skip-rules 1",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.1 -j ACCEPT",

                 "-A FORWARD_dummy1 -j SKIP --skip-rules 1",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy1 -j SKIP --skip-rules 1",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.2 -j ACCEPT",

                 "-A FORWARD_dummy2 -j SKIP --skip-rules 1",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.1 -j ACCEPT",
                 "-A FORWARD_dummy2 -j SKIP --skip-rules 1",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.2 -j ACCEPT",
                 "-A FORWARD_dummy2 -j SKIP --skip-rules 1",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.3 -j ACCEPT",

        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 0",

                  # dummy0,dummy1,dummy2
                  "-A FORWARD -j SKIP --skip-rules 1",
                  "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT",

                  # done with dummy0
                  "-A FORWARD -i dummy0 -j SKIP --skip-rules 5",

                  # dummy1,dummy2
                  "-A FORWARD -j SKIP --skip-rules 1",
                  "-A FORWARD -p tcp -s 10.0.0.2 -j ACCEPT",

                  # done with dummy1
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",

                  # dummy2
                  "-A FORWARD -j SKIP --skip-rules 1",
                  "-A FORWARD -p tcp -s 10.0.0.3 -j ACCEPT",

                  # done with dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",
        ]

        self.assertSimplePrefixMerge(rules_, rules)

class SimplePrefixSuffixMergeTest(MergeTestMixin,
                                  TcSaveTestUtils.IptablesTestMixin,
                                  unittest.TestCase):
    """Test chain merges using the prefix and suffix algorithm."""

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

    def testMergeNoOverlap(self):

        # dummy2 is a suffix of dummy1
        # dummy0 is a prefix of dummy1
        # the common prefixes and suffixes do not overlap

        # once we insert an exit rule from a prefix merge,
        # the suffix offsets from the IptablesChainSuffix objects are then broken.

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.10 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.11 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.10 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.11 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.12 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.13 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.14 -j ACCEPT",

                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.13 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.14 -j ACCEPT",
        ]

        # suffix merge but not prefix merge

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 4",
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 6",

                  # dummy0
                  "-A FORWARD -p tcp -s 10.0.0.10 -j ACCEPT",
                  "-A FORWARD -p tcp -s 10.0.0.11 -j ACCEPT",
                  "-A FORWARD -j SKIP --skip-rules 6",

                  # dummy1
                  "-A FORWARD -p tcp -s 10.0.0.10 -j ACCEPT",
                  "-A FORWARD -p tcp -s 10.0.0.11 -j ACCEPT",
                  "-A FORWARD -p tcp -s 10.0.0.12 -j ACCEPT",

                  # dummy2
                  "-A FORWARD -p tcp -s 10.0.0.13 -j ACCEPT",
                  "-A FORWARD -p tcp -s 10.0.0.14 -j ACCEPT",
                  "-A FORWARD -j SKIP --skip-rules 0",
        ]

        self.assertSimplePrefixSuffixMerge(rules_, rules,
                                           prefixOnly=True)

        # alternately we could formulate it this way

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 4",

                  # dummy0,dummy1
                  "-A FORWARD -p tcp -s 10.0.0.10 -j ACCEPT",
                  "-A FORWARD -p tcp -s 10.0.0.11 -j ACCEPT",

                  # done with dummy0, skip to the end of dummy0,dummy,dummy2
                  "-A FORWARD -i dummy0 -j SKIP --skip-rules 3",

                  # dummy1
                  "-A FORWARD -p tcp -s 10.0.0.12 -j ACCEPT",

                  # dummy1,dummy2
                  "-A FORWARD -p tcp -s 10.0.0.13 -j ACCEPT",
                  "-A FORWARD -p tcp -s 10.0.0.14 -j ACCEPT",
                  "-A FORWARD -j SKIP --skip-rules 0",
        ]

        self.assertSimplePrefixSuffixMerge(rules_, rules,
                                           prefixOnly=False)

    def testMergeAbut(self):

        # dummy2 is a suffix of dummy1
        # dummy0 is a prefix of dummy1
        # the common prefixes and suffixes are abutting

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.10 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.11 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.10 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.11 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.12 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.13 -j ACCEPT",

                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.12 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.13 -j ACCEPT",
        ]


        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 3",

                  # dummy0,dummy1
                  "-A FORWARD -p tcp -s 10.0.0.10 -j ACCEPT",
                  "-A FORWARD -p tcp -s 10.0.0.11 -j ACCEPT",

                  # done with dummy0, skip to the end of dummy0,dummy,dummy2
                  "-A FORWARD -i dummy0 -j SKIP --skip-rules 2",

                  # dummy1 (no rules)

                  # dummy1,dummy2
                  "-A FORWARD -p tcp -s 10.0.0.12 -j ACCEPT",
                  "-A FORWARD -p tcp -s 10.0.0.13 -j ACCEPT",
                  "-A FORWARD -j SKIP --skip-rules 0",
        ]

        self.assertSimplePrefixSuffixMerge(rules_, rules,
                                           prefixOnly=False)

    def testMergeOverlap(self):

        # dummy2 is a suffix of dummy1
        # dummy0 is a prefix of dummy1
        # the common prefixes and suffixes are overlapping

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.10 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.11 -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -s 10.0.0.12 -j ACCEPT",

                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.10 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.11 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.12 -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -s 10.0.0.13 -j ACCEPT",

                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.11 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.12 -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -s 10.0.0.13 -j ACCEPT",
        ]


        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 1",

                  # dummy0,dummy1
                  "-A FORWARD -p tcp -s 10.0.0.10 -j ACCEPT",

                  # dummy0,dummy1,dummy2
                  "-A FORWARD -p tcp -s 10.0.0.11 -j ACCEPT",
                  "-A FORWARD -p tcp -s 10.0.0.12 -j ACCEPT",

                  # done with dummy0
                  # skip to the end of dummy,dummy1,dummy2
                  "-A FORWARD -i dummy0 -j SKIP --skip-rules 1",

                  # dummy2
                  "-A FORWARD -p tcp -s 10.0.0.13 -j ACCEPT",
                  "-A FORWARD -j SKIP --skip-rules 0",
        ]

        self.assertSimplePrefixSuffixMerge(rules_, rules,
                                           prefixOnly=False)

if __name__ == "__main__":
    unittest.main()
