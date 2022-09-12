"""test_iptables_unroll.py

Test the unrolling API.
"""

import path_config

import unittest

import logging

from petunia.Iptables import (
    FilterTable,
)
from petunia.Unroller import Unroller

from TcSaveTestUtils import IptablesTestMixin

logger = None
def setUpModule():
    global logger
    logging.basicConfig()
    logger = logging.getLogger("unittest")
    logger.setLevel(logging.DEBUG)

class IptablesFormatTest(IptablesTestMixin,
                         unittest.TestCase):
    """Test various rule formats."""

    def setUp(self):
        self.log = logger.getChild(self.id())

    def tearDown(self):
        pass

    def testDefault(self):

        table = FilterTable.fromString(self.saveFromLines([]),
                                       log=self.log)
        chain = table.chains['INPUT']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(0, len(chain.rules))

    def testSimpleLines(self):

        ruleLines = ["-A INPUT -p tcp -i dummy0 -j ACCEPT",
                     "-A OUTPUT -p tcp -o dummy0 -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)

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

        table = FilterTable()
        table.chains['INPUT'] = table.chain_klass([], 'ACCEPT')
        table.chains['OUTPUT'] = table.chain_klass([], 'ACCEPT')
        table.chains['FORWARD'] = table.chain_klass([], 'ACCEPT')

        table_ = FilterTable.fromString(table.toSave(),
                                        log=self.log)
        chain = table_.chains['INPUT']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(0, len(chain.rules))

        rule = table.rule_klass(['-i', 'dummy0', '-p', 'tcp',], 'ACCEPT')
        table.chains['INPUT'].rules.append(rule)

        table_ = FilterTable.fromString(table.toSave(),
                                        log=self.log)
        chain = table_.chains['INPUT']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(1, len(chain.rules))
        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

class UnrollTestMixin(object):

    def assertComments(self, comments, table):
        """Do a canonical sort of the chains, and line up the comments."""

        comments_ = []
        for chainName in table.chainNames():
            for rule in table.chains[chainName].rules:
                comments_.append(rule.comment)
        self.assertEqual(comments, comments_)

    def assertInterfaces(self, interfaces, table):
        """Do a canonical sort of the chains, and line up the comments."""

        interfaces_ = []
        for chainName in table.chainNames():
            for rule in table.chains[chainName].rules:
                interfaces_.append(rule.in_interface)
        self.assertEqual(interfaces, interfaces_)

    def assertSkipRule(self, rule, stride, args=None):
        """Verify the contents of a SKIP rule."""

        self.assertEqual('SKIP', rule.target)
        self.assertEqual(['--skip-rules', str(stride),], rule.target_args)

        if args is not None:
            self.assertEqual(args, rule.args)

    def assertBranchSkip(self, chain, idx, stride, args=None):
        """Test that a test-and-skip rule was inserted."""

        self.assertSkipRule(chain.rules[idx], 1, args=args)
        # true-rule has the original rule arguments

        self.assertSkipRule(chain.rules[idx+1], stride, args=None)
        # false-rule has no args (always matches)

    def assertReturnSkip(self, chain, idx, stride, args=None):
        """Test that a skip rule was inserted in place of a RETURN."""

        self.assertSkipRule(chain.rules[idx], stride, args=args)

class UnrollTest(UnrollTestMixin,
                 IptablesTestMixin,
                 unittest.TestCase):

    def setUp(self):
        self.log = logger.getChild(self.id())

    def tearDown(self):
        pass

    def testEmpty(self):
        """Test unrolling on an empty ruleset."""

        table = FilterTable.fromString(self.saveFromLines([]),
                                       log=self.log)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()
        print(table_.toSave())

        self.assertEqual(0, len(table_.chains['INPUT'].rules))

    def testSimple(self):
        """Test unrolling on an simple ruleset."""

        ruleLines = ["-A INPUT -i dummy0 -p tcp -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()
        print(table_.toSave())

        chain = table_.chains['INPUT']
        self.assertEqual(1, len(chain.rules))

        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

    def testSimpleTarget(self):
        """Test different target types."""

        ruleLines = ["-A INPUT -i dummy0 -p tcp -j ACCEPT",
                     "-A INPUT -i dummy0 -p tcp -j DROP",
                     "-A INPUT -i dummy0 -p tcp -j REJECT",
        ]
        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()
        print(table_.toSave())

        chain = table_.chains['INPUT']
        self.assertEqual(3, len(chain.rules))

        rule = chain.rules[0]
        self.assertEqual('ACCEPT', rule.target)

        rule = chain.rules[1]
        self.assertEqual('DROP', rule.target)

        rule = chain.rules[2]
        self.assertEqual('REJECT', rule.target)

    def testSimpleComment(self):
        """Test with a simple ruleset containing comments."""

        tpl = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        ctpl = "INPUT #%d"
        ruleLines = [(tpl % i) for i in range(1, 6)]
        comments = [(ctpl % i) for i in range(1, 6)]

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        chain = table.chains['INPUT']
        self.assertEqual(5, len(chain.rules))

        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()
        chain = table_.chains['INPUT']
        self.assertEqual(5, len(chain.rules))

        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

        self.assertComments(comments, table_)

    def testSimpleJumpNoReturn(self):
        """Test a simple jump with no return.

        The end of the user-defined chain should do an implicit RETURN.
        """

        ruleLines = []
        comments = []

        # jump to OTHER in the middle of this chain

        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j OTHER"
        ctpl = "INPUT #%d"
        for i in range(1, 6):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 3 else tpl1
            ruleLines.append(tpl % i)

        tpl = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        ctpl = "OTHER #%d"
        [ruleLines.append(tpl % i) for i in range(1, 3)]
        [comments.append(ctpl % i) for i in range(1, 3)]

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        print(table.toSave())
        self.assertComments(comments, table)

        # verify the original state of rule #3

        rule = table.chains['INPUT'].rules[2]
        self.assertEqual(['-p', 'tcp',], rule.args)
        self.assertEqual('OTHER', rule.target)
        self.assertEqual([], rule.target_args)

        # default policy of 'OTHER' should be 'RETURN'
        self.assertEqual('RETURN', table.chains['OTHER'].policy)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()

        print(table_.toSave())

        comments = [
            'INPUT #1',
            'INPUT #2',


            'INPUT #3',
            'INPUT #3 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2',

            'INPUT #4',
            'INPUT #5',

        ]

        self.assertComments(comments, table_)

        chain = table_.chains['INPUT']
        otherChain = table.chains['OTHER']
        # verify the new state of rule #3

        # true-rule should skip 1
        # false-rule should skip 2 (all of the OTHER chain)
        self.assertBranchSkip(chain, 2, len(otherChain),
                              args=['-p', 'tcp',])

    def testSimpleJumpReturn(self):
        """Test a simple jump with a return."""

        ruleLines = []
        comments = []

        # jump to OTHER in the middle of this chain

        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j OTHER"
        ctpl = "INPUT #%d"
        for i in range(1, 6):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 3 else tpl1
            ruleLines.append(tpl % i)

        # RETURN from the middle of OTHER (in addition to end-of-chain)
        # (this also implies a default RETURN at the end of the inner chain)

        tpl1 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        tpl2 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j RETURN"
        ctpl = "OTHER #%d"
        for i in range(1, 4):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 2 else tpl1
            ruleLines.append(tpl % i)

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        self.assertComments(comments, table)

        print(table.toSave())

        # verify the original state of INPUT rule #2

        rule = table.chains['INPUT'].rules[2]
        self.assertEqual(['-p', 'tcp',], rule.args)
        self.assertEqual('OTHER', rule.target)
        self.assertEqual([], rule.target_args)

        # verify the original state of rule #2 in the 'OTHER' chain

        rule = table.chains['OTHER'].rules[1]
        self.assertEqual(['-p', 'tcp',], rule.args)
        self.assertEqual('RETURN', rule.target)
        self.assertEqual([], rule.target_args)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()

        print(table_.toSave())

        comments = [
            'INPUT #1',
            'INPUT #2',

            'INPUT #3',
            'INPUT #3 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2 -- return 1 frame(s)',
            'OTHER #3',

            'INPUT #4',
            'INPUT #5',

        ]

        self.assertComments(comments, table_)

        # verify the new state of INPUT rule #3 (when we JUMP to OTHER)

        chain = table_.chains['INPUT']
        otherChain = table.chains['OTHER']

        self.assertBranchSkip(chain, 2, len(otherChain),
                              args=['-p', 'tcp',])

        # verify the new state of rule #2 (the RETURN) in the 'OTHER' chain

        self.assertReturnSkip(chain, 5, 1,
                              args=['-p', 'tcp',])

    def testSimpleJumpReturnTail(self):
        """Test a simple jump with a return as the last rule."""

        ruleLines = []
        comments = []

        # jump to OTHER in the middle of this chain

        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j OTHER"
        ctpl = "INPUT #%d"
        for i in range(1, 6):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 3 else tpl1
            ruleLines.append(tpl % i)

        # RETURN at the very end of OTHER

        tpl1 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        tpl2 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j RETURN"
        ctpl = "OTHER #%d"
        for i in range(1, 3):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 2 else tpl1
            ruleLines.append(tpl % i)

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        self.assertComments(comments, table)

        print(table.toSave())

        # verify the original state of INPUT rule #2

        rule = table.chains['INPUT'].rules[2]
        self.assertEqual(['-p', 'tcp',], rule.args)
        self.assertEqual('OTHER', rule.target)
        self.assertEqual([], rule.target_args)

        # verify the original state of rule #2 in the 'OTHER' chain

        rule = table.chains['OTHER'].rules[1]
        self.assertEqual(['-p', 'tcp',], rule.args)
        self.assertEqual('RETURN', rule.target)
        self.assertEqual([], rule.target_args)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()

        print(table_.toSave())

        comments = [
            'INPUT #1',
            'INPUT #2',

            'INPUT #3',
            'INPUT #3 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2 -- return 1 frame(s)',

            'INPUT #4',
            'INPUT #5',

        ]

        self.assertComments(comments, table_)

        # verify the new state of INPUT rule #3 (when we JUMP to OTHER)

        chain = table_.chains['INPUT']
        otherChain = table.chains['OTHER']

        self.assertBranchSkip(chain, 2, len(otherChain),
                              args=['-p', 'tcp',])

        # verify the new state of rule #2 (the RETURN) in the 'OTHER' chain
        # Here this is RETURNing to the default policy ('--skip-rules 0')

        self.assertReturnSkip(chain, 5, 0,
                              args=['-p', 'tcp',])

    def testSimpleGoto(self):
        """Test a simple goto.

        When the processing ends at the sub-chain, the default rule is fired.
        """

        ruleLines = []
        comments = []

        # rule #3 is a goto --> OTHER
        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -g OTHER"
        ctpl = "INPUT #%d"
        for i in range(1, 6):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 3 else tpl1
            ruleLines.append(tpl % i)

        # simple GOTO chain
        tpl = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        ctpl = "OTHER #%d"
        for i in range(1, 3):
            comments.append(ctpl % i)
            ruleLines.append(tpl % i)

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        print(table.toSave())
        self.assertComments(comments, table)

        # check the GOTO rule

        chain = table.chains['INPUT']
        rule = chain.rules[2]
        self.assertFalse(rule.return_)
        self.assertEqual('OTHER', rule.target)

        chain = table.chains['OTHER']
        self.assertEqual('RETURN', chain.policy)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()
        print(table_.toSave())

        comments_ = [
            'INPUT #1',
            'INPUT #2',

            'INPUT #3',
            'INPUT #3 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2',

            'INPUT --> OTHER tail rule -- return 1 frame(s)',

            'INPUT #4',
            'INPUT #5',

        ]
        self.assertComments(comments_, table_)

        # check the GOTO rule

        chain = table_.chains['INPUT']
        otherChain = table.chains['OTHER']

        # false-rule should skip all the OTHER chain, plus the tail rule
        self.assertBranchSkip(chain, 2, len(otherChain)+1,
                              args=['-p', 'tcp'])

        # tail rule should skip past the end of INPUT
        self.assertReturnSkip(chain, 6, 2, args=[])

    def testDuplicateJump(self):
        """Test with multiple jump references to a child chain.

        Jump twice to a user-defined chain, so that the user-defined chain
        needs to be unrolled twice
        """

        ruleLines = []
        comments = []

        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j OTHER"
        ctpl = "INPUT #%d"
        for i in range(1, 9):
            comments.append(ctpl % i)
            tpl = tpl2 if i in (3, 6,) else tpl1
            ruleLines.append(tpl % i)

        tpl1 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        tpl2 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j RETURN"
        ctpl = "OTHER #%d"
        for i in range(1, 4):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 2 else tpl1
            ruleLines.append(tpl % i)

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        print(table.toSave())
        self.assertComments(comments, table)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()
        print(table_.toSave())

        comments_ = [
            'INPUT #1',
            'INPUT #2',

            'INPUT #3',
            'INPUT #3 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2 -- return 1 frame(s)',
            'OTHER #3',

            'INPUT #4',
            'INPUT #5',

            'INPUT #6',
            'INPUT #6 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2 -- return 1 frame(s)',
            'OTHER #3',

            'INPUT #7',
            'INPUT #8',

        ]

        self.assertComments(comments_, table_)

        chain = table_.chains['INPUT']
        otherChain = table.chains['OTHER']

        # test both jump statements

        self.assertBranchSkip(chain, 2, len(otherChain),
                              args=['-p', 'tcp',])

        self.assertBranchSkip(chain, 9, len(otherChain),
                              args=['-p', 'tcp',])

        # test both return statements

        # return past the end of the rest of OTHER up to INPUT
        self.assertReturnSkip(chain, 5, 1,
                              args=['-p', 'tcp',])

        # return past the end of the rest of OTHER up to INPUT
        self.assertReturnSkip(chain, 12, 1,
                              args=['-p', 'tcp',])

    def testDuplicateGoto(self):
        """Test with multiple goto references to a child chain."""

        ruleLines = []
        comments = []

        # rule #3 is a goto --> OTHER
        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -g OTHER"
        ctpl = "INPUT #%d"
        for i in range(1, 9):
            comments.append(ctpl % i)
            tpl = tpl2 if i in (3, 6,) else tpl1
            ruleLines.append(tpl % i)

        # simple GOTO chain
        tpl = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        ctpl = "OTHER #%d"
        for i in range(1, 3):
            comments.append(ctpl % i)
            ruleLines.append(tpl % i)

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        self.assertComments(comments, table)

        # check the GOTO rules

        chain = table.chains['INPUT']

        rule = chain.rules[2]
        self.assertFalse(rule.return_)
        self.assertEqual('OTHER', rule.target)

        rule = chain.rules[5]
        self.assertFalse(rule.return_)
        self.assertEqual('OTHER', rule.target)

        # check the default policy for the destination

        chain = table.chains['OTHER']
        self.assertEqual('RETURN', chain.policy)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()
        print(table_.toSave())

        comments_ = [
            'INPUT #1',
            'INPUT #2',

            'INPUT #3',
            'INPUT #3 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2',

            'INPUT --> OTHER tail rule -- return 1 frame(s)',

            'INPUT #4',
            'INPUT #5',

            'INPUT #6',
            'INPUT #6 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2',

            'INPUT --> OTHER tail rule -- return 1 frame(s)',

            'INPUT #7',
            'INPUT #8',

        ]
        self.assertComments(comments_, table_)

        # check the GOTO rule

        chain = table_.chains['INPUT']
        otherChain = table.chains['OTHER']

        # skip past OTHER, including the tail rule
        self.assertBranchSkip(chain, 2, len(otherChain)+1,
                              args=['-p', 'tcp',])
        self.assertBranchSkip(chain, 9, len(otherChain)+1,
                              args=['-p', 'tcp',])

        # skip past all of INPUT, past all of the second unroll of OTHER
        self.assertReturnSkip(chain, 6, 9, args=[])

        # skip past all of INPUT
        self.assertReturnSkip(chain, 13, 2, args=[])

    def testNestedJumpJump(self):
        """Nest a jump within a jump."""

        ruleLines = []
        comments = []

        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j OTHER"
        ctpl = "INPUT #%d"
        for i in range(1, 6):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 3 else tpl1
            ruleLines.append(tpl % i)

        tpl1 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        tpl2 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j OTHER2"
        ctpl = "OTHER #%d"
        for i in range(1, 6):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 3 else tpl1
            ruleLines.append(tpl % i)

        tpl1 = "-A OTHER2 -i dummy0 -p tcp -m comment --comment \"OTHER2 #%d\" -j ACCEPT"
        tpl2 = "-A OTHER2 -i dummy0 -p tcp -m comment --comment \"OTHER2 #%d\" -j RETURN"
        ctpl = "OTHER2 #%d"
        for i in range(1, 4):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 2 else tpl1
            ruleLines.append(tpl % i)

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        print(table.toSave())
        self.assertComments(comments, table)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()
        print(table_.toSave())

        comments_ = [
            'INPUT #1',
            'INPUT #2',

            'INPUT #3',
            'INPUT #3 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2',

            'OTHER #3',
            'OTHER #3 (OTHER --> OTHER2 false branch)',

            'OTHER2 #1',
            'OTHER2 #2 -- return 1 frame(s)',
            'OTHER2 #3',

            'OTHER #4',
            'OTHER #5',

            'INPUT #4',
            'INPUT #5',

        ]

        self.assertComments(comments_, table_)

        # verify the jump from INPUT --> OTHER

        chain = table_.chains['INPUT']
        otherChain = table.chains['OTHER']
        otherChain2 = table.chains['OTHER2']

        # skip all of OTHER, skip all of OTHER2 plus its false-rule
        self.assertBranchSkip(chain, 2, len(otherChain)+len(otherChain2)+1,
                              args=['-p', 'tcp',])

        self.assertBranchSkip(chain, 6, len(otherChain2),
                              args=['-p', 'tcp',])

        # verify the return from OTHER2 --> OTHER1

        # skip past the rest of the OTHER2 rules
        self.assertReturnSkip(chain, 9, 1,
                              args=['-p', 'tcp',])

    def testNestedGotoGoto(self):
        """Test a nested goto."""

        ruleLines = []
        comments = []

        # rule #3 is a goto --> OTHER
        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -g OTHER"
        ctpl = "INPUT #%d"
        for i in range(1, 6):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 3 else tpl1
            ruleLines.append(tpl % i)

        # rule #3 is a goto --> OTHER2
        tpl1 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        tpl2 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -g OTHER2"
        ctpl = "OTHER #%d"
        for i in range(1, 6):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 3 else tpl1
            ruleLines.append(tpl % i)

        # simple GOTO chain
        tpl = "-A OTHER2 -i dummy0 -p tcp -m comment --comment \"OTHER2 #%d\" -j ACCEPT"
        ctpl = "OTHER2 #%d"
        for i in range(1, 3):
            comments.append(ctpl % i)
            ruleLines.append(tpl % i)

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        self.assertComments(comments, table)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()
        print(table_.toSave())

        comments_ = [
            'INPUT #1',
            'INPUT #2',

            'INPUT #3',
            'INPUT #3 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2',

            'OTHER #3',
            'OTHER #3 (OTHER --> OTHER2 false branch)',

            'OTHER2 #1',
            'OTHER2 #2',

            'OTHER --> OTHER2 tail rule -- return 2 frame(s)',

            'OTHER #4',
            'OTHER #5',

            'INPUT --> OTHER tail rule -- return 1 frame(s)',

            'INPUT #4',
            'INPUT #5',

        ]
        self.assertComments(comments_, table_)

        # check the GOTO rule

        chain = table_.chains['INPUT']
        otherChain = table.chains['OTHER']
        otherChain2 = table.chains['OTHER2']

        # skip all of OTHER
        # skip all of OTHER2
        # skip the tail rules for OTHER, OTHER2
        # skip the false-branch of the inner OTHER2
        self.assertBranchSkip(chain, 2, len(otherChain)+1+len(otherChain2)+1+1,
                              args=['-p', 'tcp',])

        # skip all of OTHER2, including its tail rule
        self.assertBranchSkip(chain, 6, len(otherChain2)+1,
                              args=['-p', 'tcp',])

        # return 2 frames -- the rest of the OTHER and INPUT rules
        self.assertReturnSkip(chain, 10, 5, args=[])

        # return 1 frame -- the rest of the INPUT rules
        self.assertReturnSkip(chain, 13, 2, args=[])

    def testNestedJumpGoto(self):
        """Nest a goto within a jump.

        XXX rothcar -- we don't currently support this, since our
        current behavior is to invoke the root's default policy
        at the end of every GOTO (ignoring the return frame)
        """

        ruleLines = []
        comments = []

        # rule #3 is a jump --> OTHER
        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j OTHER"
        ctpl = "INPUT #%d"
        for i in range(1, 6):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 3 else tpl1
            ruleLines.append(tpl % i)

        # rule #3 is a goto --> OTHER2
        tpl1 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        tpl2 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -g OTHER2"
        ctpl = "OTHER #%d"
        for i in range(1, 6):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 3 else tpl1
            ruleLines.append(tpl % i)

        # simple GOTO chain
        tpl = "-A OTHER2 -i dummy0 -p tcp -m comment --comment \"OTHER2 #%d\" -j ACCEPT"
        ctpl = "OTHER2 #%d"
        for i in range(1, 3):
            comments.append(ctpl % i)
            ruleLines.append(tpl % i)

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        self.assertComments(comments, table)

        # this returns an invalid result
        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()
        print(table_.toSave())

        comments_ = [
            'INPUT #1',
            'INPUT #2',

            'INPUT #3',
            'INPUT #3 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2',

            'OTHER #3',
            'OTHER #3 (OTHER --> OTHER2 false branch)',

            'OTHER2 #1',
            'OTHER2 #2',

            'OTHER --> OTHER2 tail rule -- return 1 frame(s)',

            'OTHER #4',
            'OTHER #5',

            'INPUT #4',
            'INPUT #5',

        ]

        self.assertComments(comments_, table_)

        # verify the true/false branches

        chain = table_.chains['INPUT']
        otherChain = table.chains['OTHER']
        otherChain2 = table.chains['OTHER2']

        # skip all of OTHER
        # skip all of OTHER2
        # skip the OTHER2 tail rule
        # skip the OTHER2 false-rule
        self.assertBranchSkip(chain, 2, len(otherChain)+len(otherChain2)+1+1,
                              args=['-p', 'tcp',])

        # skip all of OTHER2
        # skip the OTHER2 tail rule
        self.assertBranchSkip(chain, 6, len(otherChain2)+1,
                              args=['-p', 'tcp',])

        # verify the RETURN statements

        # single-frame return from OTHER --> INPUT, skip the rest of the OTHER rules
        self.assertReturnSkip(chain, 10, 2, args=[])

    def testNestedGotoJump(self):
        """Nest a jump within a goto."""

        ruleLines = []
        comments = []

        # rule #3 is a jump --> OTHER
        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -g OTHER"
        ctpl = "INPUT #%d"
        for i in range(1, 6):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 3 else tpl1
            ruleLines.append(tpl % i)

        # rule #3 is a goto --> OTHER2
        tpl1 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        tpl2 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j OTHER2"
        ctpl = "OTHER #%d"
        for i in range(1, 6):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 3 else tpl1
            ruleLines.append(tpl % i)

        # simple GOTO chain
        tpl = "-A OTHER2 -i dummy0 -p tcp -m comment --comment \"OTHER2 #%d\" -j ACCEPT"
        ctpl = "OTHER2 #%d"
        for i in range(1, 3):
            comments.append(ctpl % i)
            ruleLines.append(tpl % i)

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        self.assertComments(comments, table)

        # this returns an invalid result
        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()
        print(table_.toSave())

        comments_ = [
            'INPUT #1',
            'INPUT #2',

            'INPUT #3',
            'INPUT #3 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2',

            'OTHER #3',
            'OTHER #3 (OTHER --> OTHER2 false branch)',

            'OTHER2 #1',
            'OTHER2 #2',

            'OTHER #4',
            'OTHER #5',

            'INPUT --> OTHER tail rule -- return 1 frame(s)',

            'INPUT #4',
            'INPUT #5',

        ]

        self.assertComments(comments_, table_)

        chain = table_.chains['INPUT']
        otherChain = table.chains['OTHER']
        otherChain2 = table.chains['OTHER2']

        # skip all of OTHER
        # skip all of OTHER2
        # skip the OTHER2 false branch
        # skip the OTHER tail rule
        self.assertBranchSkip(chain, 2, len(otherChain)+1+len(otherChain2)+1,
                              args=['-p', 'tcp',])

        self.assertBranchSkip(chain, 6, len(otherChain2),
                              args=['-p', 'tcp',])

        # single-frame return, skip the rest of the INPUT rules
        self.assertReturnSkip(chain, 12, 2, args=[])

    def testRootReturn(self):
        """Attempt to return from the root chain."""

        ruleLines = []
        comments = []

        # rule #3 is a jump --> OTHER
        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j RETURN"
        ctpl = "INPUT #%d"
        for i in range(1, 4):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 2 else tpl1
            ruleLines.append(tpl % i)

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        self.assertComments(comments, table)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()
        print(table_.toSave())

        comments_ = [
            'INPUT #1',
            'INPUT #2 -- return 1 frame(s)',
            'INPUT #3',
        ]

        self.assertComments(comments_, table_)

        chain = table_.chains['INPUT']

        self.assertReturnSkip(chain, 1, 1,
                              args=['-p', 'tcp',])

    def testMultiReturn(self):
        """Attempt to return from a goto (currently not supported)."""

        ruleLines = []
        comments = []

        # rule #3 is a jump --> OTHER
        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -g OTHER"
        ctpl = "INPUT #%d"
        for i in range(1, 6):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 3 else tpl1
            ruleLines.append(tpl % i)

        # rule #2 is a goto --> OTHER
        tpl1 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        tpl2 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j RETURN"
        ctpl = "OTHER #%d"
        for i in range(1, 4):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 2 else tpl1
            ruleLines.append(tpl % i)

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        self.assertComments(comments, table)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()
        print(table_.toSave())

        comments_ = [
            'INPUT #1',
            'INPUT #2',

            'INPUT #3',
            'INPUT #3 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2 -- return 2 frame(s)',
            'OTHER #3',

            'INPUT --> OTHER tail rule -- return 1 frame(s)',

            'INPUT #4',
            'INPUT #5',
        ]

        self.assertComments(comments_, table_)

        chain = table_.chains['INPUT']
        otherChain = table.chains['OTHER']

        # skip all of OTHER
        # skip the OTHER tail rule
        self.assertBranchSkip(chain, 2, len(otherChain)+1,
                              args=['-p', 'tcp'])

        # 2-frame return
        # skip the rest of the OTHER rules
        # skip the rest of the INPUT rules
        # skip the OTHER tail rule
        self.assertReturnSkip(chain, 5, 4,
                              args=['-p', 'tcp',])

        # 1-frame return
        # skip the rest of the INPUT rules
        self.assertReturnSkip(chain, 7, 2,
                              args=[])

    def testGotoDepth(self):
        """Concoct a deep chain with manipulation of the goto depth.

        - INPUT  goto OTHER1
        - OTHER1 jump OTHER2
        - OTHER2 goto OTHER3
        - OTHER3 goto OTHER4
        - OTHER4 jump OTHER5

        when unrolling OTHER1, gotoDepth is 1
        when unrolling OTHER2, gotoDepth is 0
        when unrolling OTHER3, gotoDepth is 1
        when unrolling OTHER4, gotoDepth is 2
        when unrolling OTHER5, gotoDepth is 0
        """

        ruleLines = []
        comments = []

        def mkChain(chain, dstChain):
            """Cook up a chain that enters the sub-chain in various ways.

            This is a torture-test, resulting in an exponential blowup in
            rule count.
            """

            ctpl = "%s #%%d" % chain

            tpl1 = ("-A %s -i dummy0 -p tcp -m comment --comment \"%s #%%d\" -j ACCEPT"
                    % (chain, chain,))

            tpl2 = ("-A %s -i dummy0 -p tcp -m comment --comment \"%s #%%d\" -j RETURN"
                    % (chain, chain,))

            tpl3 = ("-A %s -i dummy0 -p tcp -m comment --comment \"%s #%%d\" -j %s"
                    % (chain, chain, dstChain))

            tpl4 = ("-A %s -i dummy0 -p tcp -m comment --comment \"%s #%%d\" -g %s"
                    % (chain, chain, dstChain))

            comments.append(ctpl % (1,))
            ruleLines.append(tpl1 % (1,))
            comments.append(ctpl % (2,))
            ruleLines.append(tpl1 % (2,))

            comments.append(ctpl % (3,))
            ruleLines.append(tpl2 % (3,))

            comments.append(ctpl % (4,))
            ruleLines.append(tpl1 % (4,))
            comments.append(ctpl % (5,))
            ruleLines.append(tpl1 % (5,))

            comments.append(ctpl % (6,))
            ruleLines.append(tpl3 % (6,))

            comments.append(ctpl % (7,))
            ruleLines.append(tpl1 % (7,))
            comments.append(ctpl % (8,))
            ruleLines.append(tpl1 % (8,))

            comments.append(ctpl % (9,))
            ruleLines.append(tpl4 % (9,))

            comments.append(ctpl % (10,))
            ruleLines.append(tpl1 % (10,))
            comments.append(ctpl % (11,))
            ruleLines.append(tpl1 % (11,))

        def mkLeafChain(chain):

            ctpl = "%s #%%d" % chain

            tpl1 = ("-A %s -i dummy0 -p tcp -m comment --comment \"%s #%%d\" -j ACCEPT"
                    % (chain, chain,))

            tpl2 = ("-A %s -i dummy0 -p tcp -m comment --comment \"%s #%%d\" -j RETURN"
                    % (chain, chain,))

            comments.append(ctpl % (1,))
            ruleLines.append(tpl1 % (1,))
            comments.append(ctpl % (2,))
            ruleLines.append(tpl1 % (2,))

            comments.append(ctpl % (3,))
            ruleLines.append(tpl2 % (3,))

            comments.append(ctpl % (4,))
            ruleLines.append(tpl1 % (4,))
            comments.append(ctpl % (5,))
            ruleLines.append(tpl1 % (5,))

        mkChain('INPUT', 'OTHER0')
        mkChain('OTHER0', 'OTHER1')
        mkLeafChain('OTHER1')

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        print(table.toSave())
        self.assertComments(comments, table)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()
        print(table_.toSave())

        chain = table_.chains['INPUT']
        cnt = len(chain)

        comments_ = []
        for chainName in table_.chainNames():
            for rule in table_.chains[chainName].rules:
                comments_.append(rule.comment)

        # Validation #1: most return frames is 3

        # 1. INPUT goto OTHER0
        # 2. OTHER0 goto OTHER1
        # 3. OTHER1 RETURN up through to INPUT's default policy

        comment = "OTHER1 #3 -- return 3 frame(s)"
        idx = comments_.index(comment)

        skip = cnt-idx-1

        # skip the last 2 rules in OTHER1
        # skip the last 2 rules in OTHER0
        # skip the last 2 rules in INPUT
        # skip OTHER1 tail rule
        # skip OTHER0 tail rule
        rule = chain.rules[idx]
        self.assertEqual(2+2+2+1+1, int(rule.target_args[1]))

        # Validation #2: longest skip stride is from the RETURN from INPUT

        # past 8 other INPUT rules
        # past a JUMP to OTHER0
        # past a GOTO to OTHER0

        # stride of OTHER0 is
        # length of OTHER0
        # past a JUMP to OTHER1
        # past a GOTO to OTHER1

        # stride of OTHER1 is
        # length of OTHER1

        other1sz = len(table.chains['OTHER1'])
        other0sz = len(table.chains['OTHER0'])
        inputsz = len(table.chains['INPUT'])

        other1stride = other1sz
        # stride of OTHER1, not including the goto default rule

        other0stride = (other0sz
                        + other1stride + 1 + other1stride + 1 + 1)
        # stride of OTHER0, not including the goto default rule

        inputstride = (inputsz
                       + other0stride + 1 + other0stride + 1 + 1)

        comment = 'INPUT #3 -- return 1 frame(s)'
        idx = comments_.index(comment)
        rule = chain.rules[idx]

        # started from rule 3
        self.assertEqual(inputstride-3, int(rule.target_args[1]))

    def testMultiIntfJump(self):
        """Test a jump that is interface-specific.

        Here we jump to a sub-chain using a ingress interface specifier.
        All rules in the jumped-to chain should be labeled with the parent interface,
        else the slicing will fail.
        """

        ruleLines = []
        comments = []
        interfaces = []

        # jump to OTHER with no interface specifier

        tpl1 = "-A INPUT -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -p tcp -m comment --comment \"INPUT #%d\" -j OTHER"
        ctpl = "INPUT #%d"
        for i in range(1, 4):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 2 else tpl1
            ruleLines.append(tpl % i)

        # jump to OTHER with dummy0

        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j OTHER"
        ctpl = "INPUT #%d"
        for i in range(1, 4):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 2 else tpl1
            ruleLines.append(tpl % i)

        # jump to OTHER with dummy1

        tpl1 = "-A INPUT -i dummy1 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy1 -p tcp -m comment --comment \"INPUT #%d\" -j OTHER"
        ctpl = "INPUT #%d"
        for i in range(1, 4):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 2 else tpl1
            ruleLines.append(tpl % i)

        # here, the sub-chain does not use an interface specifier
        # ideally it should inherit the parent chain specifier, if any

        tpl1 = "-A OTHER -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        tpl2 = "-A OTHER -p tcp -m comment --comment \"OTHER #%d\" -j RETURN"
        ctpl = "OTHER #%d"
        for i in range(1, 4):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 2 else tpl1
            ruleLines.append(tpl % i)

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        self.assertComments(comments, table)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()

        print(table_.toSave())

        comments = [

            # no interface spec

            'INPUT #1',

            'INPUT #2',
            'INPUT #2 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2 -- return 1 frame(s)',
            'OTHER #3',

            'INPUT #3',

            # dummy0

            'INPUT #1',

            'INPUT #2',
            'INPUT #2 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2 -- return 1 frame(s)',
            'OTHER #3',

            'INPUT #3',

            # dummy1

            'INPUT #1',

            'INPUT #2',
            'INPUT #2 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2 -- return 1 frame(s)',
            'OTHER #3',

            'INPUT #3',

        ]

        self.assertComments(comments, table_)

        interfaces = [

            # no interface specified

            # INPUT

            None,
            None,
            None,
            None,

            # OTHER

            None,
            None,
            None,

            # dummy0

            # INPUT

            'dummy0',
            'dummy0',
            'dummy0',
            'dummy0',

            # OTHER

            'dummy0',
            'dummy0',
            'dummy0',

            # dummy1

            # INPUT

            'dummy1',
            'dummy1',
            'dummy1',
            'dummy1',

            # OTHER

            'dummy1',
            'dummy1',
            'dummy1',

        ]

        self.assertInterfaces(interfaces, table_)

    def testMultiIntfOverride(self):
        """Override an interface in the target of a JUMP.

        This is not an error, but still probably will not work.
        """

        ruleLines = []
        comments = []
        interfaces = []

        # jump to OTHER with dummy0

        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j OTHER"
        ctpl = "INPUT #%d"
        for i in range(1, 4):
            comments.append(ctpl % i)
            tpl = tpl2 if i == 2 else tpl1
            ruleLines.append(tpl % i)

        # OTHER uses the wrong interface specifier

        tpl1 = "-A OTHER -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        tpl2 = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        tpl3 = "-A OTHER -i dummy1 -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        ctpl = "OTHER #%d"
        ruleLines.append(tpl1 % 1)
        comments.append(ctpl % 1)
        ruleLines.append(tpl2 % 2)
        comments.append(ctpl % 2)
        ruleLines.append(tpl3 % 3)
        comments.append(ctpl % 3)

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)
        self.assertComments(comments, table)

        # this is an error by default
        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        with self.assertRaises(ValueError):
            unroller.unroll()

        # need to provide 'overrideInterface' to allow this
        unroller = Unroller(table,
                            overrideInterface=True,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()

        print(table_.toSave())

        comments = [

            # no interface spec

            'INPUT #1',

            'INPUT #2',
            'INPUT #2 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2',
            'OTHER #3 (parent --in-interface dummy0)',

            'INPUT #3',

        ]

        self.assertComments(comments, table_)

        interfaces = [

            # INPUT

            # INPUT #1
            'dummy0',

            # INPUT #2
            'dummy0',
            'dummy0',

            # OTHER

            'dummy0',
            'dummy0',
            'dummy1',

            # INPUT #3
            'dummy0',

        ]

        self.assertInterfaces(interfaces, table_)

class ExtensionTest(UnrollTestMixin,
                    IptablesTestMixin,
                    unittest.TestCase):
    """Test extensions to IPTABLES format."""

    def setUp(self):
        self.log = logger.getChild(self.id())

    def tearDown(self):
        pass

    def testSimple(self):
        """Test unrolling a simple ruleset."""

        ruleLines = ["-A INPUT -i dummy0 -p tcp -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)

        chain = table.chains['INPUT']
        self.assertEqual(1, len(chain.rules))

        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

    def testMultiInterfaceFailed(self):
        """Test multiple-interface support."""

        ruleLines = ["-A INPUT -i dummy0,dummy1 -p tcp -j ACCEPT",]

        with self.assertRaises(ValueError):
            FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)

        ruleLines = ["-A INPUT -o dummy0,dummy1 -p tcp -j ACCEPT",]
        with self.assertRaises(ValueError):
            FilterTable.fromString(self.saveFromLines(ruleLines),
                                   log=self.log)

        ruleLines = ["-A INPUT -o dummy0,dummy1 -o dummy0,dummy1 -p tcp -j ACCEPT",]
        with self.assertRaises(ValueError):
            FilterTable.fromString(self.saveFromLines(ruleLines),
                                   log=self.log)

    def testMultiInput(self):
        """Test multiple-interface support."""

        ruleLines = ["-A INPUT -i dummy0,dummy1 -p tcp -j ACCEPT",]

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       multiInterface=True,
                                       log=self.log)

        chain = table.chains['INPUT']
        self.assertEqual(2, len(chain.rules))

        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

        rule = chain.rules[1]
        self.assertEqual('dummy1', rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

    def testMultiOutput(self):
        """Test multiple-interface support."""

        ruleLines = ["-A INPUT -o dummy0,dummy1 -p tcp -j ACCEPT",]

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       multiInterface=True,
                                       log=self.log)

        chain = table.chains['INPUT']
        self.assertEqual(2, len(chain.rules))

        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.out_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

        rule = chain.rules[1]
        self.assertEqual('dummy1', rule.out_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

    def testMultiInputOutput(self):
        """Test multiple-interface support."""

        ruleLines = ["-A INPUT -i dummy0,dummy1 -o dummy2,dummy3 -p tcp -j ACCEPT",]

        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       multiInterface=True,
                                       log=self.log)

        chain = table.chains['INPUT']
        self.assertEqual(4, len(chain.rules))

        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual('dummy2', rule.out_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

        rule = chain.rules[1]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual('dummy3', rule.out_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

        rule = chain.rules[2]
        self.assertEqual('dummy1', rule.in_interface)
        self.assertEqual('dummy2', rule.out_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

        rule = chain.rules[3]
        self.assertEqual('dummy1', rule.in_interface)
        self.assertEqual('dummy3', rule.out_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

    def testMultiChainFailed(self):
        """Test multiple-chain support."""

        ruleLines = ["-A INPUT,FORWARD -i dummy0 -p tcp -j ACCEPT",]

        with self.assertRaises(ValueError):
            FilterTable.fromString(self.saveFromLines(ruleLines),
                                       log=self.log)

    def testMultiChain(self):
        """Test unrolling on an empty ruleset."""

        ruleLines = ["-A INPUT,FORWARD -i dummy0 -p tcp -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       multiChain=True,
                                       log=self.log)

        chain = table.chains['INPUT']
        self.assertEqual(1, len(chain.rules))

        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

        chain = table.chains['FORWARD']
        self.assertEqual(1, len(chain.rules))

        rule = chain.rules[0]
        self.assertEqual('dummy0', rule.in_interface)
        self.assertEqual(['-p', 'tcp',], rule.args)

    def testJumpMultiInput(self):
        """Test a simple jump with no return, using multiple inputs.

        Each enumerated interface should result in an unrolling.
        """

        ruleLines = []
        comments = []
        interfaces = []

        # jump to OTHER in the middle of this chain

        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0,dummy1 -p tcp -m comment --comment \"INPUT #%d\" -j OTHER"

        ctpl = "INPUT #%d"
        for i in range(1, 6):
            if i == 3:
                comments.append(ctpl % i)
                comments.append(ctpl % i)
                ruleLines.append(tpl2 % i)
                interfaces.append('dummy0')
                interfaces.append('dummy1')
            else:
                comments.append(ctpl % i)
                ruleLines.append(tpl1 % i)
                interfaces.append('dummy0')

        # in-interface for OTHER is not specified, anything matches
        tpl = "-A OTHER -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        ctpl = "OTHER #%d"
        [ruleLines.append(tpl % i) for i in range(1, 3)]
        [comments.append(ctpl % i) for i in range(1, 3)]
        [interfaces.append(None) for i in range(1, 3)]

        # by default this is an error
        with self.assertRaises(ValueError):
            FilterTable.fromString(self.saveFromLines(ruleLines),
                                   log=self.log)

        # need to enable multi-interface extensions
        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       multiInterface=True,
                                       log=self.log)
        print(table.toSave())
        self.assertComments(comments, table)
        self.assertInterfaces(interfaces, table)

        # verify the original state of rule #3

        rule = table.chains['INPUT'].rules[2]
        self.assertEqual(['-p', 'tcp',], rule.args)
        self.assertEqual('OTHER', rule.target)
        self.assertEqual([], rule.target_args)

        # default policy of 'OTHER' should be 'RETURN'
        self.assertEqual('RETURN', table.chains['OTHER'].policy)

        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()

        print(table_.toSave())

        comments = [
            'INPUT #1',
            'INPUT #2',

            # first copy with dummy0

            'INPUT #3',
            'INPUT #3 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2',

            # second copy with dummy0

            'INPUT #3',
            'INPUT #3 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2',

            'INPUT #4',
            'INPUT #5',

        ]

        interfaces = [
            'dummy0',
            'dummy0',

            # first copy of OTHER with dummy0

            'dummy0',
            'dummy0',

            'dummy0',
            'dummy0',

            # second copy with dummy1

            'dummy1',
            'dummy1',

            'dummy1',
            'dummy1',

            # continue

            'dummy0',
            'dummy0',
        ]

        self.assertComments(comments, table_)
        self.assertInterfaces(interfaces, table_)

        chain = table_.chains['INPUT']
        otherChain = table.chains['OTHER']

        # verify the new state of rule #3

        # true-rule should skip 1
        # false-rule should skip 2 (all of the OTHER chain)
        self.assertBranchSkip(chain, 2, len(otherChain),
                              args=['-p', 'tcp',])

        # verify the new state of rule #7

        # true-rule should skip 1
        # false-rule should skip 2 (all of the OTHER chain)
        self.assertBranchSkip(chain, 6, len(otherChain),
                              args=['-p', 'tcp',])

    def testJumpMultiInputOverride(self):
        """Test a simple jump with no return, using multiple inputs, with override."""

        ruleLines = []
        comments = []
        interfaces = []

        # jump to OTHER in the middle of this chain

        tpl1 = "-A INPUT -i dummy0 -p tcp -m comment --comment \"INPUT #%d\" -j ACCEPT"
        tpl2 = "-A INPUT -i dummy0,dummy1 -p tcp -m comment --comment \"INPUT #%d\" -j OTHER"

        ctpl = "INPUT #%d"
        for i in range(1, 6):
            if i == 3:
                comments.append(ctpl % i)
                comments.append(ctpl % i)
                ruleLines.append(tpl2 % i)
                interfaces.append('dummy0')
                interfaces.append('dummy1')
            else:
                comments.append(ctpl % i)
                ruleLines.append(tpl1 % i)
                interfaces.append('dummy0')

        # input interface for OTHER is specific to an interface,
        # may not match

        tpl = "-A OTHER -i dummy0 -p tcp -m comment --comment \"OTHER #%d\" -j ACCEPT"
        ctpl = "OTHER #%d"
        [ruleLines.append(tpl % i) for i in range(1, 3)]
        [comments.append(ctpl % i) for i in range(1, 3)]
        [interfaces.append('dummy0') for i in range(1, 3)]

        # by default this is an error
        with self.assertRaises(ValueError):
            FilterTable.fromString(self.saveFromLines(ruleLines),
                                   log=self.log)

        # need to enable multi-interface extensions
        table = FilterTable.fromString(self.saveFromLines(ruleLines),
                                       multiInterface=True,
                                       log=self.log)
        print(table.toSave())
        self.assertComments(comments, table)
        self.assertInterfaces(interfaces, table)

        # verify the original state of rule #3

        rule = table.chains['INPUT'].rules[2]
        self.assertEqual(['-p', 'tcp',], rule.args)
        self.assertEqual('OTHER', rule.target)
        self.assertEqual([], rule.target_args)

        # default policy of 'OTHER' should be 'RETURN'
        self.assertEqual('RETURN', table.chains['OTHER'].policy)

        # need to enable interface overrides
        unroller = Unroller(table,
                            log=self.log.getChild("unroll"))
        with self.assertRaises(ValueError):
            unroller.unroll()
        unroller = Unroller(table,
                            overrideInterface=True,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()

        print(table_.toSave())

        comments = [
            'INPUT #1',
            'INPUT #2',

            # first copy with dummy0

            'INPUT #3',
            'INPUT #3 (INPUT --> OTHER false branch)',

            'OTHER #1',
            'OTHER #2',

            # second copy with dummy0

            'INPUT #3',
            'INPUT #3 (INPUT --> OTHER false branch)',

            # suitably annotated

            'OTHER #1 (parent --in-interface dummy1)',
            'OTHER #2 (parent --in-interface dummy1)',

            'INPUT #4',
            'INPUT #5',

        ]

        interfaces = [
            'dummy0',
            'dummy0',

            # first copy of OTHER with dummy0

            'dummy0',
            'dummy0',

            'dummy0',
            'dummy0',

            # second copy with dummy1

            'dummy1',
            'dummy1',

            # dummy1 is not overridden

            'dummy0',
            'dummy0',

            # continue

            'dummy0',
            'dummy0',
        ]

        self.assertComments(comments, table_)
        self.assertInterfaces(interfaces, table_)

        chain = table_.chains['INPUT']
        otherChain = table.chains['OTHER']

        # verify the new state of rule #3

        # true-rule should skip 1
        # false-rule should skip 2 (all of the OTHER chain)
        self.assertBranchSkip(chain, 2, len(otherChain),
                              args=['-p', 'tcp',])

        # verify the new state of rule #7

        # true-rule should skip 1
        # false-rule should skip 2 (all of the OTHER chain)
        self.assertBranchSkip(chain, 6, len(otherChain),
                              args=['-p', 'tcp',])

if __name__ == "__main__":
    unittest.main()
