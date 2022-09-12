"""test_iptables_unslice.py

Test the unslicing algorithms.
"""

import os, sys
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

import TcSaveTestUtils

from petunia.Iptables import (
    FilterTable,
    IptablesChain,
)
from petunia.Unslicer import Unslicer
from petunia.Slicer import SliceTable

class UnsliceTestMixin(object):

    def assertToc(self, chain, toc):
        """Verify the forward-skip stride for each interface.

        Format for 'toc' is {INTERFACE : TOC-SKIP-STRIDE, ...}
        """

        tocRules = [x for x in chain.rules if x.in_interface is not None]
        bodyRules = [x for x in chain.rules if x.in_interface is None]

        self.assertEqual(len(toc), len(tocRules))

        for tocRule in tocRules:
            self.log.debug("verifying that interface %s TOC skips %d rules",
                           tocRule.in_interface, toc[tocRule.in_interface])
            self.assertEqual('SKIP', tocRule.target)
            self.assertEqual('--skip-rules', tocRule.target_args[0])
            stride = int(tocRule.target_args[1], 10)
            self.assertEqual(toc[tocRule.in_interface], stride)

    def assertOffsets(self, chain, offsets):
        """Verify sub-chain size and end-skip stride for each interface.

        Format for 'offsets' is {INTERFACE : (CHAIN-LEN, EXIT-STRIDE,), ...}
        """

        tocRules = [x for x in chain.rules if x.in_interface is not None]
        bodyRules = [x for x in chain.rules if x.in_interface is None]

        self.assertEqual(len(offsets), len(tocRules))

        for tocIdx, tocRule in enumerate(tocRules):
            self.log.debug("verifying that interface %s TOC has correct offsets",
                           tocRule.in_interface)
            self.assertEqual('SKIP', tocRule.target)
            self.assertEqual('--skip-rules', tocRule.target_args[0])
            stride = int(tocRule.target_args[1], 10)
            bodyStride = stride - len(offsets) + tocIdx + 1

            sz, exStride = offsets[tocRule.in_interface]

            self.log.debug("verifying that %s chain (offset %d, body offset %d) has %d rules",
                           tocRule.in_interface, stride, bodyStride, sz)

            bodyRules_ = bodyRules[bodyStride:bodyStride+sz+1]
            self.assertEqual(sz+1, len(bodyRules_))
            # capture the full chain, plus the exit statement

            self.log.debug("verifying that %s chain has %d-rule exit",
                           tocRule.in_interface, exStride)

            # extract the exit statement
            exitRule = bodyRules_[-1]
            self.assertEqual('SKIP', exitRule.target)
            self.assertEqual('--skip-rules', exitRule.target_args[0])
            exStride_ = int(exitRule.target_args[1], 10)
            self.assertEqual(exStride, exStride_)

    def assertUnslice(self, rules, toc, offsets):
        """Verify that chains get unsliced correctly."""

        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        self.log.info("before slice:")
        sys.stderr.write(table.toSave())

        unslicer = Unslicer(table, 'FORWARD',
                            log=self.log.getChild("slice"))
        table_ = unslicer.unslice()

        self.log.info("after slice:")
        sys.stderr.write(table_.toSave())

        chain = table_.chains['FORWARD']
        self.assertToc(chain, toc)
        self.assertOffsets(chain, offsets)

class UnsliceTest(UnsliceTestMixin,
                  TcSaveTestUtils.IptablesTestMixin,
                  unittest.TestCase):

    def setUp(self):
        self.log = logger.getChild(self.id())

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        os.environ['TEST_VLANS_JSON'] = json.dumps({})
        os.environ['TEST_SVIS_JSON'] = json.dumps({})
        # default set of interfaces, may adjust this depending
        # on the stress parameter

    def tearDown(self):
        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def testNoInterfaces(self):

        rules = []
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)
        chain = table.chains['FORWARD']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(0, len(chain.rules))

        self.log.info("ready to slice")

        unslicer = Unslicer(table, 'FORWARD',
                            log=self.log.getChild("slice"))
        table_ = unslicer.unslice()

        print(table_.toSave())

        chain = table_.chains['FORWARD']
        self.assertEqual('ACCEPT', chain.policy)

        self.assertEqual(4, len(chain.rules))
        # one rule for each interface for TOC
        # one rule for each exit statement

    def testEmptyChains(self):

        # single chain, empty

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        chain = table.chains['FORWARD']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(1, len(chain.rules))

        self.log.info("ready to slice")

        # restrict to a single interface
        unslicer = Unslicer(table, 'FORWARD',
                            onlyInterfaces=['dummy0',],
                            log=self.log.getChild("slice"))
        table_ = unslicer.unslice()
        print(table_.toSave())

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 0",   # 1. 1 --> 2
                  # toc

                  # dummy0
                  "-A FORWARD -j SKIP --skip-rules 0",             # 2. 2 --> 3
        ]

        chain = table_.chains['FORWARD']
        toc = {'dummy0' : 0,}
        offsets = {'dummy0' : [0, 0,],}
        self.assertToc(chain, toc)
        self.assertOffsets(chain, offsets)

        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(2, len(chain.rules))

        # two chains, empty

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
        ]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        chain = table.chains['FORWARD']
        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(2, len(chain.rules))

        self.log.info("ready to slice")

        unslicer = Unslicer(table, 'FORWARD',
                            log=self.log.getChild("slice"))
        table_ = unslicer.unslice()
        print(table_.toSave())

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 1",   # 1. 1 --> 3
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",   # 2. 2 --> 4
                  # toc

                  # dummy0
                  "-A FORWARD -j SKIP --skip-rules 1",             # 3. 3 --> 5

                  # dummy1
                  "-A FORWARD -j SKIP --skip-rules 0",             # 4. 4 --> 5
        ]

        chain = table_.chains['FORWARD']
        self.assertEqual(len(rules_), len(chain.rules))

        toc = {'dummy0' : 1,
               'dummy1' : 1,}
        offsets = {'dummy0' : [0, 1,],
                   'dummy1' : [0, 0,],}
        self.assertToc(chain, toc)
        self.assertOffsets(chain, offsets)

        self.assertEqual('ACCEPT', chain.policy)
        self.assertEqual(4, len(chain.rules))

    def testSingleChain(self):

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD_dummy0 -p tcp -j ACCEPT",]
        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        self.log.info("ready to slice")

        # restrict to a single interface

        unslicer = Unslicer(table, 'FORWARD',
                            onlyInterfaces=['dummy0',],
                            log=self.log.getChild("slice"))
        table_ = unslicer.unslice()

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 0",   # 1. 1 --> 2

                  # dummy0
                  "-A FORWARD -p tcp -j ACCEPT",                   # 2.
                  "-A FORWARD -j SKIP --skip-rules 0",             # 3. 3 --> 4
        ]
        print(table_.toSave())

        chain = table_.chains['FORWARD']
        toc = {'dummy0' : 0,}
        offsets = {'dummy0' : [1, 0,],}
        self.assertToc(chain, toc)
        self.assertOffsets(chain, offsets)

        # allow multiple interfaces

        unslicer = Unslicer(table, 'FORWARD',
                            log=self.log.getChild("slice"))
        table_ = unslicer.unslice()
        print(table_.toSave())

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 1",   # 1. 1 --> 3
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",   # 2. 2 --> 5

                  # dummy0
                  "-A FORWARD -p tcp -j ACCEPT",                   # 3.
                  "-A FORWARD -j SKIP --skip-rules 1",             # 4. 4 --> 6

                  # dummy1
                  "-A FORWARD -j SKIP --skip-rules 0",             # 5. 5 --> 6
        ]

        chain = table_.chains['FORWARD']
        self.assertEqual(len(rules_), len(chain.rules))

        toc = {'dummy0' : 1,
               'dummy1' : 2,}
        offsets = {'dummy0' : [1, 1,],
                   'dummy1' : [0, 0,],}
        self.assertToc(chain, toc)
        self.assertOffsets(chain, offsets)

    def testTwoChains(self):
        """Test how chains can jump across each other."""

        # start initially empty

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 1",   # 1. 1 --> 2
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",   # 2. 2 --> 4

                  # dummy0
                  "-A FORWARD -j SKIP --skip-rules 1",             # 3. 3 --> 5

                  # dummy1
                  "-A FORWARD -j SKIP --skip-rules 0",             # 4. 4 --> 5
        ]

        toc = {'dummy0' : 1,
               'dummy1' : 1,}
        offsets = {'dummy0' : [0, 1,],
                   'dummy1' : [0, 0,],}

        self.assertUnslice(rules, toc, offsets)

        # add a rule to dummy0

        rules.append("-A FORWARD_dummy0 -p tcp -j ACCEPT")

        def _updateDummy0():

            # dummy0 lengthened by 1 rule
            offsets['dummy0'][0] += 1

            # --> entry point for dummy0 moves by 1
            toc['dummy1'] += 1

            # dummy1's chain is unchanged, so exit offsets are the same

        _updateDummy0()

        self.assertUnslice(rules, toc, offsets)

        # add a rule to dummy1

        rules.append("-A FORWARD_dummy1 -p tcp -j ACCEPT")

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 1",   # 1. 1 --> 2
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",   # 2. 2 --> 4

                  # dummy0
                  "-A FORWARD -p tcp -j ACCEPT",                   # 3.
                  "-A FORWARD -j SKIP --skip-rules 2",             # 4. 4 --> 7

                  # dummy1
                  "-A FORWARD -p tcp -j ACCEPT",                   # 5.
                  "-A FORWARD -j SKIP --skip-rules 0",             # 6. 6 --> 7
        ]

        def _updateDummy1():

            # dummy1 lengthened by 1 rule

            offsets['dummy1'][0] += 1

            # entry points are unchanged
            # dummy0's exit point is now moved

            offsets['dummy0'][1] += 1

        _updateDummy1()

        self.assertUnslice(rules, toc, offsets)

        # let's add some more rules:

        rules.append("-A FORWARD_dummy0 -p tcp -j ACCEPT")
        _updateDummy0()
        self.assertUnslice(rules, toc, offsets)

        rules.append("-A FORWARD_dummy0 -p tcp -j ACCEPT")
        _updateDummy0()
        self.assertUnslice(rules, toc, offsets)

        rules.append("-A FORWARD_dummy1 -p tcp -j ACCEPT")
        _updateDummy1()
        self.assertUnslice(rules, toc, offsets)

        rules.append("-A FORWARD_dummy1 -p tcp -j ACCEPT")
        _updateDummy1()
        self.assertUnslice(rules, toc, offsets)

class ThreeChainTest(UnsliceTestMixin,
                     TcSaveTestUtils.IptablesTestMixin,
                     unittest.TestCase):
    """Test unslice results with three chains."""

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

    def testChains(self):

        # three chains, empty

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1. 1 --> 4
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",   # 2. 2 --> 5
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 2",   # 3. 3 --> 6

                  # dummy0
                  "-A FORWARD -j SKIP --skip-rules 2",             # 4. 4 --> 7

                  # dummy1
                  "-A FORWARD -j SKIP --skip-rules 1",             # 5. 5 --> 7

                  # dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",             # 6. 6 --> 7
        ]

        toc = {'dummy0' : 2,
               'dummy1' : 2,
               'dummy2' : 2,}
        offsets = {'dummy0' : [0, 2,],
                   'dummy1' : [0, 1,],
                   'dummy2' : [0, 0,],}

        self.assertUnslice(rules, toc, offsets)

        # add a rule for dummy0

        rules.append("-A FORWARD_dummy0 -p tcp -j ACCEPT")

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1. 1 --> 4
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 3",   # 2. 2 --> 6
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 3",   # 3. 3 --> 7

                  # dummy0
                  "-A FORWARD -p tcp -j ACCEPT",                   # 4.
                  "-A FORWARD -j SKIP --skip-rules 2",             # 5. 5 --> 8

                  # dummy1
                  "-A FORWARD -j SKIP --skip-rules 1",             # 6. 8 --> 8

                  # dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",             # 7. 7 --> 8
        ]

        def _updateDummy0():

            # add a rule to dummy0

            # --> start positions for dummy1, dummy2 have moved
            toc['dummy1'] += 1
            toc['dummy2'] += 1

            # --> dummy0 is now longer, exit strides are unchanged
            offsets['dummy0'][0] += 1

        _updateDummy0()

        self.assertUnslice(rules, toc, offsets)

        # add a rule for dummy1

        rules.append("-A FORWARD_dummy1 -p tcp -j ACCEPT")

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1. 1 --> 4
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 3",   # 2. 2 --> 6
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 4",   # 3. 3 --> 8

                  # dummy0
                  "-A FORWARD -p tcp -j ACCEPT",                   # 4.
                  "-A FORWARD -j SKIP --skip-rules 3",             # 5. 5 --> 9

                  # dummy1
                  "-A FORWARD -p tcp -j ACCEPT",                   # 6
                  "-A FORWARD -j SKIP --skip-rules 1",             # 7. 7 --> 9

                  # dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",             # 8. 8 --> 9
        ]

        def _updateDummy1():

            # added a rule to dummy1
            offsets['dummy1'][0] += 1

            # exit stride for dummy0 moves
            offsets['dummy0'][1] += 1

            # entry point for dummy2 moves
            toc['dummy2'] += 1

        _updateDummy1()

        self.assertUnslice(rules, toc, offsets)

        # add a rule to dummy2

        rules.append("-A FORWARD_dummy2 -p tcp -j ACCEPT")

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1. 1 --> 4
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 3",   # 2. 2 --> 6
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 4",   # 3. 3 --> 8

                  # dummy0
                  "-A FORWARD -p tcp -j ACCEPT",                   # 4.
                  "-A FORWARD -j SKIP --skip-rules 4",             # 5. 5 --> 10

                  # dummy1
                  "-A FORWARD -p tcp -j ACCEPT",                   # 6
                  "-A FORWARD -j SKIP --skip-rules 2",             # 7. 7 --> 10

                  # dummy2
                  "-A FORWARD -p tcp -j ACCEPT",                   # 8.
                  "-A FORWARD -j SKIP --skip-rules 0",             # 9. 9 --> 10
        ]

        def _updateDummy2():

            # added a rule to dummy2

            offsets['dummy2'][0] += 1

            # exit stride for dummy0, dummy1 have moved
            offsets['dummy0'][1] += 1
            offsets['dummy1'][1] += 1

            # toc entry for dummy2 has *not* moved

        _updateDummy2()

        self.assertUnslice(rules, toc, offsets)

        # OK let's add rules willy-nilly

        rules.append("-A FORWARD_dummy0 -p tcp -j ACCEPT")
        _updateDummy0()
        self.assertUnslice(rules, toc, offsets)

        rules.append("-A FORWARD_dummy1 -p tcp -j ACCEPT")
        _updateDummy1()
        self.assertUnslice(rules, toc, offsets)

        rules.append("-A FORWARD_dummy2 -p tcp -j ACCEPT")
        _updateDummy2()
        self.assertUnslice(rules, toc, offsets)

        # and more

        rules.append("-A FORWARD_dummy0 -p tcp -j ACCEPT")
        rules.append("-A FORWARD_dummy0 -p tcp -j ACCEPT")
        _updateDummy0()
        _updateDummy0()
        self.assertUnslice(rules, toc, offsets)

        rules.append("-A FORWARD_dummy1 -p tcp -j ACCEPT")
        rules.append("-A FORWARD_dummy1 -p tcp -j ACCEPT")
        _updateDummy1()
        _updateDummy1()
        self.assertUnslice(rules, toc, offsets)

        rules.append("-A FORWARD_dummy2 -p tcp -j ACCEPT")
        rules.append("-A FORWARD_dummy2 -p tcp -j ACCEPT")
        _updateDummy2()
        _updateDummy2()
        self.assertUnslice(rules, toc, offsets)

class SharedChainTest(UnsliceTestMixin,
                     TcSaveTestUtils.IptablesTestMixin,
                     unittest.TestCase):
    """Test unslice results with shared chains."""

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

    def assertUnslice(self, rules, toc, offsets, merge_fn=None):
        """Verify that chains get unsliced correctly.

        Apply a merge function to the unslice results.
        """

        table = FilterTable.fromString(self.saveFromLines(rules),
                                       log=self.log)

        self.log.info("before slice:")
        sys.stderr.write(table.toSave())

        unslicer = Unslicer(table, 'FORWARD',
                            log=self.log.getChild("slice"))
        table_ = unslicer.unslice(merge_fn=merge_fn)

        self.log.info("after slice:")
        sys.stderr.write(table_.toSave())

        chain = table_.chains['FORWARD']
        self.assertToc(chain, toc)
        self.assertOffsets(chain, offsets)

    def testEmpty(self):
        """Test merging with empty rules.

        We can't verify the contents here since the rules are... empty.
        """

        # three chains, empty, no sharing

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1. 1 --> 4
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",   # 2. 2 --> 5
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 2",   # 3. 3 --> 6

                  # dummy0
                  "-A FORWARD -j SKIP --skip-rules 2",             # 4. 4 --> 7

                  # dummy1
                  "-A FORWARD -j SKIP --skip-rules 1",             # 5. 5 --> 7

                  # dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",             # 6. 6 --> 7
        ]

        toc = {'dummy0' : 2,
               'dummy1' : 2,
               'dummy2' : 2,}
        offsets = {'dummy0' : [0, 2,],
                   'dummy1' : [0, 1,],
                   'dummy2' : [0, 0,],}

        self.assertUnslice(rules, toc, offsets)

        # merge dummy0, dummy1

        def _mergeDummy0Dummy1(table):
            r0 = table.chains['dummy0']
            r1 = table.chains['dummy1']
            chain = IptablesChain(r0.rules+r1.rules, 'RETURN')
            table.merge(chain, 'dummy0', 'dummy1')

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1. 1 --> 4
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",   # 2. 2 --> 4
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 1",   # 3. 3 --> 5

                  # dummy0,dummy1
                  "-A FORWARD -j SKIP --skip-rules 1",             # 4. 4 --> 6

                  # dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",             # 5. 5 --> 6
        ]

        toc = {'dummy0' : 2,
               'dummy1' : 1,
               'dummy2' : 1,}
        offsets = {'dummy0' : [0, 1,],
                   'dummy1' : [0, 1,],
                   'dummy2' : [0, 0,],}

        self.assertUnslice(rules, toc, offsets,
                           merge_fn=_mergeDummy0Dummy1)

        # merge dummy1, dummy2

        def _mergeDummy1Dummy2(table):
            r1 = table.chains['dummy1']
            r2 = table.chains['dummy2']
            chain = IptablesChain(r1.rules+r2.rules, 'RETURN')
            table.merge(chain, 'dummy1', 'dummy2')

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1. 1 --> 4
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",   # 2. 2 --> 4
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 1",   # 3. 3 --> 5

                  # dummy0
                  "-A FORWARD -j SKIP --skip-rules 1",             # 4. 4 --> 6

                  # dummy1,dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",             # 5. 5 --> 6
        ]

        toc = {'dummy0' : 2,
               'dummy1' : 2,
               'dummy2' : 1,}
        offsets = {'dummy0' : [0, 1,],
                   'dummy1' : [0, 0,],
                   'dummy2' : [0, 0,],}

        self.assertUnslice(rules, toc, offsets,
                           merge_fn=_mergeDummy1Dummy2)

        # merge dummy0, dummy2

        def _mergeDummy0Dummy2(table):
            r0 = table.chains['dummy0']
            r2 = table.chains['dummy2']
            chain = IptablesChain(r0.rules+r2.rules, 'RETURN')
            table.merge(chain, 'dummy0', 'dummy2')

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1. 1 --> 4
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 2",   # 2. 2 --> 4
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 0",   # 3. 3 --> 5

                  # dummy0,dummy2
                  "-A FORWARD -j SKIP --skip-rules 1",             # 4. 4 --> 6

                  # dummy1
                  "-A FORWARD -j SKIP --skip-rules 0",             # 5. 5 --> 6
        ]

        toc = {'dummy0' : 2,
               'dummy1' : 2,
               'dummy2' : 0,}
        offsets = {'dummy0' : [0, 1,],
                   'dummy1' : [0, 0,],
                   'dummy2' : [0, 1,],}

        self.assertUnslice(rules, toc, offsets,
                           merge_fn=_mergeDummy0Dummy2)

        # merge dummy0, dummy1, dummy2

        def _mergeDummy0Dummy1Dummy2(table):
            r0 = table.chains['dummy0']
            r1 = table.chains['dummy1']
            r2 = table.chains['dummy2']
            chain = IptablesChain(r0.rules+r1.rules+r2.rules, 'RETURN')
            table.merge(chain, 'dummy0', 'dummy1', 'dummy2')

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1. 1 --> 4
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",   # 2. 2 --> 4
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 0",   # 3. 3 --> 5

                  # dummy0,dummy1,dummy2
                  "-A FORWARD -j SKIP --skip-rules 0",             # 4. 4 --> 6
        ]

        toc = {'dummy0' : 2,
               'dummy1' : 1,
               'dummy2' : 0,}
        offsets = {'dummy0' : [0, 0,],
                   'dummy1' : [0, 0,],
                   'dummy2' : [0, 0,],}

        self.assertUnslice(rules, toc, offsets,
                           merge_fn=_mergeDummy0Dummy1Dummy2)

    def testNonEmpty(self):
        """Test merging with empty rules.

        We'll cheat on rule verification by picking ruleset of different length.
        """

        # three chains, empty, no sharing

        rules = ["-A FORWARD -i dummy0 -j FORWARD_dummy0",
                 "-A FORWARD -i dummy1 -j FORWARD_dummy1",
                 "-A FORWARD -i dummy2 -j FORWARD_dummy2",

                 # dummy0 --> 3 rules
                 "-A FORWARD_dummy0 -p tcp -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -j ACCEPT",
                 "-A FORWARD_dummy0 -p tcp -j ACCEPT",

                 # dummy1 --> 5 rules
                 "-A FORWARD_dummy1 -p tcp -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -j ACCEPT",
                 "-A FORWARD_dummy1 -p tcp -j ACCEPT",

                 # dummy2 --> 7 rules
                 "-A FORWARD_dummy2 -p tcp -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -j ACCEPT",
                 "-A FORWARD_dummy2 -p tcp -j ACCEPT",
        ]

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1. 1 --> 4
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 5",   # 2. 2 --> 8
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 10",  # 3. 3 --> 14

                  # dummy0
                  "-A FORWARD -p tcp -j ACCEPT",                   # 4.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 5.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 6.
                  "-A FORWARD -j SKIP --skip-rules 14",            # 7. 7 --> 22

                  # dummy1
                  "-A FORWARD -p tcp -j ACCEPT",                   # 8.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 9.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 10.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 11.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 12.
                  "-A FORWARD -j SKIP --skip-rules 8",             # 13. 13 --> 22

                  # dummy2
                  "-A FORWARD -p tcp -j ACCEPT",                   # 14.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 15.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 16.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 17.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 18.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 19.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 20.
                  "-A FORWARD -j SKIP --skip-rules 0",             # 21. 21 --> 22
        ]

        toc = {'dummy0' : 2,
               'dummy1' : 5,
               'dummy2' : 10,}
        offsets = {'dummy0' : [3, 14,],
                   'dummy1' : [5, 8],
                   'dummy2' : [7, 0,],}

        self.assertUnslice(rules, toc, offsets)

        # merge dummy0, dummy1

        def _mergeDummy0Dummy1(table):
            r0 = table.chains['dummy0']
            r1 = table.chains['dummy1']
            chain = IptablesChain(r0.rules+r1.rules, 'RETURN')
            table.merge(chain, 'dummy0', 'dummy1')

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1. 1 --> 4
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",   # 2. 2 --> 4
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 9",   # 3. 3 --> 13

                  # dummy0,dummy1 (now 8 rules long)
                  "-A FORWARD -p tcp -j ACCEPT",                   # 4.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 5.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 6.

                  "-A FORWARD -p tcp -j ACCEPT",                   # 7.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 8.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 9.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 10.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 11.
                  "-A FORWARD -j SKIP --skip-rules 8",             # 12. 12 --> 21

                  # dummy2
                  "-A FORWARD -p tcp -j ACCEPT",                   # 13.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 14.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 15.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 16.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 17.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 18.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 19.
                  "-A FORWARD -j SKIP --skip-rules 0",             # 20. 20 --> 21
        ]

        toc = {'dummy0' : 2,
               'dummy1' : 1,
               'dummy2' : 9,}
        offsets = {'dummy0' : [8, 8,],
                   'dummy1' : [8, 8,],
                   'dummy2' : [7, 0,],}

        self.assertUnslice(rules, toc, offsets,
                           merge_fn=_mergeDummy0Dummy1)

        # merge dummy1, dummy2

        def _mergeDummy1Dummy2(table):
            r1 = table.chains['dummy1']
            r2 = table.chains['dummy2']
            chain = IptablesChain(r1.rules+r2.rules, 'RETURN')
            table.merge(chain, 'dummy1', 'dummy2')

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1. 1 --> 4
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 5",   # 2. 2 --> 8
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 4",   # 3. 3 --> 8

                  # dummy0
                  "-A FORWARD -p tcp -j ACCEPT",                   # 4.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 5.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 6.
                  "-A FORWARD -j SKIP --skip-rules 13",            # 7. 7 --> 21

                  # dummy1,dummy2 (now 12 rules long)
                  "-A FORWARD -p tcp -j ACCEPT",                   # 8.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 9.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 10.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 11.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 12.

                  "-A FORWARD -p tcp -j ACCEPT",                   # 13.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 14.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 15.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 16.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 17.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 18.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 19.
                  "-A FORWARD -j SKIP --skip-rules 0",             # 20. 20 --> 21
        ]

        toc = {'dummy0' : 2,
               'dummy1' : 5,
               'dummy2' : 4,}
        offsets = {'dummy0' : [3, 13,],
                   'dummy1' : [12, 0],
                   'dummy2' : [12, 0,],}

        self.assertUnslice(rules, toc, offsets,
                           merge_fn=_mergeDummy1Dummy2)

        # merge dummy0, dummy2

        def _mergeDummy0Dummy2(table):
            r0 = table.chains['dummy0']
            r2 = table.chains['dummy2']
            chain = IptablesChain(r0.rules+r2.rules, 'RETURN')
            table.merge(chain, 'dummy0', 'dummy2')

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1. 1 --> 4
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 12",  # 2. 2 --> 15
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 0",   # 3. 3 --> 4

                  # dummy0, dummy2 --> now 10 rules long
                  "-A FORWARD -p tcp -j ACCEPT",                   # 4.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 5.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 6.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 7.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 8.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 9.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 10.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 11.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 12.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 13.
                  "-A FORWARD -j SKIP --skip-rules 6",             # 14. 14 --> 21

                  # dummy1
                  "-A FORWARD -p tcp -j ACCEPT",                   # 15.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 16.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 17.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 18.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 19.
                  "-A FORWARD -j SKIP --skip-rules 0",             # 20. 21 --> 21
        ]

        toc = {'dummy0' : 2,
               'dummy1' : 12,
               'dummy2' : 0,}
        offsets = {'dummy0' : [10, 6,],
                   'dummy1' : [5, 0],
                   'dummy2' : [10, 6,],}

        self.assertUnslice(rules, toc, offsets,
                           merge_fn=_mergeDummy0Dummy2)

        # merge dummy0, dummy1, dummy2

        def _mergeDummy0Dummy1Dummy2(table):
            r0 = table.chains['dummy0']
            r1 = table.chains['dummy1']
            r2 = table.chains['dummy2']
            chain = IptablesChain(r0.rules+r1.rules+r2.rules, 'RETURN')
            table.merge(chain, 'dummy0', 'dummy1', 'dummy2')

        rules_ = ["-A FORWARD -i dummy0 -j SKIP --skip-rules 2",   # 1. 1 --> 4
                  "-A FORWARD -i dummy1 -j SKIP --skip-rules 1",   # 2. 2 --> 4
                  "-A FORWARD -i dummy2 -j SKIP --skip-rules 0",   # 3. 3 --> 4

                  # dummy0, dummy1, dummy2 --> now 3+5+7 --> 15 rules long
                  "-A FORWARD -p tcp -j ACCEPT",                   # 4.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 5.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 6.

                  "-A FORWARD -p tcp -j ACCEPT",                   # 8.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 9.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 10.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 11.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 12.

                  "-A FORWARD -p tcp -j ACCEPT",                   # 14.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 15.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 16.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 17.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 18.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 19.
                  "-A FORWARD -p tcp -j ACCEPT",                   # 20.
                  "-A FORWARD -j SKIP --skip-rules 0",             # 21. 21 --> 22
        ]

        toc = {'dummy0' : 2,
               'dummy1' : 1,
               'dummy2' : 0,}
        offsets = {'dummy0' : [15, 0,],
                   'dummy1' : [15, 0],
                   'dummy2' : [15, 0,],}

        self.assertUnslice(rules, toc, offsets,
                           merge_fn=_mergeDummy0Dummy1Dummy2)

if __name__ == "__main__":
    unittest.main()
