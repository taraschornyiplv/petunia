"""Unslicer.py

Implement the iptables-unslice algorithm.

Here we want to add all of the interface filters
to a single chain and filter block, where we can apply
different sub-algorithms to try to find common substrings.
"""

import socket
import logging
import hashlib
import uuid

from petunia.Topology import (
    Topology,
    sortIfNames,
)

from petunia.TcStatement import Translator
from petunia.Slicer import SliceTable
from petunia.Iptables import (
    FilterTable,
    IptablesChain,
    IptablesRule,
)

class IptablesChainSuffix(object):

    def __init__(self, parent, offset):
        self.parent = parent
        self.offset = offset

class Unslicer(object):
    """Data structure to represent per-interface chains.

    Includes a 'merge' interface to support merging interfaces
    for groups of interfaces.

    This assumes that TC interface chains and 'action goto chain N'
    is not supported -- sharing is for the entire chain,
    with no support for fanout/fanin.
    """

    def __init__(self, table, chain,
                 onlyInterfaces=None, allInterfaces=None,
                 version=socket.AF_INET,
                 merge_fn=None,
                 log=None):
        self.log = log or logging.getLogger(self.__class__.__name__)
        self.table = table
        self.chain = chain
        self.onlyInterfaces = onlyInterfaces
        self.allInterfaces = allInterfaces
        self.version = version

        self.topo = Topology(log=self.log.getChild("links"))

        if self.allInterfaces is not None:
            self.topo.narrow(self.allInterfaces)
        if self.onlyInterfaces is not None:
            self.topo.narrow(self.onlyInterfaces, demote=False)

    def unslice(self, merge_fn=None):

        o = self.onlyInterfaces
        a = self.allInterfaces if self.allInterfaces is not None else self.topo.getPorts()

        table = SliceTable.fromSlice(self.table, self.chain,
                                     onlyInterfaces=o, allInterfaces=a,
                                     log=self.log.getChild("slice"))

        ifNames = sortIfNames(table.chains.keys())
        # grab the original chain names

        # operate on the slice table as per our desired merge strategy
        # merged chains should be re-inserted in the form 'swp1,swp2,...'
        # this is a simple vertical merge with no cross-chain jumps.
        if merge_fn is not None:
            merge_fn(table)

        # after the table has been modified, compute the chain map
        chainMap = {}

        ifGroups = sortIfNames(table.chains.keys())
        for ifGroup in ifGroups:
            if ',' in ifGroup:
                for ifName in ifGroup.split(','):
                    if ifName in chainMap:
                        raise ValueError("invalid interface group %s: duplicate interface %s"
                                         % (ifGroup, ifName,))
                    chainMap[ifName] = ifGroup
            elif ifGroup in chainMap:
                raise ValueError("invalid duplicate interface %s" % ifGroup)
            else:
                chainMap[ifGroup] = ifGroup

        # make sure the interface groups cover the original interfaces
        ifNames_ = sortIfNames(chainMap.keys())
        if ifNames != ifNames_:
            raise ValueError("merged chains an inconsistent interface cover")

        # compute the starting position of each ifGroup's chain
        chainPos = {}
        pos = 0

        # enumerate first-class chains

        for ifGroup in ifGroups:
            chain = table.chains[ifGroup]
            if not isinstance(chain, IptablesChainSuffix):
                chainPos[ifGroup] = pos
                pos = pos + len(chain.rules) + 1
                # add a default rule to skip past the end
        endPos = pos

        # TOC fixups for suffix chains

        for ifGroup in ifGroups:
            chain = table.chains[ifGroup]
            if isinstance(chain, IptablesChainSuffix):
                self.log.debug("fixing up %s suffix %s", chain.parent, ifGroup)
                if ',' in chain.parent:
                    chainPos[ifGroup] = chainPos[chain.parent]+chain.offset
                else:
                    chainPos[ifGroup] = chainPos[chainMap[chain.parent]]+chain.offset

        # build up the new table

        newTable = FilterTable({}, log=self.log)
        newChain = IptablesChain([], self.table.chains[self.chain].policy)
        newTable.chains[self.chain] = newChain

        # build up a jump table for each interface

        numIntfs = len(ifNames)
        for idx, ifName in enumerate(ifNames):

            stride0 = numIntfs-idx-1
            # stride to first rule

            strideN = chainPos[chainMap[ifName]]
            # stride to the correct ifGroup's block

            tocRule = IptablesRule(['-i', ifName,],
                                   target='SKIP',
                                   target_args=['--skip-rules', str(stride0+strideN),])
            newChain.rules.append(tocRule)

        # line up the chains end to end

        # compute the distance to the end for each chain
        chainSkip = endPos

        # emit each chainGroup
        for ifGroup in ifGroups:
            chain = table.chains[ifGroup]
            if isinstance(chain, IptablesChainSuffix):
                continue
            newChain.rules.extend(chain.rules)

            chainSkip -= len(chain.rules)
            chainSkip -= 1
            # offset for the length of the chain
            # plus an extra for the jump

            endRule = IptablesRule([],
                                   target='SKIP',
                                   target_args=['--skip-rules', str(chainSkip),])
            newChain.rules.append(endRule)

        # verify that this is a valid slice output
        # see e.g. the code in TcFlowerLoader.py

        return newTable

def validateUnslice(chain, interfaces):
    """Verify that this FilterTable is a valid output from Unslicer.

    XXX rothcar -- maybe also unwind the table?
    """

    # simple validation -- make sure each interface is in the table

    # validate the TOC

    for idx, ifName in enumerate(sortIfNames(interfaces)):
        try:
            tocRule = chain.rules[idx]
        except IndexError:
            raise ValueError("invalid slicer output: missing TOC entry for %s"
                             % ifName)
        if tocRule.in_interface != ifName:
            raise ValueError("invalid slicer output: unexpected in_interface %s for %s TOC entry"
                             % (tocRule.in_interface, ifName,))
        if (tocRule.target != 'SKIP'
            or tocRule.target_args[0:1] != ['--skip-rules',]):
            raise ValueError("invalid slicer output: unexpected target %s %s for %s TOC entry"
                             % (tocRule.target, tocRule.target_args, ifName,))

    # validate the individual rules

    ifSet = set(interfaces)
    for rule in chain.rules[len(interfaces):]:
        if (rule.in_interface is not None
            and rule.in_interface not in ifSet):
            raise ValueError("invalid in_interfaces in rule rule %s"
                             % rule)

def simpleMerge(table):
    """Simple merge implementation.

    Find chains that are 100% overlapping.
    """

    logger = table.log

    hashes = {}
    for ifName, chain in table.chains.items():
        if ',' in ifName:
            raise ValueError("interface groups not supported for simple merge")
        chainHash = hash(chain)
        hashes.setdefault(chainHash, [])
        hashes[chainHash].append(ifName)

    # build up the labels first so we can sort them
    # and merge them consistently

    labels = {}
    for chainHash, ifGroup in hashes.items():
        if len(ifGroup) > 1:
            label = ','.join(sortIfNames(ifGroup))
            labels[label] = ifGroup

    for label in sortIfNames(labels.keys()):
        logger.info("merging chains %s", label)
        ifGroup = labels[label]
        chain0 = table.chains[ifGroup[0]]
        table.merge(chain0, *ifGroup)

    return table

def simpleSuffixMerge(table):
    """Attempt to merge chains that have a common suffix.

    Here we say C1 and C2 have a common suffix if

      C2.rules == C1.rules[-N:] for some N

    These can be easily represented in the slice output by adjusting the TOC.

    Here we are only finding common suffixes where the shorter rule
    is completely enclosed in the longer rule. We are ignoring generalized
    fanin cases like

      C1.rules[-N:] == C2.rules[-N:] and C1.rules[:N] != C2.rules[:N]

    """

    logger = table.log

    # 1. compute all suffix hashes

    suffixes = {}
    # list of suffix hashes, per ifGroup

    hashes = {}
    # dict of suffix hashes to find collisions

    for ifGroup, chain in table.chains.items():
        hasher = hashlib.md5()
        sz = len(chain.rules)
        suffixes[ifGroup] = [None,] * sz
        for pos in range(sz-1, -1, -1):

            hasher.update(str(hash(chain.rules[pos])).encode())
            ck = hasher.hexdigest()

            suffixes[ifGroup][pos] = ck

            hashes.setdefault(ck, [])
            hashes[ck].append((ifGroup, pos,))

    logger.debug("computed %d unique hashes", len(hashes))

    # 2. for each chain C1, by descending length
    #    C2 is a suffix of C1 at pos N
    #    if hash(C1, N) == hash(C2, 0)

    chainList = [(len(y.rules), x) for x, y in table.chains.items()]
    for sz, ifGroup in sorted(chainList, reverse=True):
        chain = table.chains[ifGroup]
        logger.debug("examining chain %s (%d rules)", ifGroup, sz)
        for pos, ck in enumerate(suffixes[ifGroup]):
            coll = hashes[ck]

            coll = [x for x in coll if x[0] != ifGroup]
            # not us

            coll = [x for x in coll if x[1] == 0]
            # common suffix starting at zero (completely subsumed)

            if not coll: continue

            if pos == 0:
                # ifGroup and ifGroup_ overlap completely
                # we should have caught this with simpleMerge first
                raise ValueError("duplicate chains %s and %s"
                                 % (ifGroup, coll[0][0]))

            # found collision(s)

            for ifGroup_, pos_ in coll:
                if isinstance(table.chains[ifGroup_], IptablesChainSuffix):
                    logger.info("chain %s (already merged) is also a suffix of %s at %d",
                                ifGroup_, ifGroup, pos)
                else:
                    logger.info("chain %s is a suffix of %s at %d",
                                ifGroup_, ifGroup, pos)
                    logger.info("merging %s into %s", ifGroup_, ifGroup)
                    newChain = IptablesChainSuffix(ifGroup, pos)
                    ##table.merge(newChain, *ifGroup_.split(','))
                    table.merge(newChain, ifGroup_)

    return table

class UuidChain(IptablesChain):
    """Like an IptablesChain, but the rules have SKIP with absolute targets."""

    @classmethod
    def fromIptablesChain(cls, chain):
        """Generate a UUID-based chain based on a standard IPTABLES chain."""

        # clone all of the rules, adding UUIDs

        newRules = []
        uuids = {}
        for idx, rule in enumerate(chain.rules):
            rule_ = rule.clone()
            rule_.uuid = str(uuid.uuid4())
            newRules.append(rule_)
            uuids[rule_.uuid] = idx

        # add a sentinel rule
        ruleN = cls.rule_klass([], target='RETURN')
        ruleN.uuid = str(uuid.uuid4())
        newRules.append(ruleN)
        uuids[ruleN.uuid] = len(chain.rules)

        # scan the rules for SKIP entries

        for idx, rule in enumerate(newRules):
            if rule.target == 'SKIP':
                if rule.target_args[0:1] == ['--skip-rules',]:
                    stride = int(rule.target_args[1], 10)
                    tgt = newRules[idx+stride+1].uuid
                    rule.target_args = ['--skip-target', tgt,]
                else:
                    raise ValueError("invalid target args %s" % rule.target_args)

        return cls(newRules, chain.policy)

    def toIptablesChain(self):
        """Generate an IPTABLES chain from this UUID-based chain."""


        # gather the UUID indices

        uuids = {}
        for idx, rule in enumerate(self.rules):
            uuids[rule.uuid] = idx

        # translate all but the sentinel

        newRules = []
        for idx, rule in enumerate(self.rules[:-1]):
            rule_ = rule.clone()
            if rule_.target == 'SKIP':
                if rule_.target_args[0:1] == ['--skip-target',]:
                    tgt = rule_.target_args[1]
                    stride = uuids[tgt]-idx-1
                    rule_.target_args = ['--skip-rules', str(stride),]
                else:
                    raise ValueError("invalid target args %s" % rule.target_args)
            newRules.append(rule_)

        return IptablesChain(newRules, self.policy)

    def insertRule(self, pos, rule):
        """Insert a rule into a UUID-based chain.

        It's considered part of the chain from [pos:]
        but not part of the chain from [:pos].

        This means, all SKIP targets that point to pos
        should be update to point to the new rule.
        """

        rule_ = rule.clone()
        rule_.uuid = str(uuid.uuid4())

        if pos > len(self.rules)-1:
            raise IndexError("invalid rule position")

        # we cannot "insert" before the sentinel
        if pos == len(self.rules)-1:
            raise ValueError("cannot insert at end-of-rules")

        self.rules.insert(pos, rule_)

        # all SKIPs that end at pos should end at this new rule
        # --> we need adopt this UUID
        nextRule = self.rules[pos+1]
        rule_.uuid, nextRule.uuid = nextRule.uuid, rule_.uuid

        if rule_.target == 'SKIP':
            if rule_.target_args[0:1] == ['--skip-rules',]:
                stride = int(rule_.target_args[1], 10)
                tgt = self.rules[pos+stride+1].uuid
                rule_.target_args = ['--skip-target', tgt,]
            else:
                raise ValueError("invalid target args %s" % rule_.target_args)

    def appendRule(self, pos, rule):
        """Append a rule into a UUID-based chain.

        It's considered part of the chain from [:pos]
        but not part of the chain from [pos:].

        This means, update any SKIP targets that land at this
        position to be one rule later.
        """

        rule_ = rule.clone()
        rule_.uuid = str(uuid.uuid4())

        if pos > len(self.rules)-1:
            raise IndexError("invalid rule position")

        # OK to insert before the sentinel

        self.rules.insert(pos, rule_)

        # no UUID fixup needed

        if rule_.target == 'SKIP':
            if rule_.target_args[0:1] == ['--skip-rules',]:
                stride = int(rule_.target_args[1], 10)
                tgt = self.rules[pos+stride+1].uuid
                rule_.target_args = ['--skip-target', tgt,]
            else:
                raise ValueError("invalid target args %s" % rule_.target_args)

def mergePrefixes(table, *chainNames):
    """Merge all of chainNames.

    Here we assume that all of chains in chainNames are proper prefixes
    of the longest chain in the set. This property is *not* verified.

    Nesting this call won't work, since the exit strides then become incorrect.
    Special care needs to be taken for chains that already contain SKIPs.
    """

    logger = table.log

    logger.debug("merging %s", chainNames)

    # process chains in reverse order by length

    chainList = []
    for chainName in chainNames:
        chain = table.chains[chainName]
        chainList.append((len(chain.rules), chainName,))
    chainList.sort(reverse=True)

    # make sure there are no empty chains
    if chainList[-1][0] == 0:
        raise ValueError("empty chain %s" % chainList[-1][1])

    # make sure all of the chains are different lengths
    for idx in range(len(chainList)-1):
        l1, c1 = chainList[idx+1]
        l2, c2 = chainList[idx]
        if l1 == l2:
            raise ValueError("invalid chains (%s, %s) for prefix merge (same size)"
                             % (c1, c2,))

    parent = table.chains[chainList[0][1]]
    # longest of the chains, this is parent chain that
    # will be manipulated

    suffixes = {}
    for chainName, chain in table.chains.items():
        if (isinstance(chain, IptablesChainSuffix)
            and chain.parent == chainList[0][1]):
            logger.debug("tracking suffix chain %s for fixups", chainName)
            suffixes[chainName] = IptablesChainSuffix(chain.parent, chain.offset)
            # XXX rothcar -- note that chain.parent will need to be updated

    # make sure each segment is well-formed w.r.t. skip statements,
    # otherwise we cannot safely insert skip statements

    for idx in range(len(chainList)-1):
        l1, c1 = chainList[idx+1]
        l2, c2 = chainList[idx]

        # c1 is a prefix of c2 (l2 > l1)
        # there should not be any long skips in the gap between
        # c1 and c2 (parent.rules[l1:l2])

        gapSz = l2-l1
        for idx, rule in enumerate(parent.rules[l1:l2]):
            maxStride = gapSz-idx-1
            if rule.target == 'SKIP':
                stride = int(rule.target_args[1], 10)
                if stride > maxStride:
                    raise ValueError("invalid chain %s, %s for prefix merge (non-local SKIP)"
                                     % (c1, c2,))

    # check the last (shortest) segment for out-of-bounds SKIPs (all rules in the shortest prefix)

    gapSz = chainList[-1][0]
    for idx, rule in enumerate(parent.rules[:gapSz]):
        maxStride = gapSz-idx-1
        if rule.target == 'SKIP':
            stride = int(rule.target_args[1], 10)
            if stride > maxStride:
                raise ValueError("invalid chain %s for prefix merge (non-local SKIP)"
                                 % chainList[-1][1])

    # construct the new chain using UUID helpers
    # insert each exit route in turn
    newChain = UuidChain.fromIptablesChain(parent)
    for chainName, chain in suffixes.items():
        chain.uuid = newChain.rules[chain.offset+1].uuid
        # implicit SKIP from the suffix chain into the parent chain

    # update any suffix offset to be uuid-based

    # for all of the shorter chains (by descending order of length)
    # insert an exit rule
    # Here, chainList[0] is the parent chain

    for sz, chainName in chainList[1:]:

        logger.debug("inserting exit rule for %s", chainName)

        # at position sz, insert a SKIP to the end (sentinel)

        ifNames = chainName.split(',')
        for ifName in sortIfNames(ifNames, reverse=True):

            stride = len(newChain)-sz-1
            # gap size plus one to include the sentinel

            exitRule = IptablesRule(['-i', ifName,],
                                    target='SKIP',
                                    target_args=['--skip-rules', str(stride),])

            # here, 'insert' vs 'append', so that the semantics of the exit rule
            # attach to the suffix (not the prefix part)
            newChain.insertRule(sz, exitRule)

    # new chain is inserted with a superset of all of the interface names
    ifGroup = set()
    for chainName in chainNames:
        ifGroup.update(chainName.split(','))
    ifGroup = ','.join(sortIfNames(ifGroup))

    for chainName in chainNames:
        table.chains.pop(chainName)
    table.chains[ifGroup] = newChain.toIptablesChain()

    # fixup any suffixes now
    if suffixes:
        uuids = {}
        for idx, rule in enumerate(newChain.rules):
            uuids[rule.uuid] = idx
        for chainName, chain in suffixes.items():
            # for each suffix of this new merged chain,
            # recompute the correct suffix entry point,
            # and recompute the correct parent chain ifGroup name.
            logger.debug("suffix %s now has offset %d (was %d)",
                         chainName, uuids[chain.uuid]-1, table.chains[chainName].offset)
            table.chains[chainName] = IptablesChainSuffix(ifGroup, uuids[chain.uuid]-1)

def simplePrefixMerge(table, prefixOnly=True):
    """Attempt to merge chains that have a common prefix.

    For now we can't do suffix and prefix merges on the same chains,
    because that breaks the TOC offsets for the chains that were suffix-merged.

    XXX rothcar -- this might be fixable
    """

    logger = table.log

    # compute all prefix hashes

    prefixes = {}
    hashes = {}

    for ifGroup, chain in table.chains.items():
        if isinstance(chain, IptablesChainSuffix):
            continue
        hasher = hashlib.md5()
        sz = len(chain.rules)
        prefixes[ifGroup] = [None,] * sz
        for pos in range(sz):

            hasher.update(str(hash(chain.rules[pos])).encode())
            ck = hasher.hexdigest()

            prefixes[ifGroup][pos] = ck

            hashes.setdefault(ck, [])
            hashes[ck].append((ifGroup, pos,))

    logger.debug("computed %d unique hashes", len(hashes))

    # 2. for each chain C1, by descending length
    #    C2 is a prefix of C1 at for length N+1
    #    if hash(C1, N) == hash(C2, N) and len(C1.rules)==N+1

    chainList = []
    for chainName, chain in table.chains.items():
        if isinstance(chain, IptablesChainSuffix):
            continue
        chainList.append((len(chain.rules), chainName,))
    chainList.sort(reverse=True)

    merged = set()

    # get the set of ifGroups that are were merged during suffix scanning
    # (the TOC offsets will be incorrect)

    suffixTargets = set()
    if prefixOnly:
        for chainName, chain in table.chains.items():
            if isinstance(chain, IptablesChainSuffix):
                if chain.parent not in suffixTargets:
                    logger.debug("disabling merges for %s (prefixOnly=True)",
                                 chain.parent)
                    suffixTargets.add(chain.parent)

    for sz, ifGroup in chainList:

        if ifGroup in suffixTargets:
            logger.warning("chain %s already merged via suffix", ifGroup)
            continue

        if ifGroup in merged: continue

        logger.debug("examining chain %s (%d rules)", ifGroup, sz)

        toMerge = set()

        # enumerate all prefixes of ifGroup, by descending length
        for pos in range(len(table.chains[ifGroup].rules)-1, -1, -1):
            ck = prefixes[ifGroup][pos]

            coll = hashes[ck]

            coll = [x for x in coll if x[0] != ifGroup]
            # we are always a prefix of ourselves

            coll = [x for x in coll if x[0] not in suffixTargets]
            coll = [x for x in coll if x[0] not in merged]
            # skip chains we do not want to merge

            if not coll: continue

            if pos+1 == sz:
                # ifGroups overlap completely
                raise ValueError("duplicate chains %s and %s"
                                 % (ifGroup, coll[0][0]))

            for ifGroup_, pos_ in coll:
                logger.info("chain %s is a prefix of %s (%d rules) -- merging",
                            ifGroup_, ifGroup, pos+1)
                toMerge.add(ifGroup_)
                merged.add(ifGroup_)

        if toMerge:
            toMerge.add(ifGroup)
            mergePrefixes(table, *toMerge)
        else:
            logger.warning("no valid candidates to merge for %s", ifGroup)

    return table
