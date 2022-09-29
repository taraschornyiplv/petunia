"""TcFlowerLoader.py

Load tc-flower rules.

XXX rothcar -- add a --force-init switch to dump all qdiscs

"""

import os
import logging
import subprocess
import socket
import tempfile
import shlex
import timeit

from petunia.Topology import (
    Topology,
    sortIfNames,
)

from petunia.TcStatement import (
    Translator,
    TC_CHAIN_DEFAULT,
    TC_CHAIN_ICMP,
)

from petunia.Slicer import SliceTable
from petunia.Unslicer import validateUnslice
from petunia.Scoreboard import validateScoreboard

import json
from petunia.JsonUtils import LazyFilterParser

# handles count up, preferences count up
# (though by default the are doled out in reverse order)

RULES_MAX = 8191

HANDLE_DEFAULT = 1
PREFERENCE_DEFAULT = 0x8000

HANDLE_UPDATE = 8193
PREFERENCE_UPDATE = 0xa000

assert RULES_MAX < (HANDLE_UPDATE - HANDLE_DEFAULT)
assert RULES_MAX < (PREFERENCE_UPDATE - PREFERENCE_DEFAULT)

BUG_EGRESS_SHOW = True
# 'qdisc show' always shows the egress interface,
# even if we only want to see the ingress interface

BUG_POLICE_JSON = True
# 'tc filter show' generates invalid JSON for policer actions
# (this is more properly an iproute2 bug)

BLOCKNUM = 1
# by default, use block 1 for shared chains

class MissingHandle(ValueError):
    """Error for a TC filter missing a handle."""
    def __init__(self, rule, msg=None):
        ValueError.__init__(self, msg=msg)
        self.rule = rule

class MissingPreference(ValueError):
    """Error for a TC filter missing a preference."""
    def __init__(self, rule, msg=None):
        ValueError.__init__(self, msg=msg)
        self.rule = rule

class MissingKind(ValueError):
    """Error for a TC filter missing a kind."""
    def __init__(self, rule, msg=None):
        ValueError.__init__(self, msg=msg)
        self.rule = rule

class TimerFunction(object):

    def __init__(self, fn, label=None, log=None):
        self.log = log or logging.getLogger(label)
        self.fn = fn
        self.result = None
        self.label = label or "TimerFunction"

    def execute(self):
        self.log.debug("%s starting", self.label)
        try:
            self.result = (self.fn(), None,)
        except Exception as ex:
            self.result = (None, ex,)

    def timeit(self):
        timer = timeit.Timer(stmt=self.execute)
        ela = timer.timeit(number=1)
        self.log.debug("%s call took %dms", self.label, int(ela*1000))
        if self.result[1] is None:
            return self.result[0]
        else:
            raise self.result[1]

class ProfileMixin(object):

    def timeit(self, fn, label=None):
        fn = TimerFunction(fn,
                           label=label,
                           log=self.log.getChild("profile"))
        return fn.timeit()

class SubprocessMixin(object):

    def call(self, cmd):
        self.log.debug("+ " + " ".join(cmd))
        if self.profile:
            code = self.timeit(lambda: subprocess.call(cmd),
                               label="subprocess")
        else:
            code = subprocess.call(cmd)
        self.log.debug("+ exit %s", code)
        return code

    def check_output(self, cmd):
        try:
            self.log.debug("+ " + " ".join(cmd))
            if self.profile:
                fn = lambda: subprocess.check_output(cmd,
                                                     universal_newlines=True)
                out = self.timeit(fn,
                                  label="subprocess")
            else:
                out = subprocess.check_output(cmd,
                                              universal_newlines=True)
            self.log.debug("+ exit 0")
            return out
        except subprocess.CalledProcessError as ex:
            for line in (ex.output or "").rstrip().splitlines(False):
                self.log.warning(">>> %s", line)
            self.log.error("+ exit %s", ex.returncode)
            raise

    def check_json(self, cmd):
        if BUG_POLICE_JSON:
            # use a more lenient JSON parser that can correct
            # inline mistakes
            json_ = LazyFilterParser(log=self.log.getChild("json"))
            loads = json_.loads
        else:
            loads = json.loads
        buf = self.check_output(cmd)
        if self.profile:
            data = self.timeit(lambda: loads(buf),
                               label="json.loads")
        else:
            data = loads(buf)
        return data

class TcBatch(ProfileMixin,
              SubprocessMixin):

    def __init__(self, profile=False, log=None):
        self.log = log or logging.getLogger(self.__class__.__name__)
        self.profile = profile
        self.cmds = []

    def feed(self, args):
        """Queue up a single TC command."""
        if args[0] != 'tc':
            raise ValueError("invalid command for TC batch: %s",
                             " ".join(args))
        self.cmds.append(args)

    def commitNoBatch(self, force=False):
        code = 0
        for idx, cmd in enumerate(self.cmds):
            code_ = self.call(cmd)
            if code_:
                self.log.warning("TC failed at statement %d", idx+1)
                code = code or code_
                if not force: break
        return code

    def commit(self, batch=True, force=False):
        """Run all of the commands."""

        if not self.cmds:
            self.log.warning("no TC commands to commit")
            return 0

        if not batch:
            return self.commitNoBatch(force=force)

        self.log.info("invoking %d TC commands in batch mode...", len(self.cmds))

        fno, p = tempfile.mkstemp(prefix="tc-flower-",
                                  suffix=".in")
        with os.fdopen(fno, 'wt') as fd:
            for cmd in self.cmds:
                ##cmd_ = shlex.join(cmd[1:])
                cmd_ = " ".join(shlex.quote(x) for x in cmd[1:])
                fd.write("%s\n" % cmd_)

        if force:
            cmd = ('tc', '-force', '-batch', p,)
        else:
            cmd = ('tc', '-batch', p,)
        code = self.call(cmd)
        if code != 0:
            self.log.warning("TC batch failed:")
            with open(p, 'rt') as fd:
                for line in fd.readlines():
                    line = line.rstrip()
                    self.log.warning(">>> %s", line)

        os.unlink(p)
        return code

class TcFilterShow(ProfileMixin,
                   SubprocessMixin):

    def __init__(self, profile=False, log=None):
        self.log = log or logging.getLogger(self.__class__.__name__)
        self.profile = profile
        self.cmds = []

    def show(self, dev=None, block=None, tc_chain=None):
        """Run the commands and returns the json output"""
        if dev is not None:
            attachOpts = ['dev', dev,]
        elif block is not None:
            attachOpts = ['block', str(block),]
        else:
            raise ValueError("missing device or block")
        chainOpts = []
        if tc_chain is not None:
            chainOpts.extend(['chain', tc_chain,])

        cmd = ['tc', '-json', '-stats', 'filter', 'show',] + attachOpts + ['ingress',] + chainOpts
        data = self.check_json(cmd)
        filtersRaw = list(data)
        return data

def attachSpec(dev=None, block=None):
    if dev is not None:
        return "interface %s" % dev
    if block is not None:
        return "block %d" % block
    raise ValueError("missing device or block")

class Loader(ProfileMixin,
             SubprocessMixin):

    def __init__(self, table, chain,
                 interfaces=None, offload=None,
                 shared=False, scoreboard=False,
                 atomic=True, drop=False, continue_=False,
                 version=socket.AF_INET,
                 profile=False,
                 log_ignore=False,
                 addrtype=None,
                 match_multi=False,
                 batch=True,
                 port_unroll=None,
                 drop_mode=None,
                 hack_vlan_arp=False,
                 reject_drop=True,
                 continue_suppress=False,
                 prestera_chain_mode=False,
                 log=None):
        self.table = table
        self.chainName = chain
        self.interfaces = interfaces
        self.offload = offload
        self.shared = shared
        self.scoreboard = scoreboard

        self.atomic = atomic
        self.drop = drop
        self.continue_ = continue_

        self.version = version

        self.profile = profile

        self.log_ignore = log_ignore
        self.addrtype = addrtype

        self.match_multi = match_multi
        self.batch = batch
        self.port_unroll = port_unroll

        self.drop_mode = drop_mode
        self.hack_vlan_arp = hack_vlan_arp

        self.reject_drop = reject_drop

        self.continue_suppress = continue_suppress

        self.prestera_chain_mode = prestera_chain_mode

        self.log = log or logging.getLogger(self.__class__.__name__)

        self.updateIfNames = None
        # list of interfaces requiring filter update
        # (non-zero with shared=True means the filter block needs update)

        self.topo = Topology(log=self.log.getChild("links"))

    def shutdown(self):
        pass

    def auditOffload(self, ifName):
        """Make sure this interface support hardware offload."""

        try:
            out = self.check_output(('ethtool', '--show-offload', ifName,))
        except subprocess.CalledProcessError:
            self.log.error("cannot invoke ethtool")
            return 1

        lines = out.rstrip().splitlines(False)
        rpt = [x for x in lines if x.startswith('hw-tc-offload: ')]
        if not rpt:
            self.log.error("interface %s: hardware offload not known", ifName)
            return 1
        if rpt[0] == 'hw-tc-offload: on':
            return 0
        self.log.error("interface %s: hardware offload not supported", ifName)
        return 1

    def maybeAddIngress(self, ifName):
        """Add the default ingress filter to an interface."""

        cmd = ('tc', '-json', 'qdisc', 'show', 'dev', ifName, 'ingress',)
        try:
            data = self.check_json(cmd)
        except subprocess.CalledProcessError as ex:
            return ex.returncode

        for qdisc in data:
            if qdisc.get('kind', None) == 'ingress':
                self.log.info("found an ingress qdisc on %s (filter update required)",
                              ifName)
                self.updateIfNames.add(ifName)
                return 0
            if BUG_EGRESS_SHOW:
                self.log.warning("invalid qdisc data %s -- skipping", qdisc)
            else:
                self.log.error("invalid qdisc data %s", qdisc)
                return 1

        self.log.info("adding ingress qdisc to %s", ifName)
        code = self.call(('tc', 'qdisc', 'add', 'dev', ifName, 'ingress',))
        if code: return code

        return 0

    def maybeAddBlock(self, *interfaces):
        """Attach all interfaces to a single shared block.

        Verify that the shared block is not attached to any extra interfaces.
        Verify that the the interfaces in question are not attached
        to some other block
        Verify that the interfaces are not already attached
        directly to a qdisc.
        """

        # get the current mapping of interfaces to ingress filter blocks

        curBlocks = {}

        cmd = ('tc', '-json', 'qdisc', 'show',)
        try:
            data = self.check_json(cmd)
        except subprocess.CalledProcessError as ex:
            return ex.returncode

        for qData in data:
            if qData.get('kind', None) != 'ingress': continue
            ifName = qData['dev']
            blocknum = qData.get('ingress_block', None)
            curBlocks[ifName] = blocknum
            # 'None' here if it is not using a shared block

        needed = set(interfaces)

        # reject current configurations that are invalid
        for ifName, blocknum in curBlocks.items():

            # this interface is attached to our shared filter block
            # but it is not in the list of interfaces to be configured
            if blocknum == BLOCKNUM and ifName not in needed:
                self.log.error("interface %s unexpected on block %d",
                               ifName, blocknum)
                return 1

            if blocknum is None and ifName in needed:
                self.log.error("interface %s already has a (non-shared) qdisc",
                               ifName)
                return 1

            if blocknum != BLOCKNUM and ifName in needed:
                self.log.error("interface %s block %d unexpected",
                               ifName, blocknum)
                return 1

        # attach any of our interfaces
        for ifName in interfaces:
            if ifName not in curBlocks:
                cmd = ('tc', 'qdisc', 'add',
                       'dev', ifName,
                       'ingress_block', str(BLOCKNUM),
                       'ingress',)
                self.log.info("adding ingress qdisc to %s (via shared block %d)",
                              ifName, BLOCKNUM)
                code = self.call(cmd)
                if code: return code
            else:
                self.log.info("found shared block %d on %s (filter update required)",
                              curBlocks[ifName], ifName)
                self.updateIfNames.add(ifName)

        return 0

    def maybeAddChain(self, dev, name):
        """Create tc chain based on match keys that will be used

        Verify that the shared block is not attached to any extra interfaces.
        Verify that the the interfaces in question are not attached
        to some other block
        Verify that the interfaces are not already attached
        directly to a qdisc.
        dev - device / block name
        name - name of device or block number
        """
        # get the current mapping of interfaces to ingress filter blocks

        cmd = ('tc', '-json', 'chain', 'show', dev, name, 'ingress')
        try:
            data = self.check_json(cmd)
        except subprocess.CalledProcessError as ex:
            return ex.returncode

        # check if the match conditions are present or mismatch then create a new one.
        for chain in self.tc_chain_keys.keys():
            need_new_chain = True
            for c in data:
                if c["chain"] != chain:
                    continue
                if "options" not in c:
                    # need to create now.
                    break
                # check if a new chain has to be created by deleting the old one
                keys = ()
                if "indev" in c["options"]:
                    keys += ("indev", c["options"]["indev"],)
                if "keys" in c["options"]:
                    for k,v in c["options"]["keys"].items():
                        # ICMP handling
                        if k == "icmp_type": k="type"
                        if k == "icmp_code": k="code"
                        keys += (k,str(v),)
                # now check the keys and flush old and create new if they are different
                if set(self.tc_chain_keys[chain]+('eth_type','ip',)) == set(keys):
                    need_new_chain = False
                break
            # if we dont need to a new chain then continue
            if not need_new_chain:
                continue
            # create the chain now.
            code = self.call(('tc', 'chain', 'del', dev, name, 'ingress', "chain", chain))
            # tc chain add block 1 ingress proto 802.1q chain 0 flower  vlan_ethtype ipv4
            code = self.call(('tc', 'chain', 'add', dev, name, 'ingress', 'protocol', '802.1q', 'chain', chain, 'flower', ) + self.tc_chain_keys[chain])
            if code: return code

    def resetIntf(self, ifName):
        """Reset the ingress qdisc on this interface.

        This is a non-atomic operation, traffic may leak after the reset.
        """

        code = self.call(('tc', 'qdisc', 'del', 'dev', ifName, 'ingress',))
        ##if code: return code

        code = self.call(('tc', 'qdisc', 'add', 'dev', ifName, 'ingress',))
        if code: return code

        return 0

    def resetBlock(self):
        """Reset the ingress shared block.

        This is a non-atomic operation, traffic may leak after the reset.
        """

        cmd = ('tc', '-json', 'qdisc', 'show',)
        data = self.check_json(cmd)

        # delete all interfaces attached to this block

        intfs = []
        for qData in data:
            if qData.get('kind', None) != 'ingress': continue
            ifName = qData['dev']
            blocknum_ = qData.get('ingress_block', None)
            if blocknum_ == BLOCKNUM:
                cmd = ('tc', 'qdisc', 'del', 'dev', ifName, 'ingress',)
                self.call(cmd)
                intfs.append(ifName)

        # supposedly after the last interface is removed,
        # the block is destroyed

        # re-add the (new) shared block back to each interface

        for ifName in intfs:
            code = self.call(('tc', 'qdisc', 'del', 'dev', ifName, 'ingress',))
            code = self.call(('tc', 'qdisc', 'add',
                              'dev', ifName,
                              'ingress_block', str(BLOCKNUM),
                              'ingress',))
            if code: return code

        return 0

    def defaultDrop(self, dev=None, block=None, handle=None, preference=None):
        """Configure this interface/block to do a default-drop.

        This is "mostly" atomic, the default-drop policy is
        enforce once all of the old rules have been deleted.
        """

        filtersByHandle = self.getRuleHandles(dev=dev, block=block)

        handles = sorted(filtersByHandle.keys())
        prefs = sorted([x['pref'] for x in filtersByHandle.values()])

        # default-drop rule has higher preference (evaluated last)
        # after the existing rules

        nextPref = prefs[-1]+1 if prefs else PREFERENCE_UPDATE
        nextHandle = (handles[-1]+1) if handles else HANDLE_UPDATE

        self.log.info("adding default-drop rule %s for %s (pref %d)",
                      nextHandle, attachSpec(dev=dev, block=block), nextPref)

        if self.version == socket.AF_INET:
            versionOpts = ['protocol', 'ip',]
        elif self.version == socket.AF_INET6:
            versionOpts = ['protocol', 'ipv6',]
        else:
            raise ValueError("invalid IP version")

        if self.offload is True:
            offloadOpts = ['skip_sw',]
        elif self.offload is False:
            offloadOpts = ['skip_hw',]
        else:
            offloadOpts = []

        if self.prestera_chain_mode:
            chainOpts = ['chain', "0",]
        else:
            chainOpts = []

        if dev is not None:
            attachOpts = ['dev', dev,]
        elif block is not None:
            attachOpts = ['block', str(block),]
        else:
            raise ValueError("missing device or block")

        if self.log.isEnabledFor(logging.DEBUG):
            verboseOpts = ['verbose',]
        else:
            verboseOpts = []

        code = self.call(['tc', 'filter', 'add',]
                         + attachOpts
                         + versionOpts
                         + ['ingress',]
                         + ['handle', str(nextHandle),]
                         + ['pref', str(nextPref),]
                         + chainOpts
                         + ['flower',]
                         + verboseOpts
                         + offloadOpts
                         + ['action', 'drop',])
        if code: return code

        self.log.info("deleting filters to implement drop policy")

        code = self.deleteFilters(filtersByHandle,
                                  dev=dev, block=block,
                                  reverse=True)
        if code: return code

        # if this default-drop rule does not look like
        # a normally-inserted ruleset (low handle, low preference value)
        # then re-position the default-drop rule to a more useful location
        # so that the atomic update algorithm will work

        if (handle is None
            and preference is None
            and nextHandle < HANDLE_UPDATE
            and nextPref < PREFERENCE_UPDATE):

            # drop rule is OK where it is
            pass

        elif (handle == nextHandle
              and preference == nextPref):

            # drop rule is OK where it is
            pass

        else:

            self.log.info("adjusting default-drop rule")

            preference_ = preference or PREFERENCE_DEFAULT
            # target preference for the drop rule

            tempPref = max(preference_, nextPref)+1
            # unused preference value for the purposes of shuffling

            tempHandle = max(handle, nextHandle)+1
            # unused handle for the purposes of shuffling

            code = self.call(['tc', 'filter', 'add',]
                             + attachOpts
                             + versionOpts
                             + ['ingress',]
                             + ['handle', str(tempHandle),]
                             + ['pref', str(tempPref),]
                             + chainOpts
                             + ['flower',]
                             + verboseOpts
                             + offloadOpts
                             + ['action', 'drop',])
            if code: return code

            code = self.call(['tc', 'filter', 'del',]
                             + attachOpts
                             + ['ingress',]
                             + ['handle', str(nextHandle),]
                             + ['pref', str(nextPref),]
                             + ['flower',])
            if code: return code

            code = self.call(['tc', 'filter', 'add',]
                             + attachOpts
                             + versionOpts
                             + ['ingress',]
                             + ['handle', str(handle),]
                             + ['pref', str(preference_),]
                             + chainOpts
                             + ['flower',]
                             + verboseOpts
                             + offloadOpts
                             + ['action', 'drop',])
            if code: return code

            code = self.call(['tc', 'filter', 'del',]
                             + attachOpts
                             + ['ingress',]
                             + ['handle', str(tempHandle),]
                             + ['pref', str(tempPref),]
                             + chainOpts
                             + ['flower',])
            if code: return code

        return 0

    def mkRules(self, chain,
                dev=None, block=None,
                handle=HANDLE_DEFAULT, preference=PREFERENCE_DEFAULT,
                policy=None):
        """Generate the TC rules for an interface.

        - fill in handle and preference
        - fill in version details
        - add default policy if needed

        returns a tuple of (handle, pref, args) for each command,
        in case we need to revert.
        """

        self.log.info("generating rules for %s", attachSpec(dev=dev, block=block))

        # expand out the IPTABLES rules into an equivalent set of flower statements

        tr = Translator(version=self.version, shared=self.shared,
                        log_ignore=self.log_ignore,
                        addrtype=self.addrtype,
                        match_multi=self.match_multi,
                        port_unroll=self.port_unroll,
                        drop_mode=self.drop_mode,
                        hack_vlan_arp=self.hack_vlan_arp,
                        reject_drop=self.reject_drop,
                        continue_suppress=self.continue_suppress,
                        prestera_chain_mode=self.prestera_chain_mode,
                        log=self.log.getChild("translate"))
        for rule in chain.rules:
            tr.feed(rule, lineno=True)
        tr.commit(policy=(policy or chain.policy),
                  lineno=True)

        # construct valid tc-flower syntax

        if dev is not None:
            attachOpts = ['dev', dev,]
        elif block is not None:
            attachOpts = ['block', str(block),]
        else:
            raise ValueError("missing device or block")

        if self.version == socket.AF_INET:
            versionOpts = ['protocol', 'ip',]
        elif self.version == socket.AF_INET6:
            versionOpts = ['protocol', 'ipv6',]
        else:
            raise ValueError("invalid IP version")

        if self.offload is True:
            offloadOpts = ['skip_sw',]
        elif self.offload is False:
            offloadOpts = ['skip_hw',]
        else:
            offloadOpts = []

        if self.log.isEnabledFor(logging.DEBUG):
            verboseOpts = ['verbose',]
        else:
            verboseOpts = []

        if len(tr.stmts) >= RULES_MAX:
            raise ValueError("too many rules: %d > %d"
                             % (len(tr.stmts), RULES_MAX,))

        version = "ipv4" if self.version == socket.AF_INET else "ipv6"
        self.tc_chain_keys = {}
        for chain, keys in tr.tc_chain_keys.items():
            self.tc_chain_keys[chain] = ('vlan_ethtype', version,)
            # the keys are two part LAYER.KEY_NAME
            for k in sorted(keys, key=lambda k: int(k[1])):
                # insert only the KEY_NAME to the chain keys
                self.tc_chain_keys[chain] += (k[3:],keys[k],)

        # attach them to the interface
        # XXX rothcar -- use a filter block here
        hnd = handle
        pref = preference
        prev_stmt = {TC_CHAIN_DEFAULT:[],TC_CHAIN_ICMP:[]}
        for line in tr.stmts:
            tc_chain = line.tc_chain
            stmt = line.stmts
            # if its exatly the same rule dont sweat installing it
            if len(stmt) == len(prev_stmt[tc_chain]):
                same = True
                for t1,t2 in zip(stmt, prev_stmt[tc_chain]):
                    if t1 != t2:
                        same = False
                        break
                if same:
                    continue
            prev_stmt[tc_chain] = stmt
            cmd = ['tc', 'filter', 'add',]
            cmd.extend(attachOpts)

            if 'vlan_ethtype' in stmt:
                cmd.extend(['protocol', '802.1q',])
            else:
                cmd.extend(versionOpts)
            cmd.append('ingress')
            cmd.extend(['handle', str(hnd),])
            cmd.extend(['pref', str(pref),])
            if self.prestera_chain_mode:
                cmd.extend(['chain', tc_chain])
            cmd.append('flower')
            cmd.extend(verboseOpts)
            cmd.extend(offloadOpts)
            cmd.extend(stmt)

            yield (hnd, pref, cmd,)

            hnd += 1
            pref += 1

    def loadRules(self, chain,
                  dev=None, block=None,
                  handle=HANDLE_DEFAULT, preference=PREFERENCE_DEFAULT,
                  policy=None):
        """Load rules for an interface.

        XXX rothcar -- try using a filter block instead
        """

        recs = list(self.mkRules(chain,
                                 dev=dev, block=block,
                                 handle=handle, preference=preference,
                                 policy=policy))
        self.log.info("loading %d rules for %s at %d",
                      len(recs), attachSpec(dev=dev, block=block), preference)

        # create the chain if necessary
        if self.prestera_chain_mode:
            if self.shared:
                code = self.maybeAddChain("block", str(block),)
                if code: return code
            else:
                code = self.maybeAddChain("dev", dev,)
                if code: return code

        filtersByHandle = {}

        code = 0

        batch = TcBatch(profile=self.profile,
                        log=self.log.getChild("tc"))

        for hnd, pref, cmd in recs:
            batch.feed(cmd)
            filtersByHandle[hnd] = {'kind' : 'flower',
                                    'pref' : pref,}
            # ugh this logic no longer works in batch mode

        code = batch.commit(batch=self.batch)

        if code:
            self.log.error("rewinding %d filters", len(filtersByHandle))
            self.deleteFilters(filtersByHandle,
                               dev=dev, block=block,
                               reverse=True, force=True)
            return code

        return code

    def getRuleHandles(self, dev=None, block=None):
        """Retrieve the current rules for this interface or block.

        They are indexed into a dict by rule handle.

        For shared blocks, the filters still need to be queried by interface.
        """

        if dev is not None:
            attachOpts = ['dev', dev,]
        elif block is not None:
            attachOpts = ['block', str(block),]
        else:
            raise ValueError("missing device or block")

        cmd = ['tc', '-json', 'filter', 'show',] + attachOpts + ['ingress',]
        data = self.check_json(cmd)
        filtersRaw = list(data)
        filtersByHandle = {}
        while filtersRaw:
            fData = filtersRaw[0]

            # skip stub filters
            if 'options' not in fData:
                filtersRaw.pop(0)
                continue

            hnd = fData['options'].get('handle', None)
            if hnd is None:
                raise MissingHandle(fData, "invalid filter (no handle)")

            ##self.log.debug("interface %s: found filter %d: %s",
            ##               ifName, hnd, fData)
            filtersByHandle[hnd] = fData
            filtersRaw.pop(0)

        self.log.debug("found %d filters attached to %s",
                       len(filtersByHandle), attachSpec(dev=dev, block=block))

        return filtersByHandle

    def deleteFilters(self, filtersByHandle,
                      dev=None, block=None,
                      reverse=False, force=False):
        """Delete existing rules."""

        for filter_ in filtersByHandle.values():
            if 'pref' not in filter_:
                raise MissingPreference(filter_, "missing preference")
            if 'kind' not in filter_:
                raise MissingKind(filter_, "missing kind")

        handles = sorted(filtersByHandle.keys(), reverse=True)
        if len(handles) == 1:
            self.log.info("deleting filter %d", handles[0])
        elif handles:
            self.log.info("deleting filters %d..%d", handles[-1], handles[0])

        batch = TcBatch(profile=self.profile,
                        log=self.log.getChild("tc"))

        if dev is not None:
            attachOpts = ['dev', dev,]
        elif block is not None:
            attachOpts = ['block', str(block),]
        else:
            raise ValueError("missing dev or block")

        for hnd in handles:
            filter_ = filtersByHandle[hnd]
            pref = filter_['pref']
            kind = filter_['kind']
            cmd = (['tc', 'filter', 'del',]
                   + attachOpts
                   + ['ingress',]
                   + ['handle', str(hnd),]
                   + ['pref', str(pref),]
                   + [kind,])
            batch.feed(cmd)

        code = batch.commit(batch=self.batch, force=force)
        if code:
            self.log.error("cannot delete rules")
            return code

        return 0

    def updateRules(self, chain,
                    dev=None, block=None,
                    policy=None):

        # get the current filters, collate by handle

        filtersByHandle = self.getRuleHandles(dev=dev, block=block)

        # make sure the rule indices are correct

        handles = sorted(filtersByHandle.keys())
        if handles and handles[-1] >= HANDLE_UPDATE:
            raise ValueError("invalid filter handle %d (botched update?)" % handles[-1])

        # insert the new rules at a higher handle index, lower priority
        # (after the existing rule set)

        code = self.loadRules(chain,
                              dev=dev, block=block,
                              handle=HANDLE_UPDATE, preference=PREFERENCE_UPDATE,
                              policy=policy)
        if code:
            self.log.error("new rule load failed")
            return 1

        # delete the old rules, in reverse order
        # any traffic that spills off the end of the partial old chain
        # is fully processed by the new chain

        code = self.deleteFilters(filtersByHandle,
                                  dev=dev, block=block,
                                  reverse=True)
        if code: return code

        # get the new ruleset in preparation for re-handling

        filtersByHandle = self.getRuleHandles(dev=dev, block=block)

        # all handles should be >= HANDLE_UPDATE
        handles = sorted(filtersByHandle.keys())
        if handles and handles[0] < HANDLE_UPDATE:
            raise ValueError("invalid filter handle %d (botched update?)" % handles[0])

        # re-insert the new rules with default (higher) priority

        code = self.loadRules(chain,
                              dev=dev, block=block,
                              handle=HANDLE_DEFAULT, preference=PREFERENCE_DEFAULT,
                              policy=policy)
        if code:
            self.log.error("new rule load failed")
            return 1

        # delete the 1st copy of the new rules, in reverse order
        # (though I suspect the order does not matter)

        code = self.deleteFilters(filtersByHandle,
                                  dev=dev, block=block,
                                  reverse=True)
        if code: return code

        # one last scan to make sure the indices are sound

        filtersByHandle = self.getRuleHandles(dev=dev, block=block)

        handles = sorted(filtersByHandle.keys())
        if handles and handles[-1] >= HANDLE_UPDATE:
            raise ValueError("invalid filter handle %d (botched update?)" % handles[0])

        return 0

    def auditRules(self, dev=None, block=None, raiseExc=True):
        """Audit the existing rules on this interface to predict success."""

        filtersByHandle = self.getRuleHandles(dev=dev, block=block)
        handles = sorted(filtersByHandle.keys())
        if handles and handles[-1] >= HANDLE_UPDATE:
            if raiseExc:
                self.log.error("invalid filter handle %d (botched update?)", handles[-1])
                return 1
            else:
                self.log.warning("invalid filter handle %d (botched update?)", handles[-1])
                self.log.warning("will attempt to recover -- atomicity not guaranteed")

        return 0

    def runIntf(self, ifName, chain, policy='ACCEPT'):

        code = self.auditRules(dev=ifName,
                               raiseExc=(not self.drop and self.atomic))
        if code: return code

        if self.drop:
            code = self.defaultDrop(dev=ifName,
                                    handle=HANDLE_UPDATE,
                                    preference=PREFERENCE_UPDATE)
            if code: return code

            filtersByHandle = self.getRuleHandles(dev=ifName)
            if len(filtersByHandle) != 1:
                self.log.error("defaultDrop finished with %d filters (expected 1)",
                               len(filtersByHandle))
                return 1
            handle = next(iter(filtersByHandle))
            pref = filtersByHandle[handle]
            if handle != HANDLE_UPDATE:
                self.log.error("defaultDrop finished with filter handle %d (expected %d)",
                               handle, HANDLE_UPDATE)
                return 1

            # load here instead of update
            code = self.loadRules(chain, dev=ifName, policy=policy)
            if code: return code

            # remove rule here
            code = self.call(['tc', 'filter', 'del',]
                             + ['dev', ifName,]
                             + ['ingress',]
                             + ['handle', str(HANDLE_UPDATE),]
                             + ['pref', str(PREFERENCE_UPDATE),]
                             + ['flower',])
            if code: return code

        elif not self.atomic:
            code = self.resetIntf(ifName)
            if code: return code
            code = self.loadRules(chain, dev=ifName, policy=policy)
            if code: return code
        elif ifName in self.updateIfNames:
            code = self.updateRules(chain, dev=ifName, policy=policy)
            if code: return code
        else:
            code = self.loadRules(chain, dev=ifName, policy=policy)
            if code: return code
        return 0

    def runBlock(self, chain, policy='ACCEPT'):

        code = self.auditRules(block=BLOCKNUM,
                               raiseExc=(not self.drop and self.atomic))
        if code: return code

        if self.drop:
            code = self.defaultDrop(block=BLOCKNUM,
                                    handle=HANDLE_UPDATE,
                                    preference=PREFERENCE_UPDATE)
            if code: return code

            filtersByHandle = self.getRuleHandles(block=BLOCKNUM)
            if len(filtersByHandle) != 1:
                self.log.error("defaultDrop finished with %d filters (expected 1)",
                               len(filtersByHandle))
                return 1
            handle = next(iter(filtersByHandle))
            pref = filtersByHandle[handle]
            if handle != HANDLE_UPDATE:
                self.log.error("defaultDrop finished with handle %d filters (expected %d)",
                               handle, HANDLE_UPDATE)
                return 1

            # load here instead of update
            code = self.loadRules(chain, block=BLOCKNUM, policy=policy)
            if code: return code

            # remove rule here
            code = self.call(['tc', 'filter', 'del',]
                             + ['block', str(BLOCKNUM),]
                             + ['ingress',]
                             + ['handle', str(HANDLE_UPDATE),]
                             + ['pref', str(PREFERENCE_UPDATE),]
                             + ['flower',])
            if code: return code

        elif not self.atomic:
            code = self.resetBlock()
            if code: return code
            code = self.loadRules(chain, block=BLOCKNUM, policy=policy)
            if code: return code
        elif self.updateIfNames:
            # non-zero set of update interfaces --> update entire block
            code = self.updateRules(chain, block=BLOCKNUM, policy=policy)
            if code: return code
        else:
            code = self.loadRules(chain, block=BLOCKNUM, policy=policy)
            if code: return code
        return 0

    def run(self):

        if self.drop and not self.atomic:
            self.log.error("--non-atomic is not compatible with --drop")
            return 1

        if self.interfaces is None:
            o = None
        else:
            o = set(self.interfaces)

            self.topo.narrow(o, demote=False)
            # any interface in self.interfaces that are not
            # front-panel ports are promoted here (e.g. dummy0)

        a = self.topo.getPorts()

        if self.shared:
            if self.scoreboard:
                try:
                    validateScoreboard(self.table.chains[self.chainName], a)
                except ValueError as ex:
                    self.log.error("cannot process scoreboarded IPTABLES rules: %s", str(ex))
                    return 1
            else:
                try:
                    validateUnslice(self.table.chains[self.chainName], o or a)
                except ValueError as ex:
                    self.log.error("cannot process unsliced IPTABLES rules: %s", str(ex))
                    return 1
            table = self.table
        else:
            try:
                table = SliceTable.fromSlice(self.table, self.chainName,
                                             onlyInterfaces=o, allInterfaces=a,
                                             log=self.log.getChild("slice"))
            except ValueError as ex:
                self.log.error("cannot process sliced IPTABLES rules: %s", str(ex))
                return 1

        self.updateIfNames = set()
        # all interfaces where we need to perform in-place update

        # verify that all interfaces that *will be configured*
        # match the hardware offload requirements
        filterIfNames = sortIfNames(o or a)

        if self.offload is True:
            for ifName in sortIfNames(filterIfNames):
                code = self.auditOffload(ifName)
                if code: return code

        # add a default ingress qdisc for each interface
        # (including the ones that have no rules)

        if self.shared:
            code = self.maybeAddBlock(*(o or a))
            if code: return code
        else:
            for ifName in filterIfNames:
                code = self.maybeAddIngress(ifName)
                if code: return code

        # add the filters for each interface (via load or update)

        # XXX rothcar -- consider locking something to prevent re-entrancy

        code = 0
        rootPolicy = self.table.chains[self.chainName].policy
        if self.shared:
            chain = table.chains[self.chainName]
            if len(chain.rules):
                code = self.runBlock(chain, policy=rootPolicy)
            else:
                code = self.resetBlock()
        else:
            for ifName in filterIfNames:
                chain = table.chains.get(ifName, None)
                if chain is not None and len(chain.rules):
                    intfCode = self.runIntf(ifName, chain, policy=rootPolicy)
                    code = code or intfCode
                else:
                    # if the interface is not listed in the rules list,
                    # we still need to reset it to an empty ruleset
                    intfCode = self.resetIntf(ifName)
                    code = code or intfCode
                if intfCode and not self.continue_: break

        return code
