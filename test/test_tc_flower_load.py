"""test_tc_flower_load.py

"""

import path_config

import os, sys
import unittest
import subprocess
import tempfile
import shutil
import logging
import json
import pprint
import socket
import copy

import TcSaveTestUtils
from TcSaveTestUtils import (
    isLinux,
    isRoot,
    isDut,
    isPhysical,
    PhysicalTestMixin,
)

from petunia.Topology import (
    Topology
)

from petunia.JsonUtils import LazyFilterParser

logger = None
def setUpModule():
    global logger
    logging.basicConfig()
    logger = logging.getLogger("unittest")
    logger.setLevel(logging.DEBUG)
    if not isLinux() or not isRoot():
        logger.warning("this test needs to run on a DUT")
    elif not isPhysical():
        TcSaveTestUtils.setUpModule()

def tearDownModule():
    if isLinux() and isRoot():
        TcSaveTestUtils.tearDownModule

# json specifier for the ingress qdisc
QDISC_INGRESS = {'kind' : 'ingress', 'handle' : 'ffff:',}

# json specifier for a simple (termainal) actions on a filter
# (ignore 'index' and 'order' for now)
ACTION_PASS = {'bind' : 1,
               'kind' : 'gact',
               'control_action' : {'type' : 'pass',},}

ACTION_DROP = {'bind' : 1,
               'kind' : 'gact',
               'control_action' : {'type' : 'drop',},}

ACTION_TRAP = {'bind' : 1,
               'kind' : 'gact',
               'control_action' : {'type' : 'trap',},}

ACTION_JUMP = {'bind' : 1,
               'kind' : 'gact',
               'control_action' : {'type' : 'jump',},}

ACTION_CONTINUE = {'bind' : 1,
                   'kind' : 'gact',
                   'control_action' : {'type' : 'continue',},}

def mkActionJump(stride):
    data = copy.deepcopy(ACTION_JUMP)
    data['control_action']['jump'] = stride
    return data

def mkActionTrap(rate, burst):
    data = [{'bind' : '1',
             # XXX rothcar -- JSON wrangler does not coerce this correctly
             'kind' : 'police',
             'rate' : rate,
             'burst' : burst,
             'control_action' : {'type' : 'drop',},},
            {'bind' : 1,
             'kind' : 'gact',
             'control_action' : {'type' : 'trap',},},]
    return data

def mkActionGoto(chain):
    data = [{'bind' : 1,
             'kind' : 'gact',
             'control_action' : {'type' : 'goto', 'chain' : chain},},]
    return data

class TestMixin(object):

    def check_call(self, args):
        self.log.debug("+ " + " ".join(args))
        try:
            subprocess.check_call(args)
            code = 0
        except subprocess.CalledProcessError as ex:
            self.log.warning("+ exit %s" % ex.returncode)
            raise
        self.log.debug("+ exit %s" % code)

    def check_output(self, args, **kwargs):
        self.log.debug("+ " + " ".join(args))
        try:
            out = subprocess.check_output(args,
                                          universal_newlines=True,
                                          **kwargs)
            code = 0
        except subprocess.CalledProcessError as ex:
            out = (ex.output or "").rstrip().splitlines(False)
            [self.log.warning(">>> %s" % x) for x in out]
            self.log.warning("+ exit %s" % ex.returncode)
            raise
        self.log.debug("+ exit %s" % code)
        return out

    def check_tc_json(self, args, **kwargs):
        kwargs = dict(kwargs)
        strict = kwargs.pop('strict', True)
        cmd = ['tc', '-json', '-detail',]
        cmd.extend(args)
        if strict:
            return json.loads(self.check_output(cmd, **kwargs))
        else:
            p = LazyFilterParser(log=self.log.getChild("json"))
            return p.loads(self.check_output(cmd, **kwargs))

    def pprint(self, ob, msg=None, level=logging.INFO):
        buf = pprint.pformat(ob, indent=4)
        if msg is not None:
            self.log.log(level, msg)
        for line in buf.rstrip().splitlines(False):
            self.log.log(level, ">>> %s", line)

    def assertDict(self, dct, **kwargs):
        """Recursivly compare dict contents.

        Here 'kwargs' is a restricted subset of keys to check;
        additional keys in 'dct' are ignored.

        NOTE NOTE NOTE that the assert() argument order is reversed here,
        the *actual* arg is first.
        """
        if type(dct) is not dict:
            raise AssertionError("not a dict: %s" % repr(dct))
        for key, val in kwargs.items():
            if key not in dct:
                raise AssertionError("missing key %s in %s" % (key, repr(dct),))
            try:
                if isinstance(val, dict):
                    self.assertDict(dct[key], **val)
                elif isinstance(val, list):
                    self.assertList(val, dct[key])
                    # XXX rothcar -- reverse args here
                else:
                    self.assertEqual(val, dct[key])
            except AssertionError:
                self.log.error("invalid dict key at '%s'", key)
                self.pprint(val, "expected:", level=logging.ERROR)
                self.pprint(dct[key], "actual:", level=logging.ERROR)
                raise

    def assertList(self, specItems, dataItems):
        """Recursively compare lists.

        Use 'assertDict' for dict sub-items.
        """
        specItems = list(specItems)
        dataItems = list(dataItems)
        idx = 0

        while True:
            if not specItems: break
            if not dataItems: break

            spec = specItems.pop(0)
            data = dataItems.pop(0)

            try:
                if isinstance(spec, dict) and isinstance(data, dict):
                    self.assertDict(data, **spec)
                elif isinstance(spec, list) and isinstance(data, list):
                    self.assertList(spec, data)
                else:
                    self.assertEqual(spec, data)
            except AssertionError:
                self.log.error("mismatch at list index %d", idx)
                self.pprint(spec, "expected item:", level=logging.ERROR)
                self.pprint(data, "actual item:", level=logging.ERROR)
                raise

            idx += 1

        if specItems:
            self.pprint(specItems, "extra items:", level=logging.ERROR)
            raise AssertionError("extra items")
        if dataItems:
            self.pprint(dataItems, "missing items:", level=logging.ERROR)
            raise AssertionError("missing items")

    def assertFilters(self, filterSpec, filterData):
        """Make sure the filter list is correct.

        NOTE here that the TC filter display includes dummy entries
        with no options, we need to work with that.

        Also we need to handle filter preference (and chain index?)
        """

        # get rid of each stub filter entry

        filterData, filterData_ = [], list(filterData)
        while filterData_:

            if len(filterData_) < 2:
                self.pprint(filterData_, "filter data:", level=logging.ERROR)
                raise AssertionError("underrun in filter data (should include two items)")

            dataStub = filterData_.pop(0)
            data = filterData_.pop(0)

            try:
                self.assertDict(data, **dataStub)
            except AssertionError:
                self.log.error("filter stub mismatch at index %d", idx)
                self.pprint(dataStub, "stub filter:", level=logging.ERROR)
                self.pprint(data, "actual filter:", level=logging.ERROR)
                raise

            filterData.append(data)

        filterSpec = list(filterSpec)
        idx = 0

        # sort them by priority

        filterPrios = {}
        for data in filterData:
            filterPrios.setdefault(data['pref'], [])
            filterPrios[data['pref']].append(data)

        filterData = []
        for prio in sorted(filterPrios.keys()):
            filterData.extend(filterPrios[prio])

        # now zip down through both containers

        self.assertList(filterSpec, filterData)

    def setUpClearQdiscs(self):
        """Delete qdiscs from the interface to get us to a default state."""

        cmd = ('ip', 'link', 'show', 'dev', 'dummy0',)
        try:
            self.check_call(cmd)
        except subprocess.CalledProcessError:
            cmd = ('ip', 'link', 'add', 'dev', 'dummy0', 'type', 'dummy',)
            self.check_call(cmd)

        cmd = ('tc', 'qdisc', 'del', 'dev', 'dummy0', 'ingress',)
        try:
            self.check_call(cmd)
        except subprocess.CalledProcessError:
            pass

        cmd = ('ip', 'link', 'show', 'dev', 'dummy1',)
        try:
            self.check_call(cmd)
        except subprocess.CalledProcessError:
            cmd = ('ip', 'link', 'add', 'dev', 'dummy1', 'type', 'dummy',)
            self.check_call(cmd)

        cmd = ('tc', 'qdisc', 'del', 'dev', 'dummy1', 'ingress',)
        try:
            self.check_call(cmd)
        except subprocess.CalledProcessError:
            pass

    def setUpScripts(self):
        """Create an executable script for the DUT.

        This is because the DUT won't launch scripts generated by BrazilPython.
        XXX rothcar -- need to migrate this to something we can deploy to dentOS.
        """

        bindir = os.path.join(self.workdir, "bin")
        os.mkdir(bindir)

        srcdir = os.path.dirname(__file__)
        pydir = os.path.abspath(os.path.join(srcdir, "../src"))

        script = os.path.join(bindir, "tc-flower-load")
        with open(script, 'wt') as fd:
            fd.write("#!" + sys.executable + "\n")
            fd.write("import sys\n")
            fd.write("sys.path.insert(0, \"%s\")\n" % pydir)
            fd.write("import petunia.LoadApp\n")
            fd.write("petunia.LoadApp.main()\n")
        os.chmod(script, 0o755)

        self.os_environ_PATH = os.environ['PATH']
        os.environ['PATH'] = bindir + ':' + os.environ['PATH']

    def tearDownScripts(self):
        os.environ['PATH'] = self.os_environ_PATH

    def setUpWorkdir(self):
        self.workdir = tempfile.mkdtemp(prefix="test-",
                                        suffix=".d")

    def tearDownWorkdir(self):
        workdir, self.workdir = self.workdir, None
        if workdir and os.path.isdir(workdir):
            shutil.rmtree(workdir)

    def mkFlower(self, action, version=socket.AF_INET, **kwargs):
        """Construct a JSON-ish representation of a TC flower filter.

        XXX rothcar -- need to add 'chain', 'pref', 'handle', 'XXX_hw'
        """

        keys = dict(kwargs)

        jump = None

        if action == 'pass':
            actData = [ACTION_PASS,]
        elif action == 'drop':
            actData = [ACTION_DROP,]
        elif action == 'continue':
            actData = [ACTION_CONTINUE,]
        elif action == 'trap':
            actData = [ACTION_TRAP,]
        elif action == 'police+trap':
            rate = keys.pop('rate')
            burst = keys.pop('burst')
            actData = mkActionTrap(rate, burst)
        elif action == 'jump':
            actData = [mkActionJump(keys.pop('jump')),]
        elif action == 'goto':
            actData = mkActionGoto(keys.pop('goto_chain'))
        else:
            raise ValueError("invalid (unsupported) action %s" % action)

        handle = keys.pop('handle', None)
        indev = keys.pop('indev', None)
        vid = keys.pop('vlan_id', None)
        chain = keys.pop('chain', None)
        pref = in_hw = None
        # XXX rothcar

        proto = 'ipv6' if version == socket.AF_INET6 else 'ip'
        proto_ = 'ipv6' if version == socket.AF_INET6 else 'ipv4'

        if vid is True:
            # any vlan
            keys['vlan_ethtype'] = keys.pop('vlan_ethtype', proto)
            proto = '802.1Q'
        elif vid is not None:
            keys['vlan_ethtype'] = keys.pop('vlan_ethtype', proto)
            keys['vlan_id'] = vid
            proto = '802.1Q'

        keys['eth_type'] = keys.pop('eth_type', proto_)
        # the protocol number is in two places, ugh

        data = {'kind' : 'flower',
                'protocol' : proto,
                'options' : {'actions' : actData,
                             'keys' : keys,},}

        if chain is not None:
            data['chain'] = chain
        if pref is not None:
            data['pref'] = pref
        if handle is not None:
            data['options']['handle'] = handle
        if in_hw is True:
            data['options']['in_hw'] = True
        if in_hw is False:
            data['options']['not_in_hw'] = True
        if indev is not None:
            data['options']['indev'] = indev

        return data

    def check_load(self, cmd):
        cmd = ['tc-flower-load', '-v',] + list(cmd)
        self.check_call(cmd)

    def assertMissingIngress(self, dev=None, block=None):
        if dev is not None:
            attachOpts = ['dev', dev,]
        elif block is not None:
            attachOpts = ['block', str(block),]
        else:
            raise AssertionError("missing block or dev")
        data = self.check_tc_json(['qdisc', 'show',] + attachOpts + ['ingress',])
        ingressData = [x for x in data if x['kind'] == 'ingress']
        egressData = [x for x in data if x['kind'] != 'ingress']
        if ingressData != []:
            raise AssertionError("extra ingress data for %s: %s"
                                 % (ifName, ingressData,))

    def assertEmptyIngress(self, dev=None, block=None):
        if dev is not None:
            attachOpts = ['dev', dev,]
        elif block is not None:
            attachOpts = ['block', str(block),]
        else:
            raise AssertionError("missing block or dev")
        data = self.check_tc_json(['qdisc', 'show',] + attachOpts + ['ingress',])
        ingressData = [x for x in data if x['kind'] == 'ingress']
        egressData = [x for x in data if x['kind'] != 'ingress']
        if not ingressData:
            raise AssertionError("missing ingress qdisc on %s" % ifName)
        self.assertDict(ingressData[0], **QDISC_INGRESS)

    def assertFlower(self, iptSpec,
                     policy='ACCEPT', defaultPolicy='ACCEPT',
                     version=socket.AF_INET,
                     clear=True, atomic=True, drop=False,
                     **flowerSpec):
        """Verify that an IPTABLES rule is converted correctly.

        Here we assume that the IPTABLES rule is translated to
        a single TC filter.
        """

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n")
            fd.write(":FORWARD %s [0:0]\n" % defaultPolicy)
            fd.write(":FORWARD_dummy0 - [0:0]\n")
            fd.write("-A FORWARD -i dummy0 -j FORWARD_dummy0\n")
            fd.write("-A FORWARD_dummy0 %s -j %s\n" % (iptSpec, policy,))
            fd.write("COMMIT\n")

        if clear:
            self.setUpClearQdiscs()

        versionOpts = ['-6',] if version == socket.AF_INET6 else []
        atomicOpts = [] if atomic else ['--non-atomic',]
        dropOpts = ['--drop',] if drop else []
        self.check_load(versionOpts + atomicOpts + dropOpts + [src, 'FORWARD',])

        self.assertEmptyIngress(dev='dummy0')

        # make sure the filter got added

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        kwargs = dict(**flowerSpec)
        if 'action' in kwargs:
            action = kwargs['action']
        elif policy == 'ACCEPT':
            action = 'pass'
        elif policy == 'DROP':
            action = 'drop'
        else:
            raise ValueError("invalid TC action %s", action)
        f = self.mkFlower(action, version=version, **kwargs)
        self.assertFilters([f,], data)

    def assertFlowerExpand(self, iptSpec, flowerSpecs,
                           policy='ACCEPT', defaultPolicy='ACCEPT',
                           version=socket.AF_INET,
                           clear=True, atomic=True,
                           drop=False, port_unroll=None,
                           hack_vlan_arp=False):
        """Verify that an IPTABLES rule is expanded correctly to multiple statements."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n")
            fd.write(":FORWARD %s [0:0]\n" % defaultPolicy)
            fd.write(":FORWARD_dummy0 - [0:0]\n")
            fd.write("-A FORWARD -i dummy0 -j FORWARD_dummy0\n")
            fd.write("-A FORWARD_dummy0 %s -j %s\n" % (iptSpec, policy,))
            fd.write("COMMIT\n")

        if clear:
            self.setUpClearQdiscs()

        versionOpts = ['-6',] if version == socket.AF_INET6 else []
        atomicOpts = [] if atomic else ['--no-atomic',]
        dropOpts = ['--drop',] if drop else []
        unrollOpts = ['--port-unroll', str(port_unroll),] if port_unroll else []
        arpOpts = ['--hack-vlan-arp',] if hack_vlan_arp else []
        self.check_load(versionOpts
                        + atomicOpts
                        + dropOpts
                        + unrollOpts
                        + arpOpts
                        + [src, 'FORWARD',])

        self.assertEmptyIngress(dev='dummy0')

        # make sure the filter got added

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        def _mk(**kwargs):
            spec = dict(kwargs)

            if 'action' in spec:
                action = spec['action']
            elif policy == 'ACCEPT':
                action = 'pass'
            elif policy == 'DROP':
                action = 'drop'
            else:
                raise ValueError("invalid TC action %s", action)

            action = spec.pop('action', action)
            return self.mkFlower(action, version=version, **spec)
        specs = [_mk(**x) for x in flowerSpecs]
        self.assertFilters(specs, data)

@unittest.skipIf(not isLinux() or not isRoot(),
                 "this test only runs on Linux as root")
class LoadTest(TestMixin,
               TcSaveTestUtils.ScriptTestMixin,
               unittest.TestCase):

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        self.setUpScripts()
        self.setUpClearQdiscs()

        os.environ['TEST_DUMMY'] = '1'

    def tearDown(self):
        self.setUpClearQdiscs()
        self.tearDownScripts()
        self.tearDownWorkdir()

        os.environ.pop('TEST_DUMMY', None)

    def testDefaults(self):
        """The ingress qdiscs should not be installed yet."""

        self.assertMissingIngress(dev='dummy0')
        self.assertMissingIngress(dev='dummy1')

    def testEmptyInput(self):

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        # no filters defined, no interfaces defined

        self.assertEmptyIngress(dev='dummy0')
        self.assertEmptyIngress(dev='dummy1')

    def testEmptyChains(self):

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        # dummy0 should have a qdisc but no filters

        self.assertEmptyIngress(dev='dummy0')

        # dummy1 has a qdisc even though it is not spelled out in the filters

        self.assertEmptyIngress(dev='dummy1')

    def testInvalidChains(self):

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_extra0 - [0:0]\n"
                     "-A FORWARD -i extra0 -j FORWARD_extra0\n"
                     "COMMIT\n")

        with self.assertRaises(subprocess.CalledProcessError) as ex:
            self.check_load([src, 'FORWARD',])

        # this is not a valid interface

        with self.assertRaises(subprocess.CalledProcessError) as ex:
            data = self.check_tc_json(('qdisc', 'show', 'dev', 'extra0', 'ingress',))
            self.assertEqual([], data)

    def testSimpleFilterAccept(self):
        """Sanity check for a single with an 'accept' rule."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j ACCEPT\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        self.assertEmptyIngress(dev='dummy0')

        # make sure the filter got added

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('pass', ip_proto='tcp')
        self.assertFilters([f1,], data)

    def testSimpleFilterAcceptNoBatch(self):
        """Turn off batch mode.."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j ACCEPT\n"
                     "COMMIT\n")

        self.check_load(['--no-batch', src, 'FORWARD',])

        self.assertEmptyIngress(dev='dummy0')

        # make sure the filter got added

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('pass', ip_proto='tcp')
        self.assertFilters([f1,], data)

    def testSimpleFilterDrop(self):
        """Sanity check for a single filter with a 'drop' rule."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j DROP\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        self.assertEmptyIngress(dev='dummy0')

        # make sure the filter got added

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('drop', ip_proto='tcp')
        self.assertFilters([f1,], data)

    def testSimpleFilterDropDefault(self):
        """Sanity check for an accept rule with default 'DROP' chain policy."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD DROP [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j ACCEPT\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        self.assertEmptyIngress(dev='dummy0')

        # make sure the filter got added

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('pass', ip_proto='tcp')
        f2 = self.mkFlower('drop')
        self.assertFilters([f1, f2,], data)

    def testSimpleFilterMulti(self):
        """Sanity check for multiple rules."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j ACCEPT\n"
                     "-A FORWARD_dummy0 -p udp -j ACCEPT\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        self.assertEmptyIngress(dev='dummy0')

        # make sure the filter got added

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('pass', ip_proto='tcp')
        f2 = self.mkFlower('pass', ip_proto='udp')
        self.assertFilters([f1, f2,], data)

    def testSimpleSkip(self):
        """Test the skip action.

        Add in a drop policy to make sure the skip offset is correct.
        """

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD DROP [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j ACCEPT\n"
                     "-A FORWARD_dummy0 -p tcp -j SKIP --skip-rules 1\n"
                     "-A FORWARD_dummy0 -p tcp -j ACCEPT\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        self.assertEmptyIngress(dev='dummy0')

        # make sure the filter got added

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('pass', ip_proto='tcp')
        f2 = self.mkFlower('jump', jump=1)
        f3 = self.mkFlower('pass', ip_proto='tcp')
        f4 = self.mkFlower('drop')
        self.assertFilters([f1, f2, f3, f4,], data)

    def testComment(self):
        """Verify that IPTABLES comments are ignored."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD DROP [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -m comment --comment \"some-comment\" -j ACCEPT\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('pass', ip_proto='tcp')
        f2 = self.mkFlower('drop')
        self.assertFilters([f1, f2,], data)

    def testIpv6(self):
        """Simple IPv6 test."""

        src = os.path.join(self.workdir, "ip6tables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j ACCEPT\n"
                     "COMMIT\n")

        self.check_load(['-6', src, 'FORWARD',])

        self.assertEmptyIngress(dev='dummy0')

        # make sure the filter got added

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('pass', version=socket.AF_INET6, ip_proto='tcp')
        self.assertFilters([f1,], data)

    def testLog(self):
        """Verify that IPTABLES log actions are not supported.

        e.g.
        -A INPUT -p tcp -i $ALL-SWP-L3-INTF
          -s 0.0.0.0/0 -d 0.0.0.0/0
          --dport bgp
          -j LOG --log-prefix " DROP: INPUT-RULE#5 "
          --log-ip-options --log-tcp-options
        """

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD DROP [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j LOG --log-prefix \"some-comment\"\n"
                     "COMMIT\n")

        # should fail, LOG target is not supported
        with self.assertRaises(subprocess.CalledProcessError):
            self.check_load([src, 'FORWARD',])

        # ignore log actions
        self.check_load(['--log-ignore', src, 'FORWARD',])

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('continue', ip_proto='tcp')
        f2 = self.mkFlower('drop')
        self.assertFilters([f1, f2,], data)

        # suppress log actions
        self.check_load(['--log-ignore', '--continue-suppress', src, 'FORWARD',])

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        self.assertFilters([f2,], data)

    def testReject(self):
        """Verify that IPTABLES REJECT actions are supported."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j REJECT\n"
                     "COMMIT\n")

        # should fail, REJECT target is not supported
        with self.assertRaises(subprocess.CalledProcessError):
            self.check_load([src, 'FORWARD',])

        self.check_load(['--reject-drop', src, 'FORWARD',])

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('drop', ip_proto='tcp')
        self.assertFilters([f1,], data)

    def testVlan(self):
        """Verify that vlan interface rules are not supported.

        e.g.
        ip link add link ma1 name vlan100 type vlan id 100
        -A INPUT -i vlan900 -s 10.1.128.0/24 -p udp --dport 1757 -j ACCEPT

        These need to be processed by iptables-slice first.
        """

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD DROP [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     ":FORWARD_vlan100 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD -i vlan100 -j FORWARD_vlan100\n"
                     "-A FORWARD_dummy0 -p tcp -m comment --comment \"some-comment\" -j ACCEPT\n"
                     "-A FORWARD_vlan100 -p udp -m comment --comment \"some-comment\" -j ACCEPT\n"
                     "COMMIT\n")

        with self.assertRaises(subprocess.CalledProcessError):
            self.check_load([src, 'FORWARD',])

    def testInterfaceArg(self):
        """Verify interface specifiers work."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD', 'dummy0',])

        # dummy0 should have a qdisc but no filters

        self.assertEmptyIngress(dev='dummy0')

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        self.assertEqual([], data)

        # dummy1 should not have a qdisc

        self.assertMissingIngress(dev='dummy1')

        # try again with the other interface

        self.setUpClearQdiscs()

        self.check_load([src, 'FORWARD', 'dummy1',])

        # dummy0 should not have been initialized

        self.assertMissingIngress(dev='dummy0')

        # dummy1 was initialized

        self.assertEmptyIngress(dev='dummy1')

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy1', 'ingress',))
        self.assertEqual([], data)

    def testNoOffload(self):
        """Verify we can disable hardware offload."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD DROP [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j ACCEPT\n"
                     "COMMIT\n")

        self.check_load(['--no-offload', src, 'FORWARD',])

    def testOffload(self):
        """Verify that we require hardware offload.

        This is kind of a hokey test, since the dummy interfaces
        certainly do not support hardware offload.
        """

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD DROP [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j ACCEPT\n"
                     "COMMIT\n")

        with self.assertRaises(subprocess.CalledProcessError) as cm:
            buf = self.check_output(['tc-flower-load', '-v', '--offload', src, 'FORWARD',],
                                    stderr=subprocess.STDOUT)
        self.assertIn("hardware offload not supported", cm.exception.output)

    def testAddrType(self):
        """Verify handling of the addrtype module."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j ACCEPT\n"
                     "-A FORWARD_dummy0 -p tcp -m addrtype --src-type LOCAL -j ACCEPT\n"
                     "COMMIT\n")

        with self.assertRaises(subprocess.CalledProcessError):
            self.check_load([src, 'FORWARD',])

        # need to explicitly handle addrtype clauses
        self.check_load(['--addrtype-pass', src, 'FORWARD',])

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('pass', ip_proto='tcp')
        f2 = self.mkFlower('pass', ip_proto='tcp')
        self.assertFilters([f1, f2,], data)

        self.check_load(['--addrtype-fail', src, 'FORWARD',])

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('pass', ip_proto='tcp')
        self.assertFilters([f1,], data)

    def testVlanTag(self):
        """Verify that sliced rules with vlan tags work."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD DROP [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -m vlan --vlan-tag 100 -m comment --comment \"some-comment\" -j ACCEPT\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('pass',
                           ip_proto='tcp',
                           vlan_id=100)
        f2 = self.mkFlower('drop')
        self.assertFilters([f1, f2,], data)

    def testVlanTagAny(self):
        """Match vlan-tagged frames but ignore the tag."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD DROP [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -m vlan --vlan-tag any -m comment --comment \"some-comment\" -j ACCEPT\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('pass',
                           ip_proto='tcp',
                           vlan_id=True)
        f2 = self.mkFlower('drop')
        self.assertFilters([f1, f2,], data)

    def testDropTrap(self):
        """Test drop/trap/police functionality."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j DROP\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('drop', ip_proto='tcp')
        self.assertFilters([f1,], data)

        self.check_load(['--drop-mode', 'trap', src, 'FORWARD'])

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('trap', ip_proto='tcp')
        self.assertFilters([f1,], data)

        self.check_load(['--drop-mode', 'trap,8Kbit,100', src, 'FORWARD'])

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',),
                                  strict=False)
        f1 = self.mkFlower('police+trap', ip_proto='tcp',
                           rate='8Kbit', burst='100b')
        self.assertFilters([f1,], data)

@unittest.skipIf(not isLinux() or not isRoot(),
                 "this test only runs on Linux as root")
class BridgeLoadTest(TestMixin,
                     TcSaveTestUtils.ScriptTestMixin,
                     unittest.TestCase):

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        self.setUpScripts()
        self.setUpClearQdiscs()

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['link',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        os.environ['TEST_VLANS_JSON'] = json.dumps({})
        os.environ['TEST_SVIS_JSON'] = json.dumps({})

        # re-use the two dummy interfaces but pretend
        # they are links/ports

    def tearDown(self):
        self.setUpClearQdiscs()
        self.tearDownScripts()
        self.tearDownWorkdir()

        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def testSimple(self):

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j ACCEPT\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        self.assertEmptyIngress(dev='dummy0')

        # make sure the filter got added

        f1 = self.mkFlower('pass', ip_proto='tcp')

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        self.assertFilters([f1,], data)

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy1', 'ingress',))
        self.assertFilters([], data)

        # when we change interface specifiers, it will ignore (not reset)
        # the filters for non-front-panel ports

        self.setUpClearQdiscs()

        # load dummy1 instead of dummy0

        self.check_load([src, 'FORWARD', 'dummy1',])

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        self.assertFilters([], data)

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy1', 'ingress',))
        self.assertFilters([], data)

    def testLink(self):
        """Test non-front-panel links."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy1 - [0:0]\n"
                     "-A FORWARD -i dummy1 -j FORWARD_dummy1\n"
                     "-A FORWARD_dummy1 -p tcp -j ACCEPT\n"
                     "COMMIT\n")

        # this should fail, dummy1 is not a valid port

        with self.assertRaises(subprocess.CalledProcessError):
            self.check_load([src, 'FORWARD',])

        # try again
        self.check_load([src, 'FORWARD', 'dummy1',])

        f1 = self.mkFlower('pass', ip_proto='tcp')

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        self.assertFilters([], data)

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy1', 'ingress',))
        self.assertFilters([f1,], data)

@unittest.skipUnless(isDut() and isPhysical(),
                     "this test only runs on a switchdev device")
class SwitchdevLoadTest(TestMixin,
                        PhysicalTestMixin,
                        TcSaveTestUtils.ScriptTestMixin,
                        unittest.TestCase):

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        if not path_config.isBrazil():
            self.setUpScripts()
        self.clearPhysicalInterfaces()

        self.topo = Topology(log=self.log.getChild("links"))

    def tearDown(self):
        if not path_config.isBrazil():
            self.tearDownScripts()
        self.tearDownWorkdir()
        self.clearPhysicalInterfaces()

    def testOffload(self):
        """Verify we can enable hardware offload."""

        intfs = self.topo.matchLinks('swp+')
        ifCount = len(intfs)

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n")
            fd.write(":FORWARD DROP [0:0]\n")

            for i in range(ifCount):
                fd.write(":FORWARD_swp%d - [0:0]\n" % (i+1))
            for i in range(ifCount):
                fd.write("-A FORWARD -i swp%d -j FORWARD_swp%d\n"
                         % (i+1, i+1,))
            for i in range(ifCount):
                fd.write("-A FORWARD_swp%d -p tcp -j ACCEPT\n" % (i+1))
            fd.write("COMMIT\n")

        with open(src, 'rt') as fd:
            sys.stdout.write(fd.read())

        self.check_load(['--offload', src, 'FORWARD',])

    def testOffloadShared(self):
        """Verify we can enable hardware offload."""

        intfs = self.topo.matchLinks('swp+')
        ifCount = len(intfs)

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n")
            fd.write(":FORWARD DROP [0:0]\n")

            for idx in range(ifCount):
                tocStride = ifCount - idx - 1
                bodyStride = idx*2
                fd.write("-A FORWARD -i swp%d -j SKIP --skip-rules %d\n"
                         % (idx+1, tocStride+bodyStride,))

            for idx in range(ifCount):
                endStride = 2*(ifCount - idx - 1)
                fd.write("-A FORWARD -p tcp -j ACCEPT\n")
                fd.write("-A FORWARD -j SKIP --skip-rules %d\n" % endStride)

            fd.write("COMMIT\n")

        with open(src, 'rt') as fd:
            sys.stdout.write(fd.read())

        self.check_load(['--offload', '--shared-block', src, 'FORWARD',])

@unittest.skipIf(not isLinux() or not isRoot(),
                 "this test only runs on Linux as root")
class FilterTest(TestMixin,
                 unittest.TestCase):
    """Test individual tests for syntax."""

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        self.setUpScripts()
        self.setUpClearQdiscs()

        os.environ['TEST_DUMMY'] = '1'

    def tearDown(self):
        self.setUpClearQdiscs()
        self.tearDownScripts()
        self.tearDownWorkdir()

        os.environ.pop('TEST_DUMMY', None)

    def testProtocol(self):

        self.assertFlower("-p udp", ip_proto='udp')
        self.assertFlower("-p tcp", ip_proto='tcp')
        self.assertFlower("-p icmp", ip_proto='icmp')

        # numeric protos are looked up
        self.assertFlower("-p 1", ip_proto='icmp')
        self.assertFlower("-p 99", ip_proto='63')

        # support 'all' and '0'
        allFilters = [{'ip_proto' : 'tcp',},
                      {'ip_proto' : 'udp',},
                      {'ip_proto' : 'sctp',},
                      {'ip_proto' : 'icmp',},]
        self.assertFlowerExpand("-p all", allFilters)
        self.assertFlowerExpand("-p 0", allFilters)

        # support negation
        mostFilters = [{'ip_proto' : 'udp',},
                       {'ip_proto' : 'sctp',},
                       {'ip_proto' : 'icmp',},]
        self.assertFlowerExpand("! -p tcp", mostFilters)

    def testProtocolIpv6(self):

        self.assertFlower("-p tcp", ip_proto='tcp', version=socket.AF_INET6)
        self.assertFlower("-p icmpv6", ip_proto='icmpv6', version=socket.AF_INET6)

        # support 'all' and '0'
        allFilters = [{'ip_proto' : 'tcp',},
                      {'ip_proto' : 'udp',},
                      {'ip_proto' : 'sctp',},
                      {'ip_proto' : 'icmpv6',},]
        self.assertFlowerExpand("-p all", allFilters, version=socket.AF_INET6)
        self.assertFlowerExpand("-p 0", allFilters, version=socket.AF_INET6)

        # support negation
        mostFilters = [{'ip_proto' : 'udp',},
                       {'ip_proto' : 'sctp',},
                       {'ip_proto' : 'icmpv6',},]
        self.assertFlowerExpand("! -p tcp", mostFilters, version=socket.AF_INET6)

    def testSrcIp(self):
        """Test the --source (src_ip) option."""

        self.assertFlower("-s 1.1.1.1", src_ip='1.1.1.1')
        self.assertFlower("--source 1.1.1.1", src_ip='1.1.1.1')

        self.assertFlower("-s 1.1.1.0/24", src_ip='1.1.1.0/24')
        self.assertFlower("--source 1.1.1.0/24", src_ip='1.1.1.0/24')

        # NOTE that tc-flower does not support netmask syntax

        self.assertFlower("-s 1.1.1.0/255.255.255.0", src_ip='1.1.1.0/24')
        self.assertFlower("--source 1.1.1.0/255.255.255.0", src_ip='1.1.1.0/24')

        # test IPv6
        self.assertFlower("-s 2001::dead:beef", src_ip='2001::dead:beef',
                          version=socket.AF_INET6)
        self.assertFlower("-s fe80::/10", src_ip='fe80::/10',
                          version=socket.AF_INET6)

        # test address inversion
        filters_ = [{'src_ip' : '1.1.1.1',
                     'action' : 'jump', 'jump' : 1,},
                    {'action' : 'pass',},]
        self.assertFlowerExpand("! -s 1.1.1.1", filters_)

    def testDstIp(self):
        """Test the --destionation (src_ip) option."""

        self.assertFlower("-d 1.1.1.1", dst_ip='1.1.1.1')
        self.assertFlower("--destination 1.1.1.1", dst_ip='1.1.1.1')

        # test address inversion
        filters_ = [{'dst_ip' : '1.1.1.1',
                     'action' : 'jump', 'jump' : 1,},
                    {'action' : 'pass',},]
        self.assertFlowerExpand("! -d 1.1.1.1", filters_)

    def testSrcPort(self):

        self.assertFlower("-p tcp --sport 80",
                          ip_proto='tcp', src_port=80)
        self.assertFlower("-p tcp --source-port 80",
                          ip_proto='tcp', src_port=80)
        self.assertFlower("-p udp --sport 80",
                          ip_proto='udp', src_port=80)

        self.assertFlower("-p tcp --sport 80:81",
                          ip_proto='tcp', src_port={'start' : 80, 'end' : 81,})
        self.assertFlower("-p tcp --sport :80",
                          ip_proto='tcp', src_port={'start' : 1, 'end' : 80,})
        self.assertFlower("-p tcp --sport 30000:",
                          ip_proto='tcp', src_port={'start' : 30000, 'end' : 65535,})

        filters_ = [{'src_port' : 80,
                     'action' : 'jump', 'jump' : 1,},
                    {'action' : 'pass',},]
        self.assertFlowerExpand("-p tcp ! --sport 80", filters_)

        filters_ = [{'src_port' : 80,},
                    {'src_port' : 81,},]
        self.assertFlowerExpand("-p tcp --sport 80:81", filters_,
                                port_unroll=5)

    def testDstPort(self):

        self.assertFlower("-p tcp --dport 80",
                          ip_proto='tcp', dst_port=80)
        self.assertFlower("-p tcp --destination-port 80",
                          ip_proto='tcp', dst_port=80)

        filters_ = [{'dst_port' : 80,
                     'action' : 'jump', 'jump' : 1,},
                    {'action' : 'pass',},]
        self.assertFlowerExpand("-p tcp ! --dport 80", filters_)

    def testSrcMac(self):

        self.assertFlower("-m mac --mac-source 00:11:22:33:44:55",
                          src_mac='00:11:22:33:44:55')

        filters_ = [{'src_mac' : '00:11:22:33:44:55',
                     'action' : 'jump', 'jump' : 1,},
                    {'action' : 'pass',},]
        self.assertFlowerExpand("! --mac-source 00:11:22:33:44:55", filters_)

    def testIpFlags(self):

        self.assertFlower("--fragment", ip_flags={'frag' : True,})
        self.assertFlower("! --fragment", ip_flags={'frag' : False,})

    def testIcmpTypeCode(self):

        filter_ = {'eth_type' : 'ipv4',
                   'ip_proto' : 'icmp',
                   'icmp_type' : '3'}
        # XXX rothcar -- unlike most TC JSON dumps, the icmp_type here is a str
        self.assertFlower("-p icmp --icmp-type destination-unreachable", **filter_)

        filter_.update({'action' : 'jump', 'jump' : 1,})
        filters_ = [filter_,
                    {'action' : 'pass'},]
        self.assertFlowerExpand("-p icmp ! --icmp-type destination-unreachable",
                                filters_)

        filter_ = {'eth_type' : 'ipv4',
                   'ip_proto' : 'icmp',
                   'icmp_type' : '3',
                   'icmp_code' : '1'}
        # XXX rothcar -- unlike most TC JSON dumps, the icmp_type here is a str
        self.assertFlower("-p icmp --icmp-type host-unreachable", **filter_)

    def testIcmpV6TypeCode(self):

        filter_ = {'eth_type' : 'ipv6',
                   'ip_proto' : 'icmpv6',
                   'icmp_type' : '1'}
        self.assertFlower("-p icmpv6 --icmpv6-type destination-unreachable",
                          version=socket.AF_INET6,
                          **filter_)

        filter_.update({'action' : 'jump', 'jump' : 1,})
        filters_ = [filter_,
                    {'action' : 'pass'},]
        self.assertFlowerExpand("-p icmpv6 ! --icmpv6-type destination-unreachable",
                                filters_,
                                version=socket.AF_INET6)

        filter_ = {'eth_type' : 'ipv6',
                   'ip_proto' : 'icmpv6',
                   'icmp_type' : '1',
                   'icmp_code' : '2',}
        self.assertFlower("-p icmpv6 --icmpv6-type beyond-scope",
                          version=socket.AF_INET6,
                          **filter_)

        filter_.update({'action' : 'jump', 'jump' : 1,})
        filters_ = [filter_,
                    {'action' : 'pass'},]
        self.assertFlowerExpand("-p icmpv6 ! --icmpv6-type beyond-scope",
                                filters_,
                                version=socket.AF_INET6)

    def testPolicy(self):
        """Test flower generation with different IPTABLES policies"""

        self.assertFlower("-p udp", ip_proto='udp',
                          policy='ACCEPT', defaultPolicy='ACCEPT')

        self.assertFlower("-p udp", ip_proto='udp',
                          policy='DROP', defaultPolicy='ACCEPT')

        filters_ = [{'ip_proto' : 'udp',
                     'action' : 'pass',},
                    {'action' : 'drop',},]
        self.assertFlowerExpand("-p udp",
                                filters_,
                                policy='ACCEPT', defaultPolicy='DROP')

        filters_ = [{'ip_proto' : 'udp',
                     'action' : 'drop',},
                    {'action' : 'drop',},]
        self.assertFlowerExpand("-p udp",
                                filters_,
                                policy='DROP', defaultPolicy='DROP')

    def testProtocolEgress(self):
        """Make sure we properly ignore any egress qdiscs.
        """

        # normal protocol test with the qdiscs being cleared

        self.setUpClearQdiscs()
        self.assertFlower("-p udp", ip_proto='udp', clear=False)

        self.setUpClearQdiscs()

        # add an explicit egress qdisc
        self.check_call(('tc', 'qdisc', 'add', 'dev', 'dummy0', 'root', 'pfifo_fast',))

        # filter installation should ignore the egress qdisc
        # (even though the 'qdisc show' output is buggy)

        self.assertFlower("-p udp", ip_proto='udp', clear=False)

    def testArpHack(self):

        filters = [{'ip_proto' : 'tcp',},
        ]
        self.assertFlowerExpand("-p tcp", filters)

        filters = [{'vlan_id' : True, 'eth_type' : 'arp', 'vlan_ethtype' : 'arp',},
                   {'ip_proto' : 'tcp',},
        ]
        self.assertFlowerExpand("-p tcp", filters, hack_vlan_arp=True)

@unittest.skipIf(not isLinux() or not isRoot(),
                 "this test only runs on Linux as root")
class ReloadTest(TestMixin,
                 unittest.TestCase):
    """Test the reload behavior.

    XXX rothcar -- include some sort of trace/debug output here.
    """

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        self.setUpScripts()
        self.setUpClearQdiscs()

        os.environ['TEST_DUMMY'] = '1'

    def tearDown(self):
        self.setUpClearQdiscs()
        self.tearDownScripts()
        self.tearDownWorkdir()

        os.environ.pop('TEST_DUMMY', None)

    def assertUpdate(self, ipt1, ipt2, flowerSpecs, version=socket.AF_INET):

        src1 = os.path.join(self.workdir, "iptables1.txt")
        with open(src1, 'wt') as fd:
            fd.write("*filter\n")
            fd.write(":FORWARD ACCEPT [0:0]\n")
            fd.write(":FORWARD_dummy0 - [0:0]\n")
            fd.write("-A FORWARD -i dummy0 -j FORWARD_dummy0\n")
            for ipt in ipt1:
                fd.write("-A FORWARD_dummy0 %s -j ACCEPT\n" % ipt)
            fd.write("COMMIT\n")

        src2 = os.path.join(self.workdir, "iptables2.txt")
        with open(src2, 'wt') as fd:
            fd.write("*filter\n")
            fd.write(":FORWARD ACCEPT [0:0]\n")
            fd.write(":FORWARD_dummy0 - [0:0]\n")
            fd.write("-A FORWARD -i dummy0 -j FORWARD_dummy0\n")
            for ipt in ipt2:
                fd.write("-A FORWARD_dummy0 %s -j ACCEPT\n" % ipt)
            fd.write("COMMIT\n")

        setUpClearQdiscs()

        if version == socket.AF_INET6:
            cmd = ('-6', src1, 'FORWARD',)
        else:
            cmd = (src1, 'FORWARD',)
        self.check_load(cmd)

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        kwargs = dict(**flowerSpecs)

        pass

    def testMultiRules(self):
        """Simple test to make sure multiple rules work."""

        src = os.path.join(self.workdir, "iptables1.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n")
            fd.write(":FORWARD ACCEPT [0:0]\n")
            fd.write(":FORWARD_dummy0 - [0:0]\n")
            fd.write("-A FORWARD -i dummy0 -j FORWARD_dummy0\n")
            fd.write("-A FORWARD_dummy0 -p tcp -j ACCEPT\n")
            fd.write("-A FORWARD_dummy0 -p udp -j ACCEPT\n")
            fd.write("COMMIT\n")

        self.setUpClearQdiscs()

        self.check_load([src, 'FORWARD',])

        filters_ = [self.mkFlower('pass', ip_proto='tcp', handle=1),
                    self.mkFlower('pass', ip_proto='udp', handle=2),]
        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        self.assertFilters(filters_, data)

    def testReloadSingleSame(self):
        """Simple TC reload with the same single rule."""

        # adding an initial rule is fine, there are no existing rules

        self.assertFlower("-p tcp", ip_proto='tcp')

        # load the same rule set a second time

        self.assertFlower("-p tcp", ip_proto='tcp',
                          clear=False)

    def testReloadSingleChange(self):
        """Change a single rule."""

        # load an initial rule

        self.assertFlower("-p tcp", ip_proto='tcp')

        # load a different rule

        self.assertFlower("-p udp", ip_proto='udp',
                          clear=False)

    def testReloadDrop(self):
        """Simple TC reload with a 'drop' rule."""

        # adding an initial rule is fine, there are no existing rules

        self.assertFlower("-p tcp", ip_proto='tcp')

        # second add fails until we have an atomic update mechanism

        self.assertFlower("-p tcp", ip_proto='tcp',
                          policy='DROP',
                          clear=False)

    def testReloadDropPolicy(self):
        """Simple TC reload with a 'drop' policy."""

        # adding an initial rule is fine, there are no existing rules

        self.assertFlower("-p tcp", ip_proto='tcp')

        # second add fails until we have an atomic update mechanism

        filters_ = [{'ip_proto' : 'tcp',},
                    {'action' : 'drop',},]
        self.assertFlowerExpand("-p tcp",
                                filters_,
                                defaultPolicy='DROP',
                                clear=False)

        # try again in reverse order

        self.assertFlowerExpand("-p tcp",
                                filters_,
                                defaultPolicy='DROP')

        self.assertFlower("-p tcp", ip_proto='tcp',
                          clear=False)

    def testReloadNonAtomic(self):
        """Reload in non-atomic mode."""

        self.assertFlower("-p tcp", ip_proto='tcp')

        # second add fails until we have an atomic update mechanism

        self.assertFlower("-p udp", ip_proto='udp',
                          clear=False, atomic=False)

    def testReloadLazyDrop(self):
        """Reload using lazy-drop atomicity."""

        self.assertFlower("-p tcp", ip_proto='tcp')

        # second add fails until we have an atomic update mechanism

        self.assertFlower("-p udp", ip_proto='udp',
                          clear=False, drop=True)

    def doTestReprioritize(self, handle, preference):
        """Test code that re-priorizes an existing drop rule."""

        # load the single rule at 8392 (just shy of HANDLE_UPDATE)
        # so that the default-drop changes zones
        cmd = ('tc', 'qdisc',
               'add',
               'dev', 'dummy0',
               'ingress',)
        self.check_call(cmd)
        cmd = ('tc', 'qdisc',
               'add',
               'dev', 'dummy1',
               'ingress',)
        self.check_call(cmd)
        cmd = ('tc', 'filter',
               'add',
               'dev', 'dummy0',
               'ingress',
               'handle', str(handle), 'pref', str(preference),
               'flower',
               'action', 'drop',)
        self.check_call(cmd)
        cmd = ('tc', 'filter',
               'add',
               'dev', 'dummy1',
               'ingress',
               'handle', str(handle), 'pref', str(preference),
               'flower',
               'action', 'drop',)
        self.check_call(cmd)

        # next load needs to re-prioritize the existing rule
        self.assertFlower("-p udp", ip_proto='udp',
                          clear=False, drop=True)

    def testReloadLazyDropReprioritize(self):

        self.doTestReprioritize(1, 1)
        self.setUpClearQdiscs()

        # fuzz the handle
        self.doTestReprioritize(8191, 1)
        self.setUpClearQdiscs()
        self.doTestReprioritize(8192, 1)
        self.setUpClearQdiscs()
        self.doTestReprioritize(8193, 1)
        self.setUpClearQdiscs()

        # fuzz the prio
        self.doTestReprioritize(1, 0x7fff)
        self.setUpClearQdiscs()
        self.doTestReprioritize(1, 0x8000)
        self.setUpClearQdiscs()
        self.doTestReprioritize(1, 0x8001)
        self.setUpClearQdiscs()
        self.doTestReprioritize(1, 0x9fff)
        self.setUpClearQdiscs()
        self.doTestReprioritize(1, 0xa000)
        self.setUpClearQdiscs()
        self.doTestReprioritize(1, 0xa001)

    def sideLoad(self, cmd):
        """Side-load a TC rule."""

        self.setUpClearQdiscs()

        qCmd = ('tc', 'qdisc', 'add', 'dev', 'dummy0', 'ingress',)
        self.check_call(qCmd)

        # insert a random rule in the default handle space

        self.check_call(cmd)

    def testRecoverDefault(self):
        """Try to detect a failed reload.

        Here, the upgrade is attempted over a hand-edited ruleset.
        The hand-inserted rule has a handle/pref that appears like
        it was from a normal install/update, so atomic update works here.
        """

        # default handle space, default preference space

        cmd = ('tc', 'filter', 'add',
               'dev', 'dummy0',
               'protocol', 'ip',
               'ingress',
               'handle', '1000',
               'pref', '40000',
               'flower',
               'verbose',
               'ip_proto', 'tcp',
               'action', 'ok',)
        self.sideLoad(cmd)

        # make sure we can upgrade over it

        self.assertFlower("-p udp", ip_proto='udp',
                          clear=False)

        # default handle space, upgrade preference space space

        cmd = ('tc', 'filter', 'add',
               'dev', 'dummy0',
               'protocol', 'ip',
               'ingress',
               'handle', '1000',
               'pref', '50000',
               'flower',
               'verbose',
               'ip_proto', 'tcp',
               'action', 'ok',)
        self.sideLoad(cmd)

        # make sure we can upgrade over it

        self.assertFlower("-p udp", ip_proto='udp',
                          clear=False)

    def testRecoverUpdate(self):
        """Try to recover from a failed reload using --no-atomic.

        The hand-edited rule is inserted with a high handle index,
        making it look like it is leftover from a failed update.
        """

        # upgrade handle space, upgrade preference space
        # (as if an upgrade failed)

        cmd = ('tc', 'filter', 'add',
               'dev', 'dummy0',
               'protocol', 'ip',
               'ingress',
               'handle', '9000',
               'pref', '50000',
               'flower',
               'verbose',
               'ip_proto', 'tcp',
               'action', 'ok',)
        self.sideLoad(cmd)

        # initial upgrade attempt fails

        with self.assertRaises(subprocess.CalledProcessError):
            self.assertFlower("-p udp", ip_proto='udp',
                              clear=False)

        # non-atomic update works though

        self.assertFlower("-p udp", ip_proto='udp',
                          clear=False, atomic=False)

    def testRecoverUpdate2(self):
        """Try to recover from a failed reload using --drop.

        The hand-edited rule is inserted with a high handle index,
        making it look like it is leftover from a failed update.
        """

        # upgrade handle space, upgrade preference space
        # (as if an upgrade failed)

        cmd = ('tc', 'filter', 'add',
               'dev', 'dummy0',
               'protocol', 'ip',
               'ingress',
               'handle', '9000',
               'pref', '50000',
               'flower',
               'verbose',
               'ip_proto', 'tcp',
               'action', 'ok',)
        self.sideLoad(cmd)

        # initial upgrade attempt fails

        with self.assertRaises(subprocess.CalledProcessError):
            self.assertFlower("-p udp", ip_proto='udp',
                              clear=False)

        # default-drop update should pass

        self.assertFlower("-p udp", ip_proto='udp',
                          clear=False, drop=True)

    def testRecoverUpdateBadPreference(self):
        """Try to recover from a failed reload.

        The hand-edited rule is inserted with a normal handle index,
        but a preference that would be from a failed update.

        Since all of the new rules are inserted before any of the old rules
        (including this bogus one) are removed, the update should
        be atomic, and should not leak traffic.
        """

        # upgrade handle space, upgrade preference space
        # (as if an upgrade failed)

        cmd = ('tc', 'filter', 'add',
               'dev', 'dummy0',
               'protocol', 'ip',
               'ingress',
               'handle', '1000',
               'pref', '50000',
               'flower',
               'verbose',
               'ip_proto', 'tcp',
               'action', 'ok',)
        self.sideLoad(cmd)

        # upgrade passes, even though the preference is wrong
        self.assertFlower("-p udp", ip_proto='udp',
                          clear=False)

@unittest.skipIf(not isLinux() or not isRoot(),
                 "this test only runs on Linux as root")
class RewindTest(TestMixin,
                 unittest.TestCase):
    """Test rewind behavior if rules cannot load."""

    def setUpTcShim(self):
        scriptPath = os.path.join(self.workdir, "bin/tc")
        pyPath = os.path.join(os.path.dirname(__file__), "tc-real.py")
        with open(scriptPath, 'wt') as fd:
            fd.write("#!/bin/sh\n")
            fd.write("exec %s %s \"$@\"\n"
                     % (sys.executable, pyPath,))
        os.chmod(scriptPath, 0o755)

    def setUpTcShimRejectUdp(self):
        scriptPath = os.path.join(self.workdir, "bin/tc")
        pyPath = os.path.join(os.path.dirname(__file__), "tc-almost.py")
        with open(scriptPath, 'wt') as fd:
            fd.write("#!/bin/sh\n")
            fd.write("exec %s %s \"$@\"\n"
                     % (sys.executable, pyPath,))
        os.chmod(scriptPath, 0o755)

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        self.setUpScripts()
        self.setUpTcShim()
        self.setUpClearQdiscs()

        os.environ['TEST_DUMMY'] = '1'

    def tearDown(self):
        self.setUpClearQdiscs()
        self.tearDownScripts()
        self.tearDownWorkdir()

        os.environ.pop('TEST_DUMMY', None)

    def testSimpleFilterAccept(self):
        """Sanity check for simple accept rules."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j ACCEPT\n"
                     "-A FORWARD_dummy0 -p udp -j ACCEPT\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        # make sure the filter got added

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('pass', ip_proto='tcp')
        f2 = self.mkFlower('pass', ip_proto='udp')
        self.assertFilters([f1, f2,], data)

    def testAbort(self):
        """Abort after the first rule."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j ACCEPT\n"
                     "-A FORWARD_dummy0 -p udp -j ACCEPT\n"
                     "COMMIT\n")

        self.setUpTcShimRejectUdp()
        # cause 'tc' to fail for UDP rules

        with self.assertRaises(subprocess.CalledProcessError):
            self.check_load([src, 'FORWARD',])

        # default state, no filters

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        self.assertFilters([], data)

    def doTestRecoverAbort(self, batch=True):
        """Verify that we can recover a non-empty ruleset."""

        src1 = os.path.join(self.workdir, "iptables1.txt")
        with open(src1, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p tcp -j ACCEPT\n"
                     "COMMIT\n")

        src2 = os.path.join(self.workdir, "iptables2.txt")
        with open(src2, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     ":FORWARD_dummy0 - [0:0]\n"
                     "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                     "-A FORWARD_dummy0 -p udp -j ACCEPT\n"
                     "COMMIT\n")

        self.setUpTcShimRejectUdp()
        # cause 'tc' to fail for UDP rules

        # this one is cool, it's a TCP rule
        self.check_load([src1, 'FORWARD',])

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f = self.mkFlower('pass', ip_proto='tcp')
        self.assertFilters([f,], data)

        # but this one, not so sure

        with self.assertRaises(subprocess.CalledProcessError):
            if batch:
                self.check_load([src2, 'FORWARD',])
            else:
                self.check_load(['--no-batch', src2, 'FORWARD',])

        # should have the same set of filters
        self.assertFilters([f,], data)

    def testRecoverAbort(self):
        self.doTestRecoverAbort(batch=True)

    def testRecoverAbortNoBatch(self):
        self.doTestRecoverAbort(batch=False)

class SharedTestMixin(object):

    def check_load(self, cmd):
        cmd = ['tc-flower-load', '-v', '--shared-block',] + list(cmd)
        self.check_call(cmd)

    def assertFlower(self, iptSpec,
                     policy='ACCEPT', defaultPolicy='ACCEPT',
                     version=socket.AF_INET,
                     clear=True, atomic=True, drop=False,
                     **flowerSpec):
        """Verify that a single IPTABLES rule is converted correctly.

        Here we assume that the IPTABLES rule is translated to
        a single TC filter.
        """

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n")
            fd.write(":FORWARD %s [0:0]\n" % defaultPolicy)

            fd.write("-A FORWARD -i dummy0 -j SKIP --skip-rules 1\n")
            fd.write("-A FORWARD -i dummy1 -j SKIP --skip-rules 2\n")

            fd.write("-A FORWARD %s -j %s\n" % (iptSpec, policy,))
            fd.write("-A FORWARD -j SKIP --skip-rules 1\n")

            fd.write("-A FORWARD -j SKIP --skip-rules 0\n")

            fd.write("COMMIT\n")

        if clear:
            self.setUpClearQdiscs()

        versionOpts = ['-6',] if version == socket.AF_INET6 else []
        atomicOpts = [] if atomic else ['--non-atomic',]
        dropOpts = ['--drop',] if drop else []
        self.check_load(versionOpts + atomicOpts + dropOpts + [src, 'FORWARD',])

        self.assertEmptyIngress(dev='dummy0')

        # make sure the filter got added

        data = self.check_tc_json(('filter', 'show', 'block', '1', 'ingress',))
        kwargs = dict(**flowerSpec)
        if 'action' in kwargs:
            action = kwargs['action']
        elif policy == 'ACCEPT':
            action = 'pass'
        elif policy == 'DROP':
            action = 'drop'
        else:
            raise ValueError("invalid TC action %s", action)

        f0 = self.mkFlower('jump', jump=1, indev='dummy0', version=version)
        f1 = self.mkFlower('jump', jump=2, indev='dummy1', version=version)
        f2 = self.mkFlower(action, version=version, **kwargs)
        f3 = self.mkFlower('jump', jump=1, version=version)
        f4 = self.mkFlower('jump', jump=0, version=version)
        self.assertFilters([f0, f1, f2, f3, f4,], data)

    def assertFlowerExpand(self, iptSpec, flowerSpecs,
                           policy='ACCEPT', defaultPolicy='ACCEPT',
                           version=socket.AF_INET,
                           clear=True, atomic=True, drop=False):
        """Verify that an IPTABLES rule is expanded correctly to multiple statements."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n")
            fd.write(":FORWARD %s [0:0]\n" % defaultPolicy)

            fd.write("-A FORWARD -i dummy0 -j SKIP --skip-rules 1\n")
            fd.write("-A FORWARD -i dummy1 -j SKIP --skip-rules 2\n")

            fd.write("-A FORWARD %s -j %s\n" % (iptSpec, policy,))
            fd.write("-A FORWARD -j SKIP --skip-rules 1\n")

            fd.write("-A FORWARD -j SKIP --skip-rules 0\n")

            fd.write("COMMIT\n")

        if clear:
            self.setUpClearQdiscs()

        versionOpts = ['-6',] if version == socket.AF_INET6 else []
        atomicOpts = [] if atomic else ['--no-atomic',]
        dropOpts = ['--drop',] if drop else []
        self.check_load(versionOpts + atomicOpts + dropOpts + [src, 'FORWARD',])

        self.assertEmptyIngress(dev='dummy0')

        # make sure the filter got added

        data = self.check_tc_json(('filter', 'show', 'block', '1', 'ingress',))
        def _mk(**kwargs):
            spec = dict(kwargs)

            if 'action' in spec:
                action = spec['action']
            elif policy == 'ACCEPT':
                action = 'pass'
            elif policy == 'DROP':
                action = 'drop'
            else:
                raise ValueError("invalid TC action %s", action)

            action = spec.pop('action', action)
            return self.mkFlower(action, version=version, **spec)

        specs_ = [_mk(**x) for x in flowerSpecs]
        stride = len(specs_)

        f0 = self.mkFlower('jump', jump=1, indev='dummy0', version=version)
        f1 = self.mkFlower('jump', jump=1+stride, indev='dummy1', version=version)

        f3 = self.mkFlower('jump', jump=1, version=version)
        f4 = self.mkFlower('jump', jump=0, version=version)

        specs = [f0, f1,] + specs_ + [f3, f4,]

        self.assertFilters(specs, data)

@unittest.skipIf(not isLinux() or not isRoot(),
                 "this test only runs on Linux as root")
class LoadSharedTest(SharedTestMixin,
                     TestMixin,
                     TcSaveTestUtils.ScriptTestMixin,
                     unittest.TestCase):
    """Test shared block loading."""

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        self.setUpScripts()
        self.setUpClearQdiscs()

        # shared-block mode uses all interfaces by default,
        # including the management interfaces
        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        os.environ['TEST_VLANS_JSON'] = json.dumps({})
        os.environ['TEST_SVIS_JSON'] = json.dumps({})

    def tearDown(self):
        self.setUpClearQdiscs()
        self.tearDownScripts()
        self.tearDownWorkdir()

        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def testDefaults(self):
        """The ingress qdiscs should not be installed yet."""

        self.assertMissingIngress(dev='dummy0')
        self.assertMissingIngress(dev='dummy1')

    def testEmptyInput(self):

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     "-A FORWARD -i dummy0 -j SKIP --skip-rules 1\n"
                     "-A FORWARD -i dummy1 -j SKIP --skip-rules 0\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        # no filters defined, no interfaces defined

        self.assertEmptyIngress(dev='dummy0')

    def testEmptyChains(self):

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"

                     "-A FORWARD -i dummy0 -j SKIP --skip-rules 1\n"
                     "-A FORWARD -i dummy1 -j SKIP --skip-rules 1\n"

                     # dummy0
                     "-A FORWARD -j SKIP --skip-rules 1\n"

                     # dummy1
                     "-A FORWARD -j SKIP --skip-rules 0\n"

                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        # dummy0 should have a qdisc but no filters

        self.assertEmptyIngress(dev='dummy0')

        # dummy1 has a qdisc even though it is not spelled out in the filters

        self.assertEmptyIngress(dev='dummy0')

    def testProtocol(self):
        self.assertFlower("-p udp", ip_proto='udp')

        mostFilters = [{'ip_proto' : 'udp',},
                       {'ip_proto' : 'sctp',},
                       {'ip_proto' : 'icmp',},]
        self.assertFlowerExpand("! -p tcp", mostFilters)

    def testDrop(self):
        """Test drop mode with shared blocks."""
        self.assertFlower("-p udp", ip_proto='udp',
                          drop=True)

    def testDropNonAtomic(self):
        """Drop and non-atomic are not compatible."""
        with self.assertRaises(subprocess.CalledProcessError):
            self.assertFlower("-p udp", ip_proto='udp',
                              drop=True, atomic=False)

    def testDropReload(self):
        """Reload using lazy-drop atomicity."""

        # normal load
        self.assertFlower("-p tcp", ip_proto='tcp')

        # replace the ruleset using --drop
        self.assertFlower("-p udp", ip_proto='udp',
                          clear=False, drop=True)

    def doTestReprioritize(self, handle, preference):
        """Test code that re-priorizes an existing drop rule."""

        # load the single rule at 8392 (just shy of HANDLE_UPDATE)
        # so that the default-drop changes zones
        cmd = ('tc', 'qdisc',
               'add',
               'dev', 'dummy0',
               'ingress_block', '1',
               'ingress',)
        self.check_call(cmd)
        cmd = ('tc', 'qdisc',
               'add',
               'dev', 'dummy1',
               'ingress_block', '1',
               'ingress',)
        self.check_call(cmd)
        cmd = ('tc', 'filter',
               'add',
               'block', '1',
               'handle', str(handle), 'pref', str(preference),
               'flower',
               'action', 'drop',)
        self.check_call(cmd)

        # next load needs to re-prioritize the existing rule
        self.assertFlower("-p udp", ip_proto='udp',
                          clear=False, drop=True)

    def testReprioritize(self):

        self.doTestReprioritize(1, 1)
        self.setUpClearQdiscs()

        # fuzz the handle
        self.doTestReprioritize(8191, 1)
        self.setUpClearQdiscs()
        self.doTestReprioritize(8192, 1)
        self.setUpClearQdiscs()
        self.doTestReprioritize(8193, 1)
        self.setUpClearQdiscs()

        # fuzz the prio
        self.doTestReprioritize(1, 0x7fff)
        self.setUpClearQdiscs()
        self.doTestReprioritize(1, 0x8000)
        self.setUpClearQdiscs()
        self.doTestReprioritize(1, 0x8001)
        self.setUpClearQdiscs()
        self.doTestReprioritize(1, 0x9fff)
        self.setUpClearQdiscs()
        self.doTestReprioritize(1, 0xa000)
        self.setUpClearQdiscs()
        self.doTestReprioritize(1, 0xa001)

class ScoreboardTestMixin(object):

    def check_load(self, cmd):
        cmd = ['tc-flower-load', '-v', '--shared-block', '--scoreboard',] + list(cmd)
        self.check_call(cmd)

@unittest.skipIf(not isLinux() or not isRoot(),
                 "this test only runs on Linux as root")
class LoadScoreboardTest(ScoreboardTestMixin,
                         TestMixin,
                         TcSaveTestUtils.ScriptTestMixin,
                         unittest.TestCase):
    """Test scoreboard loading."""

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        self.setUpScripts()
        self.setUpClearQdiscs()

        # shared-block mode uses all interfaces by default,
        # including the management interfaces
        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        os.environ['TEST_VLANS_JSON'] = json.dumps({})
        os.environ['TEST_SVIS_JSON'] = json.dumps({})

    def tearDown(self):
        self.setUpClearQdiscs()
        self.tearDownScripts()
        self.tearDownWorkdir()

        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def testDefaults(self):
        """The ingress qdiscs should not be installed yet."""

        self.assertMissingIngress(dev='dummy0')
        self.assertMissingIngress(dev='dummy1')

    def testEmptyInput(self):

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"
                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        # no filters defined, no interfaces defined

        self.assertEmptyIngress(dev='dummy0')

    def testSimple(self):

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"

                     "-A FORWARD -i dummy0 -p tcp -s 10.0.0.1 -j ACCEPT\n"
                     "-A FORWARD -i dummy1 -p tcp -s 10.0.0.1 -j ACCEPT\n"

                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        data = self.check_tc_json(('filter', 'show', 'block', '1', 'ingress',))
        f1 = self.mkFlower('pass', indev='dummy0', src_ip='10.0.0.1')
        f2 = self.mkFlower('pass', indev='dummy1', src_ip='10.0.0.1')
        self.assertFilters([f1, f2,], data)

    def testCollapseInterface(self):

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"

                     "-A FORWARD -p tcp -s 10.0.0.1 -j ACCEPT\n"

                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        data = self.check_tc_json(('filter', 'show', 'block', '1', 'ingress',))
        f1 = self.mkFlower('pass', src_ip='10.0.0.1')
        self.assertFilters([f1,], data)

    def testVlan(self):

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"

                     "-A FORWARD -i dummy0 -m vlan --vlan-tag 100 -p tcp -s 10.0.0.1 -j ACCEPT\n"

                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        data = self.check_tc_json(('filter', 'show', 'block', '1', 'ingress',))
        f1 = self.mkFlower('pass', indev='dummy0', vlan_id=100, src_ip='10.0.0.1')
        self.assertFilters([f1,], data)

    def testCollapseVlan(self):

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, 'wt') as fd:
            fd.write("*filter\n"
                     ":FORWARD ACCEPT [0:0]\n"

                     "-A FORWARD -m vlan --vlan-tag any -p tcp -s 10.0.0.1 -j ACCEPT\n"

                     "COMMIT\n")

        self.check_load([src, 'FORWARD',])

        data = self.check_tc_json(('filter', 'show', 'block', '1', 'ingress',))
        f1 = self.mkFlower('pass', vlan_id=True, src_ip='10.0.0.1')
        self.assertFilters([f1,], data)

@unittest.skipIf(not isLinux() or not isRoot(), "this test only runs on Linux as root")
class TcChainTest(TestMixin, TcSaveTestUtils.ScriptTestMixin, unittest.TestCase):
    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        self.setUpScripts()
        self.setUpClearQdiscs()
        os.environ["TEST_DUMMY"] = "1"

    def tearDown(self):
        self.setUpClearQdiscs()
        self.tearDownScripts()
        self.tearDownWorkdir()
        os.environ.pop("TEST_DUMMY", None)

    def testDefaults(self):
        """The ingress qdiscs should not be installed yet."""

        self.assertMissingIngress(dev="dummy0")
        self.assertMissingIngress(dev="dummy1")

    def testSimpleChain(self):
        """Sanity check for a single filter with a 'drop' rule."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, "wt") as fd:
            fd.write(
                "*filter\n"
                ":FORWARD ACCEPT [0:0]\n"
                ":FORWARD_dummy0 - [0:0]\n"
                "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                "-A FORWARD_dummy0 -p tcp -j DROP\n"
                "-A FORWARD_dummy0 -p udp -j ACCEPT\n"
                "COMMIT\n"
            )
        self.check_load(["--prestera-chain-mode", "--non-atomic", "--no-batch", src, 'FORWARD',])

        self.assertEmptyIngress(dev='dummy0')

        # make sure the filter got added

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('drop', ip_proto='tcp', chain=0)
        f2 = self.mkFlower('pass', ip_proto='udp', chain=0)
        self.assertFilters([f1, f2,], data)

    def testSimpleICMPChain(self):
        """Sanity check for a single filter with a 'drop' rule."""

        src = os.path.join(self.workdir, "iptables.txt")
        with open(src, "wt") as fd:
            fd.write(
                "*filter\n"
                ":FORWARD ACCEPT [0:0]\n"
                ":FORWARD_dummy0 - [0:0]\n"
                "-A FORWARD -i dummy0 -j FORWARD_dummy0\n"
                "-A FORWARD_dummy0 -p tcp -j DROP\n"
                "-A FORWARD_dummy0 -p udp -j ACCEPT\n"
                "-A FORWARD_dummy0 -s 10.0.0.1 -p icmp --icmp-type 8 -j ACCEPT\n"
                "-A FORWARD_dummy0 -s 10.0.0.1 -p icmp --icmp-type 6 -j ACCEPT\n"
                "-A FORWARD_dummy0 -s 10.0.0.1 -p icmp --icmp-type 7 -j ACCEPT\n"
                "-A FORWARD_dummy0 -p icmp -j DROP\n"
                "COMMIT\n"
            )
        self.check_load(["--prestera-chain-mode", "--non-atomic", "--no-batch", src, 'FORWARD',])

        self.assertEmptyIngress(dev='dummy0')

        # make sure the filter got added

        data = self.check_tc_json(('filter', 'show', 'dev', 'dummy0', 'ingress',))
        f1 = self.mkFlower('drop', ip_proto='tcp', chain=0)
        f2 = self.mkFlower('pass', ip_proto='udp', chain=0)
        f3 = self.mkFlower('pass', ip_proto='icmp', chain=1)
        f4 = self.mkFlower('goto', ip_proto='icmp', goto_chain=1, chain=0)
        f5 = self.mkFlower('drop', ip_proto='icmp', chain=1)
        self.assertFilters([f1, # TCP
                            f2, # UDP
                            f3, # ICMP with type 8
                            f4, # ICMP with goto chain 1
                            f3, # ICMP with type 7
                            f3, # ICMP with type 6
                            f5, # ICMP Drop
                            f4, # ICMP with goto chain 1
                            ], data)

if __name__ == "__main__":
    unittest.main()
