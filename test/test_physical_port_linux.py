"""test_physical_port_linux.py

Test physical and non-physical ports.
"""

import path_config

import os
import logging
import unittest
import subprocess
import json

import TcSaveTestUtils
from TcSaveTestUtils import (
    isLinux,
    isRoot,
    isDut,
    isVirtual,
    isPhysical,
    PhysicalTestMixin,
)

from petunia.Topology import (
    Topology,
)

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

class PortTestMixin(object):

    def tearDownBridges(self):

        cmd = ('ip', '-d', '-json', 'link', 'show',)
        data = json.loads(subprocess.check_output(cmd,
                                                  universal_newlines=True))
        for link in data:
            ifName = link['ifname']
            kind = link.get('linkinfo', {}).get('info_kind', None)
            if kind == 'bridge':
                self.log.debug("tearing down bridge %s", ifName)
                cmd = ('ip', 'link', 'del', 'dev', ifName,)
                subprocess.check_call(cmd)

    def tearDownBonds(self):

        cmd = ('ip', '-d', '-json', 'link', 'show',)
        data = json.loads(subprocess.check_output(cmd,
                                                  universal_newlines=True))
        for link in data:
            ifName = link['ifname']
            kind = link.get('linkinfo', {}).get('info_kind', None)
            if kind == 'bond':
                self.log.debug("tearing down bond %s", ifName)
                cmd = ('ip', 'link', 'del', 'dev', ifName,)
                subprocess.check_call(cmd)

    def tearDownSvis(self):

        cmd = ('ip', '-d', '-json', 'link', 'show',)
        data = json.loads(subprocess.check_output(cmd,
                                                  universal_newlines=True))
        for link in data:
            ifName = link['ifname']
            kind = link.get('linkinfo', {}).get('info_kind', None)
            if kind == 'vlan':
                self.log.debug("tearing down SVI %s", ifName)
                cmd = ('ip', 'link', 'del', 'dev', ifName,)
                subprocess.check_call(cmd)

@unittest.skipUnless(isDut() and isVirtual(),
                     "this test only runs on a virtual switchdev device")
class VmPortTest(PortTestMixin,
                 unittest.TestCase):
    """Test virtual and physical ports on a VM DUT."""

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.tearDownBridges()
        self.tearDownBonds()
        self.tearDownSvis()

        os.environ['TEST_DUMMY'] = '1'
        os.environ.pop('TEST_IFNAME_PREFIX', None)

        self.topo = Topology(log=self.log)

    def tearDown(self):
        self.tearDownBridges()
        self.tearDownBonds()
        self.tearDownSvis()

        os.environ.pop('TEST_DUMMY', None)
        os.environ['TEST_IFNAME_PREFIX'] = 'dummy'

    def assertIfNames(self, ifNames):
        h = Topology(log=self.log)
        ifNames_ = h.getPorts()
        ifNames_ = [x for x in ifNames_ if not x.startswith('en')]
        ifNames_ = [x for x in ifNames_ if not x.startswith('eth')]
        ifNames_ = [x for x in ifNames_ if not x.startswith('ma1')]
        self.assertEqual(ifNames_, ifNames)

    def testDefault(self):
        """Make sure there are no virtual interfaces."""

        cmd = ('ip', '-d', '-json', 'link', 'show',)
        data = json.loads(subprocess.check_output(cmd,
                                                  universal_newlines=True))
        for link in data:
            ifName = link['ifname']
            kind = link.get('linkinfo', {}).get('info_kind', None)

            if kind == 'bridge':
                raise AssertionError("unexpected bridge interface %s", ifName)
            if kind == 'bond':
                raise AssertionError("unexpected bond interface %s", ifName)
            if kind == 'vlan':
                raise AssertionError("unexpected SVI %s", ifName)

        self.assertIfNames(['dummy0', 'dummy1',])

    def testSimpleBridge(self):
        """Test a vanilla bridge with no vlan filtering."""

        cmds = [['ip', 'link', 'add', 'name', 'br0', 'type', 'bridge',],
                ['ip', 'link', 'set', 'br0', 'up',],
                ['ip', 'link', 'set', 'dummy0', 'up',],
                ['ip', 'link', 'set', 'dummy1', 'up',],
                ['ip', 'link', 'set', 'dummy0', 'master', 'br0',],
                ['ip', 'link', 'set', 'dummy1', 'master', 'br0',],]

        self.log.info("installing a simple bridge")

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        self.log.info("verifying bridge members")

        self.assertIfNames(['dummy0', 'dummy1',])

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0'))

    def testSimpleBond(self):
        """Test a bonded interface."""

        cmds = [['ip', 'link', 'add', 'dev', 'bond0', 'type', 'bond',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'down',],
                ['ip', 'link', 'set', 'dev', 'dummy1', 'down',],
                ['ip', 'link', 'set', 'dev', 'bond0', 'down',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'master', 'bond0',],
                ['ip', 'link', 'set', 'dev', 'dummy1', 'master', 'bond0',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'up',],
                ['ip', 'link', 'set', 'dev', 'dummy1', 'up',],
                ['ip', 'link', 'set', 'dev', 'bond0', 'up',],
        ]

        self.log.info("installing a simple bonded interface")

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        self.log.info("verifying bond members")

        self.assertIfNames(['dummy0', 'dummy1',])

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('bond0'))

    def testSimpleSvi(self):
        """Test a simple SVI."""

        cmds = [['ip', 'link', 'add',
                 'link', 'dummy0',
                 'name', 'dummy0.100',
                 'type', 'vlan', 'id', '100',],
        ]

        self.log.info("installing a simple SVI")

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        self.log.info("verifying bond member(s)")

        self.assertIfNames(['dummy0', 'dummy1',])

        ifMap = {'dummy0' : 100,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('dummy0.100'))

        ifMap = {'dummy0' : 100,}
        self.assertEqual(ifMap, self.topo.getVlanPorts(100))

        vlanSvis = {100 : {'dummy0',},}
        self.assertEqual({}, self.topo.vlanMap)
        self.assertEqual(vlanSvis, self.topo.vlanSvis)

    def testComplexSvi(self):
        """Test a complex SVI."""

        cmds = [['ip', 'link', 'add',
                 'link', 'dummy0',
                 'name', 'dummy0.100',
                 'type', 'vlan', 'id', '100',],
                ['ip', 'link', 'add',
                 'link', 'dummy1',
                 'name', 'dummy1.100',
                 'type', 'vlan', 'id', '100',],

                ['ip', 'link', 'add', 'name', 'br0', 'type', 'bridge',],
                ['ip', 'link', 'set', 'br0', 'up',],

                ['ip', 'link', 'set', 'dummy0', 'up',],
                ['ip', 'link', 'set', 'dummy0.100', 'up',],
                ['ip', 'link', 'set', 'dummy0.100', 'master', 'br0',],

                ['ip', 'link', 'set', 'dummy1', 'up',],
                ['ip', 'link', 'set', 'dummy1.100', 'up',],
                ['ip', 'link', 'set', 'dummy1.100', 'master', 'br0',],
        ]

        self.log.info("installing a simple SVI")

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        self.log.info("verifying vlan member(s)")

        self.assertIfNames(['dummy0', 'dummy1',])

        ifMap = {'dummy0' : 100,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('dummy0.100'))

        ifMap = {'dummy1' : 100,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('dummy1.100'))

        # br0 is upstream from the SVIs;
        # the SVI takes precedence since the bridge did
        # not explicitly set the tag state
        ifMap = {'dummy0' : 100,
                 'dummy1' : 100,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0'))

        ifMap = {'dummy0' : 100,
                 'dummy1' : 100,}
        self.assertEqual(ifMap, self.topo.getVlanPorts(100))

        vlanSvis = {100 : {'dummy0', 'dummy1',},}
        self.assertEqual({}, self.topo.vlanMap)
        self.assertEqual(vlanSvis, self.topo.vlanSvis)

    def testSviBridge(self):
        """Test a non-vlan-aware bridge attached to an upstream SVI."""

        cmds = [['ip', 'link', 'add', 'name', 'br0', 'type', 'bridge',],
                ['ip', 'link', 'set', 'br0', 'up',],

                ['ip', 'link', 'add',
                 'link', 'br0',
                 'name', 'br0.100',
                 'type', 'vlan', 'id', '100',],

                ['ip', 'link', 'set', 'dummy0', 'up',],
                ['ip', 'link', 'set', 'dummy0', 'up',],
                ['ip', 'link', 'set', 'dummy0', 'master', 'br0',],

                ['ip', 'link', 'set', 'dummy1', 'up',],
                ['ip', 'link', 'set', 'dummy1', 'up',],
                ['ip', 'link', 'set', 'dummy1', 'master', 'br0',],
        ]

        self.log.info("installing a SVI with a bridge")

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        self.log.info("verifying vlan member(s)")

        self.assertIfNames(['dummy0', 'dummy1',])

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0'))

        ifMap = {'dummy0' : 100,
                 'dummy1' : 100,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0.100'))

        ifMap = {'dummy0' : 100,
                 'dummy1' : 100,}
        self.assertEqual(ifMap, self.topo.getVlanPorts(100))

        # Here, the vlan map is not fully resolved
        vlanSvis = {100 : {'br0'},}
        self.assertEqual({}, self.topo.vlanMap)
        self.assertEqual(vlanSvis, self.topo.vlanSvis)

    def testVlanFilter(self):
        """Test new-style vlan filtering bridges.

        XXX rothcar --
        See
        https://docs.bisdn.de/network_configuration/vlan_bridging.html
        Here we set 'vlan_default_pvid' to '0',
        so that the ports do not automatically inherit a PVID.
        """

        cmds = [['ip', 'link', 'add', 'name', 'br0',
                 'type', 'bridge',
                 'vlan_filtering', '1', 'vlan_default_pvid', '0',],
                ['ip', 'link', 'set', 'br0', 'up',],

                ['ip', 'link', 'set', 'dummy0', 'master', 'br0',],
                ['ip', 'link', 'set', 'dummy0', 'up',],

                ['ip', 'link', 'set', 'dummy1', 'master', 'br0',],
                ['ip', 'link', 'set', 'dummy1', 'up',],
        ]

        self.log.info("installing a vlan-filtering bridge with no vlans")

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        self.log.info("verifying no vlan member(s)")

        self.assertIfNames(['dummy0', 'dummy1',])

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0'))

        self.assertEqual({}, self.topo.getVlanPorts(100))

        self.log.info("add a trunk port")

        cmds = [['bridge', 'vlan', 'add', 'vid', '100', 'dev', 'dummy0',],
        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        # br0 is vlan-filtering, but we don't notice this unless
        # we specify a vlan

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0'))

        ifMap = {'dummy0' : 100,}
        self.assertEqual(ifMap, self.topo.getVlanPorts(100))

        vlanMap = {100 : {'dummy0' : True,},}
        self.assertEqual({}, self.topo.vlanSvis)
        self.assertEqual(vlanMap, self.topo.vlanMap)

        self.log.info("add a second trunk port")

        cmds = [['bridge', 'vlan', 'add', 'vid', '100', 'dev', 'dummy1',],
        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0'))

        ifMap = {'dummy0' : 100,
                 'dummy1' : 100,}
        self.assertEqual(ifMap, self.topo.getVlanPorts(100))

        vlanMap = {100 : {'dummy0' : True,
                          'dummy1' : True,},}
        self.assertEqual({}, self.topo.vlanSvis)
        self.assertEqual(vlanMap, self.topo.vlanMap)

        self.log.info("add an access port")

        cmds = [['bridge', 'vlan', 'add', 'vid', '101', 'dev', 'dummy0', 'pvid',],
        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0'))

        ifMap = {'dummy0' : 100,
                 'dummy1' : 100,}
        self.assertEqual(ifMap, self.topo.getVlanPorts(100))

        ifMap = {'dummy0' : False,}
        self.assertEqual(ifMap, self.topo.getVlanPorts(101))

        # dummy0's pvid is not 1,
        # so vid 1 must be tagged
        vlanMap = {100 : {'dummy0' : True,
                          'dummy1' : True,},
                   101 : {'dummy0' : False,},}
        self.assertEqual({}, self.topo.vlanSvis)
        self.assertEqual(vlanMap, self.topo.vlanMap)

        self.log.info("change a trunk port to an access port")

        cmds = [['bridge', 'vlan', 'add', 'vid', '100', 'dev', 'dummy1', 'pvid',],
        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        ifMap = {'dummy0' : 100,
                 'dummy1' : False,}
        self.assertEqual(ifMap, self.topo.getVlanPorts(100))

        vlanMap = {100 : {'dummy0' : True,
                          'dummy1' : False,},
                   101 : {'dummy0' : False,},}

        self.assertEqual({}, self.topo.vlanSvis)
        self.assertEqual(vlanMap, self.topo.vlanMap)

    def testBondBridge(self):
        """Add a bond interface to a bridge."""

        cmds = [['ip', 'link', 'add', 'dev', 'bond0', 'type', 'bond',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'down',],
                ['ip', 'link', 'set', 'dev', 'dummy1', 'down',],
                ['ip', 'link', 'set', 'dev', 'bond0', 'down',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'master', 'bond0',],
                ['ip', 'link', 'set', 'dev', 'dummy1', 'master', 'bond0',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'up',],
                ['ip', 'link', 'set', 'dev', 'dummy1', 'up',],
                ['ip', 'link', 'set', 'dev', 'bond0', 'up',],

                # now add a bridge
                ['ip', 'link', 'add', 'name', 'br0', 'type', 'bridge',],
                ['ip', 'link', 'set', 'br0', 'up',],

                # add the bond to the bridge
                ['ip', 'link', 'set', 'bond0', 'master', 'br0',],
        ]

        self.log.info("installing a bond within a bridge")

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        self.log.info("verifying bond members")

        self.assertIfNames(['dummy0', 'dummy1',])

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('bond0'))

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0'))

        # no vlans here

        self.assertEqual({}, self.topo.vlanSvis)
        self.assertEqual({}, self.topo.vlanMap)

    def testVlanFilterSvi(self):
        """Add an SVI to a vlan-filtering bridge."""

        cmds = [['ip', 'link', 'add', 'name', 'br0',
                 'type', 'bridge',
                 'vlan_filtering', '1', 'vlan_default_pvid', '0',],
                ['ip', 'link', 'set', 'br0', 'up',],

                ['ip', 'link', 'set', 'dummy0', 'master', 'br0',],
                ['ip', 'link', 'set', 'dummy0', 'up',],

                ['ip', 'link', 'set', 'dummy1', 'master', 'br0',],
                ['ip', 'link', 'set', 'dummy1', 'up',],

                # add vlan IDs (no pvid --> tagged)
                ['bridge', 'vlan', 'add', 'vid', '100', 'dev', 'dummy0',],
                ['bridge', 'vlan', 'add', 'vid', '100', 'dev', 'dummy1',],

        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0'))

        ifMap = {'dummy0' : 100,
                 'dummy1' : 100,}
        self.assertEqual(ifMap, self.topo.getVlanPorts(100))

        vlanMap = {100 : {'dummy0' : True,
                          'dummy1' : True,},}
        self.assertEqual({}, self.topo.vlanSvis)
        self.assertEqual(vlanMap, self.topo.vlanMap)

        # now add an SVI to this bridge
        cmds = [['ip', 'link', 'add',
                 'link', 'br0',
                 'name', 'vlan100',
                 'type', 'vlan', 'id', '100',],
        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        # should still evaluate to the same set of physical ports

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0'))

        ifMap = {'dummy0' : 100,
                 'dummy1' : 100,}
        self.assertEqual(ifMap, self.topo.getVlanPorts(100))

        # but the tag derivation is different now

        vlanSvis = {100 : {'br0'},}
        self.assertEqual(vlanSvis, self.topo.vlanSvis)

        vlanMap = {100 : {'dummy0' : True,
                          'dummy1' : True,},}
        self.assertEqual(vlanMap, self.topo.vlanMap)

        # set one of the ports to PVID mode
        # the (tagged) SVI is upstream, but the downstream
        # vlan-aware bridge port should override it

        cmds = [['bridge', 'vlan', 'add', 'vid', '100', 'dev', 'dummy0', 'pvid',],
        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        # it's a vlan-filtering bridge, but since we named
        # it by its bridge name, the upstream tags are not applied

        # bridge ports without a vlan specifier are normal

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0'))

        # even though an SVI is attached to vlan100,
        # the pvid state from the downstream vlan-filtering bridge should stick

        ifMap = {'dummy0' : False,
                 'dummy1' : 100,}
        self.assertEqual(ifMap, self.topo.getVlanPorts(100))

        vlanMap = {100 : {'dummy0' : False,
                          'dummy1' : True,},}
        self.assertEqual(vlanMap, self.topo.vlanMap)

        vlanSvis = {100 : {'br0'},}
        self.assertEqual(vlanSvis, self.topo.vlanSvis)

    def testVlanFilterBond(self):
        """Add an bond to a vlan-filtering bridge."""

        cmds = [['ip', 'link', 'add', 'dev', 'bond0', 'type', 'bond',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'down',],
                ['ip', 'link', 'set', 'dev', 'dummy1', 'down',],
                ['ip', 'link', 'set', 'dev', 'bond0', 'down',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'master', 'bond0',],
                ['ip', 'link', 'set', 'dev', 'dummy1', 'master', 'bond0',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'up',],
                ['ip', 'link', 'set', 'dev', 'dummy1', 'up',],
                ['ip', 'link', 'set', 'dev', 'bond0', 'up',],

                # now add a vlan-filtering bridge
                ['ip', 'link', 'add', 'name', 'br0',
                 'type', 'bridge',
                 'vlan_filtering', '1', 'vlan_default_pvid', '0',],
                ['ip', 'link', 'set', 'br0', 'up',],

                ['ip', 'link', 'set', 'bond0', 'master', 'br0',],

                # add vlan ID (no pvid --> tagged)
                ['bridge', 'vlan', 'add', 'vid', '100', 'dev', 'bond0',],
        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('bond0'))

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0'))

        ifMap = {'dummy0' : 100,
                 'dummy1' : 100,}
        self.assertEqual(ifMap, self.topo.getVlanPorts(100))

        # set the bond link to untagged

        cmds = [['bridge', 'vlan', 'add', 'vid', '100', 'dev', 'bond0', 'pvid',],
        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('bond0'))

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0'))

        ifMap = {'dummy0' : False,
                 'dummy1' : False,}
        self.assertEqual(ifMap, self.topo.getVlanPorts(100))

        vlanMap = {}
        self.assertEqual(vlanMap, self.topo.vlanSvis)

        vlanMap = {100 : {'bond0' : False,},}
        self.assertEqual(vlanMap, self.topo.vlanMap)

    # other pathological cases

    def testNestedBond(self):
        """Test nested bond support."""

        cmds = [['ip', 'link', 'add', 'dev', 'bond0', 'type', 'bond',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'down',],
                ['ip', 'link', 'set', 'dev', 'bond0', 'down',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'master', 'bond0',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'up',],
                ['ip', 'link', 'set', 'dev', 'bond0', 'up',],

        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        # now add a second bond
        cmds = [['ip', 'link', 'add', 'dev', 'bond1', 'type', 'bond',],

                ['ip', 'link', 'set', 'dev', 'dummy1', 'down',],

                ['ip', 'link', 'set', 'dev', 'dummy1', 'master', 'bond1',],

                ['ip', 'link', 'set', 'dev', 'dummy1', 'up',],
        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        # try to nest the two
        # tee hee, this is supported

        cmds = [['ip', 'link', 'set', 'dev', 'bond0', 'down',],
                ['ip', 'link', 'set', 'dev', 'bond0', 'master', 'bond1',],
                ['ip', 'link', 'set', 'dev', 'bond0', 'up',],
                ['ip', 'link', 'set', 'dev', 'bond1', 'up',],
        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        self.assertIfNames(['dummy0', 'dummy1',])

    # two nested bridges

    def testNestedBridge(self):
        """Test nested bridge support."""

        cmds = [['ip', 'link', 'add', 'dev', 'br0', 'type', 'bridge',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'down',],
                ['ip', 'link', 'set', 'dev', 'br0', 'down',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'master', 'br0',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'up',],
                ['ip', 'link', 'set', 'dev', 'br0', 'up',],

        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        # now add a second bridge
        cmds = [['ip', 'link', 'add', 'dev', 'br1', 'type', 'bridge',],

                ['ip', 'link', 'set', 'dev', 'dummy1', 'down',],

                ['ip', 'link', 'set', 'dev', 'dummy1', 'master', 'br1',],

                ['ip', 'link', 'set', 'dev', 'br1', 'up',],
        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        # try to nest the two
        # tee hee, this is supported

        cmds = [['ip', 'link', 'set', 'dev', 'br0', 'down',],
                ['ip', 'link', 'set', 'dev', 'br0', 'master', 'br1',],
                ['ip', 'link', 'set', 'dev', 'br0', 'up',],
                ['ip', 'link', 'set', 'dev', 'br1', 'up',],
        ]

        # cannot enslave a bridge to a bridge

        self.log.warning("XXX rothcar -- cannot directly nest two bridges")

        with self.assertRaises(subprocess.CalledProcessError):
            for cmd in cmds:
                subprocess.check_call(cmd)

    def testNestedBridgeSneaky(self):
        """Test nested bridge support.

        Insert an intervening link to try to trick the system.
        """

        self.log.info("creating a bridge for dummy0")

        cmds = [['ip', 'link', 'add', 'dev', 'br0', 'type', 'bridge',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'down',],
                ['ip', 'link', 'set', 'dev', 'br0', 'down',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'master', 'br0',],

                ['ip', 'link', 'set', 'dev', 'dummy0', 'up',],
                ['ip', 'link', 'set', 'dev', 'br0', 'up',],

        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.log.info("creating a bond for br0")

        cmds = [['ip', 'link', 'add', 'dev', 'bond0', 'type', 'bond',],
                ['ip', 'link', 'set', 'dev', 'bond0', 'down',],

                ['ip', 'link', 'set', 'dev', 'br0', 'down',],
                ['ip', 'link', 'set', 'dev', 'br0', 'master', 'bond0',],

                ['ip', 'link', 'set', 'dev', 'br0', 'up',],
                ['ip', 'link', 'set', 'dev', 'bond0', 'up',],
        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.log.info("adding a second bridge for bond0")

        cmds = [['ip', 'link', 'add', 'dev', 'br1', 'type', 'bridge',],

                ['ip', 'link', 'set', 'dev', 'bond0', 'down',],
                ['ip', 'link', 'set', 'dev', 'br1', 'down',],

                ['ip', 'link', 'set', 'dev', 'bond0', 'master', 'br1',],

                ['ip', 'link', 'set', 'dev', 'bond0', 'up',],
                ['ip', 'link', 'set', 'dev', 'br1', 'up',],
        ]

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        ifMap = {'dummy0' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br1'))

    # multiple vlan membersip (two SVIs on a single link)

    def testSviFanin(self):
        """Test multiple SVIs on a single link."""

        cmds = [['ip', 'link', 'add',
                 'link', 'dummy0',
                 'name', 'dummy0.100',
                 'type', 'vlan', 'id', '100',],
                ['ip', 'link', 'add',
                 'link', 'dummy0',
                 'name', 'dummy0.101',
                 'type', 'vlan', 'id', '101',],

                ['ip', 'link', 'set', 'dummy0', 'up',],
                ['ip', 'link', 'set', 'dummy0.100', 'up',],

                ['ip', 'link', 'set', 'dummy0', 'up',],
                ['ip', 'link', 'set', 'dummy0.101', 'up',],
        ]

        self.log.info("installing a simple SVI")

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.topo.update()

        self.log.info("verifying vlan member(s)")

        self.assertIfNames(['dummy0', 'dummy1',])

        ifMap = {'dummy0' : 100,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('dummy0.100'))

        ifMap = {'dummy0' : 101,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('dummy0.101'))

        # br0 is upstream from the SVIs;
        # the SVI takes precedence since the bridge did
        # not explicitly set the tag state
        ifMap = {'dummy0' : 100,}
        self.assertEqual(ifMap, self.topo.getVlanPorts(100))

        ifMap = {'dummy0' : 101,}
        self.assertEqual(ifMap, self.topo.getVlanPorts(101))

        vlanSvis = {100 : {'dummy0',},
                    101 : {'dummy0',},}
        self.assertEqual({}, self.topo.vlanMap)
        self.assertEqual(vlanSvis, self.topo.vlanSvis)

    # two nested svis
    # XXX rothcar -- this is QinQ, which we do not support

    # overlapping vlan membership (SVI and bridge)

    def testDummyBridge(self):
        """Test a vanilla bridge with dummy interfaces."""

        cmds = [['ip', 'link', 'add', 'name', 'br0', 'type', 'bridge',],
                ['ip', 'link', 'set', 'br0', 'up',],
                ['ip', 'link', 'set', 'dummy0', 'up',],
                ['ip', 'link', 'set', 'dummy1', 'up',],
                ['ip', 'link', 'set', 'dummy0', 'master', 'br0',],
                ['ip', 'link', 'set', 'dummy1', 'master', 'br0',],]

        self.log.info("installing a simple bridge")

        for cmd in cmds:
            subprocess.check_call(cmd)

        # make all dummy interfaces be front-panel interfaces

        os.environ['TEST_DUMMY'] = '1'
        os.environ.pop('TEST_IFNAME_PREFIX', None)

        self.topo = Topology(log=self.log)

        self.log.info("verifying bridge members")

        self.assertIfNames(['dummy0', 'dummy1',])

        ifMap = {'dummy0' : None,
                 'dummy1' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0'))

        # only one of the dummy interfaces is a front-panel port

        os.environ.pop('TEST_DUMMY', None)
        os.environ['TEST_IFNAMES'] = 'dummy0'
        os.environ.pop('TEST_IFNAME_PREFIX', None)

        self.topo = Topology(log=self.log)

        self.log.info("verifying bridge members")

        self.assertIfNames(['dummy0',])

        ifMap = {'dummy0' : None,}

        # strict mode, all bridge ports must be front-panel ports
        with self.assertRaises(ValueError):
            self.topo.getLinkPorts('br0')

        self.assertEqual(ifMap, self.topo.getLinkPorts('br0', strict=False))

@unittest.skipUnless(isDut() and isPhysical(),
                     "this test only runs on a physical device")
class SwitchdevPortTest(PortTestMixin,
                 unittest.TestCase):
    """Test virtual and physical ports on a switchdev DUT."""

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.tearDownBridges()
        self.tearDownBonds()
        self.tearDownSvis()

        self.topo = Topology(log=self.log)

    def tearDown(self):
        self.tearDownBridges()
        self.tearDownBonds()
        self.tearDownSvis()

    def testDefault(self):
        """Make sure there are no virtual interfaces."""

        cmd = ('ip', '-d', '-json', 'link', 'show',)
        data = json.loads(subprocess.check_output(cmd,
                                                  universal_newlines=True))
        for link in data:
            ifName = link['ifname']
            kind = link.get('linkinfo', {}).get('info_kind', None)

            if kind == 'bridge':
                raise AssertionError("unexpected bridge interface %s", ifName)
            if kind == 'bond':
                raise AssertionError("unexpected bond interface %s", ifName)
            if kind == 'vlan':
                raise AssertionError("unexpected SVI %s", ifName)

        self.assertIn('swp1', self.topo.getPorts())

    def testSimpleBridge(self):
        """Test a vanilla bridge with no vlan filtering."""

        cmds = [['ip', 'link', 'add', 'name', 'br0', 'type', 'bridge',],
                ['ip', 'link', 'set', 'br0', 'up',],
                ['ip', 'link', 'set', 'swp1', 'up',],
                ['ip', 'link', 'set', 'swp2', 'up',],
                ['ip', 'link', 'set', 'swp1', 'master', 'br0',],
                ['ip', 'link', 'set', 'swp2', 'master', 'br0',],]

        self.log.info("installing a simple bridge")

        for cmd in cmds:
            subprocess.check_call(cmd)

        self.log.info("verifying bridge members")

        ifMap = {'swp1' : None,
                 'swp2' : None,}
        self.assertEqual(ifMap, self.topo.getLinkPorts('br0'))

if __name__ == "__main__":
    unittest.main()
