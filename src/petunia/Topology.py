"""Topology.py

Utilities to probe/manage link topology.
Helps to derive port names and vlan tagging state.
Uses pyroute2/netlink.

Debug environment:

TEST_DUMMY=1

  Treat dummy interfaces as front-panel interfaces

TEST_LINKS_JSON
TEST_VLANS_JSON
TEST_SVIS_JSON

  Pre-populate the link, vlan, svi dicts with JSON data

TEST_IFNAMES

  Pre-populate the list of front-panel physical interfaces
  (space-separated list)

TEST_IFNAME_PREFIX

  Pre-populate the list of front-panel physical interfaces
  (prefix string)

"""

import sys, os
import functools
import json
import logging

IPR = nlmsg_base = None
def IPRoute():
    """Maintain an IPRoute singleton.

    Also this is helpful for unit testing on foreign systems.
    """

    global IPR
    global nlmsg_base

    if IPR is None:
        import pyroute2, pyroute2.netlink
        IPR = pyroute2.IPRoute()
        nlmsg_base = pyroute2.netlink.nlmsg_base

    return IPR

def tokIfName(ifName):

    while ifName:

        if ifName[0] >= '0' and ifName[0] <= '9':
            n = 0
            while ifName and ifName[0] >= '0' and ifName[0] <= '9':
                n = n * 10 + ord(ifName[0]) - ord('0')
                ifName = ifName[1:]
            yield (n, "")
            continue

        s = ""
        while ifName and (ifName[0] < '0' or ifName[0] > '9'):
            s += ifName[0]
            ifName = ifName[1:]
        yield (-1, s)

keyIfName = lambda i: list(tokIfName(i))

def sortIfNames(ifNames, reverse=False):
    return sorted(ifNames, key=keyIfName, reverse=reverse)

def matchLink(ifName, pattern):
    """Expand a candidate set of interface names against the actual interfaces.

    Uses the pseudo-pattern matching syntax for IPTABLES.

    NOTE that this will fail for patterns based on non-front-panel interfaces,
    such as 'br+' or 'vlan+'.
    """

    if pattern.startswith('!') and pattern.endswith('+'):
        pattern_ = pattern[1:-1]
        if not ifName.startswith(pattern_):
            return ifName
        return None

    if pattern.startswith('!'):
        pattern_ = pattern[1:]
        if ifName != pattern_:
            return ifName
        return None

    if pattern.endswith('+'):
        pattern_ = pattern[:-1]
        if ifName.startswith(pattern_):
            return ifName
        return None

    if pattern == ifName:
        return ifName

    return None

class Topology(object):

    def __init__(self, log=None):
        self.log = log or logging.getLogger(self.__class__.__name__)
        self.update()

    def maybeGetLinks(self):
        if self.links is None:
            self.log.debug("getting link info from kernel")
            self.links = IPRoute().get_links()
            self.parseLinks()

    def maybeGetVlans(self):
        if self.vlans is None:
            self.log.debug("getting vlan info from kernel")
            self.vlans = IPRoute().get_vlans()

    def update(self):
        self.links = self.vlans = None
        self.linkMap = self.vlanMap = self.vlanSvis = None
        self.vlanPorts = None

        if 'TEST_LINKS_JSON' in os.environ:
            self.linkMap = json.loads(os.environ['TEST_LINKS_JSON'])

        # NOTE that all json dict keys are string-valued
        if 'TEST_VLANS_JSON' in os.environ:
            data = json.loads(os.environ['TEST_VLANS_JSON'])
            self.vlanMap = dict((int(x), y,) for x, y in data.items())
        if 'TEST_SVIS_JSON' in os.environ:
            data = json.loads(os.environ['TEST_SVIS_JSON'])
            self.vlanSvis = dict((int(x), set(y),) for x, y in data.items())

        if self.linkMap is None:
            self.maybeGetLinks()
            self.parseLinkMap()
        if self.vlanMap is None:
            self.maybeGetLinks()
            self.maybeGetVlans()
            self.parseVlans()
        if self.vlanSvis is None:
            self.maybeGetLinks()
            self.parseSvis()

        # build up a mapping of port ifName to tagged vlans
        allVlans = set()
        allVlans.update(self.vlanMap.keys())
        allVlans.update(self.vlanSvis.keys())
        self.vlanPorts = {}
        for vid in allVlans:
            for ifName, tag in self.getVlanPorts(vid, strict=False).items():
                self.vlanPorts.setdefault(ifName, {})
                self.vlanPorts[ifName][vid] = tag

    def parseLinks(self):

        self.linkByIndex = {}
        self.linkByName = {}
        for link in self.links:
            self.linkByIndex[link['index']] = link
            self.linkByName[link.get_attr('IFLA_IFNAME')] = link

    def getLink(self, linkSpec):
        """Retrieve a link by index, name."""
        if isinstance(linkSpec, int):
            return self.linkByIndex[linkSpec]
        if isinstance(linkSpec, str):
            return self.linkByName[linkSpec]
        if isinstance(linkSpec, nlmsg_base):
            return linkSpec
        raise ValueError("invalid link specifier %s" % linkSpec)

    def isPhysicalLink(self, linkSpec):
        """Determine if this link is a front-panel port.

        XXX rothcar -- eventually we will want to filter out e.g. ma1
        """

        if 'TEST_IFNAMES' in os.environ:
            # getLink() may not work in test mode
            ifNames = os.environ['TEST_IFNAMES'].split()
            if isinstance(linkSpec, str):
                return linkSpec in ifNames
            if isinstance(linkSpec, nlmsg_base):
                return linkSpec.get_attr('IFLA_IFNAME') in ifNames
        if 'TEST_IFNAME_PREFIX' in os.environ:
            if isinstance(linkSpec, str):
                return linkSpec.startswith(os.environ['TEST_IFNAME_PREFIX'])
            if isinstance(linkSpec, nlmsg_base):
                return linkSpec.get_attr('IFLA_IFNAME').startswith(os.environ['TEST_IFNAME_PREFIX'])

        linkData = self.getLink(linkSpec)
        ifName = linkData.get_attr('IFLA_IFNAME')
        if ifName in ('lo',): return False

        q = ('IFLA_LINKINFO', 'IFLA_INFO_KIND',)
        kind = linkData.get_nested(*q)
        if kind in ('vlan', 'bond', 'bridge',):
            return False
        if kind == 'dummy':
            if 'TEST_DUMMY' in os.environ:
                return True
            else:
                return False

        # switchdev ports have a physical port name
        try:
            p = os.path.join("/sys/class/net/%s/phys_port_name" % ifName)
            with open(p, 'rt') as fd:
                fd.read()
            return True
        except OSError:
            pass

        # some management ports (e.g. ma1) have a phydev
        try:
            p = os.path.join("/sys/class/net/%s/phydev/phy_id" % ifName)
            with open(p, 'rt') as fd:
                fd.read()
            return True
        except OSError:
            pass

        # most management ports (e.g. eth0) have a registered hardware driver
        try:
            p = os.path.join("/sys/class/net/%s/device/modalias" % ifName)
            with open(p, 'rt') as fd:
                fd.read()
            return True
        except OSError:
            pass

        return False

    def parseVlans(self):

        self.vlanMap = {}
        # tag state for all vlan-aware bridge ports,
        # keyed by vid then by port

        self.bridges = set()
        # set of all bridges

        self.vlByName = {}
        self.vlByIndex = {}
        # lookup vlan port records by name or index

        self.log.debug("found %d vlan links", len(self.vlans))

        vcnt = 0

        for vlanLink in self.vlans:

            ifIndex = vlanLink['index']
            ifName = self.getLink(ifIndex).get_attr('IFLA_IFNAME')

            if ifName in self.vlByName:
                raise ValueError("duplicate vlan port %s" % ifName)
            self.vlByName[ifName] = vlanLink
            self.vlByIndex[ifIndex] = vlanLink

            masterIndex = vlanLink.get_attr('IFLA_MASTER')
            # should also be derivable from link

            if ifIndex == masterIndex:
                self.bridges.add(ifName)
                continue
            # skip the bridge link itself, but record it for later

            vinfo = (vlanLink
                     .get_attr('IFLA_AF_SPEC', nlmsg_base())
                     .get_attrs('IFLA_BRIDGE_VLAN_INFO'))

            ##self.vlanMap.setdefault(ifName, {})

            for vdata in vinfo:
                vid = vdata['vid']

                if vid not in self.vlanMap:
                    self.log.debug("discovered vid %d", vid)
                    vcnt += 1
                self.vlanMap.setdefault(vid, {})

                flags = vdata['flags']

                self.vlanMap.setdefault(vid, {})

                if flags & 0x2:
                    # pvid --> untagged on ingress
                    # do not include VID 1 if untagged
                    if vid == 1: continue
                    flag = False
                else:
                    # no pvid --> tagged on ingress
                    flag = True

                if ifName in self.vlanMap[vid]:
                    raise ValueError("extra vlan port %s for vid %d"
                                     % (ifName, vid,))
                self.vlanMap[vid][ifName] = flag

                ##if vid in self.vlanMap[ifName]:
                ##    raise ValueError("extra vid %d for vlan port %s"
                ##                     % (vid, ifName,))
                ##self.vlanMap[ifName][vid] = flag

        # dump an empty map for vid 1
        ifMap = self.vlanMap.get(1, {})
        if not ifMap:
            self.vlanMap.pop(1, None)

        self.log.debug("found %d bridge(s), %d vlan(s) while probing vlans",
                       len(self.bridges), vcnt)

    def parseSvis(self):
        """Find all SVIs and register them by vid.

        SVIs show up as a link of kind 'vlan',
        not as a vlan-aware bridge port.
        The 'link' pointer points to the *downstream* port (untagged).
        """

        self.vlanSvis = {}

        def _n(link):
            return link.get_attr('IFLA_IFNAME')

        def _kind(link):
            q = ('IFLA_LINKINFO', 'IFLA_INFO_KIND')
            return link.get_nested(*q)

        def _sviVid(link):
            q = ('IFLA_LINKINFO', 'IFLA_INFO_DATA', 'IFLA_VLAN_ID')
            return link.get_nested(*q)

        def _linked(link):
            return self.getLink(link.get_attr('IFLA_LINK'))

        for link in self.links:
            if _kind(link) != 'vlan': continue
            vid = _sviVid(link)
            ifName = _n(_linked(link))

            if vid not in self.vlanSvis:
                self.log.debug("discovered vid %d (via SVI %s)",
                               vid, _n(link))
            self.vlanSvis.setdefault(vid, set())
            if ifName in self.vlanSvis[vid]:
                raise ValueError("extra vlan port %s for vid %d (SVI)"
                                 % (ifName, vid,))
            self.vlanSvis[vid].add(ifName)

    def parseLinkMap(self):
        """Build up a map of links, down to the physical layer.

        Keyed by interface name.
        Physical ports --> leaf value None
        Bonds --> set of bonded physical interfaces
        Bridges --> set of bridged interfaces, bonds, SVIs
        SVIs --> tuple downstream port/bond/bridge with vid
        """

        self.linkMap = {}

        def _n(link):
            return link.get_attr('IFLA_IFNAME')

        # step one, enumerate physical links

        physicalLinkNames = set()
        otherLinks = []
        for link in self.links:
            if self.isPhysicalLink(link):
                physicalLinkNames.add(_n(link))
            else:
                otherLinks.append(link)

        self.log.debug("found %d physical link(s), %d other link(s)",
                       len(physicalLinkNames), len(otherLinks))

        # each physical link gets an entry (untagged)
        for ifName in physicalLinkNames:
            self.linkMap[ifName] = ['port',]

        def _kind(link):
            q = ('IFLA_LINKINFO', 'IFLA_INFO_KIND')
            return link.get_nested(*q)

        def _slaveKind(link):
            q = ('IFLA_LINKINFO', 'IFLA_INFO_SLAVE_KIND')
            return link.get_nested(*q)

        def _isMaster(parent, child):
            parentKind = _kind(parent)
            parentIdx = child.get_attr('IFLA_MASTER')
            childKind = _slaveKind(child)
            return (parentKind == childKind
                    and parentIdx == parent['index'])

        # find bonds
        # in case they are nested, the order in which we find them
        # is not important

        links_, otherLinks = otherLinks, []
        for link in links_:

            if not _kind(link) == 'bond':
                otherLinks.append(link)
                continue

            # find all bond members
            ifName = _n(link)
            bondLinks = [x for x in self.links if _isMaster(link, x)]
            self.log.debug("found %d link(s) for bond %s", len(bondLinks), ifName)
            bondLinkNames = set()
            for bondLink in bondLinks:
                ifName_ = _n(bondLink)
                if ifName_ not in physicalLinkNames:
                    self.log.warning("virtual link %s for bond %s",
                                     ifName_, ifName)
                bondLinkNames.add(ifName_)
            self.linkMap[ifName] = ['bond'] + sortIfNames(bondLinkNames)

        # find SVIs that feed into physical ports or bonds

        def _sviVid(link):
            q = ('IFLA_LINKINFO', 'IFLA_INFO_DATA', 'IFLA_VLAN_ID')
            return link.get_nested(*q)

        def _linked(link):
            return self.getLink(link.get_attr('IFLA_LINK'))

        links_, otherLinks = otherLinks, []
        for link in links_:

            if not _kind(link) == 'vlan':
                otherLinks.append(link)
                continue

            ifName = _n(link)
            vid = _sviVid(link)
            other = _linked(link)
            ifName_ = _n(other)

            self.log.debug("found SVI %s (vid %d) --> %s",
                           ifName, vid, ifName_)
            self.linkMap[ifName] = ['vlan', ifName_, vid,]

        # find bridges

        links_, otherLinks = otherLinks, []
        for link in links_:

            if not _kind(link) == 'bridge':
                otherLinks.append(link)
                continue

            ifName = _n(link)

            # find all downstream ports
            bridgeLinks = [x for x in self.links if _isMaster(link, x)]
            self.log.debug("found %d link(s) in bridge %s",
                           len(bridgeLinks), ifName)
            bridgeLinkNames = set()

            # every one of these bridge links should be known
            for bridgeLink in bridgeLinks:
                ifName_ = _n(bridgeLink)

                # bridge link is one we have seen before
                # (bond or physical port or svi)
                if ifName_ in self.linkMap:
                    bridgeLinkNames.add(ifName_)
                elif _kind(bridgeLink) == 'dummy':
                    # XXX rothcar -- P42003912
                    # 'dummy0' may be part of the bridge
                    self.log.warning("unsupported link %s for bridge %s",
                                     ifName_, ifName)
                    bridgeLinkNames.add(ifName_)
                else:
                    msg = ("invalid link %s for bridge %s"
                           % (ifName_, ifName,))
                    raise ValueError(msg)
            self.linkMap[ifName] = ['bridge'] + sortIfNames(bridgeLinkNames)

        # filter out other links
        links_, otherLinks = otherLinks, []
        for link in links_:
            ifName = _n(link)
            if ifName == 'lo': continue
            otherLinks.append(link)

        # at this point there should be no links left

        # make sure there are no other links left
        links_, otherLinks = otherLinks, []
        for link in links_:
            self.log.warning("invalid/unsupported link %s", _n(link))
            self.linkMap[_n(link)] = ['link',]

    def getPorts(self):
        """Return the list of front-panel ports."""
        return sortIfNames([x[0] for x in self.linkMap.items() if x[1] == ['port',]])

    def getLinkPorts(self, linkName,
                     parentVlan=1, parentTag=None,
                     strict=True,
                     forceVlan=False):
        """Expand out a link specifier to a set of front-panel ports.

        parentTag==None --> no SVI or vlan-aware bridge encountered,
                            assume not tagged
        parentTag==vid --> upstream SVI or vlan-aware bridge
                            where PVID != parentVlan
        parentTag==False --> vlan-aware bridge where PVID==parentVlan,
                             port is not tagged
        """

        if linkName.startswith('vlan') and not forceVlan:
            raise ValueError("vlans not (directly) supported")

        ports = {}
        q = [(linkName, parentVlan, parentTag,)]

        while q:
            linkName_, vid, flag = q.pop(0)
            if linkName_ not in self.linkMap:
                msg = ("invalid link %s while expanding %s"
                       % (linkName_, linkName,))
                if strict:
                    raise ValueError(msg)
                else:
                    self.log.warning(msg)
                    continue

            val = self.linkMap[linkName_]

            # non-front-panel port
            if val == ['link',]:
                msg = ("unsupported link %s while expanding %s"
                       % (linkName_, linkName,))
                if strict:
                    raise ValueError(msg)
                else:
                    self.log.warning(msg)
                    continue

            # simple port --> inherit the tag setting
            if val == ['port',]:
                if flag:
                    ports[linkName_] = vid
                else:
                    ports[linkName_] = flag
                continue

            kind, data = val[0], val[1:]

            # bond --> inherit the vid and tag setting from upstream
            if kind == 'bond':
                q.extend((x, vid, flag,) for x in data)
                continue

            # svi --> flag becomes True, tag is overridden for downstream
            if kind == 'vlan':
                linkName__, vid_ = data
                q.append((linkName__, vid_, True,))
                continue

            # bridge --> possibly override the tag setting if vlan-filtering
            if kind == 'bridge':

                for ifName_ in data:
                    flag_ = self.vlanMap.get(vid, {}).get(ifName_, None)

                    # no vlan port for this vid/ifName
                    if flag_ is None:
                        q.append((ifName_, vid, flag,))
                        continue

                    # no pvid --> tagged on ingress
                    # override flag to True (even for vid 1)
                    if flag_:
                        q.append((ifName_, vid, True,))
                        continue

                    # pvid --> untagged on ingress
                    # BUT do not explicitly untag vid 1
                    if vid == 1 and parentTag is None:
                        q.append((ifName_, vid, None,))
                        continue

                    # pvid --> untagged on ingress
                    # override flag to False
                    q.append((ifName_, vid, False,))

                continue

            raise ValueError("invalid %s link %s (maps to %s) while expanding %s"
                             % (kind, linkName_, data, linkName,))

        return ports

    def getVlanPorts(self, vid, strict=True):
        """Expand out physical ports for a given vlan.

        XXX not clear the various topologies

        - svi upstream from a vlan-aware bridge
          does the bridge port have the ability to turn off tagging
          with a PVID setting? YES
        - bridge upstream from an SVI
          here, tagging is overridden by the SVI
        """

        ports = {}

        # enumerate all bridge ports (vlan-aware or not)

        for ifName, flag in self.vlanMap.get(vid, {}).items():
            ports.update(self.getLinkPorts(ifName,
                                           parentVlan=vid, parentTag=flag,
                                           strict=strict,
                                           forceVlan=True))

        # enumerate all SVIs for this vid
        # any ports downstream from an SVI are tagged
        # as long as they are not already tagged by a vlan-aware
        # bridge

        for ifName in self.vlanSvis.get(vid, set()):
            sviPorts = self.getLinkPorts(ifName,
                                         parentVlan=vid, parentTag=True,
                                         strict=strict,
                                         forceVlan=True)
            for port, tag in sviPorts.items():
                if tag is None:
                    self.log.debug("link %s vlan tag inherited from bridge port %s",
                                   ifName, port)
                    ports.setdefault(port, tag)
                elif tag is False:
                    self.log.debug("link %s pvid %d inherited from bridge port %s",
                                   ifName, vid, port)
                    ports[port] = tag
                elif tag != vid:
                    raise ValueError("invalid vid %s tag %s" % (vid, tag,))
                else:
                    self.log.debug("link %s vlan tag %s overridden by port %s",
                                   ifName, tag, port)
                    ports[port] = tag

        return ports

    def matchLinks(self, pat):
        """Return matching links for an IPTABLES pattern."""

        ifNames = set()

        # match any ports or links
        for ifName, val in self.linkMap.items():

            # match physical ports
            if val is None and matchLink(ifName, pat):
                ifNames.add(ifName)

            # match anything but an SVI
            if val is not None and val[0] != 'vlan' and matchLink(ifName, pat):
                ifNames.add(ifName)

        # match any vlans

        # match any vlan bridge ports
        for vid in self.vlanMap.keys():
            ifName = "vlan%d" % vid
            if matchLink(ifName, pat):
                ifNames.add(ifName)

        # match SVIs by vlan name, not by link name
        for vid in self.vlanSvis.keys():
            ifName = "vlan%d" % vid
            if matchLink(ifName, pat):
                ifNames.add(ifName)

        return sortIfNames(ifNames)

    def matchLinkPatterns(self, patterns, strict=True):
        """Match a list of patterns."""

        ifNames = set()

        for pat in patterns:
            ifNames_ = self.matchLinks(pat)
            if not ifNames_:
                msg = "link specifier %s matched no links" % pat
                if strict:
                    raise ValueError(msg)
                else:
                    self.log.warning(msg)
            for ifName in ifNames_:
                if self.linkMap[ifName][0] not in ('link', 'port',):
                    raise ValueError("invalid interface specifier %s" % arg)
                ifNames.add(ifName)

        return sortIfNames(ifNames)

    def promote(self, ifName):
        """Promote a link to a port."""
        if ifName not in self.linkMap:
            raise ValueError("invalid interface %s" % ifName)
        if self.linkMap[ifName] not in (['link',], ['port',],):
            raise ValueError("cannot promote %s" % ifName)
        if self.linkMap[ifName] == ['link',]:
            self.log.info("promoting link %s to port", ifName)
            self.linkMap[ifName] = ['port',]

    def narrow(self, interfaces, demote=True):
        """Narrow the port list to the given set of interfaces.

        All of these interfaces are considered "front-panel ports",
        and all other links are considered invalid/unsupported.
        """

        # promote any links to ports
        [self.promote(x) for x in interfaces]

        # demote any ports back to links
        if demote:
            interfaces_ = set(interfaces)
            for ifName in self.linkMap.keys():
                val = self.linkMap[ifName]
                if ifName not in interfaces_ and val == ['port',]:
                    self.log.info("demoting port %s to link", ifName)
                    self.linkMap[ifName] = ['link',]

if __name__ == "__main__":
    i1 = sys.argv[1]
    i2 = sys.argv[2]
    print("compare %s %s --> %s\n"
          % (i1, i2, sortIfNames([i1, i2])))
