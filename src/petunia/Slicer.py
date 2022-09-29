"""Slicer.py

Implement the iptables-slice algorithm.
"""

import logging

from petunia.Topology import (
    Topology,
    sortIfNames,
)

class SlicerBase(object):
    """Common code for slicers and related algorithms."""

    def __init__(self, table, chain='INPUT',
                 onlyInterfaces=None, allInterfaces=None,
                 strict=True, strictVlan=False,
                 log=None):

        self.log = log or logging.getLogger(self.__class__.__name__)

        self.table = table
        self.chain = chain
        self.onlyInterfaces = onlyInterfaces
        self.allInterfaces = allInterfaces

        self.strict = strict
        # strict handling for front-panel ports

        self.strictVlan = strictVlan
        # strict handling for vlan members

        self.topo = Topology(log=self.log.getChild("links"))

        if self.allInterfaces is not None:
            self.topo.narrow(self.allInterfaces)
        if self.onlyInterfaces is not None:
            self.topo.narrow(self.onlyInterfaces, demote=False)

        self.interfacesUntagged = set()
        self.interfacesTagged = set()
        self.vlansTagged = set()

    def visitInterface(self, pat, allInterfaces):
        """Update a running set of interfaces."""

        # no interface spec --> include all interfaces untagged
        # (we will still need to iteratively discover tagged interfaces)

        if pat is None:
            self.interfacesUntagged.update(allInterfaces)
            return

        ifNames = self.topo.matchLinks(pat)
        if not ifNames:
            msg = ("invalid interface specifier %s" % pat)
            if not self.strict:
                self.log.warning(msg)
            elif pat.startswith('vlan') and not self.strictVlan:
                self.log.warning(msg)
            else:
                raise ValueError(msg)

        for ifName in ifNames:

            # physical port
            if ifName.startswith('vlan'):
                vid = int(ifName[4:], 10)
                portMap = self.topo.getVlanPorts(vid, strict=self.strict)
            else:
                portMap =  self.topo.getLinkPorts(ifName, strict=self.strict)

            for ifName_, val_ in portMap.items():
                if ifName_ in allInterfaces:
                    if val_:
                        self.interfacesTagged.add(ifName_)
                    else:
                        self.interfacesUntagged.add(ifName_)
                else:
                    if ifName == ifName_:
                        msg = ("invalid interface %s" % ifName)
                    else:
                        msg = ("invalid interface %s (via %s)"
                               % (ifName_, ifName,))
                    self.log.warning(msg)

    def visitInterfaces(self):
        """Gather rule interface data.

        Collect tagged vs untagged interface scope
        Annotate each rule with its interface set(s).
        """

        allInterfaces = self.allInterfaces
        if allInterfaces is None:
            allInterfaces = self.topo.getPorts()
        allInterfaces = set(allInterfaces)

        rootChain = self.table.chains[self.chain]

        # build up a global set of target interfaces based on the chain details

        self.interfacesUntagged = set()
        self.interfacesTagged = set()

        if self.onlyInterfaces is not None:
            self.interfacesUntagged.update(self.onlyInterfaces)
            a = self.onlyInterfaces
        else:
            a = allInterfaces
        for rule in rootChain.rules:
            self.visitInterface(rule.in_interface,
                                allInterfaces=a)

        # go back and annotate each rule with its own target interfaces

        for rule in rootChain.rules:

            if rule.in_interface is None:

                rule.in_interfaces = self.interfacesUntagged
                # applies to all untagged (front-panel) ports

                rule.in_interfaces_tagged = {}
                rule.in_vlans_tagged = {}

                for ifName in self.interfacesTagged:
                    for vid, val in self.topo.vlanPorts[ifName].items():
                        if val:
                            rule.in_interfaces_tagged.setdefault(ifName, set())
                            rule.in_interfaces_tagged[ifName].add(vid)
                            rule.in_vlans_tagged.setdefault(vid, set())
                            rule.in_vlans_tagged[vid].add(ifName)
                # additionally applies to all vlan-tagged ports

                continue

            rule.in_interfaces = set()
            rule.in_interfaces_tagged = {}
            rule.in_vlans_tagged = {}

            ifNames = self.topo.matchLinks(rule.in_interface)
            for ifName in ifNames:
                if ifName.startswith('vlan'):
                    vid = int(ifName[4:], 10)
                    portMap = self.topo.getVlanPorts(vid, strict=False)
                else:
                    portMap =  self.topo.getLinkPorts(ifName, strict=False)

                for ifName_, val_ in portMap.items():

                    if not val_ and ifName_ in self.interfacesUntagged:
                        rule.in_interfaces.add(ifName_)
                        continue

                    if val_ and ifName_ in self.interfacesTagged:
                        rule.in_interfaces_tagged.setdefault(ifName_, set())
                        rule.in_interfaces_tagged[ifName_].add(val_)
                        rule.in_vlans_tagged.setdefault(val_, set())
                        rule.in_vlans_tagged[val_].add(ifName_)

        # compute the set of all tagged vlans
        # (for possible vid collapsing)
        self.vlansTagged = set()
        for ifName, vidMap in self.topo.vlanPorts.items():
            for vid, tag in vidMap.items():
                if tag:
                    self.vlansTagged.add(vid)

class Slicer(SlicerBase):

    def slice(self):
        """Slice out the rules to per-interface chains.

        Compute the subset of interfaces to operate on from 'allInterfaces'.
        Assume here that the chain is already unrolled.
        If interfaces are specified in 'onlyInterfaces' then this restricts
        the interfaces that we support to just those.

        Each interface on the INPUT chain (for instance) is broken down to
        INPUT_eth0, INPUT_eth1, etc.
        """

        self.visitInterfaces()

        def _hasInterfaces(rule):
            if rule.in_interfaces: return True
            if rule.in_interfaces_tagged: return True
            return False

        rootChain = self.table.chains[self.chain]
        rules = [x for x in rootChain.rules if _hasInterfaces(x)]

        if not self.interfacesUntagged and not self.interfacesTagged:
            if len(rootChain):
                raise ValueError("no interfaces found for slicing")
        if not rules:
            self.log.warning("no rules found for slicing")

        # OK now on to the slicing

        table_ = self.table.clone()
        table_.chains[self.chain] = self.table.chain_klass([], rootChain.policy)

        # create a top-level jump chain for each interface (tagged or untagged)
        a = set()
        a.update(self.interfacesUntagged)
        a.update(self.interfacesTagged)
        for intf in sortIfNames(a):
            tgt = "%s_%s" % (self.chain, intf,)
            rule = self.table.rule_klass(['-i', intf,
                                          '-m', 'comment', '--comment', "TOC entry",],
                                         target=tgt)
            table_.chains[self.chain].rules.append(rule)
            table_.chains[tgt] = self.table.chain_klass([], 'RETURN')

        # now slice the rules per interface
        for rule in rules:
            a = {}

            # collate each interface with tagged/untagged
            for ifName in rule.in_interfaces:
                a.setdefault(ifName, [False, set(),])
                a[ifName][0] = True

            for ifName, vids in rule.in_interfaces_tagged.items():
                a.setdefault(ifName, [False, set(),])
                a[ifName][1].update(vids)

            for ifName in sortIfNames(a.keys()):
                u, t = a[ifName]
                if u:
                    rule_ = rule.clone()
                    rule_.in_interface = None
                    chain_ = "%s_%s" % (self.chain, ifName,)
                    table_.chains[chain_].rules.append(rule_)
                if t:
                    for vid in t:
                        rule_ = rule.clone()
                        rule_.in_interface = None
                        rule_.args.extend(['-m', 'vlan',
                                           '--vlan-tag', str(vid),])
                        chain_ = "%s_%s" % (self.chain, ifName,)
                        table_.chains[chain_].rules.append(rule_)

        return table_

class SliceTable(object):
    """Representation of the output of the Slicer.

    This is a work-alike for a FilterTable, except that the top level construct is
    a rule per interface.
    Each rule has an unspecified in_interface.
    """

    def __init__(self, chains={}, policy='ACCEPT', topo=None, log=None):
        self.chains = chains
        self.policy = policy
        self.log = log or logging.getLogger(self.__class__.__name__)
        self.topo = topo or Topology(log=self.log.getChild("links"))

    @classmethod
    def fromSlice(cls, table, chain='FORWARD',
                  onlyInterfaces=None, allInterfaces=None,
                  log=None):
        """Initialize a sliced table from the output of iptables-slice.

        Verify that the table is well-formed.
        """

        logger = log or logging.getLogger(cls.__name__)
        topo = Topology(log=logger.getChild("links"))

        if allInterfaces is None:
            allIfNames = set(topo.getPorts())
        else:
            allIfNames = set(allInterfaces)
        # all physical interfaces

        interfaceChains = {}
        # all interfaces referenced in the filter table

        if onlyInterfaces is not None:
            if not onlyInterfaces:
                raise ValueError("empty onlyInterfaces")
            for ifName in onlyInterfaces:
                if ifName not in allIfNames:
                    raise ValueError("invalid interface %s" % ifName)

        # parse the top-level TOC chain to get the interface references

        rootChain = table.chains[chain]
        rootPolicy = rootChain.policy

        for rule in rootChain.rules:

            if rule.args:
                raise ValueError("invalid rule slice TOC (args %s unexpected)"
                                 % rule.args)

            if not rule.in_interface:
                raise ValueError("invalid rule target %s %s in slice TOC, missing in_interface"
                                 % (rule.target, rule.target_args,))

            label = chain + '_' + rule.in_interface
            if rule.target != label:
                raise ValueError("invalid rule target %s in slice TOC, expected %s"
                                 % (rule.target, label,))
            if len(rule.target_args):
                raise ValueError("invalid rule target %s %s in slice TOC"
                                 % (rule.target, rule.target_args,))

            interfaceChains[rule.in_interface] = table.chains[label]

        # sanity check, look for orphan chains

        pfx = chain + '_'
        for tgt in table.chains.keys():
            if tgt.startswith(pfx):
                ifName = tgt[len(pfx):]
                if ifName not in interfaceChains:
                    raise ValueError("orphan chain %s (missing in TOC)" % tgt)

        # if we are using a restricted set of interfaces,
        # drop the unused ones

        # if we are using all interfaces, add the missing ones

        if onlyInterfaces is not None:
            extra = set(interfaceChains.keys())
            extra.difference_update(onlyInterfaces)
            for ifName in extra:
                logger.warning("ignoring rules for interface %s", ifName)
                interfaceChains.pop(ifName)
            missing = set(onlyInterfaces)
            missing.difference_update(interfaceChains.keys())
            for ifName in missing:
                logger.warning("adding empty ruleset for interface %s", ifName)
                interfaceChains[ifName] = table.chain_klass([], 'RETURN')
        else:
            extra = set(interfaceChains)
            extra.difference_update(allIfNames)
            if extra:
                raise ValueError("invalid interface(s) %s" % extra)
            missing = set(allIfNames)
            missing.difference_update(interfaceChains.keys())
            for ifName in missing:
                logger.warning("adding empty ruleset for interface %s", ifName)
                interfaceChains[ifName] = table.chain_klass([], 'RETURN')

        # scan the sub-chains to make sure they are well-formed
        for n, c in interfaceChains.items():
            for r in c.rules:
                if r.in_interface is not None:
                    raise ValueError("invalid rule (interface %s not expected)" % n)

        allIfNames_ = allIfNames if onlyInterfaces is None else onlyInterfaces

        logger.info("targeted interfaces are %s", ", ".join(allIfNames_))

        return cls(interfaceChains, rootPolicy,
                   topo=topo,
                   log=log)

    def merge(self, chain, *chainNames):
        """Replace all interfaces in chainNames with a single chain."""

        for chainName in chainNames:
            if chainName not in self.chains:
                raise ValueError("invalid chain for merge: %s" % chainName)
            self.chains.pop(chainName)

        tag = ','.join(sortIfNames(chainNames))
        if tag in self.chains:
            raise ValueError("invalid chain group for merge: %s" % tag)

        self.chains[tag] = chain

    def toSave(self, chain):
        """Generate an iptables-save output."""

        ifNames = sortIfNames(self.chains.keys())

        buf = ""
        buf += "*filter\n"

        buf += ":%s %s [0:0]\n" % (chain, self.policy,)

        for ifName in ifNames:
            tgt = chain + '_' + ifName
            buf += ":%s - [0:0]\n" % tgt

        for ifName in ifNames:
            tgt = chain + '_' + ifName
            buf += ("-A %s -i %s -j %s\n"
                    % (chain, ifName, tgt,))

        for ifName in ifNames:
            tgt = chain + '_' + ifName
            chain_ = self.chains[ifName]
            for rule in chain_.rules:
                buf += rule.toSave(tgt) + "\n"

        buf += "COMMIT\n"
        return buf
