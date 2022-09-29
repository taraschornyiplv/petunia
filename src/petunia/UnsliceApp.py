"""UnsliceApp.py

Implement the iptables-unslice script.
"""

import sys, os
import logging
import socket

CHAIN_DFL = "FORWARD"

from petunia.Iptables import (
    FilterTable
)

from petunia.Unslicer import (
    Unslicer,
    IptablesChainSuffix,
    simpleMerge,
    simpleSuffixMerge,
    simplePrefixMerge,
)

from petunia.Topology import Topology

USAGE = """\
iptables-unslice [OPTIONS] SRC DST [CHAIN] [INTERFACE ...]

Where OPTIONS is

  -4|-6          Select IPv4 vs IPv6

  --merge [STRATEGY]
  --no-merge
                 Merge strategy for shared-block loading

  Merge STRATEGY is one of

    exact        Merge identical chains
    suffix       Merge chains that have common suffixes
                 (implies exact)
    prefix       Merge chains that have common prefixes
                 (implies exact)
    all|default  Default strategy (exact+suffix+prefix)

CHAIN defaults to FORWARD
The INTERFACE list corresponds to all interfaces
Default STRATEGY with '--merge' is 'all'
"""

def applyMerge(table, *merge_fns):
    logger = table.log

    sz = 0
    for ifName, chain in table.chains.items():
        sz += len(chain.rules)
    logger.info("source table has %d rules", sz)

    for fn in merge_fns:
        logger.info("trying merge strategy %s", fn.__name__)
        table_ = fn(table)

        sz = 0

        for ifName, chain in table_.chains.items():
            if not isinstance(chain, IptablesChainSuffix):
                sz += len(chain.rules)

        # add in one rule for each TOC entry
        sz += len(table_.chains)

        logger.info("merged table has %d rules", sz)
        table = table_

    return table

simplePrefixMerge1 = lambda t: simplePrefixMerge(t, prefixOnly=True)
simplePrefixMerge2 = lambda t: simplePrefixMerge(t, prefixOnly=False)

merge_fns = {
    'exact'  : (simpleMerge,),
    'suffix' : (simpleMerge,
                simpleSuffixMerge,),
    'prefix' : (simpleMerge,
                simplePrefixMerge,),
    'most'   : (simpleMerge,
                simpleSuffixMerge,
                simplePrefixMerge1,),
    'all'    : (simpleMerge,
                simpleSuffixMerge,
                simplePrefixMerge2,),
}
merge_fns['default'] = merge_fns['all']

def main():

    logging.basicConfig()
    logger = logging.getLogger("iptables-unslice")
    logger.setLevel(logging.DEBUG)

    version = socket.AF_INET
    merge = False
    strategy = None

    args = list(sys.argv[1:])
    while len(args):

        if args[0] == '-4':
            args.pop(0)
            version = socket.AF_INET
            continue

        if args[0] == '-6':
            args.pop(0)
            version = socket.AF_INET6
            continue

        if args[0] == '--merge':
            args.pop(0)
            merge = True
            # next argument should be a merge strategy
            # but see if it's a flag or a SRC argument
            if args and args[0][0] == '-':
                strategy = 'default'
                continue
            if args and os.path.exists(args[0]):
                strategy = 'default'
                continue
            if args and args[0] in merge_fns:
                strategy = args.pop(0)
                continue
            if args:
                strategy = 'default'
                logger.warning("argument %s is not a merge strategy, not a SRC",
                               args[0])
            continue
        if args[0] == '--no-merge':
            args.pop(0)
            shared = False
            continue

        if args[0] in ('-h', '--help', '-?',):
            sys.stderr.write(USAGE)
            sys.exit(0)

        if args[0][0] == '-':
            logger.error("invalid option %s", args[0])
            sys.exit(1)

        break

    if len(args) < 2:
        logger.error("missing arguments")
        logger.error("Usage: %s" % USAGE)
        sys.exit(1)

    src = args.pop(0)
    dst = args.pop(0)

    if args:
        chain = args.pop(0)
    else:
        chain = CHAIN_DFL

    topo = Topology(log=logger.getChild("links"))
    ##allInterfaces = set(topo.getPorts())
    allInterfaces = None
    if args:
        try:
            onlyInterfaces = topo.matchLinkPatterns(args)
        except ValueError as ex:
            logger.error(str(ex))
            sys.exit(1)
    else:
        onlyInterfaces = None

    logger.info("reading iptables rules from %s", src)
    with open(src, 'rt') as fd:
        buf = fd.read()
    table = FilterTable.fromString(buf,
                                   log=logger.getChild("slice"))

    if chain not in table.chains:
        logger.error("missing chain %s in table" % chain)
        sys.exit(1)

    logger.info("unslicing %d rules in chain %s",
                len(table.chains[chain]), chain)

    unslicer = Unslicer(table, chain,
                        onlyInterfaces=onlyInterfaces,
                        allInterfaces=allInterfaces,
                        version=version,
                        log=logger.getChild("unslice"))

    if not merge:
        table_ = unslicer.unslice()
    else:
        fns = merge_fns.get(strategy, None)
        if not fns:
            logger.error("invalid merge strategy %s", strategy)
            sys.exit(1)
        merge_fn = lambda t: applyMerge(t, *fns)
        table_ = unslicer.unslice(merge_fn=merge_fn)

    logger.info("emitting %d rules to %s",
                len(table_.chains[chain]), dst)
    with open(dst, 'wt') as fd:
        fd.write(table_.toSave())

    sys.exit(0)

if __name__ == "__main__":
    main()
