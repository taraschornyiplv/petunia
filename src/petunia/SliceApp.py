"""SliceApp.py

Implement the iptables-slice script.
"""

import sys
import logging

CHAIN_DFL = "FORWARD"

from petunia.Iptables import (
    FilterTable,
)
from petunia.Slicer import Slicer
from petunia.Topology import Topology

USAGE = """\
iptables-slice SRC DST [CHAIN] [INTERFACE ...]

CHAIN defaults to FORWARD
The INTERFACE list corresponds to all interfaces
"""

def main():

    logging.basicConfig()
    logger = logging.getLogger("iptables-slice")
    logger.setLevel(logging.DEBUG)

    args = list(sys.argv[1:])
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
    allInterfaces = set(topo.getPorts())
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

    logger.info("slicing %d rules in chain %s",
                len(table.chains[chain]), chain)

    if onlyInterfaces is not None:
        slicer = Slicer(table, chain,
                        onlyInterfaces=onlyInterfaces,
                        allInterfaces=allInterfaces,
                        strict=False,
                        log=logger.getChild("slice"))
    else:
        slicer = Slicer(table, chain,
                        onlyInterfaces=onlyInterfaces,
                        allInterfaces=allInterfaces,
                        strict=True,
                        log=logger.getChild("slice"))
    table_ = slicer.slice()

    logger.info("emitting %d rules to %s",
                len(table_.chains[chain]), dst)
    with open(dst, 'wt') as fd:
        fd.write(table_.toSave())

    sys.exit(0)

if __name__ == "__main__":
    main()
