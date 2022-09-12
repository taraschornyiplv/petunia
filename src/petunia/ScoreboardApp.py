"""ScoreboardApp.py

Implement IPTABLES scoreboarding by interface.
"""

import sys
import logging

CHAIN_DFL = "FORWARD"

from petunia.Iptables import (
    FilterTable,
)
from petunia.Scoreboard import Scoreboard
from petunia.Topology import (
    Topology,
    sortIfNames,
)

USAGE = """\
iptables-scoreboard [OPTIONS] SRC DST [CHAIN] [INTERFACE ...]

Where OPTIONS are

  -v|--verbose     Verbose logging
  -q|--quiet       Quiet logging

  --strict         Do not generate rules for unspecified (wildcard) interfaces

  -h|--help|-?     Print this help

CHAIN defaults to FORWARD

The INTERFACE list corresponds to all (front-panel) interfaces

Without --strict, we can generate rules that affect un-specified interfaces
With --strict, we specify verbose rules to not affect un-specified interfaces,
at the cost of rule length.

"""

def main():

    logging.basicConfig()
    logger = logging.getLogger("iptables-scoreboard")
    logger.setLevel(logging.INFO)

    strict = False

    args = list(sys.argv[1:])
    while args:

        if args[0] in ('-v', '--verbose',):
            args.pop(0)
            logger.setLevel(logging.DEBUG)
            continue
        if args[0] in ('-q', '--quiet',):
            args.pop(0)
            logger.setLevel(logging.ERROR)
            continue

        if args[0] == '--strict':
            args.pop(0)
            strict = True
            continue

        if args[0] in ('-h', '--help', '-?',):
            sys.stderr.write("Usage: %s" % USAGE)
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

    logger.info("scoreboarding %d rules in chain %s",
                len(table.chains[chain]), chain)

    if onlyInterfaces is not None and not strict:
        extra = set()
        extra.update(allInterfaces)
        if onlyInterfaces is not None:
            extra.difference_update(onlyInterfaces)
        if extra:
            logger.warning("extra (unnamed) interfaces found:")
            for ifName in extra:
                logger.warning(ifName)

    if strict:
        scoreboard = Scoreboard(table, chain,
                                onlyInterfaces=onlyInterfaces,
                                allInterfaces=allInterfaces,
                                strict=True,
                                log=logger.getChild("scoreboard"))
    else:
        scoreboard = Scoreboard(table, chain,
                                onlyInterfaces=onlyInterfaces,
                                allInterfaces=onlyInterfaces,
                                strict=False,
                                log=logger.getChild("scoreboard"))
    table_ = scoreboard.scoreboard()

    logger.info("emitting %d rules to %s",
                len(table_.chains[chain]), dst)
    with open(dst, 'wt') as fd:
        fd.write(table_.toSave())

    sys.exit(0)

if __name__ == "__main__":
    main()
