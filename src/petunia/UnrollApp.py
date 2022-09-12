"""UnrollApp.py

Unroll a set of iptables rules into a pseudo-rule set.
"""

import sys
import logging

CHAIN_DFL = "FORWARD"

from petunia.Iptables import (
    FilterTable
)
from petunia.Unroller import Unroller

USAGE = """\
iptables-unroll [OPTIONS] SRC DST [CHAIN]

Where OPTIONS is

  --multi-chain          Allow multiple chain specifiers
                         (separated by commas)
  --multi-interface      Allow multiple interface specifiers
                         (separated by commas)
  --override-interface   Allow interface overrides in chain targets
                         (default is to raise an error)
  --extended             Support IPTABLES target extensions
"""

def main():

    logging.basicConfig()
    logger = logging.getLogger("iptables-unroll")
    logger.setLevel(logging.DEBUG)

    args = list(sys.argv[1:])
    multiChain = False
    multiInterface = False
    overrideInterface = False
    extended = False

    while args:

        if args[0] == '--multi-chain':
            args.pop(0)
            multiChain = True
            continue

        if args[0] == '--multi-interface':
            args.pop(0)
            multiInterface = True
            continue

        if args[0] == '--override-interface':
            args.pop(0)
            overrideInterface = True
            continue

        if args[0] == '--extended':
            args.pop(0)
            extended = True
            continue

        if args[0] in ('-h', '--help', '-?',):
            logger.info("Usage: %s" % USAGE)
            sys.exit(1)

        if args[0][0] == '-':
            logger.error("invalid switch %s", args[0])
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
    if args:
        logger.error("extra arguments")
        sys.exit(1)

    logger.info("reading iptables rules from %s", src)
    with open(src, 'rt') as fd:
        buf = fd.read()
    table = FilterTable.fromString(buf,
                                   multiChain=multiChain,
                                   multiInterface=multiInterface)

    if chain not in table.chains:
        logger.error("missing chain %s in table" % chain)
        sys.exit(1)

    logger.info("unrolling %d rules in chain %s",
                len(table.chains[chain]), chain)
    unroller = Unroller(table, chain,
                        overrideInterface=overrideInterface,
                        extended=extended,
                        log=logger.getChild("unroll"))
    table_ = unroller.unroll()

    logger.info("emitting %d rules to %s",
                len(table.chains[chain]), dst)
    with open(dst, 'wt') as fd:
        fd.write(table_.toSave())

    sys.exit(0)

if __name__ == "__main__":
    main()
