"""LoadApp.py

Implement the tc-flower-load script.
"""

import sys
import logging
import socket

CHAIN_DFL = "FORWARD"

from petunia.Iptables import (
    FilterTable
)

from petunia.Topology import Topology

USAGE = """tc-flower-load [OPTIONS] SRC [CHAIN] [INTERFACE ...]

Where OPTIONS is one of

  -4|-6          Select IPv4 or IPv6
  -q|--quiet     Suppress warning messages
  -v|--verbose   Show debug messages (including command traces)
  --non-atomic   Quick-load rule sets with non-atomic updates
  --drop         Quick-load rule sets with a default-drop policy
                 (atomic for load but not for update)
  --offload
  --no-offload
                 Force/disallow hardware offload

  --shared-block
  --no-shared-block
                 Choose a filter load strategy
                 (one chain per interface vs one shared block
                 for all interfaces)

  --scoreboard
                 Output is from 'iptables-scoreboard'
                 instead of 'iptables-unslice'

  --log-ignore   Ignore LOG targets

  --addrtype-pass
  --addrtype-fail
                 Treat addrtype matches as pass (always match)
                 or fail (never match)

  --multi-match  Support comma-separated matches for port, IP address

  --port-unroll N
                 Unroll statements of the form --sport M:M+N
                 into individual port matches

  --hack-vlan-arp
                 Always allow vlan-encapsulated ARPs
                 (needed if the existing rules drop all TCP/UDP,
                 which TC inadvertently interprets as "all IP, including ARP")

  --drop-mode trap
  --drop-mode trap,RATE
  --drop-mode trap,RATE,BURST
                 Configure handling for dropped packets
                 - 'trap' --> trap dropped packets to the CPU for logging
                 - 'trap,RATE,BURST' --> trap/log packets below a given RATE,
                                         allow for bursts, drop the rest
                 Specifying 'trap' without RATE,BURST is NOT RECOMMENDED!

  --profile      Enable call profiling

  --no-batch     Do not batch TC commands

  --reject-drop  Drop packets with a REJECT target
                 (otherwise report an error)

  --continue-suppress
                 Suppress no-op rules (TC 'continue' actions)
                 Enable this if your switchdev implementation does not
                 offload the 'continue' action.

  --prestera-chain-mode
                Create tc chain 0 for tcp/udp rules and chain 1 for icmp rules with type and code.
                and use it to program the tc rules. The chains are dynamically created based on the keys used.
                Scale is dependent on the input rules. Use this mode on Marvel Prestera chipset only!!

  -h|--help|-?   Print this help

  SRC should be the output of 'iptables-slice' (for --no-shared-block)
  or 'iptables-unslice' (for --shared-block)

"""

from petunia.TcFlowerLoader import Loader

def main():

    logging.basicConfig()
    logger = logging.getLogger("tc-flower-load")
    logger.setLevel(logging.INFO)

    args = list(sys.argv[1:])
    version = socket.AF_INET

    atomic = True
    drop = False
    continue_ = False
    offload = None
    profile = False

    shared = False
    scoreboard = False

    log_ignore = False

    addrtype = None

    match_multi = False

    batch = True

    port_unroll = None
    # default, do not do port unrolling

    drop_mode = None
    hack_vlan_arp = False
    # True --> always allow vlan-encapsulated IPv4 ARPs
    # otherwise a '-s 0.0.0.0/0 -j DROP' will also drop ARP

    reject_drop = False

    continue_suppress = False

    prestera_chain_mode = False

    while args:

        if args[0] == '-4':
            args.pop(0)
            version = socket.AF_INET
            continue
        if args[0] == '-6':
            args.pop(0)
            version = socket.AF_INET6
            continue

        if args[0] in ('-v', '--verbose',):
            args.pop(0)
            logger.setLevel(logging.DEBUG)
            continue
        if args[0] in ('-q', '--quiet',):
            args.pop(0)
            logger.setLevel(logging.ERROR)
            continue

        if args[0] == '--non-atomic':
            args.pop(0)
            atomic = False
            continue

        if args[0] == '--drop':
            args.pop(0)
            drop = True
            continue

        if args[0] == '--continue':
            args.pop(0)
            continue_ = True
            continue

        if args[0] == '--offload':
            args.pop(0)
            offload = True
            continue
        if args[0] == '--no-offload':
            args.pop(0)
            offload = False
            continue

        if args[0] == '--profile':
            args.pop(0)
            profile = True
            continue

        if args[0] == '--shared-block':
            args.pop(0)
            shared = True
            continue
        if args[0] == '--no-shared-block':
            args.pop(0)
            shared = False
            continue

        if args[0] == '--scoreboard':
            args.pop(0)
            scoreboard = True
            continue

        if args[0] == '--log-ignore':
            args.pop(0)
            log_ignore = True
            continue

        if args[0] == '--addrtype-pass':
            args.pop(0)
            addrtype = True
            continue
        if args[0] == '--addrtype-fail':
            args.pop(0)
            addrtype = False
            continue
        if args[0] == '--multi-match':
            args.pop(0)
            match_multi = True
            continue

        if args[0] == '--no-batch':
            args.pop(0)
            batch = False
            continue

        if args[0] == '--port-unroll':
            args.pop(0)
            port_unroll = int(args.pop(0))
            continue

        if args[0] == '--drop-mode':
            args.pop(0)
            drop_mode = args.pop(0)
            continue

        if args[0] == '--hack-vlan-arp':
            args.pop(0)
            hack_vlan_arp = True
            continue

        if args[0] == '--reject-drop':
            args.pop(0)
            reject_drop = True
            continue

        if args[0] == '--continue-suppress':
            args.pop(0)
            continue_suppress = True
            continue

        if args[0] == '--prestera-chain-mode':
            args.pop(0)
            prestera_chain_mode = True
            continue

        if args[0] in ('-h', '--help', '-?',):
            sys.stderr.write("Usage: %s" % USAGE)
            sys.exit(0)

        if args[0][0] == '-':
            logger.error("invalid option %s", args[0])
            sys.exit(1)

        break

    if len(args) < 1:
        logger.error("missing arguments")
        sys.stderr.write("Usage: %s" % USAGE)
        sys.exit(1)

    src = args.pop(0)

    if args:
        chain = args.pop(0)
    else:
        chain = CHAIN_DFL

    if drop and not atomic:
        logger.error("--drop implies --non-atomic")
        sys.exit(1)
    if prestera_chain_mode:
        # in this mode we cannot support atomic due to the following reasons
        # * to match packets in another chain, there should be a rule in chain 0 that
        #   match the packet and does action goto chain 1(2). W/o a rule with goto action in chain 0,
        #   the packet will not match the rules in another chains. This is expected by
        #   design and Linux kernel behavior.
        # * It is not possible to have one chain with different ip_proto values. In order to have
        #   a template with tcp/udp/icmp protocols there is a need to have 3 separate chains, each with
        #   different protocol and its specific attributes.
        #    - test confirms that a chain can match both tcp/udp rules and in the same chain match icmp iproto
        #      but to match the icmp type and code we need a seperate chain

        if atomic and not drop:
            logger.error(" --tc-chain does not work in atomic mode please use --non-atomic or --drop option")
            sys.exit(1)



    if drop_mode is not None:
        mode_ = drop_mode.split(',')

        if mode_[0] != 'trap':
            logger.error("invalid --drop-mode %s", drop_mode)
            sys.exit(1)
        trap = True

        if len(mode_) == 1:
            rate = burst = None
        elif len(mode_) == 3:
            rate = mode_[1]
            burst = mode_[2]
        else:
            logger.error("invalid --drop-mode %s", drop_mode)
            sys.exit(1)

        drop_mode = (rate, burst, trap,)

    topo = Topology(log=logger.getChild("links"))
    if args:
        try:
            interfaces = topo.matchLinkPatterns(args)
        except ValueError as ex:
            logger.error(str(ex))
            sys.exit(1)
    else:
        interfaces = None

    logger.info("reading processed iptables rules from %s", src)
    with open(src, 'rt') as fd:
        buf = fd.read()
    table = FilterTable.fromString(buf,
                                   log=logger.getChild("iptables"))

    if chain not in table.chains:
        logger.error("missing chain %s in table" % chain)
        sys.exit(1)

    loader = Loader(table, chain,
                    interfaces=interfaces, offload=offload,
                    shared=shared, scoreboard=scoreboard,
                    atomic=atomic, drop=drop, continue_=continue_,
                    version=version,
                    profile=profile,
                    log_ignore=log_ignore,
                    addrtype=addrtype,
                    match_multi=match_multi,
                    batch=batch,
                    port_unroll=port_unroll,
                    hack_vlan_arp=hack_vlan_arp,
                    drop_mode=drop_mode,
                    reject_drop=reject_drop,
                    continue_suppress=continue_suppress,
                    prestera_chain_mode=prestera_chain_mode,
                    log=logger.getChild("load"))
    try:
        code = loader.run()
    except:
        logger.exception("filter loader failed")
        code = 1
    loader.shutdown()

    sys.exit(code)

if __name__ == "__main__":
    main()
