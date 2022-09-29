"""ShowApp.py

Displays the tc rules in a tabular format
"""

import sys
import logging
import subprocess
import json
import time

from petunia.Topology import Topology
from petunia.TcFlowerLoader import TcFilterShow

USAGE = """tc-flower-show [-v] [-b BLOCK] [INTERFACE ...]
Where OPTIONS is one of

  -v|--verbose   Show debug messages (including command traces)
  --profile      Enable call profiling
  -h|--help|-?   Print this help

  -i|--interval  Display difference every i seconds
  -b|--block     Block to display
  -c|--tc-chain  TC Chain to display
  -n|--non-zero  display only rules with non zero hits
  INTERFACE      display rules only matching the interfaces
"""

def dump_tc_rules(tc_rules, interfaces, nz, prev_data, tc_chain="0"):
    for i, rule in enumerate(sorted(tc_rules, key=lambda k: k.get("pref", 0))):
        if "options" not in rule:
            continue
        tc_chain = rule.get("chain", tc_chain)
        line = "Pref {} Chain {} protocol {} Key [ ".format(rule["pref"], tc_chain, rule["protocol"])
        swp = rule["options"].get("indev", "any")
        # if user has requested to filter on interfaces
        if swp != "any" and interfaces is not None and swp not in interfaces:
            continue
        line += "indev {} ".format(swp)
        for k, v in rule["options"]["keys"].items():
            line += "{}=={},".format(k,v)
        line += "] Action ["
        hit = False
        for j, action in enumerate(rule["options"]["actions"]):
            old_pkt = 0
            pkt = int (action["stats"].get("packets", 0))
            if prev_data is not None:
                # find out the diff here
                diff = {}
                for k, v in action["stats"].items():
                    diff[k] = int(v) - int(prev_data[i]["options"]["actions"][j]["stats"].get(k,"0"))

                line += "{} Pkt {}(+{}) Bytes {}(+{}) HW Pkt {}(+{}) Bytes {}(+{})".format(
                    action["control_action"]["type"],
                    action["stats"].get("packets", 0), diff.get("packets", 0),
                    action["stats"].get("bytes", 0), diff.get("bytes", 0),
                    action["stats"].get("hw_packets", 0), diff.get("hw_packets", 0),
                    action["stats"].get("hw_bytes", 0), diff.get("hw_bytes", 0),
                )
                old_pkt = int(prev_data[i]["options"]["actions"][j]["stats"]["packets"])

            else:
                line += "{} Pkt {} Bytes {} HW Pkt {} Bytes {}".format(
                    action["control_action"]["type"],
                    action["stats"].get("packets", 0),
                    action["stats"].get("bytes", 0),
                    action["stats"].get("hw_packets", 0),
                    action["stats"].get("hw_bytes", 0),
                )
            hit |= True if old_pkt != pkt else False

        line += "]\n"
        # do not print  non zero hits
        if nz is True and not hit:
            continue
        sys.stdout.write(line)

def main():

    logging.basicConfig()
    logger = logging.getLogger("tc-flower-show")
    logger.setLevel(logging.INFO)

    args = list(sys.argv[1:])
    block = "1"
    tc_chain = None
    interval = None
    interfaces = None
    profile = False
    nz = False
    try :
        while args:
            if args[0] in ('-v', '--verbose',):
                args.pop(0)
                logger.setLevel(logging.DEBUG)
                continue
            if args[0] in ('-n', '--non-zero',):
                args.pop(0)
                nz = True
                continue
            if args[0] == '--profile':
                args.pop(0)
                profile = True
                continue
            if args[0] in ('-b', '--block',):
                args.pop(0)
                block = args.pop(0)
                logger.setLevel(logging.DEBUG)
                continue
            if args[0] in ('-c', '--tc-chain',):
                args.pop(0)
                tc_chain = args.pop(0)
                logger.setLevel(logging.DEBUG)
                continue
            if args[0] in ('-i', '--interval',):
                args.pop(0)
                interval = args.pop(0)
                logger.setLevel(logging.DEBUG)
                continue
            break
    except Exception:
        sys.stderr.write("Usage: %s" % USAGE)
        sys.exit(1)

    if args:
        topo = Topology(log=logger.getChild("links"))
        try:
            interfaces = topo.matchLinkPatterns(args)
        except ValueError as ex:
            logger.error(str(ex))
            sys.stderr.write("Usage: %s" % USAGE)
            sys.exit(1)
    else:
        interfaces = None

    prev_data = None
    if interval is  None:
        data = TcFilterShow(profile, logger).show(block=block, tc_chain=tc_chain)
        dump_tc_rules(data, interfaces, nz, prev_data,tc_chain)
    else:
        while True:
            data = TcFilterShow(profile, logger).show(block=block)
            dump_tc_rules(data, interfaces, nz, prev_data)
            time.sleep(int(interval))
            prev_data = data
    sys.exit(0)

if __name__ == "__main__":
    main()
