#!/usr/bin/env python

"""tc-almost.py

Behaves local normal 'tc' (including batch support)
but arbitrarily fails on any rule referring to 'udp'.
"""

import os, sys
import shlex

opts = [x for x in sys.argv[1:] if x[0] == '-']
args = [x for x in sys.argv[1:] if x[0] != '-']

if '-batch' in opts:
    force = '-force' in opts
    batchPath = args[0]
    sys.stderr.write("processing batch commands in %s\n" % batchPath)
    if force:
        forceCode = 0
    with open(batchPath, 'rt') as fd:
        for line in fd.readlines():
            line = line.rstrip()
            cmd = ["tc",] + shlex.split(line)
            if 'udp' in cmd:
                raise SystemExit("failed as per test: tc %s" % line)
            sys.stderr.write("+ tc %s\n" % line)
            pid = os.fork()
            if not pid:
                os.execvp("/sbin/tc", cmd)
                raise SystemExit("execvp failed")
            pid, sts = os.waitpid(pid, 0)
            if not os.WIFEXITED(sts):
                raise SystemExit("did not exit")
            code = os.WEXITSTATUS(sts)
            if code and not force:
                raise SystemExit("command failed")
            if code:
                sys.stderr.write("*** tc command failed\n")
                forceCode = code
    if force and forceCode:
        raise SystemExit("batch command failed")

else:

    if 'udp' in args:
        raise SystemExit("failed as per test: %s" % sys.argv)

    argv0 = "/sbin/tc"
    argv = ["tc",] + sys.argv[1:]
    sys.stderr.write("+ %s\n"
                     % " ".join(shlex.quote(x) for x in argv))
    os.execvp(argv0, argv)
