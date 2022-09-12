#!/usr/bin/env python

"""tc-real.py

"""

import os, sys
import shlex

argv0 = "/sbin/tc"
argv = ["tc",] + sys.argv[1:]
sys.stderr.write("+ %s\n"
                 % " ".join(shlex.quote(x) for x in argv))
os.execvp(argv0, argv)
