"""path_config.py

Locate release scripts from within a test script
"""

import os, sys

def isBrazil():
    for p in sys.path:
        if '/test-runtime/' in p:
            return True
        if '/runtime/' in p:
            return True
    return False

if not isBrazil():
    srcdir = os.path.dirname(__file__)
    pydir = os.path.abspath(os.path.join(srcdir, "../src"))
    sys.path.insert(0, pydir)
