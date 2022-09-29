"""test_stress.py

Load test for scripts.
"""

import os, sys
import unittest
import subprocess
import struct
import logging
import tempfile
import timeit
import random
import json
import select

import path_config

import TcSaveTestUtils
from TcSaveTestUtils import (
    ScriptTestMixin,
    PhysicalTestMixin,
    isLinux,
    isRoot,
    isDut,
    isVirtual,
    isPhysical,
)

from petunia.Topology import Topology

from petunia.Iptables import FilterTable
from petunia.Unroller import Unroller
from petunia.Scoreboard import Scoreboard
from petunia.TcFlowerLoader import Loader

logger = None
def setUpModule():

    global logger
    logging.basicConfig()
    logger = logging.getLogger("unittest")
    logger.setLevel(logging.DEBUG)

    if not isLinux() or not isRoot():
        logger.warning("some tests need to run on a DUT")
    else:
        TcSaveTestUtils.setUpModule()

def tearDownModule():
    if isLinux() and isRoot():
        TcSaveTestUtils.tearDownModule

class StressTestBase(object):

    def check_call_stress(self, cmd):

        self.log.debug("+ " + " ".join(cmd))
        pipe = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                universal_newlines=True)
        out = []
        fno = pipe.stdout.fileno()
        while True:
            rfd, wfd, xfd = select.select([fno,], [], [], 1.0)
            if fno not in rfd: continue
            try:
                out_ = os.read(fno, 4096)
            except IOError:
                out_ = ""
            if out_:
                out.append(out_)
            else:
                break
        pipe.communicate()
        sts = pipe.wait()

        out = b"".join(out).decode()
        for line in out.rstrip().splitlines(False):
            self.log.info(">>> %s", line)

        if not os.WIFEXITED(sts):
            code = -1
            self.log.error("process did not exit")
        elif os.WEXITSTATUS(sts):
            code = os.WEXITSTATUS(sts)
            self.log.error("process failed")
        else:
            code = 0
        self.log.debug("+ exit %s", code)

        if code and 'RecursionError' in out:
            raise RecursionError

        if code:
            raise subprocess.CalledProcessError(code, cmd)

class UnrollTest(StressTestBase,
                 ScriptTestMixin,
                 unittest.TestCase):
    """Stress test for unrolling."""

    DEADLINE = 1.0

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        if not path_config.isBrazil():
            self.setUpScripts()

    def tearDown(self):
        if not path_config.isBrazil():
            self.tearDownScripts()
        self.tearDownWorkdir()

    def check_stress(self, generator, deadline, opts=[]):
        """Compute the longest rule chain that can be processed within a deadline."""

        sz = 1
        ela = 0.0
        while True:
            src = generator(sz)
            dst = os.path.join(self.workdir, 'iptables-unroll.out')

            cmd = ['iptables-unroll', src, dst,]
            cmd[1:1] = opts
            fn = lambda: self.check_call_stress(cmd)

            timer = timeit.Timer(stmt=fn)
            try:
                ela = timer.timeit(number=1)
            except RecursionError:
                self.log.exception("recursion error at sz=%d", sz)
                break

            with open(src, 'rt') as fd:
                insz = len(fd.readlines())
            with open(dst, 'rt') as fd:
                outsz = len(fd.readlines())

            self.log.info("processed %d --> %d rules in %.1fs",
                          insz, outsz, ela)

            os.unlink(src)
            os.unlink(dst)

            if ela > deadline:
                break

            sz_ = max(int(sz*1.25), sz+1)
            sz = sz_

        self.log.info("max rules are %d in %.1fs", sz, ela)

    def mkRulesLinear(self, sz):
        """Generate simple (linear) rules."""

        self.log.info("generating a linear config with %d rules", sz)

        fno, p = tempfile.mkstemp(dir=self.workdir,
                                  prefix="iptables-save-",
                                  suffix=".txt")
        with os.fdopen(fno, "wt") as fd:
            fd.write("*filter\n")
            fd.write(":INPUT ACCEPT [0:0]\n")
            fd.write(":OUTPUT ACCEPT [0:0]\n")
            fd.write(":FORWARD ACCEPT [0:0]\n")
            for i in range(sz):
                buf = struct.pack('>I', i)
                octets = struct.unpack('BBBB', buf)
                addr = "10.%d.%d.%d" % octets[1:4]
                fd.write("-A FORWARD -i dummy0 -p tcp -s %s -j ACCEPT\n"
                         % (addr,))
            fd.write("COMMIT\n")

        return p

    def testStressLinear(self):
        """Simple stress test with a linear rule set."""
        self.check_stress(self.mkRulesLinear, self.DEADLINE)

    def mkRulesWide(self, sz):
        """Generate wide rules."""

        self.log.info("generating a wide config with %d rules", sz)

        fno, p = tempfile.mkstemp(dir=self.workdir,
                                  prefix="iptables-save-",
                                  suffix=".txt")
        with os.fdopen(fno, "wt") as fd:
            fd.write("*filter\n")
            fd.write(":INPUT ACCEPT [0:0]\n")
            fd.write(":OUTPUT ACCEPT [0:0]\n")
            fd.write(":FORWARD ACCEPT [0:0]\n")
            for i in range(sz):
                buf = struct.pack('>I', i)
                octets = struct.unpack('BBBB', buf)
                addr = "10.%d.%d.%d" % octets[1:4]
                intfs = []
                for swp in range(1, i+2):
                    intfs.append("swp%d" % swp)
                random.shuffle(intfs)
                in_interface = ','.join(intfs)
                fd.write("-A FORWARD -i %s -p tcp -s %s -j ACCEPT\n"
                         % (in_interface, addr,))
            fd.write("COMMIT\n")

        return p

    def testStressWide(self):
        """Simple stress test with a wire rule set."""
        self.check_stress(self.mkRulesWide, self.DEADLINE,
                          opts=['--multi-interface',])

    def mkRulesGoto(self, sz):
        """Generate deep rules."""

        self.log.info("generating a wide config with %d rules", sz)

        fno, p = tempfile.mkstemp(dir=self.workdir,
                                  prefix="iptables-save-",
                                  suffix=".txt")
        with os.fdopen(fno, "wt") as fd:
            fd.write("*filter\n")
            fd.write(":INPUT ACCEPT [0:0]\n")
            fd.write(":OUTPUT ACCEPT [0:0]\n")
            fd.write(":FORWARD ACCEPT [0:0]\n")
            for i in range(sz):
                fd.write(":OTHER%d - [0:0]\n" % (i+1,))
            for i in range(sz):
                buf = struct.pack('>I', i)
                octets = struct.unpack('BBBB', buf)
                addr = "10.%d.%d.%d" % octets[1:4]
                if i == 0:
                    fd.write("-A FORWARD -i dummy0 -p tcp -s %s -g OTHER%d\n"
                             % (addr, i+1,))
                else:
                    fd.write("-A OTHER%d -i dummy0 -p tcp -s %s -g OTHER%d\n"
                             % (i, addr, i+1,))
            fd.write("COMMIT\n")

        return p

    def testStressGoto(self):
        """Simple stress test with a deep rule set."""
        self.check_stress(self.mkRulesGoto, self.DEADLINE)

    def mkRulesRecursive(self, sz):
        """Generate recursive rules."""

        self.log.info("generating a recursive config with %d rules", sz)

        fno, p = tempfile.mkstemp(dir=self.workdir,
                                  prefix="iptables-save-",
                                  suffix=".txt")
        with os.fdopen(fno, "wt") as fd:
            fd.write("*filter\n")
            fd.write(":INPUT ACCEPT [0:0]\n")
            fd.write(":OUTPUT ACCEPT [0:0]\n")
            fd.write(":FORWARD ACCEPT [0:0]\n")
            for i in range(sz):
                fd.write(":OTHER%d - [0:0]\n" % (i+1,))
            for i in range(sz):
                buf = struct.pack('>I', i)
                octets = struct.unpack('BBBB', buf)
                addr = "10.%d.%d.%d" % octets[1:4]
                if i == 0:
                    fd.write("-A FORWARD -i dummy0 -p tcp -s %s -j DROP\n"
                             % (addr,))
                    fd.write("-A FORWARD -i dummy0 -p tcp -s %s -j RETURN\n"
                             % (addr,))
                    fd.write("-A FORWARD -i dummy0 -p tcp -s %s -g OTHER%d\n"
                             % (addr, i+1,))
                    fd.write("-A FORWARD -i dummy0 -p tcp -s %s -j DROP\n"
                             % (addr,))
                    fd.write("-A FORWARD -i dummy0 -p tcp -s %s -j OTHER%d\n"
                             % (addr, i+1,))
                    fd.write("-A FORWARD -i dummy0 -p tcp -s %s -j RETURN\n"
                             % (addr,))
                    fd.write("-A FORWARD -i dummy0 -p tcp -s %s -j DROP\n"
                             % (addr,))
                else:
                    fd.write("-A OTHER%d -i dummy0 -p tcp -s %s -j DROP\n"
                             % (i, addr,))
                    fd.write("-A OTHER%d -i dummy0 -p tcp -s %s -j RETURN\n"
                             % (i, addr,))
                    fd.write("-A OTHER%d -i dummy0 -p tcp -s %s -g OTHER%d\n"
                             % (i, addr, i+1,))
                    fd.write("-A OTHER%d -i dummy0 -p tcp -s %s -j DROP\n"
                             % (i, addr,))
                    fd.write("-A OTHER%d -i dummy0 -p tcp -s %s -j OTHER%d\n"
                             % (i, addr, i+1,))
                    fd.write("-A OTHER%d -i dummy0 -p tcp -s %s -j RETURN\n"
                             % (i, addr,))
                    fd.write("-A OTHER%d -i dummy0 -p tcp -s %s -j DROP\n"
                             % (i, addr,))
            fd.write("COMMIT\n")

        return p

    def testStressRecursive(self):
        """Simple stress test with a recursive rule set."""
        self.check_stress(self.mkRulesRecursive, self.DEADLINE)

class LinearSliceTest(StressTestBase,
                      ScriptTestMixin,
                      unittest.TestCase):
    """Stress test for slicing with a simple linear rule set."""

    DEADLINE = 1.0

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        if not path_config.isBrazil():
            self.setUpScripts()

        linkMap = {'dummy0' : ['port',],
                   'dummy1' : ['port',],}
        os.environ['TEST_LINKS_JSON'] = json.dumps(linkMap)
        os.environ['TEST_VLANS_JSON'] = json.dumps({})
        os.environ['TEST_SVIS_JSON'] = json.dumps({})

    def tearDown(self):
        if not path_config.isBrazil():
            self.tearDownScripts()
        self.tearDownWorkdir()
        os.environ.pop('TEST_LINKS_JSON', None)
        os.environ.pop('TEST_VLANS_JSON', None)
        os.environ.pop('TEST_SVIS_JSON', None)

    def check_stress(self, generator, deadline, opts=[]):
        """Compute the longest rule chain that can be processed within a deadline."""

        sz = 1
        ela = 0.0
        while True:
            src = generator(sz)
            dst = os.path.join(self.workdir, 'iptables-slice.out')

            cmd = ['iptables-slice', src, dst,]
            cmd[1:1] = opts
            fn = lambda: self.check_call_stress(cmd)

            timer = timeit.Timer(stmt=fn)
            try:
                ela = timer.timeit(number=1)
            except RecursionError:
                self.log.exception("recursion error at sz=%d", sz)
                break

            with open(src, 'rt') as fd:
                insz = len(fd.readlines())
            with open(dst, 'rt') as fd:
                outsz = len(fd.readlines())

            self.log.info("processed %d --> %d rules in %.1fs",
                          insz, outsz, ela)

            os.unlink(src)
            os.unlink(dst)

            if ela > deadline:
                break

            sz_ = max(int(sz*1.25), sz+1)
            sz = sz_

        self.log.info("max rules are %d in %.1fs", sz, ela)

    def mkRulesLinear(self, sz):
        """Generate simple (linear) rules."""

        self.log.info("generating a linear config with %d rules", sz)

        fno, p = tempfile.mkstemp(dir=self.workdir,
                                  prefix="iptables-save-",
                                  suffix=".txt")
        with os.fdopen(fno, "wt") as fd:
            fd.write("*filter\n")
            fd.write(":INPUT ACCEPT [0:0]\n")
            fd.write(":OUTPUT ACCEPT [0:0]\n")
            fd.write(":FORWARD ACCEPT [0:0]\n")
            for i in range(sz):
                buf = struct.pack('>I', i)
                octets = struct.unpack('BBBB', buf)
                addr = "10.%d.%d.%d" % octets[1:4]
                fd.write("-A FORWARD -i dummy0 -p tcp -s %s -j ACCEPT\n"
                         % (addr,))
            fd.write("COMMIT\n")

        return p

    def testStressLinear(self):
        """Simple stress test with a linear rule set."""
        self.check_stress(self.mkRulesLinear, self.DEADLINE)

class WideSliceTest(StressTestBase,
                    ScriptTestMixin,
                    unittest.TestCase):
    """Stress-test the slicing algorithm with wide rules."""

    DEADLINE = 1.0

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        if not path_config.isBrazil():
            self.setUpScripts()

    def tearDown(self):
        if not path_config.isBrazil():
            self.tearDownScripts()
        self.tearDownWorkdir()

    def check_stress(self, generator, deadline, maxIntfs=None, opts=[]):
        """Compute the longest rule chain that can be processed within a deadline."""

        sz = 1
        ela = 0.0
        while True:
            src = generator(sz)
            dst = os.path.join(self.workdir, 'iptables-slice.out')

            cmd = ['iptables-slice', src, dst,]
            cmd[1:1] = opts
            fn = lambda: self.check_call_stress(cmd)

            intfs = []
            if maxIntfs is None:
                for swp in range(1, sz+2):
                    intfs.append('swp%d' % swp)
            else:
                for swp in range(1, maxIntfs+1):
                    intfs.append('swp%d' % swp)
            random.shuffle(intfs)
            vlanMap = {}
            for ifName in intfs:
                vlanMap[ifName] = ['port',]
            os.environ['TEST_LINKS_JSON'] = json.dumps(vlanMap)
            os.environ['TEST_VLANS_JSON'] = json.dumps({})
            os.environ['TEST_SVIS_JSON'] = json.dumps({})

            timer = timeit.Timer(stmt=fn)
            try:
                ela = timer.timeit(number=1)
            except RecursionError:
                self.log.exception("recursion error at sz=%d", sz)
                break
            finally:
                os.environ.pop('TEST_LINKS_JSON', None)
                os.environ.pop('TEST_VLANS_JSON', None)
                os.environ.pop('TEST_SVIS_JSON', None)

            with open(src, 'rt') as fd:
                insz = len(fd.readlines())
            with open(dst, 'rt') as fd:
                outsz = len(fd.readlines())

            self.log.info("processed %d --> %d rules in %.1fs",
                          insz, outsz, ela)

            os.unlink(src)
            os.unlink(dst)

            if ela > deadline:
                break

            sz_ = max(int(sz*1.25), sz+1)
            sz = sz_

        self.log.info("max rules are %d in %.1fs", sz, ela)

    def mkRulesWide(self, sz):
        """Generate wide rules."""

        self.log.info("generating a wide config with %d rules", sz)

        fno, p = tempfile.mkstemp(dir=self.workdir,
                                  prefix="iptables-save-",
                                  suffix=".txt")
        with os.fdopen(fno, "wt") as fd:
            fd.write("*filter\n")
            fd.write(":INPUT ACCEPT [0:0]\n")
            fd.write(":OUTPUT ACCEPT [0:0]\n")
            fd.write(":FORWARD ACCEPT [0:0]\n")
            for i in range(sz):
                buf = struct.pack('>I', i)
                octets = struct.unpack('BBBB', buf)
                addr = "10.%d.%d.%d" % octets[1:4]
                fd.write("-A FORWARD -i swp+ -p tcp -s %s -j ACCEPT\n"
                         % (addr,))
            fd.write("COMMIT\n")

        return p

    def testStressWide(self):
        """Simple stress test with a wide rule set."""
        self.check_stress(self.mkRulesWide, self.DEADLINE)

    def testStressTypical(self):
        """Simple stress test with a wide rule set."""
        self.check_stress(self.mkRulesWide, self.DEADLINE,
                          maxIntfs=48)

class LoadTestBase(object):

    INTFS = None
    DEADLINE = 1.0

    def check_stress(self, generator, deadline, opts=[]):
        """Compute the longest rule chain that can be processed within a deadline.

        Note that this implicitly invokes the update mechanism.
        """

        sz = 1
        ela = 0.0

        allIfNames = self.topo.getPorts()

        while True:
            src = generator(sz)

            cmd = ['tc-flower-load', src, 'FORWARD',]
            cmd[1:1] = opts
            if self.INTFS is not None and len(self.INTFS) == 1:
                cmd[1:1] = ['-i', self.INTFS[0]]

            fn = lambda: self.check_call_stress(cmd)

            timer = timeit.Timer(stmt=fn)
            try:
                ela = timer.timeit(number=1)
            except RecursionError:
                self.log.exception("recursion error at sz=%d", sz)
                break

            with open(src, 'rt') as fd:
                insz = len(fd.readlines())

            outsz = 0
            for intf in allIfNames:
                cmd = ('tc', '-json', 'filter', 'show', 'dev', intf, 'ingress',)
                out = subprocess.check_output(cmd,
                                              universal_newlines=True)
                data = json.loads(out)
                data = [x for x in data if 'options' in x]
                outsz += len(data)

            self.log.info("processed %d --> %d rules in %.1fs",
                          insz, outsz, ela)

            os.unlink(src)

            if ela > deadline:
                break

            sz_ = max(int(sz*1.25), sz+1)
            sz = sz_

        self.log.info("max rules are %d in %.1fs", sz, ela)

    def mkRules(self, sz):
        """Generate a linear rule set."""

        self.log.info("generating a linear config with %d interfaces, %d rules",
                      len(self.INTFS), sz)

        fno, p = tempfile.mkstemp(dir=self.workdir,
                                  prefix="iptables-slice-",
                                  suffix=".txt")
        with os.fdopen(fno, "wt") as fd:
            fd.write("*filter\n")
            fd.write(":INPUT ACCEPT [0:0]\n")
            fd.write(":OUTPUT ACCEPT [0:0]\n")
            fd.write(":FORWARD ACCEPT [0:0]\n")
            for intf in self.INTFS:
                fd.write(":FORWARD_%s ACCEPT [0:0]\n" % intf)
            for intf in self.INTFS:
                fd.write("-A FORWARD -i %s -j FORWARD_dummy0\n" % intf)
            for i in range(sz):
                buf = struct.pack('>I', i)
                octets = struct.unpack('BBBB', buf)
                addr = "10.%d.%d.%d" % octets[1:4]
                for intf in self.INTFS:
                    fd.write("-A FORWARD_%s -p tcp -s %s -j ACCEPT\n"
                             % (intf, addr,))
            fd.write("COMMIT\n")

        return p

@unittest.skipUnless(isDut(),
                     "this test runs on a virtual DUT")
class VmLoadTest(LoadTestBase,
                 StressTestBase,
                 ScriptTestMixin,
                 unittest.TestCase):
    """Stress-test the tc-flower-load script."""

    INTFS = ['dummy0',]
    # test using a non-physical interface

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        if not path_config.isBrazil():
            self.setUpScripts()
        self.topo = Topology(log=self.log.getChild("links"))

        os.environ['TEST_DUMMY'] = '1'

    def tearDown(self):
        if not path_config.isBrazil():
            self.tearDownScripts()
        self.tearDownWorkdir()

        os.environ.pop('TEST_DUMMY', None)

    def testStress(self):
        """Simple stress test with a wide rule set."""
        self.check_stress(self.mkRules, self.DEADLINE)

@unittest.skipUnless(isDut() and isPhysical(),
                     "this test runs on a physical DUT")
class SwitchdevLoadTestLinear(PhysicalTestMixin,
                              LoadTestBase,
                              StressTestBase,
                              ScriptTestMixin,
                              unittest.TestCase):
    """Stress-test the tc-flower-load script."""

    INTFS = ['swp1',]
    # needs to be interfaces with hardware switchdev support

    DEADLINE = 15.0
    # ugh very slow

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        if not path_config.isBrazil():
            self.setUpScripts()
        self.clearPhysicalInterfaces()
        self.topo = Topology(log=self.log.getChild("links"))

    def tearDown(self):
        if not path_config.isBrazil():
            self.tearDownScripts()
        self.tearDownWorkdir()
        self.clearPhysicalInterfaces()

    def testStressKernel(self):
        """Simple stress test with a linear rule set."""
        self.check_stress(self.mkRules, self.DEADLINE,
                          opts=['-v', '--profile', '--no-offload',])

    def testStressSwitchdev(self):
        """Simple stress test with a linear rule set."""
        self.check_stress(self.mkRules, self.DEADLINE,
                          opts=['-v', '--profile', '--offload',])

@unittest.skipUnless(isDut() and isPhysical(),
                     "this test runs on a physical DUT")
class SwitchdevLoadTestWide(PhysicalTestMixin,
                            LoadTestBase,
                            StressTestBase,
                            ScriptTestMixin,
                            unittest.TestCase):
    """Stress-test the tc-flower-load script."""

    INTFS = [('swp%d' % x) for x in range(1, 49)]
    # run with all interfaces

    DEADLINE = 15.0

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        if not path_config.isBrazil():
            self.setUpScripts()
        self.clearPhysicalInterfaces()
        self.topo = Topology(log=self.log.getChild("links"))

    def tearDown(self):
        if not path_config.isBrazil():
            self.tearDownScripts()
        self.tearDownWorkdir()
        self.clearPhysicalInterfaces()

    def testStressKernel(self):
        """Simple stress test with a linear rule set."""
        self.check_stress(self.mkRules, self.DEADLINE,
                          opts=['-v', '--profile', '--no-offload',])

    def testStressSwitchdev(self):
        """Simple stress test with a linear rule set."""
        self.check_stress(self.mkRules, self.DEADLINE,
                          opts=['-v', '--profile', '--offload',])

@unittest.skipUnless(isDut(),
                     "this test runs on a DUT")
class StoreConfigTest(ScriptTestMixin,
                      unittest.TestCase):

    def setUp(self):
        self.log = logger.getChild(self.id())
        self.setUpWorkdir()
        if not path_config.isBrazil():
            self.setUpScripts()

        os.environ['TEST_DUMMY'] = '1'

        self.topo = Topology(log=self.log.getChild("links"))

    def tearDown(self):
        if not path_config.isBrazil():
            self.tearDownScripts()
        self.tearDownWorkdir()

        os.environ.pop('TEST_DUMMY', None)

    def testCompile(self):

        srcdir = os.path.dirname(__file__)
        abs_srcdir = os.path.abspath(srcdir)
        diagdir = os.path.abspath(os.path.join(abs_srcdir, "../diag"))
        src = os.path.join(diagdir, "store-config/dent.iptables")

        self.log.info("loading input rules")

        with open(src, 'rt') as fd:
            buf = fd.read()
        table = FilterTable.fromString(buf,
                                       multiChain=True,
                                       multiInterface=True,
                                       log=self.log.getChild("iptables"))

        chainName = 'FORWARD'

        logger.info("unrolling %d rules in chain %s",
                    len(table.chains[chainName]), chainName)
        unroller = Unroller(table, chainName,
                            overrideInterface=False,
                            log=self.log.getChild("unroll"))
        table_ = unroller.unroll()

        print(table_.toSave())

        onlyInterfaces = self.topo.matchLinkPatterns(['swp+'])

        scoreboard = Scoreboard(table, chainName,
                                onlyInterfaces=onlyInterfaces,
                                allInterfaces=onlyInterfaces,
                                log=self.log.getChild("scoreboard"))
        table__ = scoreboard.scoreboard()
        self.log.info("found %d rules", len(table__.chains[chainName].rules))

        dst = "dent.iptables-scoreboard.txt"
        with open(dst, 'wt') as fd:
            fd.write(table__.toSave())

        self.log.info("deleting ingress filters")

        for ifName in onlyInterfaces:
            cmd = ('tc', 'qdisc', 'del', 'dev', ifName, 'ingress',)
            try:
                subprocess.check_call(cmd)
            except subprocess.CalledProcessError:
                pass

    def testLoad(self):

        self.log.info("loading new filters")

        src = "dent.iptables-scoreboard.txt"
        chainName = 'FORWARD'

        onlyInterfaces = self.topo.matchLinkPatterns(['swp+'])

        with open(src, 'rt') as fd:
            buf = fd.read()
        table = FilterTable.fromString(buf,
                                       log=self.log.getChild("iptables"))

        loader = Loader(table, chainName,
                        interfaces=onlyInterfaces,
                        shared=True, scoreboard=True,
                        atomic=False,
                        log_ignore=True,
                        addrtype=False,
                        match_multi=True,
                        log=self.log.getChild("loader"))
        loader.run()
        loader.shutdown()

if __name__ == "__main__":
    unittest.main()
