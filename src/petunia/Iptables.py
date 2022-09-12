"""Iptables.py

Handle the persistent format for iptables-save.
"""

import socket
import subprocess
import shlex
import re

import logging

class IptablesRule(object):
    """Represent a semi-parsed iptables rule.

    The chain is implicit.
    The target and the optional target args are parsed out.

    If 'return_' is True, this rule uses --jump,
    else it uses '--goto'.

    We extend the iptables syntax in a few ways to facilitate TC migration:

    - RETURN target accepts an argument of the form
      ... -j RETURN --return-frames N
      Where 'N' is the number of frames to return from.
      This is to handle non-local RETURNS by way of GOTO.
    - -j SKIP (new target) to represent TC's ability to skip
      forward in the rule set. Syntax is
      ... -j SKIP --skip-rules N
      where 'N' is the number of rules to skip
    """

    def __init__(self, args, target,
                 return_=True,
                 target_args=[]):

        self.target = target
        self.target_args = target_args
        self.return_ = return_

        # compute some helper attributes for this rule
        self.in_interface = self.out_interface = self.comment = None

        # embed TC attributes
        self.tc_args = []

        args, self.args = list(args), []
        while args:
            if (len(args) > 1
                and args[0] in ('-i', '--in-interface',)):
                args.pop(0)
                self.in_interface = args.pop(0)
                continue
            if (len(args) > 1
                and args[0] in ('-o', '--out-interface',)):
                args.pop(0)
                self.out_interface = args.pop(0)
                continue
            if (len(args) > 1
                and args[0] in ('--comment',)):
                args.pop(0)
                self.comment = args.pop(0)
                continue
            self.args.append(args.pop(0))

        if self.comment is not None:
            args, self.args = self.args, []
            while args:
                if (len(args) > 1
                    and args[0] == '-m'
                    and args[1] == 'comment'):
                    args.pop(0)
                    args.pop(0)
                    continue
                self.args.append(args.pop(0))

        # parse the comment for any embedded TC attributes
        if self.comment is not None:
            self.comment, self.tc_args = self.decodeComment(self.comment)

    @staticmethod
    def decodeComment(comment):
        """Return a tuple of (command, tc_args)"""

        cl = comment.split()
        tl = [x for x in cl if x.startswith('TC:')]
        tl = [x[3:] for x in tl]
        cl = [x for x in cl if not x.startswith('TC:')]

        if cl:
            comment = " ".join(cl)
        else:
            comment = None
            # NOTE if the command consists of only TC args,
            # the resulting command is removed

        if tl:
            tc_args = tl
        else:
            tc_args = []

        return comment, tc_args

    def encodeComment(self):
        """Encode the TC arguments into the comment."""

        if not self.tc_args and self.comment is None:
            return None

        comment = self.comment or ""
        for arg in self.tc_args:
            if comment:
                comment += " "
            comment += 'TC:' + arg

        return comment

    def clone(self, target=None, return_=None, target_args=None):
        """Clone a rule, overriding a few select fields."""

        return_ = self.return_ if return_ is None else return_
        target = self.target if target is None else target
        target_args = self.target_args if target_args is None else target_args

        args = list(self.args)
        if self.in_interface is not None:
            args = ['-i', self.in_interface,]+args
        if self.out_interface is not None:
            args = ['-o', self.out_interface,]+args

        if self.tc_args or self.comment is not None:
            args.extend(['-m', 'comment',])
            args.append('--comment')
            args.append(self.encodeComment())

        return self.__class__(args,
                              target=target,
                              return_=return_,
                              target_args=target_args)

    @classmethod
    def fromIptablesSave(cls, line, multiInterface=False):

        oline = line

        args = []
        target = None
        return_ = True
        target_args = []

        while line:

            if line.startswith('"'):
                line = line[1:]
                tok, sep, line = line.partition('"')
                args.append(tok)
                line = line.lstrip()
                continue

            if line.startswith("'"):
                line = line[1:]
                tok, sep, line = line.partition("'")
                args.append(tok)
                line = line.lstrip()
                continue

            tok, sep, line = line.partition(' ')

            if tok in ('-j', '-g', '--jump', '--goto',):
                if not line:
                    raise ValueError("missing target for rule: %s" % oline)
                target, sep, line = line.partition(' ')
                target_args = line.split() if line else []
                return_ = True if tok in ('-j', '--jump',) else False
                break

            args.append(tok)

        if target is None:
            raise ValueError("no chain target (counting-only rules not supported)")

        baseRule = cls(args, target, return_=return_, target_args=target_args)

        if (not multiInterface
            and baseRule.in_interface is not None
            and ',' in baseRule.in_interface):
            raise ValueError("invalid multi-interface extension in --in-interface %s"
                             % baseRule.in_interface)
        if (not multiInterface
            and baseRule.out_interface is not None
            and ',' in baseRule.out_interface):
            raise ValueError("invalid multi-interface extension in --out-interface %s"
                             % baseRule.out_interface)

        q = []
        q.append(baseRule)

        while q:
            rule = q.pop(0)

            if (rule.in_interface is not None
                and ',' in rule.in_interface):
                for intf in rule.in_interface.split(','):
                    rule_ = rule.clone()
                    rule_.in_interface = intf
                    q.append(rule_)
                continue

            if (rule.out_interface is not None
                and ',' in rule.out_interface):
                for intf in rule.out_interface.split(','):
                    rule_ = rule.clone()
                    rule_.out_interface = intf
                    q.append(rule_)
                continue

            # else, nothing to expand
            yield(rule)

    def toSave(self, chain='INPUT'):
        """Generate a printable result

        XXX rothcar -- ugh, shlex.join does not show up til 3.8.
        """
        ruleBuf = ""
        ruleBuf += "-A %s" % chain
        if self.in_interface is not None:
            ruleBuf += " -i %s" % self.in_interface
        if self.out_interface is not None:
            ruleBuf += " -o %s" % self.out_interface
        if self.args:
            ruleBuf += " " + " ".join(shlex.quote(x) for x in self.args)
        if self.tc_args or self.comment:
            ruleBuf += " -m comment"
            ruleBuf += " --comment"
            ruleBuf += " "
            ruleBuf += shlex.quote(self.encodeComment())
        if self.return_:
            ruleBuf += " -j %s" % self.target
        else:
            ruleBuf += " -g %s" % self.target
        if self.target_args:
            ruleBuf += " " + " ".join(shlex.quote(x) for x in self.target_args)
        return ruleBuf

    def __repr__(self):
        buf = "<IptablesRule"
        if self.in_interface is not None:
            buf += " in=" + self.in_interface
        if self.out_interface is not None:
            buf += " out=" + self.in_interface
        if self.args:
            buf += " args=\"" + " ".join(self.args) + "\""
        if self.target == 'SKIP':
            buf += " SKIP %s" % self.target_args[1]
        elif self.return_:
            buf += " JUMP %s" % self.target
        else:
            buf += " GOTO %s" % self.target
        buf += ">"
        return buf

    def __hash__(self):
        """Compute a stable hash for an IPTABLES rule."""
        state = (self.in_interface, self.out_interface,
                 tuple(self.args),
                 self.target, tuple(self.target_args),
                 self.return_,
                 self.comment,
                 tuple(self.tc_args),)
        return hash(state)

class IptablesChain(object):
    """Simple container for an iptables chain.

    The chain name is implicit.
    """

    rule_klass = IptablesRule

    def __init__(self, rules, policy):
        self.rules = rules
        self.policy = policy

    def __len__(self):
        return len(self.rules)

    def __hash__(self):
        return hash((tuple(hash(x) for x in self.rules),
                     self.policy,))

    def toSave(self, chain):
        lines = []
        policyName = '-' if self.policy=='RETURN' else self.policy
        lines.append("%s %s [0:]" % (chain, policyName,))
        lines.extend(x.toSave(chain) for x in self.rules)
        return "\n".join(lines)

class FilterTable(object):
    """Object-based representation of iptables rules in the filter table."""

    chain_klass = IptablesChain
    rule_klass = chain_klass.rule_klass

    def __init__(self, chains={}, log=None):
        self.chains = chains

        if log is None:
            self.log = log
        else:
            self.log = logging.getLogger(self.__class__.__name__)

    @classmethod
    def fromString(cls, lines,
                   multiChain=False, multiInterface=False,
                   log=None):

        log = log or logging.getLogger(cls.__name__)

        filter_chains = {}
        filter_policies = {}

        in_table = None
        chains = {}

        for line in lines.strip().splitlines(False):
            line = line.strip()

            if not line: continue
            if line.startswith('#'): continue

            # start a table
            if in_table is None and line.startswith('*'):
                in_table = line[1:]
                if in_table == 'filter':
                    chains.setdefault('INPUT', cls.chain_klass([], 'ACCEPT'))
                    chains.setdefault('OUTPUT', cls.chain_klass([], 'ACCEPT'))
                    chains.setdefault('FORWARD', cls.chain_klass([], 'ACCEPT'))
                continue

            # define a chain
            if (in_table is not None
                and line.startswith(':')):

                buf = line[1:]
                chain, sep, buf = buf.partition(' ')
                policy, sep, buf = buf.partition(' ')

                # user-defined rules have a default policy of 'RETURN'
                policy = 'RETURN' if policy == '-' else policy
                if chain in chains:
                    chains[chain].policy = policy
                else:
                    chains.setdefault(chain, cls.chain_klass([], policy))
                continue

            # end a table
            if in_table and line == 'COMMIT':
                if in_table == 'filter':
                    filter_chains, chains = chains, {}
                else:
                    chains = {}
                in_table = None
                continue

            # add a rule to a chain
            if (in_table is not None
                and line.startswith('-A ')):
                buf = line[3:]
                chain, sep, buf = buf.partition(' ')

                if not multiChain and ',' in chain:
                    raise ValueError("invalid multi-interface extension: %s" % line)

                for chain_ in chain.split(','):
                    if chain_ not in chains:
                        raise ValueError("invalid rule %s (missing chain %s)"
                                         % (repr(line), chain_,))
                    for rule in cls.rule_klass.fromIptablesSave(buf,
                                                                multiInterface=multiInterface):
                        chains[chain_].rules.append(rule)

                continue

            raise ValueError("unrecognized statement %s" % repr(line))

        if in_table:
            raise ValueError("EOF while processing table %s" % in_table)

        return cls(filter_chains, log=log)

    @classmethod
    def fromKernel(cls, version=socket.AF_INET, log=None):

        log = log or logging.getLogger(cls.__name__)

        if version == socket.AF_INET6:
            cmd = ('ip6tables-save',)
        else:
            cmd = ('iptables-save',)

        buf = subprocess.check_output(cmd,
                                      universal_newlines=True)
        return cls.fromString(buf, log=log)

    def chainNames(self, addDefaults=False):
        """Generate a canonical list of chain names."""

        chainNameList = []
        chainNameSet = set(self.chains.keys())
        for chainName in ('INPUT', 'OUTPUT', 'FORWARD',):
            if chainName in chainNameSet:
                chainNameList.append(chainName)
                chainNameSet.discard(chainName)
        chainNameList.extend(sorted(chainNameSet))

        return chainNameList

    def toSave(self):
        """Generate an iptables-save output."""

        buf = ""
        buf += "*filter\n"

        for chainName in self.chainNames(addDefaults=True):
            chain = self.chains[chainName]
            policyName = '-' if chain.policy == 'RETURN' else chain.policy
            buf += ":%s %s [0:0]\n" % (chainName, policyName,)

        for chainName in self.chainNames():
            chain = self.chains[chainName]
            for rule in chain.rules:
                buf += rule.toSave(chainName) + "\n"

        buf += "COMMIT\n"
        return buf

    def clone(self):
        """Copy this table."""

        other = self.__class__({}, log=self.log)

        for chainName, chain in self.chains.items():
            rules = [x.clone() for x in chain.rules]
            other.chains[chainName] = self.chain_klass(rules, chain.policy)

        return other
