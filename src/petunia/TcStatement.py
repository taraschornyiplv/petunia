"""TcStatement.py

Statement manipulation for TC-flower
"""

import socket
import logging
import collections
import ipaddress

from petunia.icmp import (
    ICMP_TYPE,
    ICMP_TYPE_CODE,
)
from petunia.icmpv6 import (
    ICMPV6_TYPE,
    ICMPV6_TYPE_CODE,
)

MODULES_ALL = ('tcp', 'udp', 'icmp', 'sctp',
               'mac',
               'addrtype',
               'vlan',)
MODULES_ALL_V6 = ('tcp', 'udp', 'icmpv6', 'sctp',
                  'mac',
                  'addrtype',
                  'vlan',)

TC_CHAIN_DEFAULT = "0"
TC_CHAIN_ICMP = "1"

# these are the IPTABLES match extensions we support
# NOTE
# - limit not supported (yet)
# - comment is handled implicitly by iptables-unroll
# - mport/multiport not supported (due to laziness)
# - 'vlan' here is a slicer extension to support TC

class MissingTarget(ValueError):
    """Error for an IPTABLES rule that is missing a target."""
    def __init__(self, rule, msg=None):
        ValueError.__init__(self, msg=msg)
        self.rule = rule

class LiteralClause(object):

    def __init__(self, s):
        self.s = s

    def reduce(self):
        return self

    def __repr__(self):
        return "<LiteralClause \"%s\">" % self.s

    def clone(self):
        return self.__class__(self.s)

class MetaClause(object):
    """Meta-clause, should not expand to a TC rule."""

    def reduce(self):
        return self

class LineNumberClause(MetaClause):
    """Track the source IPTABLES line number."""

    def __init__(self, lineno):
        self.lineno = lineno

    def __repr__(self):
        return "<LineNumberClause %d>" % self.lineno

    def clone(self):
        return self.__class__(self.lineno)

class AndClause(object):

    def __init__(self, c1, c2):
        self.c1 = c1
        self.c2 = c2

    def reduce(self):

        c1_ = self.c1.reduce()
        c2_ = self.c2.reduce()

        if c1_ is not self.c1:
            return self.__class__(c1_, c2_)

        if c2_ is not self.c2:
            return self.__class__(c1_, c2_)

        # propagate OR-clauses upward

        # XXX when reducing the AND-terms, make sure we clone
        # the terms that we reference twice!

        # AND(OR(c1_.c1, c1_.c2), c2_) --> OR(AND(c1_.c1, c2_), AND(c1_.c2, c2_))
        if isinstance(c1_, OrClause):
            return OrClause(AndClause(c1_.c1, c2_),
                            AndClause(c1_.c2, c2_.clone()))

        # AND(c1_, OR(c2_.c1, c2_.c2)) --> OR(c1_, AND(c2_.c1, c2_), AND(c2_.c2))
        if isinstance(c2_, OrClause):
            return OrClause(AndClause(c1_, c2_.c1),
                            AndClause(c1_.clone(), c2_.c2))

        # maybe other collapse rules

        return self

    @classmethod
    def fromClauses(cls, *clauses):
        if not clauses:
            raise ValueError("no clauses")
        if len(clauses) == 1:
            return clauses[0]
        ob = cls(clauses[0], clauses[1])
        for clause in clauses[2:]:
            ob = cls(ob, clause)
        return ob

    def __repr__(self):
        return ("<%s AND(%s, %s)>"
                % (self.__class__.__name__, repr(self.c1), repr(self.c2),))

    def clone(self):
        return self.__class__(self.c1.clone(), self.c2.clone())

class ImmutableAndClause(AndClause):
    """AND-clause that is not subject to refactoring.

    In order for this to work, the sub-clauses should also
    be immutable.
    """
    def __init__(self, c1, c2):
        if isinstance(c1, (LiteralClause, ImmutableAndClause,)):
            self.c1 = c1
        else:
            raise ValueError("invalid clause for immutable AND: %s" % c1)
        if isinstance(c2, (LiteralClause, ImmutableAndClause,)):
            self.c2 = c2
        else:
            raise ValueError("invalid clause for immutable AND: %s" % c2)

    def reduce(self):
        return self
    # ImmutableAndClause instances are irreducible

    # fromClauses() should verify the arguments here

    def __repr__(self):
        return ("<%s AND(%s, %s)>"
                % (self.__class__.__name__, repr(self.c1), repr(self.c2),))

class OrClause(object):

    def __init__(self, c1, c2):
        self.c1 = c1
        self.c2 = c2

    def reduce(self):
        c1_ = self.c1.reduce()
        c2_ = self.c2.reduce()

        if c1_ is not self.c1:
            return self.__class__(c1_, c2_)

        if c2_ is not self.c2:
            return self.__class__(c1_, c2_)

        # maybe other collapse rules

        return self

    @classmethod
    def fromClauses(cls, *clauses):
        if not clauses:
            raise ValueError("no clauses")
        if len(clauses) == 1:
            return clauses[0]
        ob = cls(clauses[0], clauses[1])
        for clause in clauses[2:]:
            ob = cls(ob, clause)
        return ob

    def __repr__(self):
        return ("<%s OR(%s, %s)>"
                % (self.__class__.__name__, repr(self.c1), repr(self.c2),))

    def clone(self):
        return self.__class__(self.c1.clone(), self.c2.clone())

class NotClause(object):

    def __init__(self, c):
        self.c = c

    def reduce(self):
        c_ = self.c.reduce()

        if c_ is not self.c:
            return self.__class__(c_)

        # push the NOT clauses down, the AND and OR clauses up

        # NOT(AND(c_.c1, c_.c2)) --> OR(NOT(c_.c1), NOT(c_.c2))
        if (isinstance(c_, AndClause)
            and not isinstance(c_, ImmutableAndClause)):
            return OrClause(self.__class__(c_.c1), self.__class__(c_.c2))

        # NOT(OR(c_.c1, c_.c2)) --> AND(NOT(c_.c1), NOT(c_.c2))

        # but not if they are non-generic dericed AND clauses
        # that is, prevent e.g 'src_ip 1.1.1.1 src_ip 1.1.1.2'

        if isinstance(c_, OrClause):
            return AndClause(self.__class__(c_.c1), self.__class__(c_.c2))

        # NOT(NOT(c)) --> c
        # possibly a loop!
        if isinstance(c_, NotClause):
            return c_.c

        # maybe other collapse rules

        return self

    # cannot directly expand a not-clause, since we need
    # to know the length of the parent run to compute our jump

    def __repr__(self):
        return ("<%s NOT(%s) >"
                % (self.__class__.__name__, repr(self.c),))

    def clone(self):
        return self.__class__(self.c.clone())

_ = LiteralClause
a = AndClause
A = ImmutableAndClause
o = O = OrClause
n = N = NotClause

class IpProtoClause(A):

    @classmethod
    def fromIptables(cls, arg,
                     invert=False, version=socket.AF_INET,
                     log=None):
        """Expand to a set of tc argument clauses.

        XXX rothcar -- switch to a proper negation syntax with NotClause()
        """

        log = log or logging.getLogger(cls.__name__)

        # supported TC (named) protos: tcp udp sctp icmp icmpv6
        # or a protocol number in hex (0x maybe?)
        # NOTE here that 'icmpv6' probably does not match /etc/protocols
        if version == socket.AF_INET6:
            allTcProtos = ['tcp', 'udp', 'sctp', 'icmpv6',]
        else:
            allTcProtos = ['tcp', 'udp', 'sctp', 'icmp',]

        # IPTABLES supports 'all', which is unclear here

        try:
            protoNum = int(arg, 10)
        except ValueError:
            protoNum = None

        if (not invert
            and arg in ('tcp', 'udp', 'sctp',)):
            return cls(_('ip_proto'), _(arg))
        # XXX rothcar -- support others too

        if (not invert
            and arg == 'icmp'
            and version == socket.AF_INET):
            return cls(_('ip_proto'), _(arg))
        if (not invert
            and arg == 'icmpv6'
            and version == socket.AF_INET6):
            return cls(_('ip_proto'), _(arg))

        if (not invert
            and (arg == 'all'
                 or protoNum == 0)):
            log.warning("IPTABLES proto 'all' may not match here")
            def _f(x):
                return cls(_('ip_proto'), _(x))
            subclauses = [_f(x) for x in allTcProtos]
            return O.fromClauses(*subclauses)

        if not invert and protoNum is not None:
            protoNumHex = "%x" % protoNum
            return cls(_('ip_proto'), _(protoNumHex))

        if (invert
            and version == socket.AF_INET
            and arg in ('tcp', 'udp', 'sctp', 'icmp',)):
            restProtos = list(allTcProtos)
            restProtos.remove(arg)
            def _f(x):
                return cls(_('ip_proto'), _(x))
            subclauses = [_f(x) for x in restProtos]
            return O.fromClauses(*subclauses)

        if (invert
            and version == socket.AF_INET6
            and arg in ('tcp', 'udp', 'sctp', 'icmpv6',)):
            restProtos = list(allTcProtos)
            restProtos.remove(arg)
            def _f(x):
                return cls(_('ip_proto'), _(x))
            subclauses = [_f(x) for x in restProtos]
            return O.fromClauses(*subclauses)

        if invert:
            msg = "invalid inverted protocol %s -- no TC equivalent" % arg
            raise ValueError(msg)

        # try to look up in /etc/protocols
        # (as above, invert==False)
        try:
            protoNum = socket.getprotobyname(arg)
        except OSError as ex:
            msg = "invalid protocol args %s: %s" % (arg, str(ex),)
            raise ValueError(msg)

        protoNumHex = "%x" % protoNum
        return cls(_('ip_proto'), _(protoNumHex))

class IpClauseBase(A):

    CLAUSE = None

    @classmethod
    def fromIptables(cls, arg,
                     invert=False, ipOnly=False, version=socket.AF_INET):
        """Expand to a set of tc argument clauses.

        # supported syntax
        # 1.1.1.1
        # 1.1.1.1/32
        # 1.1.1.1/255.255.255.255   # not supported by tc
        # 2001::dead:beef
        # 2001::dead:beef/128
        """

        addr = None
        if version == socket.AF_INET:
            try:
                addr = ipaddress.ip_address(arg)
                if not isinstance(addr, ipaddress.IPv4Address):
                    addr = None
            except ValueError:
                pass
        if version == socket.AF_INET6:
            try:
                addr = ipaddress.ip_address(arg)
                if not isinstance(addr, ipaddress.IPv6Address):
                    addr = None
            except ValueError:
                pass

        if addr is not None:
            clause = cls(_(cls.CLAUSE), _(str(addr)))
            if invert:
                clause = N(clause)
            return clause

        network = None
        if version == socket.AF_INET:
            try:
                network = ipaddress.ip_network(arg, strict=False)
                if not isinstance(network, ipaddress.IPv4Network):
                    network = None
                if ipOnly and str(network) == '0.0.0.0/0':
                    return NoOpClause()
            except ValueError:
                pass
        if version == socket.AF_INET6:
            try:
                network = ipaddress.ip_network(arg, strict=False)
                if not isinstance(network, ipaddress.IPv6Network):
                    network = None
                if ipOnly and str(network) == '::/0':
                    return NoOpClause()
            except ValueError:
                pass

        if network is not None:
            clause = cls(_(cls.CLAUSE), _(str(network)))
            if invert:
                clause = N(clause)
            return clause

        raise ValueError("invalid source argument %s" % arg)

class SrcIpClause(IpClauseBase):
    CLAUSE = 'src_ip'

class DstIpClause(IpClauseBase):
    CLAUSE = 'dst_ip'

class MultiMatchClause(object):

    clause_klass = None

    @classmethod
    def fromIptables(cls, arg,
                     invert=False, **kwargs):

        def _f(a):
            return cls.clause_klass.fromIptables(a, invert=invert, **kwargs)

        if ',' not in arg:
            return _f(arg)

        # not inverted --> OR to match any of the addresses
        if not invert:
            clauses = [_f(x) for x in arg.split(',')]
            return O.fromClauses(*clauses)

        # inverted --> AND match with the invert of each clause

        # ! -s 1.1.1.1,1.1.1.2
        # -->
        # ! -s 1.1.1.1 ! -s 1.1.1.2
        # (AND of the inverted clauses)
        # -->
        # -s 1.1.1.1 -j SKIP --skip-rules 2
        # -s 1.1.1.2 -j SKIP --skip-rules 1
        # -j TGT
        # (OR if the clauses with an inversion fall-through

        clauses = [_f(x) for x in arg.split(',')]
        return a.fromClauses(*clauses)

class MultiSrcIpClause(MultiMatchClause):
    clause_klass = SrcIpClause

class MultiDstIpClause(MultiMatchClause):
    clause_klass = DstIpClause

class PortBase(A):

    CLAUSE = None

    @classmethod
    def fromIptables(cls, arg,
                     unroll=None,
                     invert=False):
        """Expand to a set of tc argument clauses.

        supported flags
          --source-port
          --sport
          --destination-port
          --dport

        supported syntax
          80
          80:81
          :1024
          3000:

        Use the maxUnroll to specify the largest range of ports
        that can be safely unrolled.

        arg="67:78" unroll=2 (3 ...)
        --> src_port 67 OR src_port 68
        arg="67:78" unroll=None
        --> src_port 67-68
        arg="8000:8010" maxUnroll=5
        --> ValueError (port range cannot be unrolled)
        """

        def _port(spec):
            try:
                return int(spec, 10)
            except ValueError:
                pass

            # XXX rothcar -- not specifying tcp or udp here
            try:
                return socket.getservbyname(spec)
            except OSError:
                pass

            return None

        min_, sep, max_ = arg.partition(':')

        # single port argument
        if not sep:
            portNum = _port(arg)
            if portNum is None:
                raise ValueError("invalid port specifier %s" % arg)
            clause = cls(_(cls.CLAUSE), _(str(portNum)))
            if invert:
                clause = N(clause)
            return clause

        # multiple port arguments:
        min_ = _port(min_ or '1')
        # XXX rothcar -- obvs, '0' is not a valid port number,
        # the IPTABLES man-page says '0' is the start, but, duh

        max_ = max_ or '65535'
        max_ = _port(max_ or '65535')

        if min_ is None or max_ is None:
            raise ValueError("invalid port specifier %s" % arg)

        if unroll is None:
            portArg = "%d-%d" % (min_, max_,)
            clause = cls(_(cls.CLAUSE), _(portArg))
            if invert:
                clause = N(clause)
            return clause

        if unroll < max_-min_+1:
            raise ValueError("cannot unroll %s: unroll=%d"
                             % (arg, unroll,))
        clauses = list(cls(_(cls.CLAUSE), _(str(x))) for x in range(min_, max_+1))
        if invert:
            # ! --sport 80:81
            # --> AND(NOT(src_port 80), NOT(src_port 81))
            clauses = [N(x) for x in clauses]
            return a.fromClauses(*clauses)
        else:
            # --sport 80:81
            # --> OR(src_port 80, src_port 81)
            return O.fromClauses(*clauses)

class SrcPortClause(PortBase):
    CLAUSE = 'src_port'

class DstPortClause(PortBase):
    CLAUSE = 'dst_port'

class MultiSrcPortClause(MultiMatchClause):
    clause_klass = SrcPortClause

class MultiDstPortClause(MultiMatchClause):
    clause_klass = DstPortClause

class SrcMacClause(A):

    @classmethod
    def fromIptables(cls, arg, invert=False):
        """Expand to a set of tc argument clauses."""

        # supported flags
        # --mac-source
        # (masking not supported, yay)

        clause = cls(_('src_mac'), _(arg))
        if invert:
            clause = N(clause)
        return clause

class IpFlagsClause(A):

    @classmethod
    def fromIptables(cls, fragment=False, invert=False):
        """Expand to a set of tc argument clauses.

        Support a subset of IP flags.
        """

        # supported flags
        # -f
        # --fragment

        # let's map this to tc-flower
        # --fragment    # "second or further fragment of fragmented packets"
        # --> ip_flags frag
        # ! --fragment
        # --> ip_flags nofrag
        # XXX rothcar -- YMMV

        if fragment and not invert:
            return cls(_('ip_flags'), _('frag'))
        if fragment and invert:
            return cls(_('ip_flags'), _('nofrag'))

        raise ValueError("invalid IpFlagsClause")

class IcmpTypeCodeClause(A):

    @classmethod
    def fromIptables(cls, type_, invert=False):
        """Match on ICMP type."""

        # supported flags
        # --icmp-type type-name
        # --icmp-type numeric-type
        # ! --icmp-type ...

        # IPTABLES appears to accept both a type
        # (like 'destination-unreachable')
        # as well as a code within that ('network-unreachable').
        # In that case it fills in both the 'icmptype' as well as
        # the 'code' fields.

        # See
        # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml

        # TC specifies icmp type with 'icmp type' and sub-code with 'icmp code'

        clause = None

        if type_ == 'all':
            raise ValueError("invalid ICMP type 'all'")

        if type_ in ICMP_TYPE:
            typeVal = ICMP_TYPE[type_]
            clause = cls(_('type'), _(str(typeVal)))

        if type_ in ICMP_TYPE_CODE:
            typeVal, codeVal = ICMP_TYPE_CODE[type_]

            # NOTE here that the type/code combination is ummutable
            clause = A(cls(_('type'), _(str(typeVal))),
                       cls(_('code'), _(str(codeVal))))

        if clause is None and '/' in type_:
            type_, sep, code = type_.partition('/')
            try:
                typeVal = int(type_, 10)
                codeVal = int(code, 10)
                clause = A(cls(_('type'), _(str(typeVal))),
                           cls(_('code'), _(str(codeVal))))
            except ValueError:
                pass

        if clause is None and '/' not in type_:
            try:
                typeVal = int(type_, 10)
                clause = cls(_('type'), _(str(typeVal)))
            except ValueError:
                pass

        if clause is None:
            raise ValueError("invalid ICMP type/code %s" % type_)

        if invert:
            clause = N(clause)

        return clause

class IcmpV6TypeCodeClause(A):

    @classmethod
    def fromIptables(cls, type_, invert=False):
        """Match on ICMP type."""

        # supported flags
        # --icmpv6-type type-name
        # --icmpv6-type numeric-type
        # ! --icmpv6-type ...

        # See
        # https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml

        clause = None

        if type_ in ICMPV6_TYPE:
            typeVal = ICMPV6_TYPE[type_]
            clause = cls(_('type'), _(str(typeVal)))

        if type_ in ICMPV6_TYPE_CODE:
            typeVal, codeVal = ICMPV6_TYPE_CODE[type_]

            # NOTE here that the type/code combination is ummutable
            clause = A(cls(_('type'), _(str(typeVal))),
                       cls(_('code'), _(str(codeVal))))

        if clause is None and '/' in type_:
            type_, sep, code = type_.partition('/')
            try:
                typeVal = int(type_, 10)
                codeVal = int(code, 10)
                clause = A(cls(_('type'), _(str(typeVal))),
                           cls(_('code'), _(str(codeVal))))
            except ValueError:
                pass

        if clause is None and '/' not in type_:
            try:
                typeVal = int(type_, 10)
                clause = cls(_('type'), _(str(typeVal)))
            except ValueError:
                pass

        if clause is None:
            raise ValueError("invalid ICMPv6 type/code %s" % type_)

        if invert:
            clause = N(clause)

        return clause

class GactClause(A):
    """Generic action clause.

    See
    https://fossies.org/linux/iproute2/doc/actions/gact-usage
    """

    @classmethod
    def fromIptables(cls, target, target_args=[]):
        """Expand to a set of tc argument clauses."""

        if target_args:
            raise ValueError("invalid target args %s for %s"
                             % (target_args, target,))

        if target == 'DROP':
            return cls(_('action'), _('drop'))
        if target == 'ACCEPT':
            return cls(_('action'), _('ok'))

        raise ValueError("invalid target %s" % target)

class DropClause(GactClause):

    @classmethod
    def fromIptables(cls, rate=None, burst=None, trap=False):
        """Convert a DROP to police/drop/trap actions."""

        if rate is None and burst is None:
            policeClauses = []
        else:
            policeClauses = [_('action'), _('police'),]
            if rate is not None:
                policeClauses.extend([_('rate'), _(rate),])
            if burst is not None:
                policeClauses.extend([_('burst'), _(burst),])
            policeClauses.extend([_('conform-exceed'), _('drop'),])

        trapClauses = [_('action'), _('trap'),] if trap else []

        return cls.fromClauses(*(policeClauses+trapClauses))

class GotoChainClause(GactClause):

    @classmethod
    def fromIptables(cls, chain=None):
        """Convert a goto to chain."""

        chainClauses = [_('action'), _('goto'),]
        if chain is not None:
            chainClauses.extend([_('chain'), _(chain),])

        return cls.fromClauses(*(chainClauses))

class SkipClause(GactClause):
    """Pseudo-gact clause for skipping IPTABLES rules.

    Here this is not a MetaClause, since it does have a TC expression.
    """

    @classmethod
    def fromIptables(cls, target, target_args=[], log=None):
        """Expand to a set of tc argument clauses."""

        log = log or logging.getLogger(cls.__name__)

        if target != 'SKIP':
            raise ValueError("invalid target %s (should be 'SKIP')" % target)

        if len(target_args) != 2:
            msg = "invalid target args with 'SKIP': %s" % target_args
            raise ValueError(msg)

        # IPTABLES specifies 'skip-rules',
        # later on we need to update this to 'skip-until'
        if target_args[0] != '--skip-rules':
            msg = "invalid target args with 'SKIP': %s" % target_args
            raise ValueError(msg)

        stride = target_args[1]
        try:
            strideVal = int(stride, 10)
        except ValueError as ex:
            msg = ("invalid target args with 'SKIP': %s: %s"
                   % (target_args, str(ex),))
            raise ValueError(msg)
        if not strideVal:
            log.warning("invalid target args with 'SKIP': %s: no-op",
                        target_args)

        return cls(A(_('action'), _('skip')),
                   _(stride))

        # leave this as 'skip' instead of 'jump'
        # so that we can recompute the tc-filter offsets
        # based on iptables rule line numbers

        # XXX rothcar -- will not work with NOT-clauses

    def fixup(self, lineno):
        """Create a fixed-up gact clause given an IPTABLES line number.

        By "fixed up", we create a new pseudo-gact clause with absolute
        IPTABLES rule numbers.

        Here is the reasoning:
        Skip M rules on line M -->
        start processing at the beginning of line N+M+1

        e.g.
        line 10, skip-rules 1 --> continue with line 12
        line 10, skip-rules 0 --> continue with line 11 (corner case)
        """
        stride = int(self.c2.s, 10)
        if self.c1.c2.s == 'skip':
            self.c1.c2.s = 'skip_until'
            self.c2.s = str(lineno+stride+1)
        else:
            raise ValueError("invalid clause for fixup: %s" % self)

class UnsupportedTargetClause(object):

    TARGET = None

    def __init__(self, args):
        self.args = args

    def reduce(self):
        return self

    def __repr__(self):
        if self.args:
            return ("<%s %s>"
                    % (self.__class__.__name__, " ".join(self.args),))
        else:
            return ("<%s>"
                    % (self.__class__.__name__,))

    def clone(self):
        return self.__class__(self.args)

    @classmethod
    def fromIptables(cls,
                     target, target_args=[],
                     ignore=False, accept=False):

        if target != cls.TARGET:
            raise ValueError("invalid target %s, expected %d"
                             % (target, cls.TARGET,))

        if ignore:
            return GactClause(_('action'), _('continue'))
        elif accept:
            return GactClause(_('action'), _('ok'))
        else:
            return cls(target_args)

class LogClause(UnsupportedTargetClause):
    """Logging target clause.

    Currently this is not supported in TC, but we need to parse it.

    When constructing, set 'ignore=True' to instead generate a no-op
    'continue' action.
    """

    TARGET = 'LOG'

class IndevClause(A):
    """Clause to represent the 'indev' interface specifier."""

    @classmethod
    def fromIptables(cls, ifName):
        """Expand to a set of tc argument clauses."""
        return cls(_('indev'), _(ifName))

class UnsupportedFilterClause(object):
    """Parse out a filter clause we don't intend to support.

    Here set match=True to always-match, set match=False to never-match.
    """

    def __init__(self, match=None):
        self.match = match

    def reduce(self):
        return self

class NoOpClause(UnsupportedFilterClause):
    """Represent a no-op that always matches."""

    def __init__(self):
        UnsupportedFilterClause.__init__(self, True)

    def clone(self):
        return self.__class__()

class AddrTypeClause(UnsupportedFilterClause):
    """Parse the addrtype match.

    TC does not have direct support for this.
    XXX rothcar -- we need to reject this by default

    Set extended=True to accept (TBD) address type extensions.
    Set ignore=True to ignore the addrtype match (YMMV).

    See e.g.
    https://linux.die.net/man/8/iptables
    https://unix.stackexchange.com/questions/130807/what-are-the-definitions-of-addrtype-in-iptables
    """

    TYPES = ['UNSPEC',
             'UNICAST',
             'LOCAL',
             'BROADCAST',
             'ANYCAST',
             'MULTICAST',
             'BLACKHOLE',
             'UNREACHABLE',
             'PROHIBIT',
             'THROW',
             'NAT',
             'XRESOLVE',]

    TYPES_EXT = TYPES
    # TBD

    def __init__(self, src, dst, match=None, extended=False):
        UnsupportedFilterClause.__init__(self, match=match)
        self.src = src
        self.dst = dst
        self.extended = extended

    @classmethod
    def fromIptables(cls,
                     src_type=None, dst_type=None,
                     match=None, extended=False):

        if src_type is None and dst_type is None:
            raise ValueError("missing --src-type and --dst-type")

        types = cls.TYPES_EXT if extended else cls.TYPES

        if src_type is not None and src_type not in types:
            raise ValueError("invalid --src-type %s" % src_type)

        if dst_type is not None and dst_type not in types:
            raise ValueError("invalid --dst-type %s" % src_type)

        return cls(src_type, dst_type, match=match, extended=extended)

    def __repr__(self):
        buf = "<AddrTypeClause"
        if self.match is True:
            buf += " TRUE"
        if self.match is False:
            buf += " FALSE"
        if self.extended:
            buf += " [extended]"
        if self.src is not None:
            buf += " src=%s" % self.src
        if self.dst is not None:
            buf += " src=%s" % self.dst
        buf += ">"
        return buf

    def clone(self):
        return self.__class__(self.src, self.dst,
                              match=self.match,
                              extended=self.extended)

class VlanTagClause(A):
    """Match packets with a VLAN tag.

    This is a superset of IPTABLES and ebtables functionality,
    but is supported in tc-flower in the same filter.

    NOTE that this changes the ip_proto clause above.

    e.g.

    tc filter add dev swp1 protocol ip ingress flower src_ip 1.1.1.1 action pass

    for vid 100 this becomes

    tc filter add dev swp1 protocol 802.1q ingress flower vlan_ethtype ipv4 vlan_id 100 src_ip 1.1.1.1 action pass

    We'll need to fix this up in the Organizer below.

    Currently QinQ is not supported.
    """

    @classmethod
    def fromIptables(cls, vid, version=socket.AF_INET):
        """Expand to set of tc argument clauses.

        This is the basic clause constructor that does not know
        the protocol yet.
        """

        if vid == 'any':
            if version == socket.AF_INET:
                return cls(_('vlan_ethtype'), _('ipv4'))

            if version == socket.AF_INET6:
                return cls(_('vlan_ethtype'), _('ipv6'))

        vid = int(vid, 10)
        if vid < 1 or vid >= 4095:
            raise ValueError("invalid vlan tag %d" % vid)

        if version == socket.AF_INET:
            return cls(A(_('vlan_ethtype'), _('ipv4')),
                       A(_('vlan_id'), _(str(vid))))

        if version == socket.AF_INET6:
            return cls(A(_('vlan_ethtype'), _('ipv6')),
                       A(_('vlan_id'), _(str(vid))))

        versionHex = hex(version)[2:]
        return cls(A(_('vlan_ethtype'), _(versionHex)),
                   A(_('vlan_id'), _(str(vid))))

class StatementList(object):
    """Generate a list of statements from a clause AST.

    The AST represents a single IPTABLES statement that
    may be expanded to multiple TC statements.
    """

    def __init__(self, clause, action=None, log=None):
        self.log = log or logging.getLogger(self.__class__.__name__)
        self.clause = clause
        self.action = action

    def reduce(self):
        """Iteratively reduce the clauses AST.

        Stop when it cannot be reduced further.
        """
        while True:
            clause_ = self.clause.reduce()
            if clause_ is self.clause:
                break
            self.clause = clause_

    def partitionAnd(self, c):
        """Partition and AND-tree into positive and negative terms."""

        terms = []

        if isinstance(c, (LiteralClause, MetaClause,
                          UnsupportedFilterClause,
                          UnsupportedTargetClause,)):
            term = (c, True,)
            return [term]

        if (isinstance(c, NotClause)
            and isinstance(c.c, (LiteralClause, ImmutableAndClause,))):
            term = (c.c, False,)
            return [term]

        if isinstance(c, AndClause):
            return self.partitionAnd(c.c1) + self.partitionAnd(c.c2)

        raise ValueError("cannot expand clause %s with and-clause" % c)

    def partitionOr(self, c):
        """Generate a sequence of AND-partitions from an OR-tree."""

        if isinstance(c, (LiteralClause, LineNumberClause,)):
            term = (c, True,)
            terms = [term]
            return [terms]

        if (isinstance(c, NotClause)
            and isinstance(c.c, (LiteralClause, ImmutableAndClause,))):
            term = (c.c, False,)
            terms = [term]
            return [terms]

        if isinstance(c, AndClause):
            terms = self.partitionAnd(c)
            return [terms]

        if isinstance(c, OrClause):
            return self.partitionOr(c.c1) + self.partitionOr(c.c2)

        raise ValueError("cannot expand clause %s with or-clause" % c)

    def clauseTerms(self, clause):
        """Compute a list of terms from a clause."""

        if isinstance(clause, LiteralClause):
            return [clause.s]

        if isinstance(clause, MetaClause):
            return []
        # already consumed as part of annotate()

        if (isinstance(clause, UnsupportedFilterClause)
            and clause.match is True):
            return []

        if isinstance(clause, ImmutableAndClause):
            return self.clauseTerms(clause.c1) + self.clauseTerms(clause.c2)

        raise ValueError("cannot compute terms for %s" % clause)

    def statementTerms(self, terms):
        stmt = []
        terms = list(terms)
        try:
            [stmt.extend(self.clauseTerms(t)) for t in terms]
        except ValueError as ex:
            self.log.error("invalid term list:")
            buf = ", ".join(str(t) for t in terms)
            self.log.error("<AndClause AND(%s)>" % buf)
            raise
        return stmt

    def annotate(self):
        """Annotate the clauses after they have been reduced."""

        # find the IPTABLES line number for this set of TC filters
        q = [self.clause]
        lineNumbers = set()
        while q:
            clause = q.pop(0)

            if isinstance(clause, LineNumberClause):
                lineNumbers.add(clause.lineno)
                continue
            if isinstance(clause, (AndClause, OrClause, ImmutableAndClause,)):
                q.append(clause.c1)
                q.append(clause.c2)
                continue
            if isinstance(clause, (NotClause,)):
                q.append(clause.c)
                continue

        if len(lineNumbers) > 1:
            raise ValueError("multiple line number annotations: %s"
                             % ", ".join(sorted(list(lineNumbers))))
        lineno = next(iter(lineNumbers)) if lineNumbers else None

        # find any 'skip' clauses and try to annotate them
        q = [self.clause]
        while q:
            clause = q.pop(0)

            # find all gact clauses that refer to skipping IPTABLES rules,
            # and relabel them with the target IPTABLES target lineno

            if isinstance(clause, SkipClause):
                if lineno is None:
                    raise ValueError("invalid clause (no line number): %s"
                                     % clause)
                clause.fixup(lineno)
                continue

            # else, iteratively expand

            if isinstance(clause, (AndClause, OrClause, ImmutableAndClause,)):
                q.append(clause.c1)
                q.append(clause.c2)
                continue
            if isinstance(clause, (NotClause,)):
                q.append(clause.c)
                continue

    def expand(self):
        """Iteratively expand the clauses AST.

        Here we can make assumptions about the layout of the AST.
        Return a list of TC argument tuples.
        """

        # generate a list of statements represented by term-lists
        # where each term in the term-list is a tuple of
        # (literal-value, negated)

        if isinstance(self.clause, (MetaClause, LiteralClause,
                                    UnsupportedFilterClause,
                                    UnsupportedTargetClause,)):
            # single clause consisting of a single literal or meta
            term = (self.clause, True,)
            terms = [term]
            stmts = [terms]
        elif (isinstance(self.clause, NotClause)
              and isinstance(self.clause.c, (LiteralClause, ImmutableAndClause,))):
            # single clause consisting of an inverted single literal
            # or tree of ummutable AND clauses
            term = (self.clause.c, False,)
            terms = [term]
            stmts = [terms]
        elif isinstance(self.clause, AndClause):
            # AND-tree of terminal literals, some of them negated
            terms = self.partitionAnd(self.clause)
            stmts = [terms]
        elif isinstance(self.clause, OrClause):
            # OR-tree of AND-trees and terminals
            stmts = self.partitionOr(self.clause)
        else:
            raise ValueError("cannot expand clause %s" % self.clause)

        # now, serialize the statements
        stmts_ = []
        action_ = "default" if self.action is None else self.action

        for terms in stmts:
            # (term, True/False) for x in terms

            # ignore this statement if there are any match=False terms
            falseTerms = [x for x in terms if (isinstance(x[0], UnsupportedFilterClause)
                                               and x[0].match is False)]
            if falseTerms:
                self.log.warning("dropping statement due to false-terms: %s", terms)
                continue

            # compute a LUT of indices for any negated terms
            negMap = {}
            for idx, term in enumerate(terms):
                if term[1] is False:
                    negMap[idx] = None

            if negMap:

                # generate a jump-statement using each negated term
                for stride_, negIdx in enumerate(sorted(negMap.keys())):
                    stride = len(negMap)-stride_

                    # generate a statement with all positive terms
                    # and the single negative term at negIdx
                    terms_ = []
                    for idx, term in enumerate(terms):
                        if term[1]:
                            terms_.append(term[0])
                        elif idx == negIdx:
                            terms_.append(term[0])
                    stmt_ = self.statementTerms(terms_)

                    # if the statement included an embedded action,
                    # replace it
                    if 'action' in stmt_:
                        idx = stmt_.index('action')
                        del stmt_[idx:]

                    stmt_.extend(['action', 'jump', str(stride)])
                    stmts_.append(stmt_)

                # then include a default statement with just
                # the positive terms
                stmt_ = self.statementTerms(x[0] for x in terms if x[1])

                if 'action' not in stmt_:
                    # add the default action unless one is specified
                    stmt_.extend(['action', action_,])
                elif self.action is not None:
                    # non-default action conflicts with embedded action
                    raise ValueError("non-default action '%s' with statement '%s'"
                                     % (self.action,
                                        " ".join(self.stmt_),))
                stmts_.append(stmt_)
            else:
                # no negated terms, just compute a statement
                # consisting of all positive terms
                stmt_ = self.statementTerms(x[0] for x in terms if x[1])
                if 'action' not in stmt_:
                    # add the default action unless one is specified
                    stmt_.extend(['action', action_])
                elif self.action is not None:
                    # non-default action conflicts with embedded action
                    raise ValueError("non-default action '%s' with statement '%s'"
                                     % (self.action,
                                        " ".join(stmt_),))
                stmts_.append(stmt_)

        return stmts_

class Organizer(object):

    ANNOTATIONS = (LineNumberClause,)
    ACTIONS = (GactClause, LogClause,)

    def __init__(self, clauses,
                 continue_suppress=False,
                 log=None):
        self.clauses = clauses
        self.continue_suppress = continue_suppress
        self.log = log or logging.getLogger(self.__class__.__name__)

    def reorder(self):

        annots = [x for x in self.clauses if isinstance(x, self.ANNOTATIONS)]
        clauses = [x for x in self.clauses if not isinstance(x, self.ANNOTATIONS)]
        # re-order so annotations are at the beginning

        actions = [x for x in clauses if isinstance(x, self.ACTIONS)]
        filters = [x for x in clauses if not isinstance(x, self.ACTIONS)]
        # re-order so gact clauses are at the end

        vlan_filters = [x for x in filters if isinstance(x, VlanTagClause)]
        filters = [x for x in filters if not isinstance(x, VlanTagClause)]
        # move vlan_ethtype to the beginning,
        # else ip_proto etc. will fail

        # elide any GACT clauses we don't support
        if not actions:
            raise ValueError("invalid clauses (no actions): %s"
                             % self.clauses)
        def _fn(cl):
            if not isinstance(cl, GactClause): return True
            if cl.c2.s != 'continue' : return True
            if not self.continue_suppress: return True
            return False
        actions = [x for x in actions if _fn(x)]
        if not actions:
            self.log.warning("statement suppressed: %s", self.clauses)
            return None

        # XXX rothcar -- there are likely other ordering issues with TC args

        clauses = annots+vlan_filters+filters+actions

        return a.fromClauses(*clauses)

class TcStmt(object):
    def __init__(self, tc_chain, stmts):
        """Object to contain both chain and the filter arguments"""
        self.tc_chain = tc_chain
        self.stmts = stmts

class Translator(object):

    def __init__(self, version=socket.AF_INET,
                 shared=False,
                 log_ignore=False,
                 addrtype=None,
                 match_multi=False,
                 port_unroll=None,
                 hack_vlan_arp=False,
                 drop_mode=None,
                 reject_drop=True,
                 continue_suppress=False,
                 prestera_chain_mode=False,
                 log=None):
        """IPTABLES to TC-flower translator."""
        self.version = version
        self.shared = shared
        self.log_ignore = log_ignore
        self.addrtype = addrtype
        self.match_multi = match_multi
        self.port_unroll = port_unroll
        self.hack_vlan_arp = hack_vlan_arp
        self.drop_mode = drop_mode
        self.reject_drop = reject_drop
        self.continue_suppress = continue_suppress
        self.prestera_chain_mode = prestera_chain_mode
        self.log = log or logging.getLogger(self.__class__.__name__)

        self.clear()

    def clear(self):
        self.lineno = 0
        self.stmts = []
        self.offsets = {}
        self.tc_chain_keys = {TC_CHAIN_DEFAULT:{}, TC_CHAIN_ICMP: {}} # two chains

    def feed(self, rule, lineno=None):
        """Add a single rule to the statement list."""

        args = list(rule.args)

        args.extend(rule.tc_args)
        # include embedded TC-specific args

        clauses = []
        icmp_clauses = []
        # top-level clauses, AND'd together

        modules = []
        # list of match modules invoked

        if lineno is True:
            self.lineno += 1
            lineno = self.lineno
        # lineno==True --> keep an internal counter

        if lineno is not None:
            clauses.append(LineNumberClause(lineno))

        keys = {}
        icmp_keys = {}

        if self.shared and rule.in_interface is not None:
            keys['L1.indev'] = rule.in_interface
            clause = IndevClause.fromIptables(rule.in_interface)
            clauses.append(clause)
            icmp_clauses.append(clause)

        while args:

            if (len(args) >= 2
                and args[0] in ('-p', '--protocol',)):
                args.pop(0)
                arg = args.pop(0)
                clause = IpProtoClause.fromIptables(arg,
                                                    version=self.version,
                                                    log=self.log)
                clauses.append(clause)
                icmp_clauses.append(clause)
                keys['L3.ip_proto'] = arg
                if arg in ["icmp", "icmpv6", ]:
                    icmp_keys['L3.ip_proto'] = arg
                continue

            if (len(args) >= 3
                and args[0] == '!'
                and args[1] in ('-p', '--protocol',)):
                args.pop(0)
                args.pop(0)
                arg = args.pop(0)
                clause = IpProtoClause.fromIptables(arg,
                                                    invert=True, version=self.version,
                                                    log=self.log)
                clauses.append(clause)
                icmp_clauses.append(clause)
                keys['L3.ip_proto'] = arg
                continue

            if (len(args) >= 2
                and args[0] in ('-s', '--source',)):
                args.pop(0)
                arg = args.pop(0)
                klass = MultiSrcIpClause if self.match_multi else SrcIpClause
                clause = klass.fromIptables(arg, version=self.version)
                clauses.append(clause)
                icmp_clauses.append(clause)
                keys['L3.src_ip'] = '0.0.0.0'
                continue

            if (len(args) >= 3
                and args[0] == '!'
                and args[1] in ('-s', '--source',)):
                args.pop(0)
                args.pop(0)
                arg = args.pop(0)
                klass = MultiSrcIpClause if self.match_multi else SrcIpClause
                clause = klass.fromIptables(arg, invert=True, version=self.version)
                clauses.append(clause)
                icmp_clauses.append(clause)
                keys['L3.src_ip'] = '0.0.0.0'
                continue

            if (len(args) >= 2
                and args[0] in ('-d', '--destination',)):
                args.pop(0)
                arg = args.pop(0)
                klass = MultiDstIpClause if self.match_multi else DstIpClause
                clause = klass.fromIptables(arg, version=self.version)
                clauses.append(clause)
                icmp_clauses.append(clause)
                keys['L3.dst_ip'] = '0.0.0.0'
                continue

            if (len(args) >= 3
                and args[0] == '!'
                and args[1] in ('-d', '--destination',)):
                args.pop(0)
                args.pop(0)
                arg = args.pop(0)
                klass = MultiDstIpClause if self.match_multi else DstIpClause
                clause = klass.fromIptables(arg, invert=True, version=self.version)
                clauses.append(clause)
                icmp_clauses.append(clause)
                keys['L3.dst_ip'] = '0.0.0.0'
                continue

            # parse the match modules
            if (len(args) > 2
                and args[0] in ('-m', '--match',)):
                args.pop(0)
                arg = args.pop(0)
                if self.version == socket.AF_INET and arg in MODULES_ALL:
                    modules.append(arg)
                elif self.version == socket.AF_INET6 and arg in MODULES_ALL_V6:
                    modules.append(arg)
                else:
                    raise ValueError("invalid IPTABLES match %s" % arg)
                continue

            if (len(args) >= 2
                and args[0] in ('--sport', '--source-port',)):
                args.pop(0)
                arg = args.pop(0)
                klass = MultiSrcPortClause if self.match_multi else SrcPortClause
                clause = klass.fromIptables(arg, unroll=self.port_unroll)
                clauses.append(clause)
                icmp_clauses.append(clause)
                keys['L4.src_port'] = '65535'
                continue

            if (len(args) >= 3
                and args[0] == '!'
                and args[1] in ('--sport', '--source-port',)):
                args.pop(0)
                args.pop(0)
                arg = args.pop(0)
                klass = MultiSrcPortClause if self.match_multi else SrcPortClause
                clause = klass.fromIptables(arg,
                                            unroll=self.port_unroll,
                                            invert=True)
                clauses.append(clause)
                icmp_clauses.append(clause)
                keys['L4.src_port'] = '65535'
                continue

            if (len(args) >= 2
                and args[0] in ('--dport', '--destination-port',)):
                args.pop(0)
                arg = args.pop(0)
                klass = MultiDstPortClause if self.match_multi else DstPortClause
                clause = klass.fromIptables(arg, unroll=self.port_unroll)
                clauses.append(clause)
                icmp_clauses.append(clause)
                keys['L4.dst_port'] = '65535'
                continue

            if (len(args) >= 3
                and args[0] == '!'
                and args[1] in ('--dport', '--destination-port',)):
                args.pop(0)
                args.pop(0)
                arg = args.pop(0)
                klass = MultiDstPortClause if self.match_multi else DstPortClause
                clause = klass.fromIptables(arg,
                                            unroll=self.port_unroll,
                                            invert=True)
                clauses.append(clause)
                icmp_clauses.append(clause)
                keys['L4.dst_port'] = '65535'
                continue

            if (len(args) >= 2
                and args[0] == '--mac-source'):
                args.pop(0)
                arg = args.pop(0)
                clause = SrcMacClause.fromIptables(arg)
                clauses.append(clause)
                icmp_clauses.append(clause)
                keys['L2.src_mac'] = 'ff:ff:ff:ff:ff:ff'
                continue

            if (len(args) >= 3
                and args[0] == '!'
                and args[1] == '--mac-source'):
                args.pop(0)
                args.pop(0)
                arg = args.pop(0)
                clause = SrcMacClause.fromIptables(arg, invert=True)
                clauses.append(clause)
                icmp_clauses.append(clause)
                keys['L2.src_mac'] = 'ff:ff:ff:ff:ff:ff'
                continue

            if (args[0] == '--fragment'):
                args.pop(0)
                clause = IpFlagsClause.fromIptables(fragment=True)
                clauses.append(clause)
                icmp_clauses.append(clause)
                keys['L4.ip_flags'] = 'frag'
                continue

            if (len(args) >= 2
                and args[0] == '!'
                and args[1] == '--fragment'):
                args.pop(0)
                args.pop(0)
                clause = IpFlagsClause.fromIptables(fragment=True, invert=True)
                clauses.append(clause)
                icmp_clauses.append(clause)
                keys['L4.ip_flags'] = 'frag'
                continue

            if (len(args) >= 2
                and args[0] == '--icmp-type'):
                args.pop(0)
                arg = args.pop(0)
                clause = IcmpTypeCodeClause.fromIptables(arg)
                clauses.append(clause)
                icmp_keys['L4.type'] = '0'
                icmp_keys['L4.code'] = '0'
                continue

            if (len(args) >= 3
                and args[0] == '!'
                and args[1] == '--icmp-type'):
                args.pop(0)
                args.pop(0)
                arg = args.pop(0)
                clause = IcmpTypeCodeClause.fromIptables(arg, invert=True)
                clauses.append(clause)
                icmp_keys['L4.type'] = '0'
                icmp_keys['L4.code'] = '0'
                continue

            if (len(args) >= 2
                and args[0] == '--icmpv6-type'):
                args.pop(0)
                arg = args.pop(0)
                clause = IcmpV6TypeCodeClause.fromIptables(arg)
                clauses.append(clause)
                icmp_keys['L4.code'] = '0'
                icmp_keys['L4.type'] = '0'
                continue

            if (len(args) >= 3
                and args[0] == '!'
                and args[1] == '--icmpv6-type'):
                args.pop(0)
                args.pop(0)
                arg = args.pop(0)
                clause = IcmpV6TypeCodeClause.fromIptables(arg, invert=True)
                clauses.append(clause)
                icmp_keys['L4.type'] = '0'
                icmp_keys['L4.code'] = '0'
                continue

            if (len(args) >= 2
                and args[0] == '--src-type'):
                args.pop(0)
                arg = args.pop(0)
                clause = AddrTypeClause.fromIptables(src_type=arg,
                                                     match=self.addrtype,
                                                     extended=False)
                clauses.append(clause)
                continue

            if (len(args) >= 2
                and args[0] == '--dst-type'):
                args.pop(0)
                arg = args.pop(0)
                clause = AddrTypeClause.fromIptables(dst_type=arg,
                                                     match=self.addrtype,
                                                     extended=False)
                clauses.append(clause)
                continue

            if (len(args) >= 2
                and args[0] == '--vlan-tag'):
                args.pop(0)
                arg = args.pop(0)
                clause = VlanTagClause.fromIptables(arg, version=self.version)
                clauses.append(clause)
                keys['L2.vlan_id'] = '4095'
                continue

            raise ValueError("invalid IPTABLES arg %s" % args[0])

        # populate the keys here for chain that is used
        for k,v in keys.items():
            # if there are any icmp keys then dont bother touching the chain 0
            if k == "L3.ip_proto" and k in self.tc_chain_keys[TC_CHAIN_DEFAULT] and icmp_keys:
                continue
            self.tc_chain_keys[TC_CHAIN_DEFAULT][k] = v
        # now if there are icmp keys then program the second chain
        if self.prestera_chain_mode and icmp_keys:
            # need the normal key's as well
            for k,v in keys.items():
                self.tc_chain_keys[TC_CHAIN_ICMP][k] = v
            for k,v in icmp_keys.items():
                self.tc_chain_keys[TC_CHAIN_ICMP][k] = v

        if rule.target == 'SKIP':
            clause = SkipClause.fromIptables(rule.target,
                                             target_args=rule.target_args)
            clauses.append(clause)
        elif rule.target == 'LOG':
            clause = LogClause.fromIptables(rule.target,
                                            target_args=rule.target_args,
                                            ignore=self.log_ignore)
            clauses.append(clause)
        elif rule.target == 'DROP' and self.drop_mode is not None:
            if rule.target_args:
                raise ValueError("invalid target args %s for %s"
                                 % (rule.target_args, rule.target,))
            # police rate, burst window, trap-mode
            police, burst, trap = self.drop_mode
            if police or burst or trap:
                clause = DropClause.fromIptables(police, burst, trap)
            else:
                clause = GactClause.fromIptables(rule.target,
                                                 target_args=rule.target_args)
            clauses.append(clause)
        elif rule.target == 'REJECT':
            if self.reject_drop:
                clause = GactClause.fromIptables('DROP')
                clauses.append(clause)
            else:
                raise ValueError("invalid target %s" % rule.target)
        elif rule.target:
            clause = GactClause.fromIptables(rule.target,
                                             target_args=rule.target_args)
            clauses.append(clause)
        else:
            raise MissingTarget(rule, "IPTABLES rule has no action")

        # detect the protocol version (IP or IPv6)

        # XXX rothcar -- here is our chance to re-order the TC actions
        # to be syntactically correct (IPTABLES is a bit more leniant)
        org = Organizer(clauses,
                        continue_suppress=self.continue_suppress,
                        log=self.log)
        clause = org.reorder()

        if clause is not None:
            # XXX rothcar -- no need to add an action to StatementList,
            # we added a proper GactClause above before expansion
            sl = StatementList(clause, log=self.log)
            sl.reduce()
            sl.annotate()
            newStmts = sl.expand()
        else:
            newStmts = []

        if newStmts is None:
            raise ValueError("cannot translate rule %s", rule)

        # store the starting offset for this current line number
        if lineno is not None:
            self.offsets[lineno] = len(self.stmts)

        if self.prestera_chain_mode and icmp_keys:
            self.stmts.extend([TcStmt(TC_CHAIN_ICMP, s) for s in newStmts])

            # now put the jump in chain 0 to goto chain 1
            icmp_clauses.append(GotoChainClause.fromIptables(chain=TC_CHAIN_ICMP))
            org = Organizer(icmp_clauses,
                            continue_suppress=self.continue_suppress,
                            log=self.log)
            clause = org.reorder()
            # XXX rothcar -- no need to add an action to StatementList,
            # we added a proper GactClause above before expansion
            sl = StatementList(clause, log=self.log)
            sl.reduce()
            sl.annotate()
            newStmts = sl.expand()
            self.stmts.extend([TcStmt(TC_CHAIN_DEFAULT, s) for s in newStmts])
        else:
            self.stmts.extend([TcStmt(TC_CHAIN_DEFAULT, s) for s in newStmts])

    def commit(self, policy='ACCEPT', lineno=None):
        """Perform any fixups after all of the rules are added."""

        # add a final offset for end-of-rules

        if lineno is True:
            lineno = self.lineno+1
        if lineno is not None:
            self.offsets[lineno] = len(self.stmts)

        if policy == 'ACCEPT':
            pass
        elif policy == 'DROP':
            self.stmts.append(TcStmt(TC_CHAIN_DEFAULT,['action', 'drop',]))
        else:
            raise ValueError("invalid chain policy %s" % policy)

        # fixup the skip_until actions
        for idx, stmt in enumerate(self.stmts):
            if stmt.stmts[-3:-1] == ['action', 'skip_until',]:
                tgt = int(stmt.stmts[-1], 10)
                if tgt not in self.offsets:
                    raise ValueError("invalid IPTABLES line %d (statement %s)"
                                     % (tgt, stmt.stmts,))
                stride = self.offsets[tgt] - idx - 1
                self.log.debug("rule index %d: target IPTABLES line %d --> jump %d",
                               idx, tgt, stride)
                stmt.stmts[-2:] = ['jump', str(stride),]

        if self.hack_vlan_arp and self.version != socket.AF_INET:
            raise ValueError("--hack-vlan-arp only applies to IPv4")
        if self.hack_vlan_arp:
            self.stmts[0:0] = [TcStmt(TC_CHAIN_DEFAULT, ['vlan_ethtype', 'arp', 'action', 'ok',])]
