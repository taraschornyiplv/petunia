"""JsonUtils.py

Work around warts in the iproute2 JSON output.
"""

import json

import logging

import re
KEY_RE = re.compile('([^\s,}]+)(?=\s)')
VAL_RE = re.compile('([^\s,}]+)(?=[\s,}])')

class LazyParser(object):

    TOKENS = []

    def __init__(self, log=None):
        self.log = log or logging.getLogger(self.__class_.__name__)

    def loads(self, buf):

        pos = 0
        warned = False

        while True:
            try:
                return json.loads(buf)
            except json.JSONDecodeError as ex:

                if ex.pos <= pos:
                    self.log.warning("unable to fix parse error at %s", str(ex))
                    raise

                pos = ex.pos

                if 'Expecting \',\'' in ex.msg:
                    if not warned:
                        self.log.warning("found garbled text in dict context at %d",
                                         ex.pos)
                        self.log.warning("JSON fixups may be needed...")
                        warned = True
                    buf = self.tokenizeDict(buf, ex.pos)
                    continue

                self.log.error("uncorrectedable error %s", str(ex))

    def tokenizeDict(self, buf, pos):
        """Try to force tokenization of a corrupted JSON stream."""

        lhs, rhs = buf[:pos], buf[pos:]
        lhs = lhs.rstrip()
        rhs = rhs.lstrip()

        while True:

            m = KEY_RE.match(rhs)
            if m is None:
                return lhs+rhs

            tok = rhs[:m.end(1)]
            rhs = rhs[m.end(1):].lstrip()

            if tok not in self.TOKENS:
                return lhs+rhs

            m = VAL_RE.match(rhs)
            if m is None:
                self.log.warning("cannot find a value at %d", pos)
                self.log.warning("JSON fixups failed!")
                return lhs+rhs
            val = rhs[:m.end(1)]
            rhs = rhs[m.end(1):]

            tok, val = self.handle_attr(tok, val)
            if type(val) == int:
                lhs += ", \"%s\" : %d" % (tok, val)
            else:
                lhs += ", \"%s\" : \"%s\"" % (tok, val,)

    def handle_attr(self, token, value):
        return (token, value,)

class LazyFilterParser(LazyParser):
    """Fixup broken JSON emitted by m_police.c."""

    TOKENS = ['police',
              'rate', 'burst',
              'mtu', 'overhead', 'linklayer',
              'ref', 'bind',]

    def handle_attr(self, token, value):
        if token == 'police':
            return ('kind', token,)
        return LazyParser.handle_attr(self, token, value)
