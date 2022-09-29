"""Unroller.py

Implement the unroll algorithm.
"""

import logging

class Unroller(object):

    def __init__(self, table, chain='INPUT',
                 overrideInterface=False, extended=True,
                 log=None):
        self.log = log or logging.getLogger(self.__class__.__name__)
        self.table = table
        self.chain = chain
        self.overrideInterface = overrideInterface
        self.extended = extended

    def unrollChain(self, chain='INPUT',
                    in_interface=None, overrideInterface=False,
                    gotoDepth=0):
        """Unroll a single filter chain.

        Use a pseudo-target for skipping rules (will be translated into
        a TC 'skip' action)

        Returns a list of rules.

        Keep track of the number of nested GOTO statements here,
        so that we can properly compute the number of frames to pop
        when we eventually RETURN.

        Keep track of the in_interface specifier for the parent rule;
        unless it is overridden in a child rule, the child rules are
        attached to the same in_interface (otherwise slicing does not work).
        """

        expandedRules = []
        if chain not in self.table.chains:
            raise ValueError("invalid chain/target %s" % chain)
        rootChain = self.table.chains[chain]
        rules = [x.clone() for x in rootChain.rules]

        for ruleIdx, rule in enumerate(rules):

            if (in_interface is not None
                and rule.in_interface is not None
                and in_interface != rule.in_interface):
                self.log.warning("parent rule: --in-interface %s", in_interface)
                self.log.warning("chain %s child rule #%d: --in-interface %s",
                                 chain, ruleIdx+1, rule.in_interface)
                if overrideInterface:
                    self.log.warning("JUMP/GOTO interface override, probably does not match")
                else:
                    self.log.error("JUMP/GOTO interface override not allowed")
                    raise ValueError("chain/interface mismatch during unrolling")

                rule = rule.clone()
                if rule.comment is not None:
                    comment_ = ("%s (parent --in-interface %s)"
                                % (rule.comment, in_interface,))
                else:
                    comment_ = "parent --in-interface %s" % in_interface
                rule.comment = comment_

            # if the parent rule has an in_interface specifier,
            # it is provided as the default
            # (though it does not override a rule-specific explicit in_interface)
            if (in_interface is not None
                and rule.in_interface is None):
                rule = rule.clone()
                rule.in_interface = in_interface

            # simple rules, no expansion
            if rule.target in ('ACCEPT', 'DROP', 'REJECT',):
                expandedRules.append(rule)
                continue

            # supported by IPTABLES but not by TC
            if self.extended and rule.target in ('LOG',):
                self.log.warning("chain %s rule #%d target %s may be unsupported",
                                 chain, ruleIdx+1, rule.target)
                expandedRules.append(rule)
                continue

            if rule.target == 'SKIP':
                msg = "invalid SKIP target in chain %s" % chain
                raise ValueError(msg)

            # 'RETURN' --> skip to the end of this chain,
            # assuming it is being inserted inline into a parent
            # chain with a matching JUMP.
            # We have not computed the length of the child rule(s),
            # so here we keep track of the index for fixups later.
            if rule.target == 'RETURN':
                # we only add RETURN target args when popping
                if rule.target_args:
                    msg = ("invalid RETURN args [%s] in chain %s rule #%d"
                           % (rule.target_args, chain, ruleIdx+1,))
                    raise ValueError(msg)
                frames = 1+gotoDepth
                if rule.comment is not None:
                    comment_ = ("%s -- return %d frame(s)"
                                % (rule.comment, frames,))
                else:
                    comment_ = ("return %d frame(s)"
                                % (frames,))
                rule.comment = comment_
                rule.target_args = ['--return-frames', str(frames),]
                expandedRules.append(rule)
                continue

            # else, this is a chain reference, decompose recursively
            # while keeping track of the number of GOTOs
            try:
                if rule.return_:
                    childRules = self.unrollChain(rule.target,
                                                  in_interface=rule.in_interface,
                                                  overrideInterface=overrideInterface,
                                                  gotoDepth=0)
                else:
                    childRules = self.unrollChain(rule.target,
                                                  in_interface=rule.in_interface,
                                                  overrideInterface=overrideInterface,
                                                  gotoDepth=gotoDepth+1)
            except ValueError as ex:
                self.log.error("unrolling %s failed in chain %s rule #%d: %s",
                               rule.target, chain, ruleIdx+1, str(ex))
                raise

            if rule.return_:
                # unrolling a jump-with-return:
                # 1. original jump acl (true-clause) is rewritten to
                #    skip one rule (past the false clause)
                # 2. false clause is inserted (always match)
                #    that skips N rules, where N is the length of the sub-chain
                # 3. sub-chain is inserted inline
                # 4. no terminal statement required for the sub-chain,
                #    since the fall-through is an implcit 'RETURN'.
                tgt = 'SKIP'
                tgt_args = ['--skip-rules', '1',]
                trueRule = rule.clone(target=tgt, target_args=tgt_args)
                tgt_args = ['--skip-rules', str(len(childRules)),]
                if rule.comment is not None:
                    comment_ = ("%s (%s --> %s false branch)"
                                % (rule.comment, chain, rule.target,))
                    args = ['-m', 'comment', '--comment', comment_,]
                else:
                    comment_ = ("%s false branch" % chain)
                    args = []
                falseRule = rule.clone(target=tgt, target_args=tgt_args)
                falseRule.args = []
                falseRule.comment = comment_
                expandedRules.append(trueRule)
                expandedRules.append(falseRule)
                expandedRules.extend(childRules)
                if not len(childRules):
                    self.log.warning("empty RETURN (no-op) during unroll: %s", falseRule)
            else:
                # unrolling a goto (assuming no return)
                # 1. add a terminal rule to the child chain
                #    that stops processing and does a RETURN
                # 2. original jump acl (true-clause) is rewritten to
                #    skip one rule (past the false clause)
                # 3. false clause is inserted (always match)
                #    that skips N+1 rules, where N is the length of the sub-chain,
                #    and the N+1'th rule is from step (1)
                # 4. sub-chain is inserted inline

                frames = 1+gotoDepth
                comment_ = ("%s --> %s tail rule -- return %d frame(s)"
                            % (chain, rule.target, frames,))
                args = ('-m', 'comment', '--comment', comment_,)
                tgt = 'RETURN'
                tgt_args = ['--return-frames', str(frames),]
                tailRule = self.table.rule_klass(args, target=tgt, target_args=tgt_args)
                childRules.append(tailRule)

                tgt = 'SKIP'
                tgt_args = ['--skip-rules', '1',]
                trueRule = rule.clone(target=tgt, target_args=tgt_args)
                tgt_args = ['--skip-rules', str(len(childRules)),]
                if rule.comment is not None:
                    comment_ = ("%s (%s --> %s false branch)"
                                % (rule.comment, chain, rule.target,))
                    args = ['-m', 'comment', '--comment', comment_,]
                else:
                    comment_ = ("%s false branch" % chain)
                    args = ['-m', 'comment', '--comment', comment_,]
                falseRule = rule.clone(target=tgt, target_args=tgt_args)
                falseRule.args = []
                falseRule.comment = comment_
                expandedRules.append(trueRule)
                expandedRules.append(falseRule)
                expandedRules.extend(childRules)

        # finished expanding child rules, now handle the return statements
        # - each direct RETURN (--return-frames 1) jumps to the end
        #   of this chain
        # - each other RETURN has its return-frames argument decremented.
        for stmtIdx, rule in enumerate(expandedRules):
            remain = len(expandedRules)-stmtIdx-1

            if (rule.target == 'RETURN'
                and rule.target_args == ['--return-frames', '1',]):
                rule.target = 'SKIP'
                rule.target_args = ['--skip-rules', str(remain),]
                if not remain:
                    self.log.warning("empty RETURN (no-op) during unroll: %s", rule)
                continue

            if (rule.target == 'RETURN'
                and rule.target_args[0:1] == ['--return-frames',]):
                frames = int(rule.target_args[1], 10)
                frames -= 1
                if frames <= 0:
                    raise ValueError("return frames underflow in rule %d"
                                     % stmtIdx)
                rule.target_args[1] = str(frames)
                continue

            if rule.target == 'RETURN':
                raise ValueError("unhandled RETURN frame")

        return expandedRules

    def unroll(self, chain='INPUT', overrideInterface=False):
        """Unroll a single chain in a filter table.

        Returns an updated table with the unrolled chain.

        All of the other chains and tables are deleted in the new table.
        """
        rootChain = self.table.chains[self.chain]
        rootPolicy = rootChain.policy
        expandedRules = self.unrollChain(chain=self.chain,
                                         overrideInterface=self.overrideInterface)
        table = self.table.__class__(log=self.log)
        table.chains[self.chain] = table.chain_klass(expandedRules, rootPolicy)
        return table
