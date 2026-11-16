import logging
import os
from typing import Callable, Optional
from dataclasses import dataclass
from .parser import Rule

log = logging.getLogger(__name__)

add_if_missing_rule = "__add_if_missing_rule__"


# eq=False so instances hash and compare by identity. (`inputs` is a dict, which is
# unhashable, and the sequencer tracks instances in a set.)
@dataclass(eq=False)
class RuleExecutionToStart:
    rule_name: str
    inputs: dict
    rule_execution_id: Optional[int] = None


@dataclass
class RuleCompletion:
    origin: RuleExecutionToStart
    success: bool
    outputs: list[dict]
    # True if the execution didn't run because it was replaced by another one (for example
    # when an input artifact was rewritten). That isn't a failure of the rule.
    superseded: bool = False


def _has_an_all_input(rule: Rule) -> bool:
    """True if any of the rule's inputs is an `all` input (ie: `x = all {...}`).

    Such rules must be deferred until no other executions are pending or in
    progress, because we can't know we've seen every matching artifact until
    everything that could produce one has finished.
    """
    return rule.has_for_all_input()


class Sequencer:
    rules: list[Rule]
    in_progress: set

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = list(rules)
        self.in_progress = set()

    def next(
        self,
        event: RuleCompletion,
        get_next_executions: Callable[[str], list[RuleExecutionToStart]],
    ) -> list[RuleExecutionToStart]:
        raise NotImplementedError()

    def is_done(self) -> bool:
        raise NotImplementedError()


class SimpleSequencer(Sequencer):
    rules_to_defer: set

    def __init__(self, rules: list[Rule]) -> None:
        super().__init__(rules)

        rules_to_defer = set()
        for rule in rules:
            if _has_an_all_input(rule):
                rules_to_defer.add(rule.name)

        self.rules_to_defer = rules_to_defer

    def next(
        self,
        event: RuleCompletion,
        get_next_executions: Callable[[str], list[RuleExecutionToStart]],
    ) -> list[RuleExecutionToStart]:

        if event.origin.rule_name != add_if_missing_rule:
            self.in_progress.remove(event.origin)

        pending_executions = []
        for rule in self.rules:
            # evaluate every rule that's not deferred
            if rule.name in self.rules_to_defer:
                continue

            executions = get_next_executions(rule.name)
            pending_executions.extend(executions)

        if len(pending_executions) == 0 and len(self.in_progress) == 0:
            # if there are no new executions and there are no executions which are still
            # in progress, we might be done. But before we can be certain, check all the
            # deferred rules

            for rule_name in self.rules_to_defer:
                executions = get_next_executions(rule_name)
                pending_executions.extend(executions)

        # remember that we've indicated that these should run and consider them in progress
        # until we see a completion event
        self.in_progress.update(pending_executions)

        return pending_executions

    def is_done(self):
        return len(self.in_progress) == 0


class BlockingSequencer(Sequencer):
    """Runs a rule with an "all" input only after every rule which could produce its inputs has finished.

    The rules are arranged in a graph (see createDAG) where there's an edge from a rule to each rule
    which consumes something it could produce. Then:

      * rules without any "all" input are evaluated whenever a rule directly upstream of them
        completes, because each new artifact simply results in new executions. (Only those rules
        can have new work, so the rest aren't evaluated. Everything is evaluated at the start, and
        when an execution is superseded.)
      * a rule with an "all" input is evaluated once all of the rules directly upstream of it have
        "settled". It's evaluated even if it has no matching artifacts, in which case the input is
        empty.

    A rule is settled when all of the rules upstream of it are settled, it has been evaluated since
    the last time anything upstream of it completed, and none of its executions are in progress. (So being settled is transitive: all rules
    which could contribute to the rule's inputs, however indirectly, have finished.)

    A rule with an execution which failed never settles during this run, so everything which
    depends on it through an "all" input is never run. (Running it on a partial set of inputs would
    produce wrong results.)

    This raises CycleDetected or UnreachableRules when the rules can't be arranged in a graph
    like that.
    """

    def __init__(self, rules: list[Rule]) -> None:
        super().__init__(rules)
        from .static_analysis.convert import convert_rules
        from .static_analysis.dag import compute_blockers, createDAG

        dag = createDAG(convert_rules(rules))
        blockers_by_name = {b.rule.name: b for b in compute_blockers(dag)}
        by_name = {rule.name: rule for rule in rules}

        self.has_all_input = {rule.name: _has_an_all_input(rule) for rule in rules}
        # the rules which directly feed each rule
        self.upstream: dict[str, list[str]] = {
            name: sorted(
                r.name for r in blockers.completion_blocked_by_uncompleted_rules
            )
            for name, blockers in blockers_by_name.items()
        }
        # the rules which directly consume something each rule could produce
        self.downstream: dict[str, list[str]] = {name: [] for name in self.upstream}
        for name, upstream_names in self.upstream.items():
            for upstream_name in upstream_names:
                self.downstream.setdefault(upstream_name, []).append(name)
        self.order = self._topological_order(by_name.keys())
        # rules which need to be evaluated, because something which could feed them has
        # completed since they were last evaluated. Initially that's every rule.
        self.dirty: set[str] = set(self.order)
        self.failed_rules: set[str] = set()
        # for tests and diagnostics: the rules which were settled as of the last call to next()
        self.settled: set[str] = set()

    def _topological_order(self, names) -> list[str]:
        order: list[str] = []
        visited: set[str] = set()

        def visit(name: str) -> None:
            # createDAG has already confirmed that there are no cycles
            if name in visited:
                return
            visited.add(name)
            for upstream in self.upstream[name]:
                visit(upstream)
            order.append(name)

        for name in sorted(names):
            visit(name)
        return order

    def next(
        self,
        event: RuleCompletion,
        get_next_executions: Callable[[str], list[RuleExecutionToStart]],
    ) -> list[RuleExecutionToStart]:
        completed_rule = event.origin.rule_name
        if completed_rule == add_if_missing_rule or event.superseded:
            # At the start (add-if-missing artifacts) anything could have new work. A
            # superseded execution means an input artifact was rewritten, which can affect the
            # rule itself and its siblings, so rather than be clever, re-evaluate everything.
            self.dirty.update(self.order)
        else:
            # only the rules which consume what the completed rule produces can have new work
            self.dirty.update(self.downstream.get(completed_rule, []))

        if completed_rule != add_if_missing_rule:
            self.in_progress.remove(event.origin)
            if not event.success and not event.superseded:
                self.failed_rules.add(completed_rule)

        in_progress_count: dict[str, int] = {}
        for execution in self.in_progress:
            in_progress_count[execution.rule_name] = (
                in_progress_count.get(execution.rule_name, 0) + 1
            )

        new_executions: list[RuleExecutionToStart] = []
        settled: set[str] = set()
        # go through the rules from the ones with no dependencies down, so that whether a rule's
        # upstream has settled is known by the time we get to the rule
        for name in self.order:
            upstream_settled = all(u in settled for u in self.upstream[name])

            if self.has_all_input[name] and not upstream_settled:
                # it's too early to evaluate this rule. (It stays dirty, so it gets evaluated
                # once its upstream settles.)
                continue

            if name in self.dirty:
                self.dirty.discard(name)
                executions = get_next_executions(name)
                new_executions.extend(executions)
                in_progress_count[name] = in_progress_count.get(name, 0) + len(
                    executions
                )

            if (
                upstream_settled
                and in_progress_count.get(name, 0) == 0
                and name not in self.failed_rules
            ):
                settled.add(name)

        self.settled = settled
        self.in_progress.update(new_executions)
        return new_executions

    def is_done(self):
        return len(self.in_progress) == 0


SEQUENCER_ENV_VAR = "CONSEQ_SEQ"


def use_blocking_sequencer() -> bool:
    """True if CONSEQ_SEQ=blockers is set.

    That setting selects the BlockingSequencer, and it also means that every rule is required to
    declare what it produces (with `outputs` or `output_types`), because the BlockingSequencer
    needs that to know which rules feed which.
    """
    return os.environ.get(SEQUENCER_ENV_VAR) == "blockers"


def create_sequencer(rules: list[Rule]) -> Sequencer:
    """Creates the sequencer to use. SimpleSequencer unless CONSEQ_SEQ=blockers is set."""
    choice = os.environ.get(SEQUENCER_ENV_VAR)
    if use_blocking_sequencer():
        log.warning(
            "%s=blockers is set. Using the experimental BlockingSequencer",
            SEQUENCER_ENV_VAR,
        )
        return BlockingSequencer(rules)

    if choice:
        log.warning(
            "Unrecognized value %r for %s, using the default sequencer",
            choice,
            SEQUENCER_ENV_VAR,
        )
    return SimpleSequencer(rules)
