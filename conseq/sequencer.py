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
    """Not implemented yet.

    The plan is to construct a DAG of the rules (see createDAG) and compute, for each rule, which
    other rules block it from starting. A rule with an "all" input will wait until every rule which
    could (transitively) produce its inputs has completed successfully, and then run, even if there
    are no matching artifacts. That would replace SimpleSequencer's approach of deferring those
    rules until nothing at all is in progress.
    """

    def __init__(self, rules: list[Rule]) -> None:
        super().__init__(rules)

    def next(
        self,
        event: RuleCompletion,
        get_next_executions: Callable[[str], list[RuleExecutionToStart]],
    ) -> list[RuleExecutionToStart]:
        raise NotImplementedError("BlockingSequencer is not implemented yet")

    def is_done(self):
        raise NotImplementedError("BlockingSequencer is not implemented yet")


SEQUENCER_ENV_VAR = "CONSEQ_SEQ"


def create_sequencer(rules: list[Rule]) -> Sequencer:
    """Creates the sequencer to use. SimpleSequencer unless CONSEQ_SEQ=blockers is set."""
    choice = os.environ.get(SEQUENCER_ENV_VAR)
    if choice == "blockers":
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
