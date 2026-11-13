"""
Support code for fuzz testing the scheduler (see fuzz_test.py).

The approach:
  * A randomly generated pipeline (`Pipeline`) is rendered as a .conseq file. Every rule's
    outputs are a pure function of its inputs, so the correct final state doesn't depend on
    scheduling.
  * `expected_state()` computes that final state independently of conseq (a trivial level by level
    evaluation), acting as the oracle.
  * `run_pipeline()` runs the real `depexec.main()` with two things replaced:
      - `depexec.execute` wraps the real function, but the execution it returns doesn't report
        completion until the harness releases it.
      - `time.sleep` (which main_loop calls whenever it's idle) becomes a "tick", where the
        harness chooses which running executions complete next. (Optionally it crashes the run
        at a chosen tick to exercise restarting.)
    All of the choices come from the caller, so Hypothesis can generate and shrink schedules.
"""
import collections
import itertools
import logging
import os
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple
from unittest import mock

from conseq import dep, depexec
from conseq.exec_client import ExecResult

MAX_TICKS = 5000


@dataclass(frozen=True)
class InputSpec:
    var: str
    level: int  # the input matches artifacts of type f"T{level}"
    is_all: bool


@dataclass(frozen=True)
class RuleSpec:
    name: str
    level: int  # rule produces artifacts of type f"T{level}"
    inputs: Tuple[InputSpec, ...]
    n_outputs: int


@dataclass(frozen=True)
class Pipeline:
    initial_values: Tuple[str, ...]  # added as artifacts of type T0
    rules: Tuple[RuleSpec, ...]  # in ascending level order


def _value_template(rule: RuleSpec, output_index: int) -> str:
    parts = []
    for i in rule.inputs:
        if i.is_all:
            parts.append("{{ inputs.%s|length }}" % i.var)
        else:
            parts.append("{{ inputs.%s.value }}" % i.var)
    return "%s[%s]#%d" % (rule.name, ",".join(parts), output_index)


def render_conseq(p: Pipeline) -> str:
    lines = []
    for v in p.initial_values:
        lines.append('add-if-missing {"type": "T0", "value": "%s"}' % v)
    for rule in p.rules:
        lines.append("rule %s:" % rule.name)
        if rule.inputs:
            specs = [
                '%s=%s{"type": "T%d"}' % (i.var, "all " if i.is_all else "", i.level)
                for i in rule.inputs
            ]
            lines.append("    inputs: " + ", ".join(specs))
        outputs = [
            '{"type": "T%d", "value": "%s"}' % (rule.level, _value_template(rule, k))
            for k in range(rule.n_outputs)
        ]
        lines.append("    outputs: " + ", ".join(outputs))
    return "\n".join(lines) + "\n"


@dataclass
class State:
    artifacts: Set[Tuple[str, str]] = field(default_factory=set)  # (type, value)
    executions_per_rule: Dict[str, int] = field(default_factory=dict)


def expected_state(p: Pipeline) -> State:
    """What the pipeline should produce, regardless of the order things run in.

    Evaluates level by level, so every rule sees the complete set of artifacts from lower levels.
    (This is the intended semantics of "all" inputs.)
    """
    by_level: Dict[int, List[str]] = collections.defaultdict(list)
    for v in p.initial_values:
        by_level[0].append(v)

    state = State()
    for rule in p.rules:
        state.executions_per_rule[rule.name] = 0

    for rule in sorted(p.rules, key=lambda r: r.level):
        foreach_inputs = [i for i in rule.inputs if not i.is_all]
        all_inputs = [i for i in rule.inputs if i.is_all]
        # a rule with an "all" input doesn't run if there are no matching artifacts
        if any(len(by_level[i.level]) == 0 for i in all_inputs):
            continue

        for combo in itertools.product(*[by_level[i.level] for i in foreach_inputs]):
            foreach_values = dict(zip([i.var for i in foreach_inputs], combo))
            parts = []
            for i in rule.inputs:
                if i.is_all:
                    parts.append(str(len(by_level[i.level])))
                else:
                    parts.append(foreach_values[i.var])
            for k in range(rule.n_outputs):
                value = "%s[%s]#%d" % (rule.name, ",".join(parts), k)
                by_level[rule.level].append(value)
            state.executions_per_rule[rule.name] += 1

    for level, values in by_level.items():
        for v in values:
            state.artifacts.add(("T%d" % level, v))
    return state


def actual_state(state_dir: str) -> State:
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    state = State()
    for obj in j.find_objs("public", {}):
        state.artifacts.add((obj.props["type"], obj.props["value"]))
    for e in j.get_all_executions():
        assert e.status == dep.STATUS_COMPLETED, f"execution not completed: {e}"
        state.executions_per_rule[e.transform] = (
            state.executions_per_rule.get(e.transform, 0) + 1
        )
    # no rule executions should be left over from the run
    assert len(j.get_pending()) == 0
    assert len(j.get_started_executions()) == 0
    return state


class SimulatedCrash(Exception):
    pass


class ControlledExecution:
    """Wraps an execution returned by the real execute() so that it doesn't report completion
    until released by the harness."""

    def __init__(self, inner):
        self.inner = inner
        self.released = False

    @property
    def id(self):
        return self.inner.id

    @property
    def transform(self):
        return self.inner.transform

    @property
    def job_dir(self):
        # stubs don't have a job_dir, but the summary code expects a string
        return getattr(self.inner, "job_dir", None) or "fuzz-job-%s" % self.id

    @property
    def desc_name(self) -> str:
        return "%s (fuzz)" % self.transform

    def get_state_label(self) -> str:
        return "fuzz"

    def get_external_id(self) -> str:
        return "fuzz:%s" % self.id

    def get_completion(self):
        if not self.released:
            return ExecResult(None, None)  # still running
        return self.inner.get_completion()


def run_pipeline(
    conseq_path: str,
    state_dir: str,
    slots: int,
    choose_releases: Callable[[int], Set[int]],
    crash_at_tick: Optional[int] = None,
) -> None:
    """Runs conseq on the file, controlling which executions complete when.

    :param choose_releases: called each time the loop is idle with the number of executions which
       are still running. Returns the (non-empty) subset of indices which should complete now.
    :param crash_at_tick: if set, raises SimulatedCrash at that idle tick.
    """
    unreleased: List[ControlledExecution] = []
    ticks = [0]

    real_execute = depexec.execute

    def execute(*args, **kwargs):
        e = ControlledExecution(real_execute(*args, **kwargs))
        unreleased.append(e)
        return e

    def tick(_seconds):
        ticks[0] += 1
        assert ticks[0] < MAX_TICKS, "run did not terminate"
        if crash_at_tick is not None and ticks[0] == crash_at_tick:
            raise SimulatedCrash()
        assert len(unreleased) > 0, "main_loop is idle but nothing is running"
        chosen = choose_releases(len(unreleased))
        assert len(chosen) > 0
        for index in sorted(chosen, reverse=True):
            unreleased.pop(index).released = True

    # main_loop warns if it stops while the sequencer still thinks executions are in progress,
    # which means it lost track of an execution. Treat that as a failure.
    sequencer_warnings = _WarningCollector("sequencer still considers")
    depexec_logger = logging.getLogger("conseq.depexec")
    depexec_logger.addHandler(sequencer_warnings)

    try:
        _run_main(conseq_path, state_dir, slots, execute, tick)
    finally:
        depexec_logger.removeHandler(sequencer_warnings)

    assert (
        len(sequencer_warnings.messages) == 0
    ), f"sequencer lost track of executions: {sequencer_warnings.messages}"


class _WarningCollector(logging.Handler):
    def __init__(self, containing: str):
        super().__init__(level=logging.WARNING)
        self.containing = containing
        self.messages: List[str] = []

    def emit(self, record):
        message = record.getMessage()
        if self.containing in message:
            self.messages.append(message)


def _run_main(conseq_path, state_dir, slots, execute, tick):
    with mock.patch.object(depexec, "execute", execute), mock.patch.object(
        depexec.time, "sleep", tick
    ):
        depexec.main(
            conseq_path,
            state_dir,
            [],
            {},
            slots,
            False,
            False,
            None,  # type: ignore[arg-type]  # config_file is optional despite the annotation
            remove_unknown_artifacts=True,
            reattach_existing=False,
        )
