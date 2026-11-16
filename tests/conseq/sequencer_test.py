from conseq.sequencer import BlockingSequencer, SimpleSequencer, create_sequencer


def test_default_sequencer(monkeypatch):
    monkeypatch.delenv("CONSEQ_SEQ", raising=False)
    assert type(create_sequencer([])) is SimpleSequencer


def test_blockers_sequencer_selected_by_env_var(monkeypatch, caplog):
    monkeypatch.setenv("CONSEQ_SEQ", "blockers")
    assert type(create_sequencer([])) is BlockingSequencer
    assert "BlockingSequencer" in caplog.text


def test_unrecognized_env_var_falls_back_to_default(monkeypatch, caplog):
    monkeypatch.setenv("CONSEQ_SEQ", "bogus")
    assert type(create_sequencer([])) is SimpleSequencer
    assert "bogus" in caplog.text


# ---- BlockingSequencer

import pytest

from conseq import parser
from conseq.config import EvalContext, Rules, _eval_stmts, _resolve_output_types
from conseq.exceptions import CycleDetected, UnreachableRules
from conseq.hashcache import HashCache
from conseq.sequencer import (
    RuleCompletion,
    RuleExecutionToStart,
    add_if_missing_rule,
)
from conseq.template import create_jinja2_env


def load_rules(tmpdir, text):
    rules = Rules()
    path = str(tmpdir.join("t.conseq"))
    _eval_stmts(
        parser.parse_str(text, filename=path),
        EvalContext(
            rules, path, HashCache(str(tmpdir.join("hc"))), create_jinja2_env()
        ),
    )
    _resolve_output_types(rules)
    return list(rules)


class Harness:
    """Drives a sequencer, reporting a fixed set of new executions per rule when asked"""

    def __init__(self, sequencer):
        self.sequencer = sequencer
        self.available = (
            {}
        )  # rule name -> executions which `get_next_executions` will report
        self.evaluated = []  # names of rules evaluated by the last call
        self.running = []

    def make(self, rule_name):
        return RuleExecutionToStart(rule_name, {})

    def offer(self, rule_name, count=1):
        self.available.setdefault(rule_name, []).extend(
            self.make(rule_name) for _ in range(count)
        )

    def _get_next(self, rule_name):
        self.evaluated.append(rule_name)
        return self.available.pop(rule_name, [])

    def step(self, origin, success=True, superseded=False):
        self.evaluated = []
        started = self.sequencer.next(
            RuleCompletion(origin, success, [], superseded=superseded), self._get_next
        )
        self.running.extend(started)
        return [e.rule_name for e in started]

    def start(self):
        return self.step(RuleExecutionToStart(add_if_missing_rule, {}))

    def finish(self, rule_name, success=True, superseded=False):
        origin = next(e for e in self.running if e.rule_name == rule_name)
        self.running.remove(origin)
        return self.step(origin, success, superseded)


CHAIN = """
type thing (value)
rule a:
    outputs: {"type": "a"}
rule b:
    inputs: x={"type": "a"}
    outputs: {"type": "b"}
rule c:
    inputs: xs=all {"type": "b"}
    outputs: {"type": "c"}
"""


def test_all_rule_waits_for_everything_upstream_of_it(tmpdir):
    h = Harness(BlockingSequencer(load_rules(tmpdir, CHAIN)))
    h.offer("a")

    assert h.start() == ["a"]
    assert "c" not in h.evaluated

    # b gets work once a finishes. c still can't be evaluated, because b is running
    h.offer("b", 2)
    assert h.finish("a") == ["b", "b"]
    assert "c" not in h.evaluated

    assert h.finish("b") == []
    assert "c" not in h.evaluated

    # only when the last b is done does c get evaluated
    h.offer("c")
    assert h.finish("b") == ["c"]
    assert "c" in h.evaluated


def test_all_rule_runs_when_nothing_could_match(tmpdir):
    # a produced nothing, so b never has anything to do. c still gets evaluated, to run on []
    h = Harness(BlockingSequencer(load_rules(tmpdir, CHAIN)))
    h.offer("c")
    h.start()  # a has no work
    assert [e.rule_name for e in h.running] == ["c"]


def test_all_rule_with_no_upstream_rules_is_evaluated_immediately(tmpdir):
    rules = load_rules(
        tmpdir,
        """
        rule c:
            inputs: xs=all {"type": "from-add-if-missing"}
            outputs: {"type": "c"}
        """,
    )
    h = Harness(BlockingSequencer(rules))
    h.offer("c")
    assert h.start() == ["c"]


def test_failed_upstream_execution_blocks_the_all_rule_forever(tmpdir):
    h = Harness(BlockingSequencer(load_rules(tmpdir, CHAIN)))
    h.offer("a")
    h.start()
    h.offer("b", 2)
    h.finish("a")

    h.finish("b", success=False)
    assert h.finish("b") == []
    assert h.sequencer.is_done()
    assert "c" not in h.evaluated

    # even later, nothing makes c eligible
    h.step(RuleExecutionToStart(add_if_missing_rule, {}))
    assert "c" not in h.evaluated


def test_superseded_execution_is_not_a_failure(tmpdir):
    h = Harness(BlockingSequencer(load_rules(tmpdir, CHAIN)))
    h.offer("a")
    h.start()
    h.offer("b")
    h.finish("a")

    # b was replaced by a new execution, which is what's offered when the rules are re-evaluated
    h.offer("b")
    assert h.finish("b", success=False, superseded=True) == ["b"]
    h.offer("c")
    assert h.finish("b") == ["c"]


def test_waiting_is_transitive_through_a_rule_without_all_inputs(tmpdir):
    # d consumes all of x. b consumes d's output one at a time. c consumes all of b's output.
    # While d is running, b doesn't have any executions yet, but c still has to wait for it.
    rules = load_rules(
        tmpdir,
        """
        rule x:
            outputs: {"type": "x"}
        rule d:
            inputs: xs=all {"type": "x"}
            outputs: {"type": "d"}
        rule b:
            inputs: in={"type": "d"}
            outputs: {"type": "b"}
        rule c:
            inputs: bs=all {"type": "b"}
            outputs: {"type": "c"}
        """,
    )
    h = Harness(BlockingSequencer(rules))
    h.offer("x")
    h.offer("c")  # c would have something to run on, but must not be evaluated yet
    assert h.start() == ["x"]

    h.offer("d")
    assert h.finish("x") == ["d"]
    assert "c" not in h.evaluated

    # b has nothing in progress and nothing to do, but its upstream (d) is still running
    assert "c" not in h.evaluated
    h.offer("b")
    assert h.finish("d") == ["b"]
    assert "c" not in h.evaluated

    assert h.finish("b") == ["c"]


def test_rules_without_all_inputs_are_always_evaluated(tmpdir):
    h = Harness(BlockingSequencer(load_rules(tmpdir, CHAIN)))
    h.offer("a")
    h.start()
    assert {"a", "b"} <= set(h.evaluated)


BRANCHES = """
rule a:
    outputs: {"type": "a"}
rule b:
    outputs: {"type": "b"}
rule a2:
    inputs: x={"type": "a"}
    outputs: {"type": "a2"}
rule b2:
    inputs: x={"type": "b"}
    outputs: {"type": "b2"}
rule c:
    inputs: xs=all {"type": "a2"}, ys=all {"type": "b2"}
    outputs: {"type": "c"}
"""


def test_only_consumers_of_the_completed_rule_are_evaluated(tmpdir):
    h = Harness(BlockingSequencer(load_rules(tmpdir, BRANCHES)))
    h.offer("a")
    h.offer("b")
    assert sorted(h.start()) == ["a", "b"]
    assert {"a", "b", "a2", "b2"} <= set(h.evaluated)

    h.offer("a2")
    assert h.finish("a") == ["a2"]
    assert h.evaluated == ["a2"]

    # a2 completing only affects c, which still has to wait for b's side
    assert h.finish("a2") == []
    assert h.evaluated == []

    # b2 has no work, so everything upstream of c has settled and c is evaluated too
    h.offer("c")
    assert h.finish("b") == ["c"]
    assert h.evaluated == ["b2", "c"]

    # c completing has no consumers, so nothing is evaluated
    assert h.finish("c") == []
    assert h.evaluated == []
    assert h.sequencer.is_done()


def test_all_rule_is_evaluated_when_upstream_settles_without_a_direct_completion(
    tmpdir,
):
    # c's direct upstream (b) never runs anything. c becomes eligible when a finishes, even
    # though a doesn't feed c directly.
    h = Harness(BlockingSequencer(load_rules(tmpdir, CHAIN)))
    h.offer("a")
    h.start()
    h.offer("c")
    assert h.finish("a") == ["c"]
    assert h.evaluated == ["b", "c"]


def test_superseded_execution_re_evaluates_everything(tmpdir):
    h = Harness(BlockingSequencer(load_rules(tmpdir, BRANCHES)))
    h.offer("a")
    h.offer("b")
    h.start()
    h.finish("a", success=False, superseded=True)
    assert {"a", "b", "a2", "b2"} <= set(h.evaluated)


def test_cycle_is_an_error(tmpdir):
    rules = load_rules(
        tmpdir,
        """
        rule root:
            outputs: {"type": "r"}
        rule a:
            inputs: x={"type": "r"}, y={"type": "b"}
            outputs: {"type": "a"}
        rule b:
            inputs: x={"type": "a"}
            outputs: {"type": "b"}
        """,
    )
    with pytest.raises(CycleDetected):
        BlockingSequencer(rules)


def test_rules_which_are_unreachable_are_an_error(tmpdir):
    rules = load_rules(
        tmpdir,
        """
        rule a:
            inputs: x={"type": "b"}
            outputs: {"type": "a"}
        rule b:
            inputs: x={"type": "a"}
            outputs: {"type": "b"}
        """,
    )
    with pytest.raises(UnreachableRules):
        BlockingSequencer(rules)
