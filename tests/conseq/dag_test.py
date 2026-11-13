from typing import Literal

import pytest

from conseq.exceptions import CycleDetected, UnreachableRules
from conseq.static_analysis.dag import compute_blockers, createDAG
from conseq.parser import RegEx
from conseq.static_analysis.model import (
    UNKNOWN,
    Artifact,
    Binding,
    Constraints,
    OutputArtifact,
    Pair,
    Rule,
)


def out(**props):
    return OutputArtifact(Artifact([Pair(k, v) for k, v in props.items()]), "one")


def inp(var, cardinality: Literal["one", "all"] = "one", **props):
    return Binding(
        var, cardinality, Constraints([Pair(k, v) for k, v in props.items()])
    )


def rule(name, inputs=(), outputs=()):
    return Rule(name, list(inputs), list(outputs), False)


def names(rules):
    return sorted(r.name for r in rules)


def edges(dag):
    return sorted(
        (m.produced_by.rule.name, m.consumed_by.rule.name)
        for node in dag.rules
        for m in node.outputs
    )


def test_chain_links_producers_to_consumers():
    a = rule("A", [], [out(type="a")])
    b = rule("B", [inp("x", type="a")], [out(type="b")])
    c = rule("C", [inp("x", type="b")], [])

    dag = createDAG([a, b, c])

    assert edges(dag) == [("A", "B"), ("B", "C")]
    assert [n.rule.name for n in dag.roots] == ["A"]


def test_rules_which_dont_match_are_not_linked():
    a = rule("A", [], [out(type="a")])
    b = rule("B", [inp("x", type="something-else")], [])

    assert edges(createDAG([a, b])) == []


def test_blockers_for_chain():
    a = rule("A", [], [out(type="a")])
    b = rule("B", [inp("x", type="a")], [out(type="b")])
    c = rule("C", [inp("x", type="b")], [])

    by_name = {bl.rule.name: bl for bl in compute_blockers(createDAG([a, b, c]))}

    assert names(by_name["A"].completion_blocked_by_uncompleted_rules) == []
    assert names(by_name["B"].completion_blocked_by_uncompleted_rules) == ["A"]
    # blockers only list the direct producers. (A is reachable via B, but isn't listed for C)
    assert names(by_name["C"].completion_blocked_by_uncompleted_rules) == ["B"]
    # nothing consumes "all" so nothing is blocked from starting
    for blockers in by_name.values():
        assert blockers.start_blocked_by_uncompleted_rules == []


def test_all_input_blocks_start_until_producers_complete():
    a = rule("A", [], [out(type="a")])
    b = rule("B", [], [out(type="a")])
    c = rule("C", [inp("x", cardinality="all", type="a")], [])

    by_name = {bl.rule.name: bl for bl in compute_blockers(createDAG([a, b, c]))}

    assert names(by_name["C"].start_blocked_by_uncompleted_rules) == ["A", "B"]
    assert names(by_name["C"].completion_blocked_by_uncompleted_rules) == ["A", "B"]


def test_foreach_input_does_not_block_start():
    a = rule("A", [], [out(type="a")])
    c = rule("C", [inp("x", cardinality="one", type="a")], [])

    by_name = {bl.rule.name: bl for bl in compute_blockers(createDAG([a, c]))}

    assert names(by_name["C"].start_blocked_by_uncompleted_rules) == []
    assert names(by_name["C"].completion_blocked_by_uncompleted_rules) == ["A"]


def test_unknown_output_value_could_match_any_constraint():
    a = rule("A", [], [OutputArtifact(Artifact([Pair("type", UNKNOWN)]), "one")])
    b = rule("B", [inp("x", type="anything")], [])

    assert edges(createDAG([a, b])) == [("A", "B")]


def test_output_missing_a_constrained_property_doesnt_match():
    # A's output has no "type" property at all, so B's constraint on "type" can't be satisfied
    a = rule("A", [], [out(kind="a")])
    b = rule("B", [inp("x", type="a")], [])

    assert edges(createDAG([a, b])) == []


def test_output_missing_a_regex_constrained_property_doesnt_match():
    a = rule("A", [], [out(kind="a")])
    b = rule("B", [Binding("x", "one", Constraints([Pair("type", RegEx("a.*"))]))], [],)

    assert edges(createDAG([a, b])) == []


def test_output_with_extra_properties_still_matches():
    a = rule("A", [], [out(type="a", extra="whatever")])
    b = rule("B", [inp("x", type="a")], [])

    assert edges(createDAG([a, b])) == [("A", "B")]


def test_cycle_reachable_from_a_root_is_detected():
    r = rule("R", [], [out(type="r")])
    a = rule("A", [inp("x", type="r"), inp("y", type="b")], [out(type="a")])
    b = rule("B", [inp("x", type="a")], [out(type="b")])

    with pytest.raises(CycleDetected):
        createDAG([r, a, b])


def test_cycle_without_a_root_is_reported_as_unreachable():
    # A needs B's output and B needs A's, so neither rule can be reached from a root
    a = rule("A", [inp("x", type="b")], [out(type="a")])
    b = rule("B", [inp("x", type="a")], [out(type="b")])

    with pytest.raises(UnreachableRules) as excinfo:
        createDAG([a, b])
    assert sorted(excinfo.value.rule_names) == ["A", "B"]


def test_rules_downstream_of_an_unreachable_cycle_are_reported():
    a = rule("A", [inp("x", type="b")], [out(type="a")])
    b = rule("B", [inp("x", type="a")], [out(type="b")])
    downstream = rule("D", [inp("x", type="a")], [])
    reachable = rule("R", [], [out(type="r")])

    with pytest.raises(UnreachableRules) as excinfo:
        createDAG([a, b, downstream, reachable])
    assert sorted(excinfo.value.rule_names) == ["A", "B", "D"]


def test_rule_which_consumes_its_own_output_is_unreachable():
    a = rule("A", [inp("x", type="a")], [out(type="a")])

    with pytest.raises(UnreachableRules):
        createDAG([a])


def test_diamonds_dont_cause_exponential_work():
    # every rule in a layer consumes everything produced by the layer above, so the number of
    # distinct paths from the first layer to the last is 3**15
    layers, width = 16, 3
    rules = []
    for layer in range(layers):
        for i in range(width):
            inputs = [] if layer == 0 else [inp("x", type=f"t{layer - 1}")]
            rules.append(rule(f"r{layer}_{i}", inputs, [out(type=f"t{layer}")]))

    dag = createDAG(rules)

    assert len(dag.rules) == layers * width


def test_long_chain_doesnt_hit_recursion_limit():
    rules = [rule("r0", [], [out(type="t0")])]
    for i in range(1, 1200):
        rules.append(rule(f"r{i}", [inp("x", type=f"t{i - 1}")], [out(type=f"t{i}")]))

    assert len(createDAG(rules).rules) == 1200
