import os
import tempfile
from conseq.exceptions import CycleDetected
import pytest
from conseq.static_analysis.model import (
    Rule,
    Binding,
    Constraints,
    Pair,
    Artifact,
    OutputArtifact,
)
from conseq.static_analysis.analyze import createDAG, compute_blockers, create_dag_from_file


def test_simple_dag():
    """Test that we can create a simple DAG and analyze it"""
    # Create a simple rule chain: A -> B -> C
    rule_a = Rule(
        name="A",
        inputs=[],
        outputs=[
            OutputArtifact(
                artifact=Artifact(properties=[Pair(name="type", value="a_output")]),
                cardinality="one",
            )
        ],
    )

    rule_b = Rule(
        name="B",
        inputs=[
            Binding(
                variable="a_out",
                cardinality="one",
                constraints=Constraints(
                    properties=[Pair(name="type", value="a_output")]
                ),
            )
        ],
        outputs=[
            OutputArtifact(
                artifact=Artifact(properties=[Pair(name="type", value="b_output")]),
                cardinality="one",
            )
        ],
    )

    rule_c = Rule(
        name="C",
        inputs=[
            Binding(
                variable="b_out",
                cardinality="one",
                constraints=Constraints(
                    properties=[Pair(name="type", value="b_output")]
                ),
            )
        ],
        outputs=[],
    )

    # Create the DAG
    dag = createDAG([rule_a, rule_b, rule_c])

    # Verify the structure
    assert len(dag.rules) == 3
    assert len(dag.roots) == 1

    # Find rule A (should be the root)
    rule_a_node = next(node for node in dag.rules if node.rule.name == "A")
    assert len(rule_a_node.inputs) == 0
    assert len(rule_a_node.outputs) == 1

    # Find rule B (middle)
    rule_b_node = next(node for node in dag.rules if node.rule.name == "B")
    assert len(rule_b_node.inputs) == 1
    assert len(rule_b_node.outputs) == 1

    # Find rule C (end)
    rule_c_node = next(node for node in dag.rules if node.rule.name == "C")
    assert len(rule_c_node.inputs) == 1
    assert len(rule_c_node.outputs) == 0

    # Verify connections
    assert rule_a_node.outputs[0].consumed_by.rule.name == "B"
    assert rule_b_node.inputs[0].produced_by.rule.name == "A"
    assert rule_b_node.outputs[0].consumed_by.rule.name == "C"
    assert rule_c_node.inputs[0].produced_by.rule.name == "B"


def test_blockers_with_sample_file(tmpdir):
    """Test with a sample conseq file"""
    # Create a temporary conseq file
    f = tmpdir.join("input.conseq")
    f.write(
        b"""
rule step1:
outputs: {"type": "step1_output", "value": "data1"}

rule step2:
inputs: input1 = {"type": "step1_output"}
outputs: {"type": "step2_output", "value": "data2"}

rule step3:
inputs: input2 = {"type": "step2_output"}
outputs: {"type": "final_output", "value": "data3"}
"""
    )

    dag = create_dag_from_file(str(tmpdir.join("state")), str(f), True)
    blockers = compute_blockers(dag)
    assert len(blockers) == 4 # the three rules above and a synthetic one for any artifacts defined

    by_name = {b.rule.name: b for b in blockers}
    assert by_name["step1"].completion_blocked_by_uncompleted_rules == []
    assert by_name["step1"].start_blocked_by_uncompleted_rules == []

    assert by_name["step2"].completion_blocked_by_uncompleted_rules == [by_name["step1"].rule]
    assert by_name["step2"].start_blocked_by_uncompleted_rules == []

    assert by_name["step3"].completion_blocked_by_uncompleted_rules == [by_name["step2"].rule]
    assert by_name["step3"].start_blocked_by_uncompleted_rules == []

def test_blockers_with_cycle(tmpdir):
    # Create a temporary conseq file
    f = tmpdir.join("input.conseq")
    f.write(
        b"""
add-if-missing {"type": "step1_output", "value": "data1"}

rule step2:
inputs: input1 = {"type": "step1_output"}
outputs: {"type": "step2_output", "value": "data2"}

rule step3:
inputs: input2 = {"type": "step2_output"}
outputs: {"type": "final_output", "value": "data3"}

rule step4:
inputs: input = {"type": "step2_output"}
outputs: {"type": "step1_output", "value": "data3"}

"""
    )

    # there's a cycle so this should fail
    with pytest.raises(CycleDetected):
        create_dag_from_file(str(tmpdir.join("state")), str(f), True)


def _to_rule_names(rules):
    return sorted([x.name for x in rules])

def test_blockers_with_complex_depends(tmpdir):
    # Create a temporary conseq file
    f = tmpdir.join("input.conseq")
    f.write(
        b"""
add-if-missing {"type": "step1_output", "value": "data1"}

rule step2:
inputs: input1 = {"type": "step1_output"}
outputs: {"type": "step2_output", "value": "data2"}

rule step3:
inputs: 
    input2 = {"type": "step2_output"}
outputs: 
    {"type": "step3_output", "value": "data3"},
    {"type": "step3_output", "value": "data4"}

rule step4:
inputs: 
    input1 = {"type": "step1_output"},
    input2 = {"type": "step2_output"},
    input3 = {"type": "step3_output"}
outputs: {"type": "final", "value": "x"}
"""
    )

    dag = create_dag_from_file(str(tmpdir.join("state")), str(f), True)
    blockers = compute_blockers(dag)

    by_name = {b.rule.name: b for b in blockers}
    assert by_name["step4"].start_blocked_by_uncompleted_rules == []
    assert len(by_name["step4"].completion_blocked_by_uncompleted_rules) == 3


def test_blockers_with_all_input(tmpdir):
    # Create a temporary conseq file
    f = tmpdir.join("input.conseq")
    f.write(
        b"""
add-if-missing {"type": "origin", "value": "data1"}

rule step1:
outputs: {"type": "step1_output", "value": "data2"}

rule step2:
inputs: input1 = {"type": "origin"}
outputs: {"type": "step2_output", "value": "data2"},
    {"type": "x", "value": "data4"}

rule step3:
inputs: 
    input2 = {"type": "step2_output"}
outputs: 
    {"type": "step3_output", "value": "data3"},
    {"type": "x", "value": "data5"}

rule step4:
inputs: 
    input3 = all {"type": "x"}, input1={"type": "step1_output"}
outputs: {"type": "final", "value": "x"}
"""
    )

    dag = create_dag_from_file(str(tmpdir.join("state")), str(f), True)
    blockers = compute_blockers(dag)

    by_name = {b.rule.name: b for b in blockers}
    assert _to_rule_names(by_name["step4"].start_blocked_by_uncompleted_rules) == ["step2", "step3"]
    assert _to_rule_names(by_name["step4"].completion_blocked_by_uncompleted_rules) == ["step1", "step2", "step3"]


def test_blockers_with_all_input_an_unspecified_outputs(tmpdir):
    # Create a temporary conseq file
    f = tmpdir.join("input.conseq")
    f.write(
        b"""
add-if-missing {"type": "origin", "value": "data1"}

rule step1:
outputs: {"type": "step1_output", "value": "data2"}

rule step2:
inputs: input1 = {"type": "origin"}
output_types: ( x* )

type "x" ( value )

rule step3:
inputs: 
    input2 = {"type": "step2_output"}
output_types: ( x* )

rule step4:
inputs: 
    input3 = all {"type": "x"}, input1={"type": "step1_output"}
outputs: {"type": "final", "value": "x"}
"""
    )

    dag = create_dag_from_file(str(tmpdir.join("state")), str(f), True)
    blockers = compute_blockers(dag)

    by_name = {b.rule.name: b for b in blockers}
    assert _to_rule_names(by_name["step4"].start_blocked_by_uncompleted_rules) == ["step2", "step3"]
    assert _to_rule_names(by_name["step4"].completion_blocked_by_uncompleted_rules) == ["step1", "step2", "step3"]


