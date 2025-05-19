import os
import tempfile
from conseq.static_analysis.model import createDAG, Rule, Binding, Constraints, Pair, Artifact, OutputArtifact

def test_simple_dag():
    """Test that we can create a simple DAG and analyze it"""
    # Create a simple rule chain: A -> B -> C
    rule_a = Rule(
        name="A",
        inputs=[],
        outputs=[
            OutputArtifact(
                artifact=Artifact(properties=[Pair(name="type", value="a_output")]),
                cardinality="one"
            )
        ]
    )
    
    rule_b = Rule(
        name="B",
        inputs=[
            Binding(
                variable="a_out",
                cardinality="one",
                constraints=Constraints(properties=[Pair(name="type", value="a_output")])
            )
        ],
        outputs=[
            OutputArtifact(
                artifact=Artifact(properties=[Pair(name="type", value="b_output")]),
                cardinality="one"
            )
        ]
    )
    
    rule_c = Rule(
        name="C",
        inputs=[
            Binding(
                variable="b_out",
                cardinality="one",
                constraints=Constraints(properties=[Pair(name="type", value="b_output")])
            )
        ],
        outputs=[]
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

def test_with_sample_file():
    """Test with a sample conseq file"""
    # Create a temporary conseq file
    with tempfile.NamedTemporaryFile(suffix=".conseq", delete=False) as f:
        f.write(b"""
rule step1:
    inputs:
    outputs: {"type": "step1_output", "value": "data1"}
    run "echo 'Step 1'"

rule step2:
    inputs: input1 = {"type": "step1_output"}
    outputs: {"type": "step2_output", "value": "data2"}
    run "echo 'Step 2'"

rule step3:
    inputs: input2 = {"type": "step2_output"}
    outputs: {"type": "final_output", "value": "data3"}
    run "echo 'Step 3'"
""")
        filename = f.name
    
    try:
        # This is just a placeholder - in a real test we would use the command
        # But for unit testing, we'd need to mock the command execution
        # Here we're just verifying the file was created correctly
        assert os.path.exists(filename)
    finally:
        # Clean up
        os.unlink(filename)
