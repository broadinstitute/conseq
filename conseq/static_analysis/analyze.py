from conseq.config import read_deps, read_rules
from conseq.hashcache import HashCache
from conseq.template import create_jinja2_env
from conseq.static_analysis.model import (
    Rule,
    Binding,
    Constraints,
    Pair,
    Artifact,
    OutputArtifact,
)
import os
from .model import createDAG, DAG
from typing import Optional

def analyze(file: str, dir: str, dot_output: Optional[str] = None):
    jinja2_env = create_jinja2_env()
    rules = read_rules(
    state_dir=dir,
    depfile=file,
    config_file=None,
    jinja2_env=jinja2_env)

    # Convert conseq rules to static analysis model rules
    model_rules = []
    for rule in rules:
        # Convert inputs to bindings
        bindings = []
        for input_spec in rule.inputs:
            constraints_props = []
            for key, value in input_spec.json_obj.items():
                if not isinstance(value, str):
                    continue
                # if isinstance(value, dict) or isinstance(value, list):
                #     # Skip complex objects for simplicity
                #     continue
                assert isinstance(key, str)
                assert isinstance(value, str), f"value is {value}"
                constraints_props.append(Pair(name=key, value=value))

            cardinality = "all" if input_spec.for_all else "one"
            binding = Binding(
                variable=input_spec.variable,
                cardinality=cardinality,
                constraints=Constraints(properties=constraints_props),
            )
            bindings.append(binding)

        # Convert outputs to output artifacts
        outputs = []
        if rule.outputs:
            for output in rule.outputs:
                props = []
                for key, value in output.items():
                    if isinstance(value, dict) or isinstance(value, list):
                        # Skip complex objects for simplicity
                        continue
                    assert isinstance(key, str)
                    assert isinstance(value, str)
                    props.append(Pair(name=key, value=value))

                # Assume "one" cardinality for outputs
                artifact = Artifact(properties=props)
                output_artifact = OutputArtifact(artifact=artifact, cardinality="one")
                outputs.append(output_artifact)

        model_rule = Rule(name=rule.name, inputs=bindings, outputs=outputs)
        model_rules.append(model_rule)

    # Create the DAG
    dag = createDAG(model_rules)

    # Print the DAG
    print(f"DAG Analysis for {file}:")
    print(f"Total rules: {len(dag.rules)}")
    print(f"Root rules (no inputs): {len(dag.roots)}")

    # Write DOT file if requested
    if dot_output:
        writeDOT(dag, dot_output)
        print(f"DOT file written to: {dot_output}")

    print("\nRule dependencies:")
    for rule_node in dag.rules:
        print(f"\nRule: {rule_node.rule.name}")
        if rule_node.inputs:
            print("  Inputs:")
            for input_node in rule_node.inputs:
                print(
                    f"    - From rule '{input_node.produced_by.rule.name}' via binding '{input_node.binding.variable}'"
                )
        if rule_node.outputs:
            print("  Outputs:")
            for output_node in rule_node.outputs:
                print(
                    f"    - To rule '{output_node.consumed_by.rule.name}' via binding '{output_node.binding.variable}'"
                )

    return 0


def writeDOT(dag: DAG, filename: str):
    """
    Write the DAG as a Graphviz DOT file.
    
    Args:
        dag: The DAG object to visualize
        filename: Path to the output DOT file
    """
    with open(filename, 'w') as f:
        f.write('digraph conseq {\n')
        f.write('  rankdir=LR;\n')  # Left to right layout
        f.write('  node [shape=box, style=filled, fillcolor=lightblue];\n\n')
        
        # Write all nodes
        for rule_node in dag.rules:
            rule_name = rule_node.rule.name
            # Escape quotes in rule name if needed
            safe_name = rule_name.replace('"', '\\"')
            f.write(f'  "{safe_name}" [label="{safe_name}"];\n')
        
        f.write('\n')
        
        # Write all edges
        for rule_node in dag.rules:
            source_name = rule_node.rule.name
            safe_source = source_name.replace('"', '\\"')
            
            for output_node in rule_node.outputs:
                if output_node.consumed_by:
                    target_name = output_node.consumed_by.rule.name
                    safe_target = target_name.replace('"', '\\"')
                    
                    # Use the binding variable as the edge label if available
                    edge_label = output_node.binding.variable if hasattr(output_node, 'binding') and output_node.binding else ""
                    if edge_label:
                        safe_edge_label = edge_label.replace('"', '\\"')
                        f.write(f'  "{safe_source}" -> "{safe_target}" [label="{safe_edge_label}"];\n')
                    else:
                        f.write(f'  "{safe_source}" -> "{safe_target}";\n')
        
        f.write('}\n')
