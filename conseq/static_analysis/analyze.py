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
    ArtifactMatchNode,
    RuleNode,
)
import os
from .model import createDAG, DAG
from typing import Optional, List, Set
from conseq.parser import AddIfMissingStatement

from ..parser import RememberExecutedStmt, Rule as ConseqRule


def _convert_conseq_remember_exec_to_dag_rule(rem_exec: RememberExecutedStmt):
    """
    Convert a RememberExecutedStmt to a Rule for the DAG.
    
    Args:
        rem_exec: The RememberExecutedStmt to convert
        
    Returns:
        A Rule object representing the remembered execution
    """
    # Convert inputs to bindings
    bindings = []
    for var_name, input_value in rem_exec.inputs.items():
        # Handle both single objects and lists of objects
        if isinstance(input_value, list):
            # For lists, create a binding with "all" cardinality
            for obj in input_value:
                constraints_props = []
                for key, value in obj.items():
                    if not isinstance(value, str):
                        continue
                    constraints_props.append(Pair(name=key, value=value))
                
                binding = Binding(
                    variable=var_name,
                    cardinality="all",
                    constraints=Constraints(properties=constraints_props),
                )
                bindings.append(binding)
        else:
            # For single objects, create a binding with "one" cardinality
            constraints_props = []
            for key, value in input_value.items():
                if not isinstance(value, str):
                    continue
                constraints_props.append(Pair(name=key, value=value))
            
            binding = Binding(
                variable=var_name,
                cardinality="one",
                constraints=Constraints(properties=constraints_props),
            )
            bindings.append(binding)
    
    # Convert outputs to output artifacts
    outputs = []
    for output in rem_exec.outputs:
        props = []
        for key, value in output.items():
            if isinstance(value, dict) or isinstance(value, list):
                # Skip complex objects for simplicity
                continue
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            props.append(Pair(name=key, value=value))
        
        if props:  # Only add if we have valid properties
            artifact = Artifact(properties=props)
            output_artifact = OutputArtifact(artifact=artifact, cardinality="one")
            outputs.append(output_artifact)
    
    # Create a rule with the transform name
    rule_name = f"remember-executed:{rem_exec.transform}"
    model_rule = Rule(name=rule_name, inputs=bindings, outputs=outputs)
    return model_rule


def _convert_conseq_rule_to_dag_rule(rule: ConseqRule):
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
    return model_rule


def _create_synthetic_add_if_missing_rule(rules):
    # Collect all add-if-missing statements
    add_if_missing_artifacts = []
    for obj in rules.objs:
        add_if_missing_artifacts.append(obj)

    add_if_missing_outputs = []
    for artifact_props in add_if_missing_artifacts:
        props = []
        for key, value in artifact_props.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            props.append(Pair(name=key, value=value))

        if props:  # Only add if we have valid properties
            artifact = Artifact(properties=props)
            output_artifact = OutputArtifact(artifact=artifact, cardinality="one")
            add_if_missing_outputs.append(output_artifact)

    add_if_missing_rule = Rule(
        name="add-if-missing", inputs=[], outputs=add_if_missing_outputs
    )
    return add_if_missing_rule


def analyze(
    file: str, dir: str, dot_output: Optional[str] = None, static_analyis: bool = False
):
    jinja2_env = create_jinja2_env()
    rules = read_rules(
        state_dir=dir, depfile=file, config_file=None, jinja2_env=jinja2_env
    )

    model_rules = []

    # Create a synthetic rule for add-if-missing artifacts if any exist
    model_rules.append(_create_synthetic_add_if_missing_rule(rules))

    if static_analyis:
        # Convert conseq rules to static analysis model rules
        for rule in rules:
            model_rule = _convert_conseq_rule_to_dag_rule(rule)
            model_rules.append(model_rule)
    else:
        for rem_exec in rules.remember_executed:
            model_rule = _convert_conseq_remember_exec_to_dag_rule(rem_exec)
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
        write_artifact_terminal_rules(dag, f"{dot_output}.txt")

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


def write_artifact_terminal_rules(dag: DAG, filename: str):
    add_if_missing_outputs = None
    for rule in dag.rules:
        if rule.rule == "add-if-missing":
            add_if_missing_outputs = rule.outputs
    assert add_if_missing_outputs

    with open(filename, "wt") as fd:
        for artifact_node in add_if_missing_outputs:
            fd.write(f"{artifact_node}\n")
            for terminal_node in get_terminal_children(dag, artifact_node):
                fd.write(f"{terminal_node}\n")
            fd.write("\n")


def get_terminal_children(dag: DAG, artifact_node: ArtifactMatchNode) -> Set[RuleNode]:
    """
    Returns the set of downstream terminal rules reachable from the given artifact node.
    
    A terminal rule is a rule that has no outputs or whose outputs are not consumed by any other rule.
    
    Args:
        dag: The DAG object
        artifact_node: The starting artifact node
        
    Returns:
        A set of terminal RuleNode objects
    """
    terminal_rules = set()
    visited_rules = set()

    def dfs(node):
        if node.consumed_by is None:
            # This artifact is not consumed by any rule
            return

        rule = node.consumed_by

        if rule in visited_rules:
            # Avoid cycles
            return

        visited_rules.add(rule)

        # Check if this rule is terminal (has no outputs or outputs not consumed)
        is_terminal = True
        for output in rule.outputs:
            if output.consumed_by is not None:
                is_terminal = False
                dfs(output)

        if is_terminal:
            terminal_rules.add(rule)

    # Start DFS from the given artifact node
    dfs(artifact_node)

    return terminal_rules


def writeDOT(dag: DAG, filename: str):
    """
    Write the DAG as a Graphviz DOT file.
    
    Args:
        dag: The DAG object to visualize
        filename: Path to the output DOT file
    """
    with open(filename, "w") as f:
        f.write("digraph conseq {\n")
        f.write("  rankdir=LR;\n")  # Left to right layout
        f.write("  node [shape=box, style=filled, fillcolor=lightblue];\n\n")

        # Write all nodes
        for rule_node in dag.rules:
            rule_name = rule_node.rule.name
            # Escape quotes in rule name if needed
            safe_name = rule_name.replace('"', '\\"')
            f.write(f'  "{safe_name}" [label="{safe_name}"];\n')

        f.write("\n")

        # Write all edges
        for rule_node in dag.rules:
            source_name = rule_node.rule.name
            safe_source = source_name.replace('"', '\\"')

            for output_node in rule_node.outputs:
                if output_node.consumed_by:
                    target_name = output_node.consumed_by.rule.name
                    safe_target = target_name.replace('"', '\\"')

                    # Use the binding variable as the edge label if available
                    edge_label = (
                        output_node.binding.variable
                        if hasattr(output_node, "binding") and output_node.binding
                        else ""
                    )
                    if edge_label:
                        safe_edge_label = edge_label.replace('"', '\\"')
                        f.write(
                            f'  "{safe_source}" -> "{safe_target}" [label="{safe_edge_label}"];\n'
                        )
                    else:
                        f.write(f'  "{safe_source}" -> "{safe_target}";\n')

        f.write("}\n")
