import io
import sys
import re

from conseq.config import read_rules
from conseq.template import create_jinja2_env
from conseq.static_analysis.model import (
    Rule,
    Binding,
    Constraints,
    Pair,
    Artifact,
    OutputArtifact,
    ArtifactMatchNode,
    RuleNode, UNKNOWN,
)
from .model import DAG, Unknown, Blockers
from typing import Optional, List, Set, Union
from conseq.parser import RegEx
from ..exceptions import CycleDetected

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
    for var_name, input_value in rem_exec.inputs:
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

    # hack: is_publish_rule being defaulted to False, but we can't really tell
    model_rule = Rule(name=rule_name, inputs=bindings, outputs=outputs, is_publish_rule=False)
    return model_rule


def _convert_conseq_rule_to_dag_rule(rule: ConseqRule):
    # Convert inputs to bindings
    bindings = []

    for input_spec in rule.inputs:
        constraints_props = []
        for key, value in input_spec.json_obj.items():
            if not (isinstance(value, str) or isinstance(value, RegEx)):
                if key == "type":
                    print(f"warning: {rule.name} had input with type={value} and so could not be included as a constraint")
                continue
            # if isinstance(value, dict) or isinstance(value, list):
            #     # Skip complex objects for simplicity
            #     continue
            assert isinstance(key, str)
            assert isinstance(value, str) or isinstance(value, RegEx), f"value is {value}"
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
    if rule.is_publish_rule:
        assert rule.outputs is None
        assert rule.output_types is None
    elif rule.outputs is not None:
        for output in rule.outputs:
            props = []
            for key, value in output.items():
                if isinstance(value, dict) or isinstance(value, list):
                    # Treat complex objects as unknown for simplicity
                    value = UNKNOWN
                else:
                    assert isinstance(key, str)
                    assert isinstance(value, str)
                    if "{{" in value: # does it look like this isn't a fixed value?
                        value = UNKNOWN
                props.append(Pair(name=key, value=value))

            # Assume "one" cardinality for outputs
            artifact = Artifact(properties=props)
            output_artifact = OutputArtifact(artifact=artifact, cardinality="one")
            outputs.append(output_artifact)
    else:
        assert rule.resolved_output_types is not None, f"Rule {rule.name} must either have an 'output' block or an 'output_types' block"
        for output_type in rule.resolved_output_types:
            props = [Pair(name="type", value=output_type.type_def.name)]
            for field in output_type.type_def.fields:
                props.append(Pair(name=field, value=UNKNOWN))
            artifact = Artifact(properties=props)
            output_artifact = OutputArtifact(artifact=artifact, cardinality="many")
            outputs.append(output_artifact)

    model_rule = Rule(name=rule.name, inputs=bindings, outputs=outputs, is_publish_rule=rule.is_publish_rule)

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
        name="add-if-missing", inputs=[], outputs=add_if_missing_outputs, is_publish_rule=False
    )
    return add_if_missing_rule

def create_dag_from_file(dir: str, file : str, static_analyis: bool):
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

    return dag

def analyze(
    file: str, dir: str, dot_output: Optional[str] = None, static_analyis: bool = False
):
    dag = create_dag_from_file(dir, file, static_analyis)

    # Print the DAG
    print(f"DAG Analysis for {file}:")
    print(f"Total rules: {len(dag.rules)}")
    print(f"Root rules (no inputs): {len(dag.roots)}")

    # Write DOT file if requested
    if dot_output:
        blockers = compute_blockers(dag)
        with open(dot_output, "w") as f:
            _write_blockers_dot(blockers, f)
        # writeDOT(dag, dot_output)
        print(f"DOT file written to: {dot_output}")
        # write_artifact_terminal_rules(dag, f"{dot_output}.txt")

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
        if rule.rule.name == "add-if-missing":
            add_if_missing_outputs = rule.outputs
    assert add_if_missing_outputs

    with open(filename, "wt") as fd:
        for artifact_node in add_if_missing_outputs:
            fd.write(f"{artifact_node.artifact.artifact.properties}\n")
            for terminal_node in get_terminal_children(dag, artifact_node):
                fd.write(f"{terminal_node.rule.name}\n")
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

        if id(rule) in visited_rules:
            # Avoid cycles
            return

        visited_rules.add(id(rule))

        # Check if this rule is terminal (has no outputs or outputs not consumed)
        is_terminal = True
        for output in rule.outputs:
            if output.consumed_by is not None:
                is_terminal = False
                dfs(output)

        if is_terminal:
            terminal_rules.add(id(rule))

    # Start DFS from the given artifact node
    dfs(artifact_node)

    return terminal_rules

def printDOT(dag: DAG):
    _writeDOT(dag, sys.stdout)

def _writeDOT(dag: DAG, f: io.TextIOBase):
    f.write("digraph conseq {\n")
    f.write("  rankdir=LR;\n")  # Left to right layout
    f.write("  node [shape=box, style=filled, fillcolor=lightblue];\n\n")

    # Write all nodes
    for rule_node in dag.rules:
        rule_name = rule_node.rule.name
        # Escape quotes in rule name if needed
        safe_name = rule_name.replace('"', '\\"')
        if rule_node.rule.is_publish_rule:
            f.write(f'  "{safe_name}" [label="{safe_name}" fillcolor=lightred];\n')
        else:
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

def _write_blockers_dot(all_blockers: List[Blockers], f: io.TextIOBase):
    f.write("digraph conseq {\n")
    f.write("  rankdir=LR;\n")  # Left to right layout
    f.write("  node [shape=box, style=filled, fillcolor=lightblue1];\n\n")

    def _to_safe_name(x):
        return x.replace('"', '\\"')

    # Write all nodes
    for blockers in all_blockers:
        rule_name = blockers.rule.name
        # Escape quotes in rule name if needed
        safe_name = _to_safe_name(rule_name)
        if blockers.rule.is_publish_rule:
            f.write(f'  "{safe_name}" [label="{safe_name}" fillcolor=lightblue3];\n')
        else:
            f.write(f'  "{safe_name}" [label="{safe_name}"];\n')

    f.write("\n")

    # Write all edges
    for blockers in all_blockers:
        rule_name = blockers.rule.name
        rule_node_name = _to_safe_name(rule_name)

        seen = set()
        for rule in blockers.start_blocked_by_uncompleted_rules:
            f.write(
                f'  "{_to_safe_name(rule.name)}" -> "{rule_node_name}" [style="dotted"];\n'
            )
            seen.add(rule.name)

        for rule in blockers.completion_blocked_by_uncompleted_rules:
            if rule.name not in seen:
                f.write(
                    f'  "{_to_safe_name(rule.name)}" -> "{rule_node_name}";\n'
                )

    f.write("}\n")

def writeDOT(dag: DAG, filename: str):
    """
    Write the DAG as a Graphviz DOT file.
    
    Args:
        dag: The DAG object to visualize
        filename: Path to the output DOT file
    """
    with open(filename, "w") as f:
        _writeDOT(dag, f)



def artifact_satisfies_constraints(
        artifact: Artifact,
        constraints: Constraints,
        cache: dict[Union[Constraints, Artifact], set[tuple[str, Union[str, Unknown]]]],
) -> bool:
    """
    Check if an artifact satisfies the given constraints.

    Args:
        artifact: Artifact with the artifact properties
        constraints: Constraints object with properties to match against

    Returns:
        bool: True if the artifact satisfies all constraints, False otherwise
    """
    by_name = {p.name: p.value for p in artifact.properties}

    for pair in constraints.properties:
        if isinstance(pair.value, RegEx):
            artifact_value = by_name[pair.name]
            if artifact_value is UNKNOWN:
                # possible so continue
                continue
            else:
                assert isinstance(artifact_value,str)
                if not re.match(pair.value.expression, artifact_value):
                    return False
        else:
            assert isinstance(pair.value, str)
            artifact_value = by_name[pair.name]
            if artifact_value is UNKNOWN:
                # possible so continue
                continue
            else:
                assert isinstance(artifact_value,str)
                if artifact_value != pair.value:
                    return False

    return True



class IdentitySet:
    def __init__(self):
        self.d = IdentityDict()

    def __contains__(self, value):
        return value in self.d

    def add(self, value):
        self.d[value] = value

    def values(self):
        return self.d.values()

class IdentityDict:
    def __init__(self):
        self.m = {}

    def __contains__(self, value):
        return id(value) in self.m

    def __setitem__(self, key, value):
        self.m[id(key)] = value

    def __getitem__(self, key):
        return self.m[id(key)]

    def values(self):
        return self.m.values()

def walk_all_paths(rule_node: RuleNode, path : list[RuleNode]):
    if rule_node in path:
        raise CycleDetected([x.rule.name for x in path] + [rule_node.rule.name])
    for output in rule_node.outputs:
        walk_all_paths(output.consumed_by, path + [rule_node])

def assert_no_cycles(dag : DAG):
    for rule_node in dag.roots:
        walk_all_paths(rule_node, [])

def createDAG(rules: list[Rule]) -> DAG:
    # Create a mapping of property patterns to rule nodes
    rule_nodes: dict[Rule, RuleNode] = IdentityDict()
    cache = IdentityDict()

    # First pass: create RuleNodes for all rules
    for rule in rules:
        rule_node = RuleNode(rule=rule, inputs=[], outputs=[])
        rule_nodes[rule] = rule_node

    def all_bindings():
        for rule in rules:
            for input in rule.inputs:
                yield rule, input

    def all_artifact_outputs():
        for rule in rules:
            for output in rule.outputs:
                yield rule, output

    # Second pass: For each constraint, find all matching input artifacts and set up bi-directional references
    for binding_rule, binding in all_bindings():
        for output_rule, artifact_output in all_artifact_outputs():

            # if binding_rule.name == "assemble_feature_matrix" and output_rule.name == "make_pred_biomarker_matrix":
            #     breakpoint()
            # if rule.name in ["assemble_feature_matrix", "make_pred_biomarker_matrix"]:
            #     breakpoint()

            if artifact_satisfies_constraints(
                    artifact_output.artifact, binding.constraints, cache
            ):
                # The output artifact matches the input constraints of a different rule. So link them up
                match = ArtifactMatchNode(
                    produced_by=rule_nodes[output_rule],
                    binding=binding,
                    artifact=artifact_output,
                    consumed_by=rule_nodes[binding_rule],
                )

                match.produced_by.outputs.append(match)
                match.consumed_by.inputs.append(match)

    # Return the DAG with all rule nodes
    dag =  DAG(rules=list(rule_nodes.values()))
    assert_no_cycles(dag)
    return dag



def compute_blockers(dag: DAG) -> list[Blockers]:
    # if a rule has an "all" input, then it needs to wait for all rules which _could_ produce such an artifact
    # to complete before it can start. This determines the set of rules in `start_blocked_by_uncompleted_rules`

    # Similarly a rule cannot be completed if an input _could_ be produced by a rule which is not complete yet
    # This is what determines the set of rules in `start_blocked_by_uncompleted_rules`

    blockers = []
    for rule_node in dag.rules:

        start_blocked_by_uncompleted_rules = IdentitySet()
        completion_blocked_by_uncompleted_rules = IdentitySet()

        for input in rule_node.inputs:
            completion_blocked_by_uncompleted_rules.add(input.produced_by.rule)

            # if we have a node which consumes "all" artifacts, we need to wait for the rules
            # which could possibly create these artifacts to fully complete before we know
            # we have all such artifacts.
            if input.binding.cardinality == "all":
                start_blocked_by_uncompleted_rules.add(input.produced_by.rule)

        blockers.append(
            Blockers(
                rule=rule_node.rule,
                start_blocked_by_uncompleted_rules=list(start_blocked_by_uncompleted_rules.values()),
                completion_blocked_by_uncompleted_rules=list(completion_blocked_by_uncompleted_rules.values()),
            )
        )

    return blockers
