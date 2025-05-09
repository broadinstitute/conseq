from dataclasses import dataclass
from typing import Union, Literal


class Unknown:
    pass


UNKNOWN = Unknown()


@dataclass
class Pair:
    name: str
    value: Union[str, Unknown]


@dataclass
class Artifact:
    properties: list[Pair]


@dataclass
class Constraints:
    properties: list[Pair]


@dataclass
class Binding:
    variable: str
    cardinality: Literal["one", "all"]
    constraints: Constraints


@dataclass
class OutputArtifact:
    artifact: Artifact
    cardinality: Literal["one", "many"]


@dataclass
class Rule:
    name: str
    inputs: list[Binding]
    outputs: list[OutputArtifact]


@dataclass
class ArtifactNode:
    produced_by: "RuleNode"
    artifact: Artifact
    consumed_by: list["RuleNode"]


@dataclass
class RuleNode:
    rule: Rule
    inputs: list[ArtifactNode]
    outputs: list[ArtifactNode]


@dataclass
class DAG:
    rules: list[RuleNode]


def artifact_satisfies_constraints(
    artifact: Artifact, constraints: Constraints
) -> bool:
    """
    Check if an artifact satisfies the given constraints.
    
    Args:
        artifact: Artifact with the artifact properties
        constraints: Constraints object with properties to match against
        
    Returns:
        bool: True if the artifact satisfies all constraints, False otherwise
    """

    required = {
        (name, value)
        for name, value in constraints.properties
        if not isinstance(value, Unknown)
    }
    artifact_pairs = [(pair.name, pair.value) for pair in artifact.properties]

    return required.issubset(artifact_pairs)


def createDAG(rules: list[Rule]) -> DAG:
    # Create a mapping of property patterns to rule nodes
    rule_nodes: dict[Rule, RuleNode] = {}
    artifact_nodes: dict[Artifact, ArtifactNode] = {}

    # First pass: create RuleNodes for all rules
    for rule in rules:
        rule_node = RuleNode(rule=rule, inputs=[], outputs=[])
        rule_nodes[rule] = rule_node

    # Second pass: create ArtifactNodes and connect them
    for rule in rules:
        rule_node = rule_nodes[rule]

        # Create output artifact nodes
        for output in rule.outputs:
            artifact_node = ArtifactNode(
                produced_by=rule_node, consumed_by=[], artifact=output.artifact
            )
            artifact_nodes[output.artifact] = artifact_node

            rule_node.outputs.append(artifact_node)

    # Third pass: For each constraint, find all matching input artifacts
    for rule in rules:
        rule_node = rule_nodes[rule]

        # Connect input constraints to matching artifact nodes
        for binding in rule.inputs:
            constraints = binding.constraints

            # Find matching artifacts based on constraints
            for artifact_node in artifact_nodes.values():
                if artifact_satisfies_constraints(artifact_node, constraints):
                    # This artifact matches the constraints
                    rule_node.inputs.append(artifact_node)
                    artifact_node.consumed_by.append(rule_node)

    # Return the DAG with all rule nodes
    return DAG(rules=list(rule_nodes.values()))
