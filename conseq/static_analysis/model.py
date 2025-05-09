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
    consumed_by: list["RuleNode"]


@dataclass
class RuleNode:
    rule: Rule
    inputs: list[ArtifactNode]
    outputs: list[ArtifactNode]


@dataclass
class DAG:
    rules: list[RuleNode]


def createDAG(rules: list[Rule]) -> DAG:
    # Create a mapping of property patterns to rule nodes
    rule_nodes = {}
    artifact_nodes = {}
    
    # First pass: create RuleNodes for all rules
    for rule in rules:
        rule_node = RuleNode(rule=rule, inputs=[], outputs=[])
        rule_nodes[rule] = rule_node
    
    # Second pass: create ArtifactNodes and connect them
    for rule in rules:
        rule_node = rule_nodes[rule]
        
        # Create output artifact nodes
        for output in rule.outputs:
            # Create a unique key for this artifact based on its properties
            artifact_key = tuple((p.name, str(p.value)) for p in output.artifact.properties)
            
            # Create or get the artifact node
            if artifact_key not in artifact_nodes:
                artifact_nodes[artifact_key] = ArtifactNode(produced_by=rule_node, consumed_by=[])
            
            artifact_node = artifact_nodes[artifact_key]
            rule_node.outputs.append(artifact_node)
        
        # Connect input constraints to matching artifact nodes
        for binding in rule.inputs:
            constraints = binding.constraints
            
            # Find matching artifacts based on constraints
            for artifact_key, artifact_node in artifact_nodes.items():
                # Check if this artifact matches the constraints
                matches = True
                for constraint in constraints.properties:
                    constraint_name = constraint.name
                    constraint_value = constraint.value
                    
                    # Skip unknown constraints
                    if isinstance(constraint_value, Unknown):
                        continue
                    
                    # Check if the artifact has a matching property
                    artifact_matches = False
                    for prop_name, prop_value in artifact_key:
                        if prop_name == constraint_name and prop_value == constraint_value:
                            artifact_matches = True
                            break
                    
                    if not artifact_matches:
                        matches = False
                        break
                
                if matches:
                    # This artifact matches the constraints
                    rule_node.inputs.append(artifact_node)
                    artifact_node.consumed_by.append(rule_node)
    
    # Return the DAG with all rule nodes
    return DAG(rules=list(rule_nodes.values()))
