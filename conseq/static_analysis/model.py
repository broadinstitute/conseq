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
class ArtifactMatchNode:
    produced_by: "RuleNode"
    binding: Binding
    artifact: OutputArtifact
    consumed_by: "RuleNode"


@dataclass
class RuleNode:
    rule: Rule
    inputs: list[ArtifactMatchNode]
    outputs: list[ArtifactMatchNode]


@dataclass
class DAG:
    rules: list[RuleNode]

    @property
    def roots(self):
        return [node for node in self.rules if len(node.inputs) == 0]


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
    if constraints in cache:
        required: set[tuple[str, Union[str, Unknown]]] = cache[constraints]
    else:
        required: set[tuple[str, Union[str, Unknown]]] = {
            (pair.name, pair.value)
            for pair in constraints.properties
            if not isinstance(pair.value, Unknown)
        }
        cache[constraints] = required

    if artifact in cache:
        artifact_pairs = cache[artifact]
    else:
        artifact_pairs = {(pair.name, pair.value) for pair in artifact.properties}
        cache[artifact] = artifact_pairs

    return required.issubset(artifact_pairs)


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
    return DAG(rules=list(rule_nodes.values()))


class Transitions:
    rule: Rule
    start_blocked_by_uncompleted_rules: list[Rule]
    completion_blocked_by_uncompleted_rules: list[Rule]


def calc_run_depenendencies(dag: DAG) -> list[Transitions]:
    # all rules can be one of three states: start-blocked -> not-complete -> complete
    # based on the DAG, identify a set of checks per rule which determine when to transition.
    transitions = []
    for rule_node in dag.rules:
        start_blocked_by_uncompleted_rules = []
        completion_blocked_by_uncompleted_rules = []
        for input in rule_node.inputs:
            completion_blocked_by_uncompleted_rules.append(input.produced_by.rule)
        for input in rule_node.inputs:
            # if we have a node which consumes "all" artifacts, we need to wait for the rules
            # which could possibly create these artifacts to fully complete before we know
            # we have all such artifacts.
            if input.binding.cardinality == "all":
                start_blocked_by_uncompleted_rules.append(input.produced_by.rule)
        transitions.append(
            Transitions(
                rule=rule_node.rule,
                start_blocked_by_uncompleted_rules=start_blocked_by_uncompleted_rules,
                completion_blocked_by_uncompleted_rules=completion_blocked_by_uncompleted_rules,
            )
        )
    return transitions
