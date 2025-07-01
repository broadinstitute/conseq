from collections import defaultdict
from dataclasses import dataclass
from typing import Union, Literal
from conseq.parser.model import RegEx

class Unknown:
    def __str__(self):
        return "UNKNOWN"
    def __repr__(self):
        return self.__str__()

UNKNOWN = Unknown()

@dataclass
class Pair:
    name: str
    value: Union[str, Unknown, RegEx]


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
    is_publish_rule: bool


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

def _is_unsatisfiable(node :RuleNode) :
    return False
    # by_var_name = defaultdict(lambda: [])
    # for input_node in node.inputs:
    #     by_var_name[input_node.binding.variable].append(input_node)
    #
    # if len(node.rule.inputs) != len(node.inputs):
    #     return True
    # else:
    #     return False

class DAG:
    rules: list[RuleNode]
    unsatisfiable: list[RuleNode]
    roots: list[RuleNode]

    def __init__(self, rules: list[RuleNode]):
        unsatisfiable = []
        roots = []
        rules_ = []

        for node in rules:
            if _is_unsatisfiable(node):
                unsatisfiable.append(node)
                continue
            else:
                if len(node.inputs) == 0:
                    roots.append(node)
            rules_.append(node)

        self.unsatisfiable = unsatisfiable
        self.roots = roots
        self.rules = rules_


@dataclass
class Blockers:
    rule: Rule
    start_blocked_by_uncompleted_rules: list[Rule]
    completion_blocked_by_uncompleted_rules: list[Rule]
