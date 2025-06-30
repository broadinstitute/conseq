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

@dataclass
class Blockers:
    rule: Rule
    start_blocked_by_uncompleted_rules: list[Rule]
    completion_blocked_by_uncompleted_rules: list[Rule]
