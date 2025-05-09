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
    # todo: implement
    return DAG(rules=[])
