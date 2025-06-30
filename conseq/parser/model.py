import json
import re
from collections import namedtuple
import six
from typing import Dict, Optional, Any
from dataclasses import dataclass
from conseq.parser import depfile
from typing import List, Union
import dataclasses


@dataclass
class Cardinality:
    min: int
    max: Optional[int]


@dataclass
class QueryVariable:
    name: str


@dataclass
class RunStmt:
    exec_profile: str
    command: str
    script: str


@dataclass
class TypeDefStmt:
    name: str
    description: Optional[str]
    fields: List[str]


@dataclass
class ResolvedOutputType:
    type_def: TypeDefStmt
    cardinality: Cardinality


@dataclass
class TypeDefFields:
    fields: List[str]


@dataclass
class TypeDefDescription:
    description: str


@dataclass
class TypeDefinition:
    description: Optional[str]
    fields: List[str]


@dataclass
class ExecProfileStmt:
    name: str
    properties: Dict[str, Any]


@dataclass
class RememberExecutedStmt:
    transform: str
    inputs: Dict[str, Any]
    outputs: List[Any]


@dataclass
class InputSpec:
    variable: str
    json_obj: Dict[str, Any]
    for_all: object
    copy_to: str


@dataclass
class IncludeStatement:
    filename: str


@dataclass
class LetStatement:
    name: str
    value: str


@dataclass
class AddIfMissingStatement:
    json_obj: Dict[str, Any]


@dataclass
class IfStatement:
    condition: str
    when_true: List["Statement"]
    when_false: List["Statement"]


@dataclass
class EvalStatement:
    body: str


class FileRef:
    def __init__(self, filename, copy_to=None):
        self.filename = filename
        self.copy_to = copy_to


RegEx = namedtuple("RegEx", "expression")


class CustomRuleEncoder(json.JSONEncoder):
    def default(self, o):
        obj = o
        if isinstance(obj, RegEx):
            return {"re_pattern": obj.expression}
        if dataclasses.is_dataclass(obj):
            return dataclasses.asdict(obj)
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


class Rule:
    resource: Dict[str, float]
    inputs: List[InputSpec]

    def __init__(self, name):
        self.name = name
        self.filename: Optional[str] = None
        self.lineno: Optional[int] = None
        self.inputs = []
        self.outputs: Optional[Any] = None
        self.output_types: Optional[List[OutputType]] = None
        self.resolved_output_types: Optional[List[ResolvedOutputType]] = None
        self.run_stmts: List[RunStmt] = []
        self.executor = "default"
        self.executor_parameters = {}
        self.watch_regex = None
        assert self.name != "" and self.name != " "
        self.resources = {"slots": 1.0}
        self.description = None
        self.publish_location = None
        self.cache_key_constructor = []
        self.uses_files = []

    def to_json(self):
        return json.dumps(
            {
                "name": self.name,
                "inputs": self.inputs,
                "outputs": self.outputs,
                "run_stmts": self.run_stmts,
            },
            sort_keys=True,
            cls=CustomRuleEncoder,
        )

    def has_for_all_input(self):
        return any([x.for_all for x in self.inputs])

    @property
    def is_publish_rule(self):
        return self.publish_location != None

    def __repr__(self):
        return "<Rule {} inputs={}>".format(self.name, self.inputs)


@dataclass
class OutputType:
    type: str
    cardinality: Cardinality


Statement = Union[LetStatement, IfStatement, IncludeStatement, TypeDefStmt, Rule]
