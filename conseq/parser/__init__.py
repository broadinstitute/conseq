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
    def default(self, obj):
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
        self.output_expectations = None

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


def unquote(s):
    # TODO: Handle escaped quotes
    if len(s) > 0 and s[:3] == '"""':
        assert s[-3:] == '"""'
        return s[3:-3]
    if s[:3] == "'''":
        assert s[-3:] == "'''"
        return s[3:-3]
    if s[0] == '"':
        assert s[-1] == '"'
        return s[1:-1]
    if s[0] == "'":
        assert s[-1] == "'"
        return s[1:-1]
    raise Exception("{} does not look like a valid string".format(s))


class Semantics(object):
    def __init__(self, filename):
        self.filename = filename

    def rule_parameters(self, ast):
        # print("rule_parameters", ast)
        return tuple(ast)

    def run_statement(self, ast):
        exec_profile = "default"
        if ast[0] == "using":
            exec_profile = ast[1]
            ast = ast[2:]

        assert ast[0] == "run"
        if len(ast) > 3:
            script_body = ast[3]
        else:
            script_body = None
        return RunStmt(exec_profile, ast[1], script_body)

    def identifier_list(self, ast):
        identifiers = [ast[0]]
        rest = ast[1]
        for x in rest:
            identifiers.append(x[1])
        return identifiers

    def construct_cache_key_run(self, ast):
        exec_profile = "default"
        assert ast[0] == "construct-cache-key-run"
        if len(ast) > 3:
            script_body = ast[3]
        else:
            script_body = None
        return RunStmt(exec_profile, ast[1], script_body)

    def input_spec_each(self, ast):
        inspec = InputSpec(ast[0], ast[2], False, None)
        return inspec

    def input_spec_all(self, ast):
        inspec = InputSpec(ast[0], ast[3], True, None)
        return inspec

    def json_name_value_pair(self, ast):
        return (ast.name, ast.value)

    def json_array(self, ast):
        if len(ast) == 2:
            return []
        return [ast.first] + [x[1] for x in ast.rest]

    def json_obj(self, ast):
        pairs = [ast.first]
        for x in ast.rest:
            pairs.append(x[1])
        return dict(pairs)

    def query_name_value_pair(self, ast):
        if ast[1] == "~":
            return (ast[0], RegEx(ast[2]))
        else:
            return (ast[0], ast[2])

    def pattern_based_query_obj(self, ast):
        pairs = [ast[1]]
        rest = ast[2]
        for x in rest:
            pairs.append(x[1])
        return dict(pairs)

    def remember_executed(self, ast):
        return RememberExecutedStmt(transform=ast[3], inputs=ast[4], outputs=ast[5])

    def remember_executed_input(self, ast):
        value = ast[3][0]
        assert isinstance(value, list) or isinstance(value, dict)
        if isinstance(value, list):
            assert isinstance(value[0], dict)
        return (ast[1], value)

    def remember_executed_output(self, ast):
        return ast[2]

    def query_variable(self, ast):
        assert isinstance(ast, six.string_types)
        return QueryVariable(ast)

    def type_definition_component(self, ast):
        if ast[0] == "fields":
            return TypeDefFields(ast[2])
        else:
            assert ast[0] == "description"
            return TypeDefDescription(ast[2])

    def type_definition(self, ast):
        fields = []
        description = None
        components = [ast[0]]
        components.extend(ast[1])
        for component in components:
            if isinstance(component, TypeDefFields):
                fields = component.fields
            else:
                assert isinstance(component, TypeDefDescription)
                description = component.description
        return TypeDefinition(fields=fields, description=description)

    def rule(self, ast):
        # raise Exception()
        # print("rule", repr(ast))
        rule_name = ast.name
        rule_parameters = ast.params
        runs = ast.stmts
        rule = Rule(rule_name)
        rule.lineno = ast.parseinfo.line
        rule.filename = self.filename
        for statement in rule_parameters:
            if statement[0] == "inputs":
                rule.inputs = statement[2]
            elif statement[0] == "outputs":
                rule.outputs = statement[2]
            elif statement[0] == "options":
                # print("----> options", statement)
                options = [statement[2]]
                rest = statement[3]
                for i in range(0, len(rest), 2):
                    options.append(rest[1])
                rule.options = options
            elif statement[0] == "watch-regex":
                rule.watch_regex = re.compile(statement[2])
            elif statement[0] == "executor":
                rule.executor = statement[2]
                if len(statement) == 4:
                    rule.executor_parameters = statement[3]
                else:
                    assert len(statement) == 3
                    rule.executor_parameters = {}
            elif statement[0] == "resources":
                rule.resources = dict([(k, float(v)) for k, v in statement[2].items()])
                if "slots" not in rule.resources:
                    rule.resources["slots"] = 1
            elif statement[0] == "description":
                rule.description = statement[2]
            elif statement[0] == "publish":
                rule.publish_location = statement[2]
                assert rule.is_publish_rule
            elif statement[0] == "uses":
                rule.uses_files = statement[2]
            else:
                raise Exception("unknown {}".format(statement[0]))
        rule.run_stmts.extend(runs)
        rule.cache_key_constructor.extend(ast.cachekeystmts)
        # print("rule:", repr(rule))
        return rule

    def exec_profile(self, ast):
        return ExecProfileStmt(ast[1], ast[2])

    def quoted_string(self, ast):
        return unquote(ast)

    def input_specs(self, ast):
        specs = [ast[0]]
        rest = ast[1]
        for x in rest:
            specs.append(x[1])
        return specs

    def output_specs(self, ast):
        if ast == "none":
            return []

        specs = [ast[0]]
        rest = ast[1]
        for x in rest:
            specs.append(x[1])
        return specs

    def type_def_stmt(self, ast):
        return TypeDefStmt(ast[1], ast[3].description, ast[3].fields)

    def var_stmt(self, ast):
        return LetStatement(ast[1], ast[3])

    def include_stmt(self, ast):
        return IncludeStatement(ast[1])

    def add_if_missing(self, ast):
        return AddIfMissingStatement(ast[1])

    def type_def(self, ast):
        properties = [ast[4]] + ast[5]
        return TypeDefStmt(ast[1], properties)

    def conditional_expr(self, ast):
        exp = compile(ast, "<conseq-config>", "eval")
        return exp

    def conditional(self, ast):
        else_clause = []
        if ast.else_clause != None:
            else_clause = ast.else_clause[2]
        for i in reversed(range(len(ast.elif_clauses))):
            else_clause = IfStatement(
                ast.elif_clauses[i][1], ast.elif_clauses[i][3], else_clause
            )
        return IfStatement(ast.condition, ast.true_body, else_clause)

    def eval_statement(self, ast):
        return EvalStatement(ast[1])

    def fileref_query_obj(self, ast):
        # import pdb
        # pdb.set_trace()
        copy_to = None
        for option in ast.options:
            name = option[1]
            value = option[3]
            assert name == "copy_to"
            copy_to = value
        return FileRef(ast.filename, copy_to)

    def file_list(self, ast):
        files = [ast[0]]
        for x in ast[1]:
            files.append(x[1])
        return files


Statement = Union[LetStatement, IfStatement, IncludeStatement, TypeDefStmt, Rule]


def parse_str(text, filename=None):
    parser = depfile.depfileParser(parseinfo=False)
    statements = parser.parse(
        text,
        "all_declarations",
        filename=filename,
        trace=False,
        nameguard=None,
        parseinfo=True,
        semantics=Semantics(filename),
    )
    if statements is None:
        return []
    return statements


def parse(filename):
    with open(filename) as f:
        text = f.read()
    return parse_str(text, filename)
