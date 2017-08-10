from collections import namedtuple
from conseq.parser import depfile
import re
import six

QueryVariable = namedtuple("QueryVariable", ["name"])
RunStmt = namedtuple("RunStmt", ["exec_profile", "command", "script"])
FlockInclude = namedtuple("FlockInclude", ["path"])
FlockStmt = namedtuple("FlockStmt", ["language", "fn_prefix", "scripts"])
TypeDefStmt = namedtuple("TypeDefStmt", "name properties")
ExecProfileStmt = namedtuple("ExecProfileStmt", "name properties")
RememberExecutedStmt = namedtuple("RememberExecutedStmt", "transform inputs outputs")
ExpectKeyIs = namedtuple("ExpectKeyIs", "key value")
ExpectKey = namedtuple("ExpectKey", "key")
ExpectedTemplate = namedtuple("ExpectedTemplate", "predicates")

class XRef:
    def __init__(self, url, obj):
        self.url = url
        self.obj = obj

class Rule:
    def __init__(self, name):
        self.name = name
        self.inputs = []
        self.outputs = None
        self.options = []
        self.run_stmts = []
        self.executor = "default"
        assert self.name != "" and self.name != " "
        self.resources = {"slots": 1}
        self.if_defined = []
        self.output_expectations = []

    def output_matches_expectation(self, key_values):
        # if outputs were defined, then not checks needed
        if self.outputs is not None:
            return True

        for e in self.output_expectations:
            matched_all = True
            unchecked_keys = set(key_values.keys())
            for predicate in e.predicates:
                if isinstance(predicate, ExpectKey):
                    if predicate.key not in key_values:
                        matched_all = False
                        break
                else:
                    assert isinstance(predicate, ExpectKeyIs)
                    if predicate.key not in key_values or key_values[predicate.key] != predicate.value:
                        matched_all = False
                        break
                unchecked_keys.remove(predicate.key)

            if matched_all and len(unchecked_keys) == 0:
                return True

        return False

    @property
    def language(self):
        if "exec-python" in self.options:
            return "python"
        elif "exec-R" in self.options:
            return "R"
        else:
            return "shell"

    def __repr__(self):
        return "<Rule {} inputs={} options={}>".format(self.name, self.inputs, self.options)

InputSpec = namedtuple("InputSpec", ["variable", "json_obj", "for_all"])
IncludeStatement = namedtuple("IncludeStatement", ["filename"])
LetStatement = namedtuple("LetStatement", ["name", "value"])
AddIfMissingStatement = namedtuple("AddIfMissingStatement", "json_obj")

def unquote(s):
    # TODO: Handle escaped quotes
    if len(s) > 0 and s[:3] == '"""':
        assert s[-3:] == '"""'
        return s[3:-3]
    if s[:3] == "'''":
        assert s[-3:] == "'''"
        return s[3:-3]
    if s[0] == "\"":
        assert s[-1] == '"'
        return s[1:-1]
    if s[0] == "'":
        assert s[-1] == "'"
        return s[1:-1]
    raise Exception("{} does not look like a valid string".format(s))

class Semantics(object):
    def rule_parameters(self, ast):
        #print("rule_parameters", ast)
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

    def input_spec_each(self, ast):
        inspec = InputSpec(ast[0], ast[2], False)
        return inspec

    def input_spec_all(self, ast):
        inspec = InputSpec(ast[0], ast[3], True)
        return inspec

    def json_name_value_pair(self, ast):
        return (ast[0], ast[2])

    def json_array(self, ast):
        if len(ast) == 2:
            return []
        return [ast[1]] + [x[1] for x in ast[2]]

    def json_obj(self, ast):
        pairs = [ast[1]]
        rest = ast[2]
        for x in rest:
            pairs.append(x[1])
        return dict(pairs)

    def query_name_value_pair(self, ast):
        if ast[1] == "~":
            return (ast[0], re.compile(ast[2]))
        else:
            return (ast[0], ast[2])

    def query_obj(self, ast):
        pairs = [ast[1]]
        rest = ast[2]
        for x in rest:
            pairs.append(x[1])
        return dict(pairs)

    def xref(self, ast):
        #print("xref ast", ast)
        return XRef(ast[1],ast[2])

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

    def output_expected_key_value(self, ast):
        #print("output_expected_key_value", ast)
        assert len(ast) == 2
        if len(ast[1][0]) != 0:
            value = ast[1][0][0][1]
            #print("key", ast[0], "value", value)
            assert isinstance(value, str)
            return ExpectKeyIs(ast[0], value)
        else:
            return ExpectKey(ast[0])

    def output_expected_def(self, ast):
        #print("outputs_expected_def", ast)
        predicates = [ast[1]]
        for x in ast[2]:
            predicates.append(x[1])
        #print("predicates", predicates)
        return ExpectedTemplate(predicates)

    def outputs_expected_defs(self, ast):
        expectations = [ast[0]]
        for x in ast[1]:
            expectations.append(x[1])
        return expectations

    def rule(self, ast):
        #print("rule", repr(ast))
        rule_name = ast[1]
        rule_parameters = ast[3]
        runs = ast[4]
        rule = Rule(rule_name)
        for statement in rule_parameters:
            if statement[0] == "inputs":
                rule.inputs = statement[2]
            elif statement[0] == "outputs":
                rule.outputs = statement[2]
            elif statement[0] == "options":
                #print("----> options", statement)
                options = [statement[2]]
                rest = statement[3]
                for i in range(0,len(rest),2):
                    options.append(rest[1])
                rule.options = options
            elif statement[0] == "executor":
                rule.executor = statement[2]
            elif statement[0] == "resources":
                rule.resources = dict([ (k, float(v)) for k,v in statement[2].items() ])
                if "slots" not in rule.resources:
                    rule.resources["slots"] = 1
            elif statement[0] == "if-defined":
                rule.if_defined.extend ( [statement[2]] + [x[1] for x in statement[3]] )
            elif statement[0] == "outputs-expected":
                rule.output_expectations = statement[2]
            else:
                raise Exception("unknown {}".format(statement[0]))
        rule.run_stmts.extend(runs)
        #print("rule:", repr(rule))
        return rule

    def exec_profile(self, ast):
        return ExecProfileStmt(ast[1], ast[2])

    def r_flock_file(self, ast):
        if type(ast) == list:
            assert ast[0] == 'include'
            return IncludeStatement(ast[1])
        else:
            return ast

    def r_flock_files(self, ast):
        scripts = [ast[0]]
        for x in ast[1]:
            scripts.append(x[1])
        return scripts

    def quoted_string(self, ast):
        return unquote(ast)

    def input_specs(self, ast):
        specs = [ast[0]]
        rest = ast[1]
        for x in rest:
            specs.append(x[1])
        return specs

    def output_specs(self, ast):
        specs = [ast[0]]
        rest = ast[1]
        for x in rest:
            specs.append(x[1])
        return specs

    def var_stmt(self, ast):
        return LetStatement(ast[1], ast[3])

    def include_stmt(self, ast):
        return IncludeStatement(ast[1])

    def add_if_missing(self, ast):
        return AddIfMissingStatement(ast[1])

    def type_def(self, ast):
        properties = [ast[4]] + ast[5]
        return TypeDefStmt(ast[1], properties)

def parse_str(text, filename=None):
    parser = depfile.depfileParser(parseinfo=False)
    return parser.parse(
        text,
        "declarations",
        filename=filename,
        trace=False,
        nameguard=None,
        semantics = Semantics())

def parse(filename):
    with open(filename) as f:
        text = f.read()
    return parse_str(text, filename)