from collections import namedtuple
from conseq.parser import depfile
import re
import six

QueryVariable = namedtuple("QueryVariable", ["name"])
RunStmt = namedtuple("RunStmt", ["command", "script"])
FlockInclude = namedtuple("FlockInclude", ["path"])
FlockStmt = namedtuple("FlockStmt", ["language", "fn_prefix", "scripts"])
TypeDefStmt = namedtuple("TypeDefStmt", "name properties")


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
        assert self.name != "" and self.name != " "

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
    def statement(self, ast):
        return tuple(ast)

    def input_spec_each(self, ast):
        inspec = InputSpec(ast[0], ast[2], False)
        return inspec

    def input_spec_all(self, ast):
        inspec = InputSpec(ast[0], ast[3], True)
        return inspec

    def statements(self, ast):
        return ast

    def json_name_value_pair(self, ast):
        return (ast[0], ast[2])

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

    def query_variable(self, ast):
        assert isinstance(ast, six.string_types)
        return QueryVariable(ast)

    def rule(self, ast):
        #print("rule", repr(ast))
        rule_name = ast[1]
        statements = ast[3]
        #print("rule: {}".format(repr(ast)))
        rule = Rule(rule_name)
        for statement in statements:
            if statement[0] == "inputs":
                rule.inputs = statement[2]
            elif statement[0] == "outputs":
                rule.outputs = statement[2]
            elif statement[0] == "run":
                if len(statement) > 3:
                    script_body = statement[3]
                else:
                    script_body = None
                rule.run_stmts.append( RunStmt(statement[1], script_body) )
            elif statement[0] == "options":
                #print("----> options", statement)
                options = [statement[2]]
                rest = statement[3]
                for i in range(0,len(rest),2):
                    options.append(rest[1])
                rule.options = options
            elif statement[0] == "submit-r-flock":
                rule.run_stmts.append( FlockStmt("R", statement[1], statement[2]) )
            else:
                raise Exception("unknown {}".format(statement[0]))
        #print("rule:", repr(rule))
        return rule

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