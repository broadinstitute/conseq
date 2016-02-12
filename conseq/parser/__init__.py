from collections import namedtuple
from . import depfile

QueryVariable = namedtuple("QueryVariable", ["name"])

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
        self.script = None
        self.postscript = None
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

InputSpec = namedtuple("InputSpec", ["variable", "json_obj"])
IncludeStatement = namedtuple("IncludeStatement", ["filename"])
LetStatement = namedtuple("LetStatement", ["name", "value"])

def unquote(s):
    if len(s) > 0 and s[:3] == '"""':
        assert s[-3:] == '"""'
        return s[3:-3]
    assert s[0] == '"'
    assert s[-1] == '"'
    return s[1:-1]


class Semantics(object):
    def statement(self, ast):
        return tuple(ast)

    def input_spec(self, ast):
        return InputSpec(ast[0], ast[2])

    def statements(self, ast):
        return ast

    def json_name_value_pair(self, ast):
        return (ast[0], ast[2])

    def json_obj(self, ast):
        pairs = [ast[1]]
        rest = ast[2]
        for x in range(0, len(rest), 2):
            pairs.append(rest[x+1])
        return dict(pairs)

    def query_name_value_pair(self, ast):
        return (ast[0], ast[2])

    def query_obj(self, ast):
        pairs = [ast[1]]
        rest = ast[2]
        for x in range(0, len(rest), 2):
            pairs.append(rest[x+1])
        return dict(pairs)

    def xref(self, ast):
        #print("xref ast", ast)
        return XRef(ast[1],ast[2])

    def query_variable(self, ast):
        assert isinstance(ast, str)
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
            elif statement[0] == "script":
                rule.script = statement[2]
            elif statement[0] == "postscript":
                rule.postscript = statement[2]
            elif statement[0] == "options":
                #print("----> options", statement)
                options = [statement[2]]
                rest = statement[3]
                for i in range(0,len(rest),2):
                    options.append(rest[1])
                rule.options = options
            else:
                raise Exception("unknown {}".format(statement[0]))
        #print("rule:", repr(rule))
        return rule

    def quoted_string(self, ast):
        return unquote(ast)

    def input_specs(self, ast):
        specs = [ast[0]]
        rest = ast[1]
        for i in range(0,len(rest),2):
            specs.append(rest[1])
        return specs

    def output_specs(self, ast):
        specs = [ast[0]]
        rest = ast[1]
        for i in range(0,len(rest),2):
            specs.append(rest[1])
        return specs

    def var_stmt(self, ast):
        return LetStatement(ast[1], ast[3])

    def include_stmt(self, ast):
        return IncludeStatement(ast[1])


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