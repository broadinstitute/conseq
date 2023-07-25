import os

import jinja2

from conseq import depexec
from conseq import parser
from conseq.parser import Semantics
from conseq.parser import depfile
from conseq.parser import TypeDefStmt

pair_of_rules = """
# ignore this comment

rule create_numbers:
    run "python" with \"\"\"
        import conseq
        conseq.publish({"value": "2", "type": "number"}, {"value": "3", "type": "number"})
        \"\"\"

rule square:
    inputs: n={"type": "number"}
    run "python" with \"\"\"
        import conseq
        result = {{inputs.n.value}} ** 2
        conseq.publish(dict(type="squared", value=str(result)))
        \"\"\"
"""


def test_parse_three_rules():
    decs = parser.parse_str(pair_of_rules)
    assert len(decs) == 2

    r = decs[1]
    assert isinstance(r, parser.Rule)

    assert len(r.inputs) == 1
    assert len(r.run_stmts) == 1


constrained_query = """
rule a:
    inputs: a={"type": "number", "value": value}, b={"type": "other", "value": value}
    run "bash"
"""


def test_parse_constrained_query():
    jinja2_env = jinja2.Environment(undefined=jinja2.StrictUndefined)

    decs = parser.parse_str(constrained_query)
    assert len(decs) == 1
    rule = decs[0]
    assert len(rule.inputs) == 2
    a, b = rule.inputs
    print(a, b)
    assert isinstance(a.json_obj["value"], parser.QueryVariable)
    assert isinstance(b.json_obj["value"], parser.QueryVariable)

    template = depexec.to_template(jinja2_env, rule, {})
    assert template.transform == "a"
    assert len(template.foreach_queries) == 2
    assert len(template.forall_queries) == 0
    assert len(template.predicates) == 1

    pred = template.predicates[0]
    print("predicate", pred)
    assert pred.satisfied({"a": {"value": "1"}, "b": {"value": "1"}})
    assert not pred.satisfied({"a": {"value": "1"}, "b": {"value": "2"}})


def test_parse_vars():
    decs = parser.parse_str('let a="x"\n')
    assert len(decs) == 1
    assignment = decs[0]
    assert assignment.name == "a"
    assert assignment.value == "x"


rule_with_forall = """
rule create_numbers:
    inputs: a=all {"type": "box"}, b={"name": "shoe"}
    run "command"
"""


def test_forall_query():
    decs = parser.parse_str(rule_with_forall)
    assert len(decs) == 1
    rule = decs[0]
    assert len(rule.inputs) == 2
    assert rule.inputs[0].variable == "a"
    assert rule.inputs[0].for_all
    assert rule.inputs[1].variable == "b"
    assert not rule.inputs[1].for_all
    assert not rule.is_publish_rule


publish_rule = """
rule pub:
    inputs: a = {"type": "foo"}
    publish: "sample{{inputs.a.other}}"
"""


def test_publish_rule(monkeypatch):
    decs = parser.parse_str(publish_rule)
    assert len(decs) == 1
    rule = decs[0]
    assert rule.is_publish_rule
    assert rule.publish_location == "sample{{inputs.a.other}}"


def _parse_exp(text, nonterminal):
    parser = depfile.depfileParser(parseinfo=True)
    return parser.parse(
        text, nonterminal, trace=False, nameguard=None, semantics=Semantics("<none>")
    )


def test_parse_empty():
    statements = parser.parse_str(
        """
    # empty
    """
    )
    assert len(statements) == 0


def test_parse_trailing_commas():
    # make sure we tolerate trailing commas
    statements = parser.parse_str(
        """
    rule a:
        inputs: x={"a":"b"},
        outputs: {"out": "b",},
        run "cmd"
    """
    )
    assert len(statements) == 1
    assert len(statements[0].inputs) == 1
    assert len(statements[0].outputs) == 1


def test_parse_json():
    value = _parse_exp(
        """
    {"a": "b", "c": '1'}
    """,
        "json_obj",
    )
    assert value == {"a": "b", "c": "1"}

    value = _parse_exp(
        """
    {"a": ["1", "2"]}
    """,
        "json_obj",
    )
    assert value == {"a": ["1", "2"]}


from typing import List, Any
from conseq.template import create_jinja2_env
from conseq.config import Rules, _eval_stmts
from conseq.hashcache import HashCache


def eval_stmts(rules: Rules, statements: List[Any], tmpdir, filename="none"):
    from conseq.config import _eval_stmts, EvalContext

    context = EvalContext(
        rules, filename, HashCache(str(tmpdir.join("hashcache"))), create_jinja2_env()
    )
    _eval_stmts(statements, context)


def test_parse_if(tmpdir):

    rules = Rules()
    # from conseq.parser import IfStatement, LetStatement

    statements = parser.parse_str(
        """
    if "'x' == 'y'":
      let a='1'
    else:
      let a='2'
    endif
    """,
        "declarations",
    )
    eval_stmts(rules, statements, tmpdir)
    assert rules.vars["a"] == "2"

    # else:
    #   let x='2'


def test_eval_if(tmpdir):

    rules = Rules()
    # rules.set_var(name, value)

    statements = parser.parse_str(
        """
    if "'x' == 'y'":
      let a='1'
    else:
      let a='2'
    endif
    """
    )
    eval_stmts(rules, statements, tmpdir)
    assert rules.vars["a"] == "2"


def test_generic_eval(tmpdir):

    rules = Rules()
    # rules.set_var(name, value)

    statements = parser.parse_str(
        """
    eval \"\"\"
        print('here')
        rules.set_var('x', 'y')
        print(config['x'])
        print(rules.vars)
        print(config)
        \"\"\"

    if "config.x == 'y'":
      let a='1'
    else:
      let a='2'
    endif
    """
    )
    eval_stmts(rules, statements, tmpdir)
    assert rules.vars["a"] == "1"


def test_file_ref(tmpdir):
    rules = Rules()
    # rules.set_var(name, value)

    localfile = tmpdir.join("xyz")
    localfile.write("x")

    statements = parser.parse_str(
        f"""
    rule a:
        inputs: x=filename("{localfile}")
    """,
        filename=str(tmpdir.join("sample.conseq")),
    )

    eval_stmts(rules, statements, tmpdir, filename=str(tmpdir) + "/none")
    a = rules.get_rule("a")
    assert a is not None
    print(a.inputs)
    assert a.inputs[0].json_obj["name"] == os.path.relpath(str(localfile), str(tmpdir))
    assert a.inputs[0].json_obj["type"] == "$fileref"
    assert a.inputs[0].copy_to is None
    assert len(rules.objs) == 1


def test_file_ref_with_copy_to(tmpdir):
    rules = Rules()
    # rules.set_var(name, value)

    localfile = tmpdir.join("xyz")
    localfile.write("x")

    statements = parser.parse_str(
        f"""
    rule a:
        inputs: x=filename("{localfile}", copy_to="z")
    """,
        filename=str(tmpdir.join("sample.conseq")),
    )
    eval_stmts(rules, statements, tmpdir)

    a = rules.get_rule("a")
    assert a is not None
    assert a.inputs[0].copy_to == "z"


def test_file_refs_with_vars(tmpdir):
    # make sure we can use variables work in filenames
    rules = Rules()
    rules.set_var("VARIABLE", str(tmpdir))
    rules.set_var("NUMBER", 2)

    localfile = tmpdir.join("xyz-2")
    localfile.write("x")

    statements = parser.parse_str(
        """
    rule a:
        inputs: x=filename("{{config.VARIABLE}}/xyz-{{config.NUMBER}}")
    """,
        filename=str(tmpdir.join("sample.conseq")),
    )
    eval_stmts(rules, statements, tmpdir)
    a = rules.get_rule("a")
    assert a is not None
    assert os.path.abspath(a.inputs[0].json_obj["name"]) == str(localfile)


def test_relative_file_paths(tmpdir):
    # get a relative path to __file__ using tmpdir as the directory
    root_dir = os.path.abspath(str(tmpdir))
    # bunch of asserts to help debug why this test is failing under github actions but not locally
    assert os.path.exists(root_dir)
    assert os.path.exists(__file__)
    sample_abs_path = os.path.abspath(__file__)
    assert os.path.exists(sample_abs_path)
    sample_rel_path = os.path.relpath(os.path.abspath(__file__), root_dir)
    # make sure this really is a relative path
    assert sample_rel_path[0] != "/"
    assert os.path.exists(os.path.join(root_dir, sample_rel_path))
    print(
        f"relative={sample_rel_path}, abspath={sample_abs_path}, relative-to={root_dir}"
    )

    statements = parser.parse_str(
        f"""
    rule a:
        inputs: x=filename("{sample_rel_path}")
    """,
        filename=str(tmpdir.join("sample.conseq")),
    )

    rules = Rules()
    eval_stmts(rules, statements, tmpdir)

    # created an artifact for the sample file
    assert len(rules.objs) == 1
    assert os.path.abspath(rules.objs[0]["filename"]["$filename"]) == sample_abs_path
    assert os.path.abspath(rules.objs[0]["name"]) == sample_abs_path

    a = rules.get_rule("a")
    assert a is not None
    print(a.inputs)
    assert os.path.abspath(a.inputs[0].json_obj["name"]) == sample_abs_path


def test_construct_cache_key(tmpdir):
    statements = parser.parse_str(
        '''
    rule a:
        construct-cache-key-run """python""" with """print(0)"""
    '''
    )
    assert len(statements) == 1
    assert statements[0].cache_key_constructor == [
        parser.RunStmt(exec_profile="default", command="python", script="print(0)")
    ]


def test_type_def_no_fields():
    statements = parser.parse_str(
        """
        type sample:
          description: "desc" 
    """
    )
    assert len(statements) == 1
    assert statements[0] == TypeDefStmt("sample", "desc", [])


def test_type_def_no_desc():
    statements = parser.parse_str(
        """
        type sample:
          fields: x
    """
    )
    assert len(statements) == 1
    assert statements[0] == TypeDefStmt("sample", None, ["x"])


def test_type_def_full():
    statements = parser.parse_str(
        """
        type sample:
          description: "both"
          fields: x, y,z
    """
    )
    assert len(statements) == 1
    assert statements[0] == TypeDefStmt("sample", "both", ["x", "y", "z"])


def test_parse_rule_with_description():
    example = """
    rule A:
        description: "sample rule"
        run "echo hello"
    """
    decs = parser.parse_str(example)
    assert len(decs) == 1

    r = decs[0]
    assert isinstance(r, parser.Rule)
    assert r.description == "sample rule"


def test_parse_rule_with_executor():
    example = """
    rule A:
        executor: executor_name
        run "echo hello"
    """
    decs = parser.parse_str(example)
    assert len(decs) == 1

    r = decs[0]
    assert isinstance(r, parser.Rule)
    assert r.executor == "executor_name"
    assert r.executor_parameters == {}


def test_parse_rule_with_executor_params():
    example = """
    rule A:
        executor: executor_name {"param1": "1", "param2": "2"}
        run "echo hello"
    """
    decs = parser.parse_str(example)
    assert len(decs) == 1

    r = decs[0]
    assert isinstance(r, parser.Rule)
    assert r.executor == "executor_name"
    assert r.executor_parameters == {"param1": "1", "param2": "2"}
