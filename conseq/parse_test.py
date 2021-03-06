import os

import jinja2

from conseq import depexec
from conseq import parser

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
    decs = parser.parse_str("let a=\"x\"\n")
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


rule_with_expected_outputs = """
rule dynamic_outputs:
    outputs-expected: {"type": "literal", "hasprop"}, {"type": "other"}
    run "command"
"""


def test_expected_outputs():
    decs = parser.parse_str(rule_with_expected_outputs)
    assert len(decs) == 1
    rule = decs[0]
    assert rule.output_matches_expectation({"type": "literal", "hasprop": "a"})
    assert rule.output_matches_expectation({"type": "other"})
    assert not rule.output_matches_expectation({"type": "bad", "hasprop": "a"})
    assert not rule.output_matches_expectation({"type": "literal"})
    assert not rule.output_matches_expectation({"type": "literal", "hasprop": "a", "extra": "bad"})


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


from conseq.parser import Semantics
from conseq.parser import depfile


def _parse_exp(text, nonterminal):
    parser = depfile.depfileParser(parseinfo=True)
    return parser.parse(
        text,
        nonterminal,
        trace=False,
        nameguard=None,
        semantics=Semantics())


def test_parse_empty():
    statements = parser.parse_str("""
    # empty
    """)
    assert len(statements) == 0


def test_parse_trailing_commas():
    # make sure we tolerate trailing commas
    statements = parser.parse_str("""
    rule a:
        inputs: x={"a":"b"},
        outputs: {"out": "b",},
        run "cmd"
    """)
    assert len(statements) == 1
    assert len(statements[0].inputs) == 1
    assert len(statements[0].outputs) == 1


def test_parse_json():
    value = _parse_exp("""
    {"a": "b", "c": '1'}
    """, "json_obj")
    assert value == {"a": "b", "c": "1"}

    value = _parse_exp("""
    {"a": ["1", "2"]}
    """, "json_obj")
    assert value == {"a": ["1", "2"]}


def test_parse_if():
    from conseq.config import Rules, _eval_stmts
    rules = Rules()
    # from conseq.parser import IfStatement, LetStatement

    statements = parser.parse_str("""
    if "'x' == 'y'":
      let a='1'
    else:
      let a='2'
    endif
    """, "declarations")
    _eval_stmts(rules, statements, "none", None)
    assert rules.vars["a"] == "2"

    # else:
    #   let x='2'


def test_eval_if():
    from conseq.config import Rules, _eval_stmts
    rules = Rules()
    # rules.set_var(name, value)

    statements = parser.parse_str("""
    if "'x' == 'y'":
      let a='1'
    else:
      let a='2'
    endif
    """)
    _eval_stmts(rules, statements, "none", None)
    assert rules.vars["a"] == "2"


def test_generic_eval():
    from conseq.config import Rules, _eval_stmts
    rules = Rules()
    # rules.set_var(name, value)

    statements = parser.parse_str("""
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
    """)
    _eval_stmts(rules, statements, "none", None)
    assert rules.vars["a"] == "1"


from conseq.config import Rules, _eval_stmts
from conseq.hashcache import HashCache


def test_file_ref(tmpdir):
    rules = Rules()
    # rules.set_var(name, value)

    localfile = tmpdir.join("xyz")
    localfile.write("x")

    statements = parser.parse_str("""
    rule a:
        inputs: x=filename("{}")
    """.format(localfile))
    _eval_stmts(rules, statements, "none", HashCache(str(tmpdir.join("hashcache"))))
    a = rules.get_rule("a")
    assert a is not None
    print(a.inputs)
    a.inputs[0].json_obj["name"] == str(localfile)
    a.inputs[0].json_obj["type"] == "fileref"
    assert len(rules.objs) == 1


def test_file_refs_with_vars(tmpdir):
    # make sure we can use variables work in filenames
    rules = Rules()
    rules.set_var("VARIABLE", str(tmpdir))
    rules.set_var("NUMBER", 2)

    localfile = tmpdir.join("xyz-2")
    localfile.write("x")

    statements = parser.parse_str("""
    rule a:
        inputs: x=filename("{{config.VARIABLE}}/xyz-{{config.NUMBER}}")
    """)
    _eval_stmts(rules, statements, "none", HashCache(str(tmpdir.join("hashcache"))))
    a = rules.get_rule("a")
    assert a is not None
    print(a.inputs)
    a.inputs[0].json_obj["name"] == str(localfile)


def test_relative_file_paths(tmpdir):
    sample_rel_path = os.path.relpath(__file__, os.path.abspath("."))
    assert sample_rel_path[0] != "/"

    statements = parser.parse_str("""
    rule a:
        inputs: x=filename("{}")
    """.format(sample_rel_path))

    rules = Rules()
    _eval_stmts(rules, statements, "none", HashCache(str(tmpdir.join("hashcache"))))
    a = rules.get_rule("a")
    assert a is not None
    print(a.inputs)
    a.inputs[0].json_obj["name"] == os.path.abspath(sample_rel_path)
