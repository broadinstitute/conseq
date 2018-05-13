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
import jinja2


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
    from conseq.parser import IfStatement, LetStatement

    value = _parse_exp("""
    if 'x' == 'y':
      let x='1'
    else:
      let x='2'
    endif
    """, "declarations")
    print(value)
    assert value == [IfStatement(["x", "==", "y"], [LetStatement("x", "1")], [LetStatement("x", "2")])]

    # else:
    #   let x='2'


def test_eval_if():
    from conseq.config import Rules, _eval_stmts
    rules = Rules()
    # rules.set_var(name, value)

    statements = parser.parse_str("""
    if 'x' == 'y':
      let a='1'
    else:
      let a='2'
    endif
    """)
    _eval_stmts(rules, statements, "none")
    assert rules.vars["a"] == "2"
