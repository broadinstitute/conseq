from . import parser
from . import depexec

pair_of_rules = """
xref http://foo.org {"a": "b"}

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
    assert len(decs) == 3

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
