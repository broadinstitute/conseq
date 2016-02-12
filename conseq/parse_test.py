from . import parser
from . import depexec

pair_of_rules = """
xref http://foo.org {"a": "b"}

rule create_numbers:
    options: exec-python
    script: \"\"\"
        import conseq
        conseq.publish({"value": "2", "type": "number"}, {"value": "3", "type": "number"})
        \"\"\"

rule square:
    inputs: n={"type": "number"}
    options: exec-python
    script: \"\"\"
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
    script: "script_body"
"""

def test_parse_constrained_query():
    decs = parser.parse_str(constrained_query)
    assert len(decs) == 1
    rule = decs[0]
    assert len(rule.inputs) == 2
    a, b = rule.inputs
    print(a, b)
    assert isinstance(a.json_obj["value"], parser.QueryVariable)
    assert isinstance(b.json_obj["value"], parser.QueryVariable)

    template = depexec.to_template(rule)
    assert template.transform == "a"
    assert len(template.foreach_queries) == 2
    assert len(template.forall_queries) == 0
    assert len(template.predicates) == 1

    pred = template.predicates[0]
    print("predicate", pred)
    assert pred.satisfied({"a": {"value": "1"}, "b": {"value": "1"}})
    assert not pred.satisfied({"a": {"value": "1"}, "b": {"value": "2"}})
