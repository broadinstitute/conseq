from conseq import parser
from conseq.config import Rules, _eval_stmts, _resolve_output_types, EvalContext
from conseq.hashcache import HashCache
from conseq.parser import RegEx
from conseq.static_analysis.convert import convert_rule, convert_rules
from conseq.static_analysis.dag import createDAG
from conseq.static_analysis.model import UNKNOWN
from conseq.template import create_jinja2_env


def load(tmpdir, text):
    rules = Rules()
    path = str(tmpdir.join("t.conseq"))
    statements = parser.parse_str(text, filename=path)
    _eval_stmts(
        statements,
        EvalContext(
            rules, path, HashCache(str(tmpdir.join("hc"))), create_jinja2_env()
        ),
    )
    _resolve_output_types(rules)
    return rules


def props(artifact):
    return {p.name: p.value for p in artifact.properties}


def test_literal_outputs_and_inputs(tmpdir):
    rules = load(
        tmpdir,
        """
        rule a:
            inputs: x={"type": "in"}, ys=all {"type": "other", "lib": "avana"}
            outputs: {"type": "out", "name": "n"}
        """,
    )
    rule = convert_rule(rules.get_rule("a"))

    assert [(i.variable, i.cardinality) for i in rule.inputs] == [
        ("x", "one"),
        ("ys", "all"),
    ]
    assert {p.name: p.value for p in rule.inputs[1].constraints.properties} == {
        "type": "other",
        "lib": "avana",
    }
    assert len(rule.outputs) == 1
    assert props(rule.outputs[0].artifact) == {"type": "out", "name": "n"}
    assert not rule.outputs[0].artifact.open


def test_templated_and_structured_output_values_are_unknown(tmpdir):
    rules = load(
        tmpdir,
        """
        rule a:
            inputs: x={"type": "in"}
            outputs: {"type": "out", "name": "{{ inputs.x.name }}", "file": {"$filename": "f"}}
        """,
    )
    rule = convert_rule(rules.get_rule("a"))
    assert props(rule.outputs[0].artifact) == {
        "type": "out",
        "name": UNKNOWN,
        "file": UNKNOWN,
    }


def test_inputs_which_cant_be_resolved_statically_are_unconstrained(tmpdir):
    rules = load(
        tmpdir,
        """
        let LIB = "avana"
        rule a:
            inputs: x={"type": "in", "name": name}, y={"type": "in2", "lib": "{{ config.LIB }}"}
            outputs: none
        """,
    )
    rule = convert_rule(rules.get_rule("a"))
    # a variable and a template are dropped, which can only make the input match more artifacts
    assert {p.name: p.value for p in rule.inputs[0].constraints.properties} == {
        "type": "in"
    }
    assert {p.name: p.value for p in rule.inputs[1].constraints.properties} == {
        "type": "in2"
    }


def test_regex_input_constraint_is_kept(tmpdir):
    rules = load(
        tmpdir,
        """
        rule a:
            inputs: x={"type" ~ "abc.*"}
            outputs: none
        """,
    )
    rule = convert_rule(rules.get_rule("a"))
    assert rule.inputs[0].constraints.properties[0].value == RegEx("abc.*")


def test_output_types_become_open_artifacts_with_unknown_fields(tmpdir):
    rules = load(
        tmpdir,
        """
        type matrix (filename, label)
        type report (name)
        rule a:
            output_types: (matrix+, report?)
        """,
    )
    rule = convert_rule(rules.get_rule("a"))
    assert [props(o.artifact) for o in rule.outputs] == [
        {"type": "matrix", "filename": UNKNOWN, "label": UNKNOWN},
        {"type": "report", "name": UNKNOWN},
    ]
    assert all(o.artifact.open for o in rule.outputs)
    assert [o.cardinality for o in rule.outputs] == ["many", "one"]


def test_outputs_none_and_publish_rules_have_no_outputs(tmpdir):
    rules = load(
        tmpdir,
        """
        rule a:
            outputs: none
        rule b:
            inputs: x={"type": "x"}
            publish: "gs://bucket/path"
        """,
    )
    assert convert_rule(rules.get_rule("a")).outputs == []
    assert convert_rule(rules.get_rule("b")).outputs == []


def test_converted_rules_build_a_graph(tmpdir):
    rules = load(
        tmpdir,
        """
        type thing (value)
        rule a:
            output_types: (thing*)
        rule b:
            inputs: xs=all {"type": "thing"}
            outputs: {"type": "done"}
        """,
    )
    dag = createDAG(convert_rules(rules))
    edges = sorted(
        (m.produced_by.rule.name, m.consumed_by.rule.name)
        for n in dag.rules
        for m in n.outputs
    )
    assert edges == [("a", "b")]
