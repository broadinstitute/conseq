from conseq import parser
from conseq.config import EvalContext, Rules, _eval_stmts, _resolve_output_types
from conseq.hashcache import HashCache
from conseq.static_analysis.new_artifacts import rules_invalidated_by_new_inputs
from conseq.template import create_jinja2_env


def load_rules(tmpdir, text):
    rules = Rules()
    path = str(tmpdir.join("t.conseq"))
    _eval_stmts(
        parser.parse_str(text, filename=path),
        EvalContext(
            rules, path, HashCache(str(tmpdir.join("hc"))), create_jinja2_env()
        ),
    )
    _resolve_output_types(rules)
    return list(rules)


PIPELINE = """
rule b:
    inputs: in={"type": "a"}
    outputs: {"type": "b"}
rule c:
    inputs: bs=all {"type": "b"}
    outputs: {"type": "c"}
rule d:
    inputs: in={"type": "c"}
    outputs: {"type": "d"}
rule x:
    inputs: xs=all {"type": "x"}
    outputs: {"type": "x-out"}
rule y:
    inputs: in={"type": "y"}
    outputs: {"type": "y-out"}
"""


def affected(tmpdir, new_artifacts, new_rules=()):
    return set(
        rules_invalidated_by_new_inputs(
            load_rules(tmpdir, PIPELINE), new_artifacts, new_rules
        )
    )


def test_no_new_artifacts_affects_nothing(tmpdir):
    assert affected(tmpdir, []) == set()


def test_new_artifact_which_directly_feeds_an_all_rule(tmpdir):
    assert affected(tmpdir, [{"type": "x"}]) == {"x"}


def test_new_artifact_which_feeds_an_all_rule_through_upstream_rules(tmpdir):
    # a feeds b, which feeds c
    assert affected(tmpdir, [{"type": "a"}]) == {"c"}


def test_only_rules_with_an_all_input_are_affected(tmpdir):
    # d and b are downstream of "a" too, but they don't have "all" inputs. (Their old results aren't
    # affected by the list getting longer. Whatever depended on c is removed with c's outputs)
    assert "b" not in affected(tmpdir, [{"type": "a"}])
    assert "d" not in affected(tmpdir, [{"type": "a"}])


def test_artifact_which_feeds_only_foreach_rules_affects_nothing(tmpdir):
    assert affected(tmpdir, [{"type": "y"}]) == set()


def test_unrelated_artifact_affects_nothing(tmpdir):
    assert affected(tmpdir, [{"type": "nothing-consumes-this"}]) == set()


def test_several_new_artifacts(tmpdir):
    assert affected(tmpdir, [{"type": "x"}, {"type": "a"}, {"type": "y"}]) == {"x", "c"}


def test_reasons_name_the_artifact_and_the_rule_it_feeds(tmpdir):
    result = rules_invalidated_by_new_inputs(
        load_rules(tmpdir, PIPELINE), [{"type": "a", "n": "7"}]
    )
    assert len(result["c"]) == 1
    assert "'n': '7'" in result["c"][0]
    assert "feeds rule b" in result["c"][0]


def test_new_rule_upstream_of_an_all_rule_affects_it(tmpdir):
    # b feeds c, so a new b could add to c's list
    assert affected(tmpdir, [], ["b"]) == {"c"}


def test_new_rule_feeding_an_all_rule_directly_affects_it(tmpdir):
    # c's output is consumed by d. d has no "all" input, so only rules with one are listed
    assert affected(tmpdir, [], ["c"]) == set()


def test_new_rule_which_is_not_upstream_of_an_all_rule_affects_nothing(tmpdir):
    assert affected(tmpdir, [], ["y"]) == set()
    assert affected(tmpdir, [], ["d"]) == set()


def test_a_new_all_rule_isnt_affected_by_itself(tmpdir):
    # it hasn't run yet, so there's nothing to remove
    assert affected(tmpdir, [], ["c"]) == set()
    assert affected(tmpdir, [], ["x"]) == set()


def test_new_rule_reason_names_the_rule(tmpdir):
    result = rules_invalidated_by_new_inputs(load_rules(tmpdir, PIPELINE), [], ["b"])
    assert result == {"c": ["rule b is new and could produce its inputs"]}
