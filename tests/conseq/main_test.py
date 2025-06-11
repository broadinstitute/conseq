# from conseq.main import _parse_rule_filters

# # (filename: str) -> Callable[[Sequence[Tuple[str, "Obj"]], str], bool]:
# from conseq.dep import Obj


# def mk_obj(**props):
#     return Obj(None, "", "", props)


# def test_parse_rule_filters_basic(tmpdir):
#     sample = tmpdir.join("sample")
#     sample.write(
#         """
#     # a comment
# skipme
#     """
#     )
#     predicate = _parse_rule_filters(str(sample))
#     assert predicate([], "runme")
#     assert not predicate([], "skipme")


# def test_parse_rule_filters_w_inclusion(tmpdir):
#     sample = tmpdir.join("sample")
#     sample.write(
#         """
# #skip everything
# .*
# #except for runme
# !runme
#     """
#     )
#     predicate = _parse_rule_filters(str(sample))
#     assert predicate([], "runme")
#     assert not predicate([], "skipme")


# def test_parse_rule_filters_w_one_okay_artifact(tmpdir):
#     sample = tmpdir.join("sample")
#     sample.write(
#         """
# rule1
# !rule1 in:label=runme
#     """
#     )
#     predicate = _parse_rule_filters(str(sample))
#     assert predicate([("in", mk_obj(label="runme"))], "rule1")
#     assert not predicate([("in", mk_obj(label="skipme"))], "rule1")


# def test_parse_rule_filters_w_one_skipped_artifact(tmpdir):
#     sample = tmpdir.join("sample")
#     sample.write(
#         """
# rule1 in:label=skipme
#     """
#     )
#     predicate = _parse_rule_filters(str(sample))
#     assert predicate([("in", mk_obj(label="runme"))], "rule1")
#     assert not predicate([("in", mk_obj(label="skipme"))], "rule1")
