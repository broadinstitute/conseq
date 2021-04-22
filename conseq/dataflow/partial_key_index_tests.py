from .partial_key_index import _is_compatible_with, PartialKeyIndex


def test_satisfies():
    assert _is_compatible_with([("A", "a")], set(["A", "B"]),
                               [("A", "a")], set(["A", "B"]))

    assert _is_compatible_with([("A", "a")], set(["A"]),
                               [("A", "a")], set(["A", "B"]))

    assert not _is_compatible_with([("A", "a")], set(["A"]),
                                   [("A", "b")], set(["A", "B"]))

    assert not _is_compatible_with([("A", "a")], set(["A", "C"]),
                                   [("A", "a")], set(["A", "B"]))


def test_partial_key_index():
    p = PartialKeyIndex()
    p.add([("A", "a"), ("B", "b"), ("C", "c")], "1")
    p.add([("A", "a"), ("B", "b2")], "2")
    p.add([("A", "a"), ("D", "d")], "3")

    assert p.get([("D", "d")]) == ["3"]
    assert set(p.get([("A", "a")])) == set(["1", "2", "3"])
    assert p.get([("A", "a"), ("B", "b2")]) == ["2"]
