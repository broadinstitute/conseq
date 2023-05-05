from conseq import depquery

store = depquery.AugmentedStore(
    [
        dict(type="atlantis", name="alpha", id="A"),
        dict(type="demeter", library="ach21", id="D"),
        dict(type="atlantis", name="beta", id="B"),
        dict(type="atlantis", name="gamma", id="C"),
        dict(type="demeter", library="ach22", id="E"),
    ]
)


def test_get_instances():
    r = store.get_instances([("type", "atlantis")], ["id"], None, 100)
    inst = r["instances"]
    assert len(inst) == 3
    assert r["common"] == ["type"]
    assert r["properties"] == ["id", "name"]


def test_get_instances_with_limit():
    r = store.get_instances([], ["id"], None, 3)
    inst = r["instances"]
    assert len(inst) == 3
    assert inst[0]["id"] == "A"
    assert inst[1]["id"] == "B"
    assert inst[2]["id"] == "C"
    assert r["next"] == 3

    r = store.get_instances([], ["id"], 3, 10)
    inst = r["instances"]
    assert len(inst) == 2
    assert inst[0]["id"] == "D"
    assert inst[1]["id"] == "E"
    assert r["next"] == None


def test_find_props():
    r = store.find_props([], None, 100)
    p = r["properties"]
    assert len(p) == 4
    assert p[0] == ("id", 5)
    assert p[1] == ("library", 2)


def test_find_values_for_prop():
    r = store.find_prop_values([], "type", None, 100)
    v = r["values"]
    assert len(v) == 2
    assert v[0] == ("atlantis", 3)
    assert v[1] == ("demeter", 2)
