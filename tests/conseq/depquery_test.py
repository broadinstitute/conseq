from conseq.depquery import count_unique_values_per_property, split_props_by_counts
import collections

def count_instances_with_values(property, instances):
    per_value = collections.defaultdict(lambda: 0)
    for x in instances:
        assert isinstance(x, dict)
        if property in x:
            per_value[x[property]] += 1
    return per_value.items()

def count_instances_with_properties(properties, instances):
    per_property = collections.defaultdict(lambda: 0)
    for x in instances:
        for property in properties:
            if property in x:
                per_property[property] += 1
    return per_property.items()

class MockStore:
    def __init__(self, values):
        self.values = values

    def _satisifies(self, instance, query):
        for property, value in query:
            if not (property in instance and instance[property] == value):
                return False
        return True

    def get_instances(self, query):
        results = [x for x in self.values if self._satisifies(x, query)]
        return results

    def find_props(self, query):
        instances = self.get_instances(query)
        property_counts = count_unique_values_per_property(instances)
        common, varying = split_props_by_counts(property_counts)
        return count_instances_with_properties(varying, instances)

    def find_prop_values(self, query, property):
        instances = self.get_instances(query)
        return count_instances_with_values(property, instances)
    
class AugmentedStore:
    def __init__(self, instances):
        self.store = MockStore(instances)

    def slice_range(self, l, first, max_count, get_row_key):
        l = list(l)
        l.sort()

        if first != None:
            found_i = None
            for i in range(len(l)):
                if get_row_key(l[i]) == first:
                    found_i = i
                    break

            if found_i == None:
                raise Exception("Could not find {}".format(first))
            l = l[found_i:]

        if max_count < len(l):
            next = get_row_key(l[max_count])
            l = l[:max_count]
        else:
            next = None

        return l, next

    # query = list of PropConsts
    def find_props(self, query, first, max_count):
        "Returns list of {properties: (prop, instance count), next: token} "
        p = self.store.find_props(query)
        p, next = self.slice_range(p, first, max_count, lambda x: x[0])
        return {"properties": p, "next": next}

    def find_prop_values(self, query, property, first, max_count):
        "Returns list of {values: (value, instance count), next: token}"
        v = self.store.find_prop_values(query, property)
        v, next = self.slice_range(v, first, max_count, lambda x: x[0])
        return {"values": v, "next": next}
    
    def get_instances(self, query, sort_props, first, max_count):
        "returns: {common: list of PropConsts, properties: list of string, instances: list of dicts, next: token}"

        def row_key_fn(x):
            key = []
            for p in sort_props:
                key.append(x.get(p))
            return tuple(key)

        instances = self.store.get_instances(query)
        instances.sort(key=row_key_fn)

        # add row numbers
        rows = list(enumerate(instances))
        subset, next = self.slice_range(rows, first, max_count, lambda x: x[0])
        # now drop row numbers
        subset = [x for i, x in subset]

        counts = count_unique_values_per_property(subset)
        common, varying = split_props_by_counts(counts)

        return {"common": common, "properties": varying, "instances": subset, "next": next}    

store = AugmentedStore(
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
