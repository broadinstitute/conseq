import collections
from typing import Sequence, Dict, Any, Tuple

def count_unique_values_per_property(instances : Sequence[Dict[str, Any]]):
    per_prop = collections.defaultdict(lambda: set())

    # first determine all properties
    all_properties = set()
    for x in instances:
        assert isinstance(x, dict)
        all_properties.update(x.keys())

    for x in instances:
        for k in all_properties:
            v = x.get(k)
            if isinstance(v, dict):
                if "$value" in v:
                    v = v["$value"]
                elif "$filename" in v:
                    v = v["$filename"]
                elif "$file_url" in v:
                    v = v["$file_url"]
                else:
                    raise Exception("key: {} had dict: {}".format(k, v))
            elif isinstance(v, list):
                import json

                v = json.dumps(v)
            per_prop[k].add(v)
    return [(property, len(values)) for property, values in per_prop.items()]


def split_props_by_counts(property_counts : Sequence[Tuple[str, int]]):
    common = []
    varying = []
    for property, count in property_counts:
        if count == 1:
            common.append(property)
        else:
            varying.append(property)
    common.sort()
    varying.sort()
    return common, varying

   


