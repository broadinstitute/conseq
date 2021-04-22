from typing import Sequence, Tuple, Union, Set
from .models import AbstractArtifact, ANY_VALUE
from collections import defaultdict

def _is_compatible_with(fixed_attributes: Sequence[Tuple[str, str]], attribute_names: Set[str],
                        _fixed_attributes: Sequence[Tuple[str, str]], _attribute_names: Set[str]):
    if not attribute_names.issubset(_attribute_names):
        return False

    f_d = dict(_fixed_attributes)
    for key, value in fixed_attributes:
        if key in f_d:
            if f_d[key] != value:
                return False

    return True


def _split_attributes(attributes):
    fixed_attributes = set()
    all_attributes = set()
    for name, value in attributes:
        if value != ANY_VALUE:
            fixed_attributes.add((name, value))
        all_attributes.add(name)
    return fixed_attributes, all_attributes

class PartialKeyIndex:
    def __init__(self):
        self.d = defaultdict(lambda: [])

    def add(self, attributes: AbstractArtifact, value):
        fixed_attributes, all_attributes = _split_attributes(attributes)

        entry = (fixed_attributes, all_attributes, value)
        for component in fixed_attributes:
            self.d[component].append(entry)

    def get(self, attributes: AbstractArtifact):
        fixed_attributes, all_attributes = _split_attributes(attributes)

        single_component_matches = []
        for component in fixed_attributes:
            matches = self.d[component]
            if len(matches) == 0:
                return []
            single_component_matches.append(matches)

        # use the component that is most selective to minimize the number of other keys we need to check
        single_component_matches.sort(key=lambda x: len(x))
        smallest = single_component_matches[0]

        result = []
        for _fixed_attributes, _other_attributes, value in smallest:
            if _is_compatible_with(fixed_attributes, all_attributes, _fixed_attributes, _other_attributes):
                result.append(value)

        return result
