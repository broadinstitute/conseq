from typing import Dict

class ForEach:
    def __init__(self, variable: str, const_constraints: Dict[str, str] = {}) -> None:
        assert variable != ""
        self.variable = variable
        self.const_constraints = const_constraints

    def __repr__(self):
        return "<ForEach {} where {}>".format(self.variable, self.const_constraints)


class ForAll:
    def __init__(self, variable: str, const_constraints: Dict[str, str] = {}) -> None:
        self.variable = variable
        self.const_constraints = const_constraints


class PropsMatch:
    def __init__(self, pairs):
        self.pairs = pairs

    def __repr__(self):
        return "<PropsMatch pairs={}>".format(self.pairs)

    def satisfied(self, bindings):
        first = True
        prev_value = None
        for name, prop in self.pairs:
            value = bindings[name][prop]
            if first:
                prev_value = value
            else:
                if prev_value != value:
                    return False
            first = False
        return True
