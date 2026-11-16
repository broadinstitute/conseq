_CYCLE_EXPLANATION = """
This check is done when CONSEQ_SEQ=blockers is set. Conseq works out which rules feed which others
from what each rule declares it produces (`outputs` or `output_types`) and what its inputs
match, without running anything. So this is a *possible* cycle, and it may not be a real one. The
analysis is deliberately cautious, and assumes the worst when it can't tell:
  - an output property whose value is a template (for example "{{ inputs.x.name }}-done") is
    assumed to be able to match any input constraint on that property,
  - an artifact from `output_types` is assumed to be able to have any additional properties,
  - an input constraint which depends on a variable or on config is ignored, so it matches more.
If the cycle is a real one, the rules would keep feeding each other and never finish. If it's not,
make the property which causes the match a fixed value in the rule's `outputs` (or in the input
constraint) so that the rule's output can't be mistaken for its own input. (A rule can't be told to ignore
a possible cycle. Unset CONSEQ_SEQ to run without this check.)"""


class CycleDetected(Exception):
    """Raised when the rules might form a dependency cycle. `path` lists the rules, starting from
    a rule with no inputs, ending with the rule which was reached for a second time."""

    def __init__(self, path):
        self.path = list(path)
        super().__init__(
            "Possible dependency cycle between rules: "
            + " -> ".join(self.path)
            + "\n"
            + _CYCLE_EXPLANATION
        )


class UnreachableRules(Exception):
    """Raised when some rules can't be reached starting from the rules which have no inputs. This
    means they might be part of a dependency cycle, or depend on one."""

    def __init__(self, rule_names):
        self.rule_names = list(rule_names)
        super().__init__(
            "These rules could not be reached from any rule without inputs, so they are probably "
            "part of (or depend on) a possible dependency cycle: "
            + ", ".join(self.rule_names)
            + "\n"
            + _CYCLE_EXPLANATION
        )
