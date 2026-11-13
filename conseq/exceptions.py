class CycleDetected(Exception):
    pass


class UnreachableRules(Exception):
    """Raised when some rules can't be reached starting from the rules which have no inputs. This
    means they're part of a dependency cycle, or depend on one."""

    def __init__(self, rule_names):
        super().__init__(
            "These rules could not be reached from any rule without inputs (they are "
            f"part of, or depend on, a cycle): {', '.join(rule_names)}"
        )
        self.rule_names = list(rule_names)
