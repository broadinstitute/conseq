from ..types import PropsType

# These methods exist solely to monkey patch in hooks to record events in the context of tests
def signal_remove_obj(id):
    pass


def signal_remove_rule(id):
    pass


def signal_remove_rule_execution(id):
    pass


def signal_add_obj(id: int, space: str, props: PropsType):
    pass
