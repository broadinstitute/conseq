from typing import Sequence, Tuple, Union

FOR_EACH = "for_each"
FOR_ALL = "for_all"

class AnyValueSingleton:
    pass

AbstractArtifact = Sequence[Tuple[str, Union[str, AnyValueSingleton]]]

ANY_VALUE = AnyValueSingleton()

START = "__start__"
