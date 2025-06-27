from typing import Dict, Union, Sequence, Tuple, Optional, TypeVar
from dataclasses import dataclass

STATUS_STARTED = "started"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

RE_STATUS_PENDING = "pending"
RE_STATUS_STARTED = "started"
RE_STATUS_COMPLETE = "complete"
RE_STATUS_FAILED = "failed"
RE_STATUS_DEFERRED = "deferred"


@dataclass
class BoundInput:
    name: str
    value: Dict
    copy_to: Optional[str]


PropValue = TypeVar("PropValue", bound=Union[str, Dict[str, str]])

PropsType = Dict[str, PropValue]


class Obj:
    "Models an any input or output artifact by a set of key-value pairs"

    def __init__(self, id: int, space: str, timestamp: str, props: PropsType) -> None:
        """
        :param id:
        :param props: either a dictionary or a sequence of (key, value) tuples
        :return:
        """
        self.id = id
        self.space = space
        self.timestamp = timestamp
        self.props = props

    def get(self, prop_name):
        """
        :param prop_name:
        :return: the value for the given property
        """
        return self.props[prop_name]

    def __getitem__(self, item):
        return self.get(item)

    def __repr__(self):
        return "<{}:{} {}>".format(self.space, self.id, repr(self.props))


BindingsValue = TypeVar("BindingsValue", bound=Union[Obj, Sequence[Obj]])
BindingsDict = Dict[str, BindingsValue]
InputsType = Sequence[Tuple[str, Obj]]
