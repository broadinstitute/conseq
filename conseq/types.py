from typing import Dict, Union, Sequence, Tuple, Optional
from dataclasses import dataclass


@dataclass
class BoundInput:
    name: str
    value: Dict
    copy_to: Optional[str]


PropsType = Dict[str, Union[str, Dict[str, str]]]


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


BindingsDict = Dict[str, Union[Obj, Sequence[Obj]]]
InputsType = Sequence[Tuple[str, Obj]]
