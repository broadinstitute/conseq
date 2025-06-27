from typing import Optional, Dict, Any, List, Tuple
import json
from ..types import PropsType, BindingsDict, Obj
from conseq.db import get_cursor, transaction
from . import signals
from ..model.objects import PUBLIC_SPACE

def split_props_into_key_and_other(
    props: PropsType,
) -> Tuple[Dict[str, str], Dict[str, str]]:
    key_props = {}
    other_props = {}

    for k, v in props.items():
        if isinstance(v, dict) and len(v) == 1 and list(v.keys())[0].startswith("$"):
            other_props[k] = list(v.values())[0]
        elif k == "$hash":
            other_props[k] = v
        else:
            key_props[k] = v

    return key_props, other_props


class ObjHistory:
    def __init__(self) -> None:
        pass

    def get(self, id: int) -> Optional[Obj]:
        c = get_cursor()
        c.execute("SELECT id, space, timestamp, json FROM past_obj WHERE id = ?", [id])
        o = c.fetchone()
        if o == None:
            return None
        id, space, timestamp, _json = o
        return Obj(id, space, timestamp, json.loads(_json))

    def add(self, obj):
        # first check to see if this already exists
        if self.get(obj.id) != None:
            return

        c = get_cursor()
        c.execute(
            "INSERT INTO past_obj (id, space, timestamp, json) VALUES (?, ?, ?, ?)",
            [obj.id, obj.space, obj.timestamp, json.dumps(obj.props)],
        )


class ObjSet:
    """
    Models the universe of all known artifacts.

    This prototype implementation does everything in memory but is intended to be replaced with one that read/writes to a persistent DB
    """

    def __init__(self) -> None:
        self.add_listeners = []
        self.remove_listeners = []
        self.default_space = PUBLIC_SPACE

    def initialize(self) -> None:
        c = get_cursor()
        c.execute("SELECT default_space FROM settings")
        self.default_space = c.fetchone()[0]

    def __iter__(self):
        c = get_cursor()
        c.execute("SELECT id, space, timestamp, json FROM cur_obj")
        objs = []
        for id, space, timestamp, _json in c.fetchall():
            objs.append(Obj(id, space, timestamp, json.loads(_json)))
        return iter(objs)

    def get(self, id, must=True):
        c = get_cursor()
        c.execute("SELECT id, space, timestamp, json FROM cur_obj WHERE id = ?", [id])
        rec = c.fetchone()
        if rec is None:
            if must:
                raise Exception(
                    "Attempted to get object {}, but did not exist".format(id)
                )
            else:
                return None
        id, space, timestamp, _json = rec
        return Obj(id, space, timestamp, json.loads(_json))

    def remove(self, id):
        from .execution import _delete_execution_by_id

        signals.signal_remove_obj(id)
        obj = self.get(id)
        c = get_cursor()
        c.execute("DELETE FROM cur_obj WHERE id = ?", [id])
        c.execute(
            "SELECT execution_id FROM execution_output WHERE obj_id = ? UNION SELECT execution_id FROM execution_input WHERE obj_id = ?",
            (id, id),
        )
        execution_ids = set([x[0] for x in c.fetchall()])
        for execution_id in execution_ids:
            _delete_execution_by_id(c, execution_id)
        for remove_listener in self.remove_listeners:
            remove_listener(obj)

    def get_last_id(self):
        c = get_cursor()
        c.execute("SELECT max(id) FROM cur_obj")
        id = c.fetchone()
        if id is None:
            id = 0
        else:
            id = id[0]
        return id

    def add(self, space: str, timestamp: str, props: PropsType):
        assert space == PUBLIC_SPACE

        # first check to see if this already exists
        assert len(props) > 0
        match = self.find_by_key(space, props)

        if match != None:
            if match.timestamp == timestamp:
                return match.id

            if (
                "$hash" in props
                and "$hash" in match.props
                and props["$hash"] == match.props["$hash"]
            ):
                return match.id

            self.remove(match.id)

        c = get_cursor()
        c.execute(
            "INSERT INTO cur_obj (space, timestamp, json) VALUES (?, ?, ?)",
            [space, timestamp, json.dumps(props)],
        )
        id = c.lastrowid
        assert isinstance(id, int)
        signals.signal_add_obj(id, space, props)

        obj = Obj(id, space, timestamp, props)

        for add_listener in self.add_listeners:
            add_listener(obj)

        return id

    def find_by_key(self, space: str, props: PropsType) -> Optional[Obj]:
        assert space == PUBLIC_SPACE
        key_props = split_props_into_key_and_other(props)[0]
        matches = self.find(space, key_props)
        if len(matches) > 1:
            raise Exception(
                "Too many matches: key_props={}, matches={}".format(key_props, matches)
            )
        elif len(matches) == 1:
            return matches[0]
        else:
            return None

    def find(self, space: str, properties: Dict[str, Any]) -> List[Obj]:
        assert space == PUBLIC_SPACE

        result = []
        for o in self:
            if o.space != space:
                continue

            skip = False
            for k, v in properties.items():
                if not (k in o.props):
                    skip = True
                    break

                ov = o.props[k]
                if isinstance(ov, dict) and "$value" in ov:
                    ov = ov["$value"]
                if isinstance(ov, dict) and "$filename" in ov:
                    ov = ov["$filename"]
                if isinstance(ov, dict) and "$file_url" in ov:
                    ov = ov["$file_url"]

                if hasattr(v, "match"):
                    assert isinstance(
                        ov, str
                    ), "checking match of {} against ov={} for key {}".format(
                        repr(v), repr(ov), k
                    )
                    matched = v.match(ov) != None
                else:
                    matched = ov == v

                if not matched:
                    skip = True
                    break

            if not skip:
                result.append(o)

        return result
