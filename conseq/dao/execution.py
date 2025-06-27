from typing import Literal, Dict, List, Any, Optional, Iterable, Union, Tuple
from sqlite3 import Cursor
from .objects import Obj, ObjHistory
import collections
from ..db import get_cursor
from ..types import RE_STATUS_PENDING, RE_STATUS_DEFERRED, RE_STATUS_STARTED, STATUS_COMPLETED, RE_STATUS_COMPLETE, STATUS_FAILED, RE_STATUS_FAILED, STATUS_STARTED
from .signals import signal_remove_rule, signal_remove_rule_execution

def assertInputsValid(inputs: Iterable[Tuple[str, Union[Obj, Iterable[Obj]]]]) -> None:
    for x in inputs:
        assert isinstance(x, tuple) and len(x) == 2
        name, value = x
        assert isinstance(value, Obj) or (
            isinstance(value, tuple) and isinstance(value[0], Obj)
        )

def _delete_execution_by_id(c, execution_id):
    c.execute("SELECT id FROM rule_execution WHERE execution_id = ?", (execution_id,))
    rule_execution_ids = [x[0] for x in c.fetchall()]

    for rule_execution_id in rule_execution_ids:
        c.execute(
            "DELETE FROM rule_execution_input WHERE rule_execution_id = ?",
            (rule_execution_id,),
        )
        c.execute("DELETE FROM rule_execution WHERE id = ?", (rule_execution_id,))

    c.execute("DELETE FROM execution_input WHERE execution_id = ?", (execution_id,))
    c.execute("DELETE FROM execution_output WHERE execution_id = ?", (execution_id,))
    c.execute("DELETE FROM execution WHERE id = ?", (execution_id,))

class RuleExecution:
    """
    Represents a statement describing what transform to run to generate a set of Objs (outputs) from a different set of Objs (inputs)
    """

    def __init__(
        self,
        id: int,
        space: str,
        inputs: Any,
        transform: str,
        state: str,
        execution_id: Optional[int] = None,
    ) -> None:
        assertInputsValid(inputs)

        self.space = space
        self.inputs = inputs
        self.transform = transform
        self.id = id
        self.state = state
        self.execution_id = execution_id

    def __repr__(self):
        return "<Rule {} in:{}:{} transform:{} state:{}>".format(
            self.space, self.id, self.inputs, self.transform, self.state
        )


class RuleSet:
    """
        The all active rules
    """

    def __init__(self, objects: ObjHistory) -> None:
        self.remove_rule_listeners = []
        self.add_rule_listeners = []
        self.objects = objects

    def _find_rule_execs(
        self, where_class: str = "", where_params: Tuple = ()
    ) -> List[RuleExecution]:
        results = []
        c = get_cursor()
        query = "select id, space, transform, key, state, execution_id from rule_execution re"
        if where_class != "":
            query += " WHERE " + where_class
        c.execute(query, where_params)
        for id, space, transform, key, state, execution_id in list(c.fetchall()):
            c.execute(
                "SELECT name, obj_id, is_list FROM rule_execution_input WHERE rule_execution_id = ?",
                (id,),
            )

            is_list_by_name = {}
            objs_by_name = collections.defaultdict(lambda: [])
            for name, obj_id, is_list in c.fetchall():
                is_list_by_name[name] = is_list
                objs_by_name[name].append(obj_id)

            inputs = []
            for name, is_list in is_list_by_name.items():
                obj_ids = objs_by_name[name]
                objs = tuple([self.objects.get(obj_id) for obj_id in obj_ids])
                if is_list:
                    inputs.append((name, objs))
                else:
                    inputs.append((name, objs[0]))

            results.append(
                RuleExecution(
                    id,
                    space,
                    tuple(inputs),
                    transform,
                    state,
                    execution_id=execution_id,
                )
            )
        return results

    def __iter__(self):
        return iter(self._find_rule_execs())

    def _mk_rule_natural_key(
        self, inputs: Any, transform: str, include_all_inputs: bool
    ) -> str:
        flattened_inputs = []
        for n, vs in inputs:
            if isinstance(vs, tuple):
                # if this is an "all" parameter, skip if include_all_inputs is not set
                if not include_all_inputs:
                    continue
            else:
                vs = (vs,)
            flattened_inputs.append((str(n), tuple([x.id for x in vs])))
        flattened_inputs.sort()
        return repr((tuple(flattened_inputs), str(transform)))

    def find_by_name(self, transform):
        return self._find_rule_execs("transform = ?", (transform,))

    def get_rule_specifications(self):
        c = get_cursor()
        query = "select transform, definition from rule_snapshot"
        c.execute(query, [])
        return list(c.fetchall())

    def write_rule_specifications(self, rule_specs):
        # existing_specs = self.get_rule_specifications()
        c = get_cursor()
        c.execute("delete from rule_snapshot", [])

        for transform, spec in rule_specs.items():
            # if transform in existing_specs:
            #     c.execute("delete from rule_snapshot where transform = ?", [transform])
            #
            c.execute(
                "insert into rule_snapshot (transform, definition) values (?, ?)",
                [transform, spec],
            )

    def find_by_input(self, input_id):
        "given an input id, find all of the rule executions ids which refer to that input"
        rules = self._find_rule_execs(
            "EXISTS (select 1 from rule_execution_input rei where rei.rule_execution_id = re.id and rei.obj_id = ?)",
            (input_id,),
        )
        rule_ids = [x.id for x in rules]
        return rule_ids

    def get(self, id):
        rules = self._find_rule_execs("id = ?", (id,))
        if len(rules) == 0:
            return None
        return rules[0]

    def add_rule(self, space: str, inputs: Any, transform: str) -> int:
        # first check to make sure rule isn't duplicated
        key = self._mk_rule_natural_key(inputs, transform, False)

        existing_rules = self._find_rule_execs("key = ?", (key,))
        if len(existing_rules) != 0:
            existing_rule = existing_rules[0]
            # now, "all" parameters get treated differently.  We allow all parameters to change a rule.  Compare
            # this one and the existing rule with all parameters to see if we need to replace it.

            existing_key_with_all = self._mk_rule_natural_key(
                existing_rule.inputs, existing_rule.transform, True
            )
            new_key_with_all = self._mk_rule_natural_key(inputs, transform, True)

            if existing_key_with_all == new_key_with_all:
                return existing_rule.id
            else:
                # key mismatches, meaning the all params must have changed.  Remove the existing and let the add
                # continue
                self.remove_rule(existing_rule.id)

        state = RE_STATUS_PENDING
        for name, obj in inputs:
            if not isinstance(obj, Obj):
                state = RE_STATUS_DEFERRED

        c = get_cursor()
        c.execute(
            "INSERT INTO rule_execution (space, transform, key, state) VALUES (?, ?, ?, ?)",
            (space, transform, key, state),
        )
        rule_execution_id = c.lastrowid
        assert isinstance(rule_execution_id, int)
        for name, objs in inputs:

            if isinstance(objs, Obj):
                is_list = False
                objs = [objs]
            else:
                is_list = True

            for obj in objs:
                self.objects.add(obj)
                c.execute(
                    "INSERT INTO rule_execution_input (rule_execution_id, name, obj_id, is_list) VALUES (?, ?, ?, ?)",
                    (rule_execution_id, name, obj.id, is_list),
                )

        rule = RuleExecution(rule_execution_id, space, inputs, transform, state)
        for add_rule_listener in self.add_rule_listeners:
            add_rule_listener(rule)

        return rule_execution_id

    def assert_db_sane(self):
        c = get_cursor()
        c.execute(
            "SELECT * from execution e where not exists (select 1 from rule_execution re where re.execution_id = e.id)"
        )
        assert len(c.fetchall()) == 0, "Found execution which has no rule_execution"
        c.execute(
            "SELECT * from rule_execution_input rei where not exists (select 1 from rule_execution re where re.id = rei.rule_execution_id)"
        )
        assert len(c.fetchall()) == 0
        c.execute(
            "SELECT * from rule_execution_input rei where not exists (select 1 from cur_obj o where o.id = rei.obj_id)"
        )
        assert len(c.fetchall()) == 0
        c.execute(
            "SELECT * from execution_output eo where not exists (select 1 from execution e where e.id = eo.execution_id)"
        )
        assert len(c.fetchall()) == 0
        c.execute(
            "SELECT * from execution_output eo where not exists (select 1 from cur_obj o where o.id = eo.obj_id)"
        )
        assert len(c.fetchall()) == 0

    def remove_rule(self, rule_id):
        signal_remove_rule(rule_id)
        c = get_cursor()
        c.execute("SELECT execution_id from rule_execution WHERE id = ?", (rule_id,))
        execution_ids = [x[0] for x in c.fetchall()]
        c.execute(
            "DELETE FROM rule_execution_input WHERE rule_execution_id = ?", (rule_id,)
        )
        c.execute("DELETE FROM rule_execution WHERE id = ?", (rule_id,))
        for execution_id in execution_ids:
            _delete_execution_by_id(c, execution_id)

        for l in self.remove_rule_listeners:
            l(rule_id)

    def get_pending(self) -> List[Any]:
        return self._find_rule_execs("state = ?", (RE_STATUS_PENDING,))

    def enable_deferred(self) -> None:
        c = get_cursor()
        c.execute(
            "UPDATE rule_execution SET state = ? WHERE state = ?",
            (RE_STATUS_PENDING, RE_STATUS_DEFERRED),
        )

    def started(self, rule_id, execution_id):
        c = get_cursor()
        c.execute(
            "UPDATE rule_execution SET state = ?, execution_id = ? WHERE id = ?",
            (RE_STATUS_STARTED, execution_id, rule_id),
        )

    def completed_execution(
        self, execution_id, new_status
    ) -> Union[int, Literal["norow"]]:
        # returns rule_execution_id
        assert execution_id != None
        if new_status == STATUS_COMPLETED:
            s = RE_STATUS_COMPLETE
        elif new_status == STATUS_FAILED:
            s = RE_STATUS_FAILED
        else:
            raise Exception("invalid state")

        c = get_cursor()
        c.execute(
            "UPDATE rule_execution SET state = ? WHERE execution_id = ?",
            (s, execution_id),
        )

        c.execute(
            "SELECT id FROM rule_execution WHERE execution_id = ?", (execution_id,)
        )
        rule_exec_id = c.fetchone()
        if rule_exec_id is None:
            return "norow"
        else:
            return rule_exec_id[0]

    def get_by_execution_id(self, execution_id):
        rules = self._find_rule_execs("execution_id = ?", (execution_id,))
        if len(rules) == 0:
            return None
        return rules[0]

    def remove_unsuccessful(self) -> None:
        incomplete = self._find_rule_execs(
            "state in (?, ?, ?)",
            (RE_STATUS_FAILED, RE_STATUS_PENDING, RE_STATUS_DEFERRED),
        )
        for rule in incomplete:
            self.remove_rule(rule.id)


class Execution:
    def __init__(self, id, inputs, outputs, transform, status, exec_xref, job_dir):
        # would be nice to have a status history (list of timestamp and new status, so we could see when job start/stopped)
        assertInputsValid(inputs)

        self.id = id
        self.transform = transform
        self.inputs = inputs
        self.status = status
        self.outputs = outputs
        self.exec_xref = exec_xref
        self.job_dir = job_dir

    def __repr__(self):
        return "<Execution id:{} inputs:{} outputs:{} transform:{} status:{} exec_xref:{}>".format(
            self.id,
            self.inputs,
            self.outputs,
            self.transform,
            self.status,
            self.exec_xref,
        )


class ExecutionLog:
    def __init__(self, obj_history: ObjHistory) -> None:
        self.obj_history = obj_history

    def _make_copy_get_id(self, x):
        self.obj_history.add(x)
        return x.id

    def started_execution(self, rule):
        status = STATUS_STARTED

        c = get_cursor()
        c.execute(
            "INSERT INTO execution (transform, status) VALUES (?, ?)",
            [rule.transform, status],
        )
        exec_id = c.lastrowid
        for name, objs in rule.inputs:
            is_list = True
            if isinstance(objs, Obj):
                objs = [objs]
                is_list = False
            for obj in objs:
                obj_id = self._make_copy_get_id(obj)
                c.execute(
                    "INSERT INTO execution_input (execution_id, name, obj_id, is_list) VALUES (?, ?, ?, ?)",
                    [exec_id, name, obj_id, is_list],
                )
        return exec_id

    def get_started_executions(self) -> List[Execution]:
        c = get_cursor()
        c.execute(
            "SELECT id, transform, status, execution_xref, job_dir FROM execution e WHERE status = ?",
            [STATUS_STARTED],
        )
        return self._as_RuleList(c)

    def _as_RuleList(self, c: Cursor) -> List[Execution]:
        pending = []
        for exec_id, transform, status, exec_xref, job_dir in c.fetchall():
            inputs = collections.defaultdict(lambda: [])
            var_is_list = {}
            c.execute(
                "SELECT name, obj_id, is_list FROM execution_input WHERE execution_id = ?",
                [exec_id],
            )
            for name, obj_id, is_list in c.fetchall():
                if name in var_is_list:
                    assert is_list
                var_is_list[name] = is_list
                inputs[name].append(self.obj_history.get(obj_id))
            in_name_values = []
            for name, values in inputs.items():
                if var_is_list[name]:
                    values = tuple(values)
                else:
                    assert len(values) == 1
                    values = values[0]
                in_name_values.append((name, values))

            outputs = []
            c.execute(
                "SELECT obj_id FROM execution_output WHERE execution_id = ?", [exec_id]
            )
            for (obj_id,) in c.fetchall():
                outputs.append(self.obj_history.get(obj_id))

            pending.append(
                Execution(
                    exec_id,
                    tuple(in_name_values),
                    outputs,
                    transform,
                    status,
                    exec_xref,
                    job_dir,
                )
            )
        return pending

    def get_downstream_object_ids(self, transform: str):
        c = get_cursor()
        c.execute(
            "SELECT eo.obj_id FROM execution e join execution_output eo on eo.execution_id = e.id WHERE transform = ?",
            [transform],
        )
        return [x[0] for x in c.fetchall()]

    def get(self, id) -> Optional[Execution]:
        c = get_cursor()
        c.execute(
            "SELECT id, transform, status, execution_xref, job_dir FROM execution WHERE id = ?",
            [id],
        )
        rules = self._as_RuleList(c)
        if len(rules) == 1:
            return rules[0]
        elif len(rules) == 0:
            return None
        else:
            raise Exception("Multiple rows fetched for id {}".format(id))

    def delete(self, id: int):
        signal_remove_rule_execution(id)
        c = get_cursor()
        c.execute("SELECT id FROM rule_execution where execution_id = ?", [id])
        rule_execution_ids = [x[0] for x in c.fetchall()]
        for rule_execution_id in rule_execution_ids:
            c.execute(
                "DELETE FROM rule_execution_input where rule_execution_id = ?",
                [rule_execution_id],
            )
            c.execute("DELETE FROM rule_execution WHERE id = ?", [rule_execution_id])

        _delete_execution_by_id(c, id)

    def get_by_output(self, obj):
        # probably won't really make a copy, just want to get the corresponding id
        obj_id = self._make_copy_get_id(obj)
        c = get_cursor()
        c.execute(
            "SELECT id, transform, status, execution_xref, job_dir FROM execution e WHERE exists (SELECT 1 FROM execution_output o WHERE o.execution_id = e.id AND obj_id = ?)",
            [obj_id],
        )
        return self._as_RuleList(c)

    def get_all(self):
        c = get_cursor()
        c.execute(
            "SELECT id, transform, status, execution_xref, job_dir FROM execution"
        )
        return self._as_RuleList(c)

    def update_exec_xref(self, exec_id, xref, job_dir):
        c = get_cursor()
        c.execute(
            "UPDATE execution SET execution_xref = ?, job_dir = ? WHERE id = ?",
            [xref, job_dir, exec_id],
        )

    def record_completed(self, execution_id, new_status, outputs):
        c = get_cursor()
        c.execute(
            "UPDATE execution SET status = ? WHERE id = ?", [new_status, execution_id]
        )
        for x in outputs:
            obj_id = self._make_copy_get_id(x)
            c.execute(
                "INSERT INTO execution_output (execution_id, obj_id) VALUES (?, ?)",
                [execution_id, obj_id],
            )

    def find_all_reachable_objs(self, root_obj_ids):
        c = get_cursor()
        objs_to_explore = list(root_obj_ids)
        objs_reached = set()

        while len(objs_to_explore) > 0:
            obj_id = objs_to_explore[-1]
            del objs_to_explore[-1]

            objs_reached.add(obj_id)

            c.execute(
                "SELECT ei.obj_id FROM execution_output eo JOIN execution e ON eo.execution_id = e.id JOIN execution_input ei ON e.id = ei.execution_id WHERE eo.obj_id = ?",
                [obj_id],
            )
            input_obj_ids = [x[0] for x in c.fetchall()]

            for input_obj_id in input_obj_ids:
                if input_obj_id in objs_reached:
                    continue
                objs_to_explore.append(input_obj_id)

        return objs_reached

    def find_all_reachable_downstream_objs(self, root_obj_ids):
        c = get_cursor()
        objs_to_explore = list(root_obj_ids)
        objs_reached = set()

        while len(objs_to_explore) > 0:
            obj_id = objs_to_explore[-1]
            del objs_to_explore[-1]

            if obj_id is None:
                print("Got missing obj_id")
                continue

            objs_reached.add(obj_id)

            c.execute(
                "SELECT eo.obj_id FROM execution_input ei JOIN execution e ON ei.execution_id = e.id JOIN execution_output eo ON e.id = eo.execution_id WHERE ei.obj_id = ?",
                [obj_id],
            )
            output_obj_ids = [x[0] for x in c.fetchall()]

            for output_obj_id in output_obj_ids:
                if output_obj_id in objs_reached:
                    continue
                if output_obj_id is None:
                    print("dropped none obj_id")
                    continue
                objs_to_explore.append(output_obj_id)

        return objs_reached

