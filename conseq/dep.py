import collections
import json
import logging
import os
import re
import sqlite3

import six

log = logging.getLogger(__name__)

DISABLE_AUTO_CREATE_RULES = False


class InstanceTemplate:
    def __init__(self, props):
        pass


STATUS_UNKNOWN = "unknown"
STATUS_STARTED = "started"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

RE_STATUS_PENDING = "pending"
RE_STATUS_STARTED = "started"
RE_STATUS_COMPLETE = "complete"
RE_STATUS_FAILED = "failed"
RE_STATUS_DEFERRED = "deferred"


class DefaultSpace:
    pass


PUBLIC_SPACE = "public"
DEFAULT_SPACE = DefaultSpace()

from contextlib import contextmanager
import threading

current_db_cursor_state = threading.local()


@contextmanager
def transaction(db):
    cursor = None
    depth = 0
    if hasattr(current_db_cursor_state, "cursor"):
        cursor = current_db_cursor_state.cursor
        depth = current_db_cursor_state.depth
    if cursor == None:
        cursor = db.cursor()
        current_db_cursor_state.cursor = cursor
    depth += 1
    current_db_cursor_state.depth = depth
    try:
        yield
    finally:
        current_db_cursor_state.depth -= 1
        if current_db_cursor_state.depth == 0:
            current_db_cursor_state.cursor.close()
            current_db_cursor_state.cursor = None
            db.commit()


def get_cursor():
    assert current_db_cursor_state.cursor != None
    return current_db_cursor_state.cursor


def split_props_into_key_and_other(props):
    key_props = {}
    other_props = {}

    for k, v in props.items():
        if (isinstance(v, dict) and len(v) == 1 and list(v.keys())[0].startswith("$")):
            other_props[k] = list(v.values())[0]
        elif k == '$hash':
            other_props[k] = v
        else:
            key_props[k] = v

    return key_props, other_props


class Obj:
    "Models an any input or output artifact by a set of key-value pairs"

    def __init__(self, id, space, timestamp, props):
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
        # if prop_name in self.key_props:
        #     return self.key_props[prop_name]
        # else:
        #     return self.other_props[prop_name]

    def __getitem__(self, item):
        return self.get(item)

    # @property
    # def props(self):
    #     d = dict(self.key_props)
    #     d.update(self.other_props)
    #     return d

    def __repr__(self):
        return "<{}:{} {}>".format(self.space, self.id, repr(self.props))


class ObjHistory:
    def __init__(self):
        pass

    def get(self, id):
        c = get_cursor()
        c.execute("select id, space, timestamp, json from past_obj where id = ?", [id])
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
        c.execute("insert into past_obj (id, space, timestamp, json) values (?, ?, ?, ?)",
                  [obj.id, obj.space, obj.timestamp, json.dumps(obj.props)])


class ObjSet:
    """
    Models the universe of all known artifacts.

    This prototype implementation does everything in memory but is intended to be replaced with one that read/writes to a persistent DB
    """

    def __init__(self):
        self.add_listeners = []
        self.remove_listeners = []
        self.default_space = PUBLIC_SPACE

    def initialize(self):
        c = get_cursor()
        c.execute("select default_space from settings")
        self.default_space = c.fetchone()[0]

    def __iter__(self):
        c = get_cursor()
        c.execute("select id, space, timestamp, json from cur_obj")
        objs = []
        for id, space, timestamp, _json in c.fetchall():
            objs.append(Obj(id, space, timestamp, json.loads(_json)))
        return iter(objs)

    def get(self, id):
        c = get_cursor()
        c.execute("select id, space, timestamp, json from cur_obj where id = ?", [id])
        id, space, timestamp, _json = c.fetchone()
        return Obj(id, space, timestamp, json.loads(_json))

    def remove(self, id):
        obj = self.get(id)
        c = get_cursor()
        c.execute("delete from cur_obj where id = ?", [id])
        for remove_listener in self.remove_listeners:
            remove_listener(obj)

    def get_spaces(self, parent=None):
        c = get_cursor()
        c.execute("select name, parent from space")
        return [x[0] for x in c.fetchall() if parent is None or parent == x[1] or x[0] == parent]

    def select_space(self, name, create_if_missing):
        c = get_cursor()
        self.assert_space_exists(name, create_if_missing, None)
        c.execute("update settings set default_space = ?", [name])

    def assert_space_exists(self, name, create_if_missing, parent):
        c = get_cursor()
        c.execute("select name from space where name = ?", [name])
        if c.fetchone() is None:
            if create_if_missing:
                c.execute("insert into space (name, parent) values (?, ?)", [name, parent])
            else:
                raise Exception("No space named: {}".format(name))

    def get_last_id(self):
        c = get_cursor()
        c.execute("select max(id) from cur_obj")
        id = c.fetchone()
        if id is None:
            id = 0
        else:
            id = id[0]
        return id

    def add(self, space, timestamp, props):
        if space == DEFAULT_SPACE:
            space = self.default_space

        # first check to see if this already exists
        match = self.find_by_key(space, props)

        if match != None:
            if match.timestamp == timestamp:
                return match.id

            if "$hash" in props and "$hash" in match.props and props["$hash"] == match.props["$hash"]:
                return match.id

            self.remove(match.id)

        self.assert_space_exists(space, True, self.default_space)

        c = get_cursor()
        c.execute("insert into cur_obj (space, timestamp, json) values (?, ?, ?)",
                  [space, timestamp, json.dumps(props)])
        id = c.lastrowid

        obj = Obj(id, space, timestamp, props)

        for add_listener in self.add_listeners:
            add_listener(obj)

        return id

    def find_by_key(self, space, props):
        key_props = split_props_into_key_and_other(props)[0]
        matches = self.find(space, key_props)
        if len(matches) > 1:
            raise Exception("Too many matches: key_props={}, matches={}".format(key_props, matches))
        elif len(matches) == 1:
            return matches[0]
        else:
            return None

    def find(self, space, properties):
        if space == DEFAULT_SPACE:
            space = self.default_space

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

                if hasattr(v, "match"):
                    matched = v.match(ov) != None
                else:
                    matched = (ov == v)

                if not matched:
                    skip = True
                    break

            if not skip:
                result.append(o)

        return result


def assertInputsValid(inputs):
    for x in inputs:
        assert isinstance(x, tuple) and len(x) == 2
        name, value = x
        assert isinstance(value, Obj) or (isinstance(value, tuple) and isinstance(value[0], Obj))


class RuleExecution:
    """
    Represents a statement describing what transform to run to generate a set of Objs (outputs) from a different set of Objs (inputs)
    """

    def __init__(self, id, space, inputs, transform, state, execution_id=None):
        assertInputsValid(inputs)

        self.space = space
        self.inputs = inputs
        self.transform = transform
        self.id = id
        self.state = state
        self.execution_id = execution_id

    def __repr__(self):
        return "<Rule {} in:{}:{} transform:{} state:{}>".format(self.space, self.id, self.inputs, self.transform,
                                                                 self.state)


class RuleSet:
    """
        The all active rules
    """

    def __init__(self, objects):
        self.remove_rule_listeners = []
        self.add_rule_listeners = []
        self.objects = objects

    def _find_rule_execs(self, where_class="", where_params=()):
        results = []
        c = get_cursor()
        query = "select id, space, transform, key, state, execution_id from rule_execution re"
        if where_class != "":
            query += " WHERE " + where_class
        c.execute(query, where_params)
        for id, space, transform, key, state, execution_id in list(c.fetchall()):
            c.execute("select name, obj_id, is_list from rule_execution_input where rule_execution_id = ?", (id,))

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

            results.append(RuleExecution(id, space, tuple(inputs), transform, state, execution_id=execution_id))
        return results

    def __iter__(self):
        return iter(self._find_rule_execs())

    def _mk_rule_natural_key(self, inputs, transform, include_all_inputs):
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

    def find_by_input(self, input_id):
        "given an input id, find all of the rule executions ids which refer to that input"
        rules = self._find_rule_execs(
            "EXISTS (select 1 from rule_execution_input rei where rei.rule_execution_id = re.id and rei.obj_id = ?)",
            (input_id,))
        rule_ids = [x.id for x in rules]
        return rule_ids

    def find_downstream_from_rule(self, rule_id):
        n_obj_ids = set()
        n_rule_ids = set()

        obj_ids = self.get_outputs(rule_id)

        n_obj_ids.update(obj_ids)
        for obj_id in obj_ids:
            _rule_ids, _obj_ids = self.find_downstream_from_obj(obj_id)
            n_obj_ids.update(_obj_ids)
            n_rule_ids.update(_rule_ids)

        return n_rule_ids, n_obj_ids

    def find_downstream_from_obj(self, input_id):
        "given an object, return all the rule_execution ids and object that executed downstream of that object"
        n_obj_ids = set()
        n_rule_ids = set()

        rule_ids = self.find_by_input(input_id)
        n_rule_ids.update(rule_ids)
        for rule_id in rule_ids:
            _rule_ids, _obj_ids = self.find_downstream_from_rule_exec(rule_id)
            n_obj_ids.update(_obj_ids)
            n_rule_ids.update(_rule_ids)

        return n_rule_ids, n_obj_ids

    def get(self, id):
        rules = self._find_rule_execs("id = ?", (id,))
        if len(rules) == 0:
            return None
        return rules[0]

    def add_rule(self, space, inputs, transform):
        # first check to make sure rule isn't duplicated
        key = self._mk_rule_natural_key(inputs, transform, False)

        existing_rules = self._find_rule_execs("key = ?", (key,))
        if len(existing_rules) != 0:
            existing_rule = existing_rules[0]
            # now, "all" parameters get treated differently.  We allow all parameters to change a rule.  Compare
            # this one and the existing rule with all parameters to see if we need to replace it.

            existing_key_with_all = self._mk_rule_natural_key(existing_rule.inputs, existing_rule.transform, True)
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
        c.execute("insert into rule_execution (space, transform, key, state) values (?, ?, ?, ?)",
                  (space, transform, key, state))
        rule_execution_id = c.lastrowid
        for name, objs in inputs:

            if isinstance(objs, Obj):
                is_list = False
                objs = [objs]
            else:
                is_list = True

            for obj in objs:
                self.objects.add(obj)
                c.execute(
                    "insert into rule_execution_input (rule_execution_id, name, obj_id, is_list) values (?, ?, ?, ?)",
                    (rule_execution_id, name, obj.id, is_list))

        rule = RuleExecution(rule_execution_id, space, inputs, transform, state)
        for add_rule_listener in self.add_rule_listeners:
            add_rule_listener(rule)

        return rule_execution_id

    def remove_rule(self, rule_id):
        c = get_cursor()
        c.execute("delete from rule_execution_input where rule_execution_id = ?", (rule_id,))
        c.execute("delete from rule_execution where id = ?", (rule_id,))

        for l in self.remove_rule_listeners:
            l(rule_id)

    def get_pending(self):
        return self._find_rule_execs("state = ?", (RE_STATUS_PENDING,))

    def enable_deferred(self):
        c = get_cursor()
        c.execute("update rule_execution set state = ? where state = ?", (RE_STATUS_PENDING, RE_STATUS_DEFERRED))

    def started(self, rule_id, execution_id):
        c = get_cursor()
        c.execute("update rule_execution set state = ?, execution_id = ? where id = ?",
                  (RE_STATUS_STARTED, execution_id, rule_id))

    def get_space_by_execution_id(self, execution_id):
        rule = self.get_by_execution_id(execution_id)
        if rule == None:
            return None
        return rule.space

    def completed_execution(self, execution_id, new_status):
        # returns rule_execution_id
        assert execution_id != None
        if new_status == STATUS_COMPLETED:
            s = RE_STATUS_COMPLETE
        elif new_status == STATUS_FAILED:
            s = RE_STATUS_FAILED
        else:
            raise Exception("invalid state")

        c = get_cursor()
        c.execute("update rule_execution set state = ? where execution_id = ?", (s, execution_id))

        c.execute("select id from rule_execution where execution_id = ?", (execution_id,))
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

    def remove_unsuccessful(self):
        incomplete = self._find_rule_execs("state in (?, ?, ?)",
                                           (RE_STATUS_FAILED, RE_STATUS_PENDING, RE_STATUS_DEFERRED))
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
        return "<Execution id:{} inputs:{} outputs:{} transform:{} status:{} exec_xref:{}>".format(self.id, self.inputs,
                                                                                                   self.outputs,
                                                                                                   self.transform,
                                                                                                   self.status,
                                                                                                   self.exec_xref)


class ExecutionLog:
    def __init__(self, obj_history):
        self.obj_history = obj_history

    def mark_incomplete(self):
        c = get_cursor()
        c.execute("update execution set status = ? where status = ?", [STATUS_UNKNOWN, STATUS_STARTED])

    def _make_copy_get_id(self, x):
        self.obj_history.add(x)
        return x.id

    def started_execution(self, rule):
        status = STATUS_STARTED

        c = get_cursor()
        c.execute("insert into execution (transform, status) values (?, ?)", [rule.transform, status])
        exec_id = c.lastrowid
        for name, objs in rule.inputs:
            is_list = True
            if isinstance(objs, Obj):
                objs = [objs]
                is_list = False
            for obj in objs:
                obj_id = self._make_copy_get_id(obj)
                c.execute("insert into execution_input (execution_id, name, obj_id, is_list) values (?, ?, ?, ?)",
                          [exec_id, name, obj_id, is_list])
        return exec_id

    def get_started_executions(self):
        c = get_cursor()
        c.execute("select id, transform, status, execution_xref, job_dir from execution e where status = ?",
                  [STATUS_STARTED])
        return self._as_RuleList(c)

    def _as_RuleList(self, c):
        pending = []
        for exec_id, transform, status, exec_xref, job_dir in c.fetchall():
            inputs = collections.defaultdict(lambda: [])
            var_is_list = {}
            c.execute("select name, obj_id, is_list from execution_input where execution_id = ?", [exec_id])
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
            c.execute("select obj_id from execution_output where execution_id = ?", [exec_id])
            for obj_id, in c.fetchall():
                outputs.append(self.obj_history.get(obj_id))

            pending.append(Execution(exec_id, tuple(in_name_values), outputs, transform, status, exec_xref, job_dir))
        return pending

    def get(self, id):
        c = get_cursor()
        c.execute("select id, transform, status, execution_xref, job_dir from execution where id = ?", [id])
        rules = self._as_RuleList(c)
        if len(rules) == 1:
            return rules[0]
        elif len(rules) == 0:
            return None
        else:
            raise Exception("Multiple rows fetched for id {}".format(id))

    def delete(self, id):
        c = get_cursor()
        c.execute("delete from execution_input where execution_id = ?", [id])
        c.execute("delete from execution_output where execution_id = ?", [id])
        c.execute("delete from execution where id = ?", [id])

    def get_by_output(self, obj):
        # probably won't really make a copy, just want to get the corresponding id
        obj_id = self._make_copy_get_id(obj)
        c = get_cursor()
        c.execute(
            "select id, transform, status, execution_xref, job_dir from execution e where exists (select 1 from execution_output o where o.execution_id = e.id and obj_id = ?)",
            [obj_id])
        return self._as_RuleList(c)

    def get_all(self):
        c = get_cursor()
        c.execute("select id, transform, status, execution_xref, job_dir from execution")
        return self._as_RuleList(c)

    def update_exec_xref(self, exec_id, xref, job_dir):
        c = get_cursor()
        c.execute("update execution set execution_xref = ?, job_dir = ? where id = ?", [xref, job_dir, exec_id])

    def record_completed(self, execution_id, new_status, outputs):
        c = get_cursor()
        c.execute("update execution set status = ? where id = ?", [new_status, execution_id])
        for x in outputs:
            obj_id = self._make_copy_get_id(x)
            c.execute("insert into execution_output (execution_id, obj_id) values (?, ?)", [execution_id, obj_id])

    def find_all_reachable_objs(self, root_obj_ids):
        c = get_cursor()
        objs_to_explore = list(root_obj_ids)
        objs_reached = set()

        while len(objs_to_explore) > 0:
            obj_id = objs_to_explore[-1]
            del objs_to_explore[-1]

            objs_reached.add(obj_id)

            c.execute(
                "select ei.obj_id from execution_output eo join execution e on eo.execution_id = e.id join execution_input ei on e.id = ei.execution_id where eo.obj_id = ?",
                [obj_id])
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

            objs_reached.add(obj_id)

            c.execute(
                "select eo.obj_id from execution_input ei join execution e on ei.execution_id = e.id join execution_output eo on e.id = eo.execution_id where ei.obj_id = ?",
                [obj_id])
            output_obj_ids = [x[0] for x in c.fetchall()]

            for output_obj_id in output_obj_ids:
                if output_obj_id in objs_reached:
                    continue
                objs_to_explore.append(output_obj_id)

        return objs_reached

    def to_dot(self, detailed):
        """
        :return: a graphviz graph in dot syntax of all objects and rules created
        """
        stmts = []
        objs = {}
        # state_color = {WAITING:"gray", READY:"red", STARTED:"blue", FAILED:"green", COMPLETED:"turquoise"}
        for rule in self.get_all():
            if rule.status == "canceled":
                continue

            for name, value in rule.inputs:
                if not isinstance(value, tuple):
                    value = [value]
                for v in value:
                    stmts.append("o{} -> r{} [label=\"{}\"]".format(v.id, rule.id, name))
                    objs[v.id] = v
            for output in rule.outputs:
                stmts.append("r{} -> o{}".format(rule.id, output.id))
                objs[output.id] = output

            # color=state_color[self.get_rule_state(rule.id)]
            color = "gray"

            stmts.append(
                "r{} [shape=box, label=\"{}\", style=\"filled\" fillcolor=\"{}\"]".format(rule.id, rule.transform,
                                                                                          color))

        for obj in objs.values():
            prop_values = []
            for k, v in obj.props.items():
                if not isinstance(v, dict) or detailed:
                    prop_values.append("{}: {}".format(k, v))
            label = "\\n".join(prop_values)
            stmts.append("o{} [label=\"{}\"]".format(obj.id, label))
        return "digraph { " + (";\n".join(stmts)) + " } "


class ForEach:
    def __init__(self, variable, const_constraints={}):
        assert variable != ""
        self.variable = variable
        self.const_constraints = const_constraints

    def __repr__(self):
        return "<ForEach {} where {}>".format(self.variable, self.const_constraints)


class ForAll:
    def __init__(self, variable, const_constraints={}):
        self.variable = variable
        self.const_constraints = const_constraints


class PropEqualsConstant:
    def __init__(self, variable, property, constant):
        self.variable = variable
        self.property = property
        self.constant = constant

    def satisfied(self, bindings):
        return bindings[self.variable][self.property] == self.constant


class PropMatchesRegexp:
    def __init__(self, variable, property, regexp):
        self.variable = variable
        self.property = property
        if isinstance(regexp, six.string_types):
            self.regexp = re.compile(regexp)
        else:
            self.regexp = regexp

    def satisfied(self, bindings):
        return self.regexp.match(bindings[self.variable][self.property]) != None


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


from conseq.timeit import timeblock


class Template:
    def __init__(self, queries, predicates, transform, output_matches_expectation=lambda x: True):
        self.foreach_queries = []
        self.forall_queries = []
        for q in queries:
            if isinstance(q, ForEach):
                self.foreach_queries.append(q)
            elif isinstance(q, ForAll):
                self.forall_queries.append(q)
            else:
                raise Exception("Bad query type: {}".format(q))
        self.predicates = predicates
        self.transform = transform
        self.output_matches_expectation = output_matches_expectation

    def is_interested_in(self, obj):
        assert isinstance(obj, Obj), "obj is of type {}".format(type(obj))
        props = obj.props
        assert isinstance(props, dict)

        key_value_pairs = set()
        for k, v in obj.props.items():
            if isinstance(v, str):
                key_value_pairs.add((k, v))

        for q in self.foreach_queries + self.forall_queries:
            matched = True
            for k, v in q.const_constraints.items():
                if isinstance(v, str):
                    if (k, v) not in key_value_pairs:
                        matched = False
                        break
                else:
                    if k not in obj.props:
                        matched = False
                        break
                    if not v.match(obj.props[k]):
                        matched = False
                        break
            if matched:
                return True
        return False

    @property
    def name(self):
        return self.transform

    def _predicate_satisifed(self, bindings):
        for p in self.predicates:
            if not p.satisfied(bindings):
                return False
        return True

    def _rewrite_queries(self, props_to_fix, obj, queries):
        # props_to_fix is a list of (prop name, list of (name, propr))
        q_map = dict([(q.variable, q) for q in queries])
        for prop, targets in props_to_fix:
            if prop in obj.props:
                value = obj[prop]
                for target_name, target_prop in targets:
                    if target_name in q_map:
                        q = q_map[target_name]
                        const_constraints = dict(q.const_constraints)
                        const_constraints[target_prop] = value
                        new_q = ForEach(q.variable, const_constraints)
                        q_map[target_name] = new_q
            else:
                # if the object is missing the prop, then there's no queries that should be done
                return [ForEach("_INVALID_", {"_INVALID_": "_INVALID_"})]
        return list(q_map.values())

    def _create_rules(self, obj_set, space, bindings, queries):
        # queries is a list of ForEach
        if len(queries) == 0:
            if self._predicate_satisifed(bindings):
                return [bindings]
            else:
                return []

        q_rest = queries[:-1]
        q = queries[-1]

        # find constraints that depend on this query
        props_to_fix = []
        for p in self.predicates:
            if isinstance(p, PropsMatch):
                uses_this_prop = None
                other_targets = []
                for name, prop in p.pairs:
                    if q.variable == name:
                        uses_this_prop = prop
                    else:
                        other_targets.append((name, prop))
                if uses_this_prop is not None:
                    props_to_fix.append((uses_this_prop, other_targets))

        results = []
        for obj in obj_set.find(space, q.const_constraints):
            new_binding = dict(bindings)
            new_binding[q.variable] = obj

            # refine future queries based on the obj we just found

            results.extend(
                self._create_rules(obj_set, space, new_binding, self._rewrite_queries(props_to_fix, obj, q_rest)))
        return results

    def _execute_forall_queries(self, bindings, obj_set, space):
        bindings = dict(bindings)
        for q in self.forall_queries:
            objs = tuple(obj_set.find(space, q.const_constraints))
            if len(objs) == 0:
                return None
            bindings[q.variable] = objs
        return bindings

    def create_rules(self, obj_set):
        # print ("create_rules, transform:",self.transform,", queries: ", self.foreach_queries)
        with timeblock(log, "create_rules({})".format(self.transform), min_time=1):
            results = []
            for space in obj_set.get_spaces(parent=obj_set.default_space):
                if len(self.foreach_queries) == 0 and space == obj_set.default_space:
                    bindings = [{}]
                else:
                    bindings = self._create_rules(obj_set, space, {}, self.foreach_queries)

                # after all for-eaches are resolved, try the for-alls
                for b in bindings:
                    b = self._execute_forall_queries(b, obj_set, space)
                    if b == None:
                        continue
                    inputs = tuple(b.items())
                    results.append((space, inputs, self.transform))

            log.debug("Created rules for %s: %s", self.transform, results)
            return results


class RuleAndDerivativesFilter:
    def __init__(self, rules_allowed, last_existing_id):
        self.rules_allowed = rules_allowed
        self.last_existing_id = last_existing_id

    def rule_allowed(self, inputs, transform):
        # if we are executing a rule we've explictly whitelisted
        for is_allowed in self.rules_allowed:
            if is_allowed(inputs, transform):
                return True

        # or we are executing a rule which uses an object that was created since this
        # process started (implying it must have come from a whitelisted rule) then
        # let this rule get created
        for name, _obj in inputs:
            if isinstance(_obj, Obj):
                objs = [_obj]
            else:
                objs = _obj
            for obj in objs:
                if obj.id > self.last_existing_id:
                    return True
        # All others should be dropped
        return False


class Jobs:
    """
        Top level class gluing everything together
    """

    def __init__(self, db):
        self.db = db
        self.objects = ObjSet()
        with transaction(db):
            self.objects.initialize()
        object_history = ObjHistory()
        self.rule_set = RuleSet(object_history)
        self.rule_templates = []
        self.rule_template_by_name = {}
        self.add_new_obj_listener(self._object_added)
        self.objects.remove_listeners.append(self._object_removed)
        self.log = ExecutionLog(object_history)
        self.rule_allowed = lambda inputs, transform: True
        self.pending_rules_to_evaluate = set()

    def has_template(self, rule_name):
        return rule_name in self.rule_template_by_name

    def limitStartToTemplates(self, rules_allowed):
        with transaction(self.db):
            last_existing_id = self.objects.get_last_id()
            if last_existing_id is None:
                last_existing_id = -1
        filter = RuleAndDerivativesFilter(rules_allowed, last_existing_id)
        self.rule_allowed = filter.rule_allowed

    def _object_removed(self, obj):
        for rule_id in self.rule_set.find_by_input(obj.id):
            self.rule_set.remove_rule(rule_id)

        # forall might result in rules being recreated even without this input
        new_rules = []
        if not DISABLE_AUTO_CREATE_RULES:
            for template in self.rule_templates:
                if template.is_interested_in(obj):
                    log.info("Need to refresh %s on next pass", template.transform)
                    self.pending_rules_to_evaluate.add(template.transform)
                    # new_rules.extend(template.create_rules(self.objects))

        for space, inputs, transform in new_rules:
            self._add_rule(space, inputs, transform)

    def _object_added(self, obj):
        new_rules = []
        if not DISABLE_AUTO_CREATE_RULES:
            for template in self.rule_templates:
                if template.is_interested_in(obj):
                    self.pending_rules_to_evaluate.add(template.transform)
                    # new_rules.extend(template.create_rules(self.objects))

        for space, inputs, transform in new_rules:
            self._add_rule(space, inputs, transform)

    def _add_rule(self, space, inputs, transform):
        if self.rule_allowed(inputs, transform):
            self.rule_set.add_rule(space, inputs, transform)

    def add_new_obj_listener(self, listener):
        self.objects.add_listeners.append(listener)

    def transaction(self):
        return transaction(self.db)

    def to_dot(self, detailed):
        with transaction(self.db):
            return self.log.to_dot(detailed)

    def query_template(self, template):
        with transaction(self.db):
            return template.create_rules(self.objects)

    def add_template(self, template):
        with transaction(self.db):
            self.rule_templates.append(template)
            self.rule_template_by_name[template.name] = template

            new_rules = template.create_rules(self.objects)
            for rule in new_rules:
                self._add_rule(*rule)

    def refresh_rules(self):
        if len(self.pending_rules_to_evaluate) == 0:
            return

        with transaction(self.db):
            refresh_count = 0
            add_executions = 0
            pending_rules_to_evaluate = self.pending_rules_to_evaluate
            self.pending_rules_to_evaluate = set()
            for template in self.rule_templates:
                if template.transform not in pending_rules_to_evaluate:
                    continue
                refresh_count += 1
                new_rules = template.create_rules(self.objects)
                add_executions += len(new_rules)
                for rule in new_rules:
                    self._add_rule(*rule)
                    # log.info("Refreshed the following templates: %s, refresh_count=%s, added=%s", pending_rules_to_evaluate, refresh_count, add_executions)

    def add_obj(self, space, timestamp, obj_props, overwrite=True):
        """
        Used to record the creation of an object with a given timestamp

        :param obj_props: either a dict or sequence of (key, value) tuples
        :param timestamp:
        """

        with transaction(self.db):
            if not overwrite:
                existing = self.objects.find_by_key(space, obj_props)
                if existing != None:
                    return existing.id

            return self.objects.add(space, timestamp, obj_props)

    def remove_obj(self, obj_id, with_invalidate):
        with transaction(self.db):
            obj = self.objects.get(obj_id)
            if with_invalidate:
                for x in self.log.get_by_output(obj):
                    rule = self.rule_set.get_by_execution_id(x.id)
                    if rule is not None:
                        self.rule_set.remove_rule(rule.id)
                    self.log.delete(x.id)
            self.objects.remove(obj_id)

    def find_all_reachable_downstream_objs(self, obj_id):
        with transaction(self.db):
            obj_ids = self.log.find_all_reachable_downstream_objs(obj_id)
            return [self.objects.get(obj_id) for obj_id in obj_ids]

    def remove_objects(self, obj_ids):
        with transaction(self.db):
            for obj_id in obj_ids:
                self.remove_obj(obj_id, True)

    def find_objs(self, space, query):
        with transaction(self.db):
            return self.objects.find(space, query)

    def get_pending(self):
        with transaction(self.db):
            return self.rule_set.get_pending()

    def get_started_executions(self):
        with transaction(self.db):
            return self.log.get_started_executions()

    def get_all_executions(self):
        with transaction(self.db):
            return self.log.get_all()

    def enable_deferred(self):
        with transaction(self.db):
            return self.rule_set.enable_deferred()

    def record_started(self, rule_id):
        assert isinstance(rule_id, int)
        with transaction(self.db):
            rule = self.rule_set.get(rule_id)
            execution_id = self.log.started_execution(rule)
            self.rule_set.started(rule_id, execution_id)
            return execution_id

    def cancel_execution(self, exec_id):
        with transaction(self.db):
            self.rule_set.completed_execution(exec_id, RE_STATUS_FAILED)
            self.log.record_completed(exec_id, STATUS_FAILED, [])

    def _record_completed(self, execution_id, new_status, interned_outputs):
        self.log.record_completed(execution_id, new_status, interned_outputs)
        return self.rule_set.completed_execution(execution_id, new_status)

    def record_completed(self, timestamp, execution_id, new_status, outputs):
        with transaction(self.db):
            default_space = self.rule_set.get_space_by_execution_id(execution_id)
            if default_space == None:
                log.warning("No associated rule execution for execution_id %s.  Dropping outputs: %s",
                            repr(execution_id), outputs)
                self.log.record_completed(execution_id, new_status, [])
            else:
                def get_space(obj):
                    if "$space" in obj:
                        o = dict(obj)
                        del o["$space"]
                        return obj["$space"], o
                    else:
                        return default_space, obj

                rule_exec = self.rule_set.get_by_execution_id(execution_id)
                if rule_exec is None:
                    log.warning("Could not find rule for execution id %s", execution_id)
                else:
                    rule_def = self.rule_template_by_name[rule_exec.transform]
                    for output in outputs:
                        if not rule_def.output_matches_expectation(output):
                            log.warning("Output %s did not match any of the expected outputs on rule \"%s\"", output,
                                        rule_exec.transform)

                interned_outputs = []
                for output in outputs:
                    space, output = get_space(output)

                    obj_id = self.add_obj(space, timestamp, output)
                    interned_outputs.append(self.objects.get(obj_id))
                return self._record_completed(execution_id, new_status, interned_outputs)

    def update_exec_xref(self, exec_id, xref, job_dir):
        with transaction(self.db):
            self.log.update_exec_xref(exec_id, xref, job_dir)

    def remember_executed(self, exec_stmt):
        space = self.get_current_space()
        transform = exec_stmt.transform

        def resolve_obj(props):
            assert isinstance(props, dict)
            objs = self.objects.find(space, props)
            if len(objs) != 1:
                raise Exception("Expected to find a single object with properties: {}".format(props))
            return objs[0]

        log.info("Remembering execution: %s, %s", transform, exec_stmt.inputs)
        # find inputs in repo.  Errors if no such object exists
        inputs_json = exec_stmt.inputs
        inputs = []
        for name, value_json in inputs_json:
            if isinstance(value_json, list) or isinstance(value_json, tuple):
                value = tuple([resolve_obj(i) for i in value_json])
            else:
                value = resolve_obj(value_json)
            inputs.append((name, value))

        outputs_json = exec_stmt.outputs
        interned_outputs = [resolve_obj(o) for o in outputs_json]

        rule_id = self.rule_set.add_rule(space, inputs, transform)
        execution_id = self.record_started(rule_id)
        self._record_completed(execution_id, STATUS_COMPLETED, interned_outputs)

    def cleanup_unsuccessful(self):
        with transaction(self.db):
            self.rule_set.remove_unsuccessful()
            # self.log.mark_incomplete()

    def invalidate_rule_execution(self, transform):
        with transaction(self.db):
            for r in self.rule_set.find_by_name(transform):
                self.rule_set.remove_rule(r.id)

    def gc(self, rm_callback):
        with transaction(self.db):
            root_objs = [o.id for o in self.objects]
            obj_ids = self.log.find_all_reachable_objs(root_objs)

            def has_reachable_output(e):
                for o in e.outputs:
                    if o.id in obj_ids:
                        return True
                return False

            to_drop = []
            for e in self.log.get_all():
                if not has_reachable_output(e):
                    to_drop.append(e.id)

            for e_id in to_drop:
                self.log.delete(e_id)
                rm_callback(e_id)

        return to_drop

    def get_spaces(self):
        with transaction(self.db):
            return self.objects.get_spaces()

    def select_space(self, name, create_if_missing):
        with transaction(self.db):
            return self.objects.select_space(name, create_if_missing)

    def get_current_space(self):
        return self.objects.default_space

    def dump(self):
        with transaction(self.db):
            for obj in self.objects:
                print("obj:", obj)
            for rs in self.rule_set:
                print("rule:", rs)
            for job in self.log.get_all():
                print("all job:", job)


# for job in self.log.get_pending():
#                print("pending job:", job)

def open_state_dir(state_dir):
    return open_job_db(os.path.join(state_dir, "db.sqlite3"))


def open_job_db(filename):
    needs_create = not os.path.exists(filename)

    db = sqlite3.connect(filename)

    stmts = []
    if needs_create:
        stmts.extend([
            "create table rule (id INTEGER PRIMARY KEY AUTOINCREMENT, transform STRING, key STRING)",
            "create table cur_obj (id INTEGER PRIMARY KEY AUTOINCREMENT, space string, timestamp STRING, json STRING)",
            "create table past_obj (id INTEGER PRIMARY KEY AUTOINCREMENT, space string, timestamp STRING, json STRING)",
            "create table rule_execution (id INTEGER PRIMARY KEY AUTOINCREMENT, space STRING, transform STRING, key STRING, state STRING, execution_id integer)",
            "create table rule_execution_input (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_execution_id INTEGER, name STRING, obj_id INTEGER, is_list INTEGER)",
            "create table execution (id INTEGER PRIMARY KEY AUTOINCREMENT, transform STRING, status STRING, execution_xref STRING, job_dir STRING)",
            "create table execution_input (id INTEGER PRIMARY KEY AUTOINCREMENT, execution_id INTEGER, name STRING, obj_id INTEGER, is_list INTEGER)",
            "create table execution_output (id INTEGER PRIMARY KEY AUTOINCREMENT, execution_id INTEGER, obj_id INTEGER)",
            "create table settings (schema_version integer, default_space string)",
            "insert into settings (schema_version, default_space) values (1, 'public')",
            "create table space (name string, parent string)",
            "insert into space (name) values ('public')"
        ])
    else:
        c = db.cursor()
        try:
            c.execute("SELECT schema_version FROM settings")
            schema_version = c.fetchone()[0]
        except sqlite3.OperationalError:
            schema_version = 0
        c.close()

        if schema_version < 1:
            stmts.extend([
                "create table settings (schema_version integer, default_space string)",
                "insert into settings (schema_version, default_space) values (1, 'public')",
                "create table space (name string, parent string)",
                "insert into space (name) values ('public')"
            ])

    for stmt in stmts:
        db.execute(stmt)

    return Jobs(db)
