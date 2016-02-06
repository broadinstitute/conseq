import json
import sqlite3
import os
import collections

#WAITING="waiting"
#READY="ready"
#STARTED="started"
#FAILED="failed"
#COMPLETED="completed"
class Wildcard:
    pass

WILDCARD = Wildcard()

class InstanceTemplate:
    def __init__(self, props):
        pass


STATUS_READY = "ready"
STATUS_CANCELED = "canceled"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

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
    yield
    current_db_cursor_state.depth -= 1
    if current_db_cursor_state.depth == 0:
        current_db_cursor_state.cursor.close()
        current_db_cursor_state.cursor = None
    db.commit()

def get_cursor():
    assert current_db_cursor_state.cursor != None
    return current_db_cursor_state.cursor

class Obj:
    "Models an any input or output artifact by a set of key-value pairs"
    def __init__(self, id, timestamp, props):
        """
        :param id:
        :param props: either a dictionary or a sequence of (key, value) tuples
        :return:
        """
        self.id = id
        self.timestamp = timestamp
        self.props = dict(props)

    def __eq__(self, other):
        """
        :param other: an instance of Obj to compare to
        :return: true of this object has the same properties as "other" does
        """
        return self.props == other.props

    def get(self, prop_name):
        """
        :param prop_name:
        :return: the value for the given property
        """
        return self.props[prop_name]

    def __repr__(self):
        return "<{} {}>".format(self.id, repr(self.props))

class ObjSet:
    """
    Models the universe of all known artifacts.

    This prototype implementation does everything in memory but is intended to be replaced with one that read/writes to a persistent DB
    """
    def __init__(self, table_name):
        self.table_name = table_name
        self.add_listeners = []
        self.remove_listeners = []

    def __iter__(self):
        c = get_cursor()
        c.execute("select id, timestamp, json from {}".format(self.table_name))
        objs = []
        for id, timestamp, _json in c.fetchall():
            objs.append( Obj(id, timestamp, json.loads(_json)) )
        return iter(objs)

    def get(self, id):
        c = get_cursor()
        c.execute("select id, timestamp, json from {} where id = ?".format(self.table_name), [id])
        id, timestamp, _json = c.fetchone()
        return Obj(id, timestamp, json.loads(_json))

    def remove(self, id):
        c = get_cursor()
        c.execute("delete from {} where id = ?".format(self.table_name), [id])
        for remove_listener in self.remove_listeners:
            remove_listener(id)

    def add(self, timestamp, props):
        # first check to see if this already exists
        matches = self.find(props)
        matches = [m for m in matches if m.props == props]
        assert len(matches) <= 1
        if len(matches) == 1:
            if matches[0].timestamp != timestamp:
                self.remove(matches[0].id)
            else:
                return matches[0].id

        c = get_cursor()
        c.execute("insert into {} (timestamp, json) values (?, ?)".format(self.table_name), [timestamp, json.dumps(props)])
        id = c.lastrowid

        obj = Obj(id, timestamp, props)

        for add_listener in self.add_listeners:
            add_listener(obj)

        return id

    def find(self, properties):
        result = []
        for o in self:
            skip = False
            for k, v in properties.items():
                if not ((k in o.props) and (o.props[k] == v)):
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

class Rule:
    """
    Represents a statement describing what transform to run to generate a set of Objs (outputs) from a different set of Objs (inputs)
    """
    def __init__(self, id, inputs, transform):
        assertInputsValid(inputs)

        self.inputs = inputs
        self.transform = transform
        self.id = id

    def __repr__(self):
        return "<Rule in:{} out:{} transform:{}>".format(self.inputs, self.outputs, self.transform)


class RuleSet:
    """
        The all active rules

        This prototype implementation does everything in memory but is intended to be replaced with one that read/writes to a persistent DB
    """
    def __init__(self):
        self.remove_rule_listeners = []
        self.add_rule_listeners = []

    def __iter__(self):
        return iter(self.rule_by_id.values())

    def get(self, id):
        return self.rule_by_id[id]

    def remove_rule(self, rule_id):
        get_cursor().execute("delete from rule where id = ?", [rule_id])
        for remove_rule_listener in self.remove_rule_listeners:
            remove_rule_listener(rule_id)

    def _mk_rule_natural_key(self, inputs, transform):
        flattened_inputs = []
        for n, vs in inputs:
            if not isinstance(vs, tuple):
                vs = (vs,)
            flattened_inputs.append( (n, tuple([x.id for x in vs]))  )
        return repr((tuple(flattened_inputs), transform))

    def add_rule(self, inputs, transform):
        # first check to make sure rule isn't duplicated
        key = self._mk_rule_natural_key(inputs, transform)

        c = get_cursor()
        c.execute("select id from rule where key = ?", [key])
        rule_id = c.fetchone()
        if rule_id != None:
            return rule_id[0]

        c.execute("insert into rule (transform, key) values (?, ?)", [transform, key])
        rule_id = c.lastrowid
        for name, objs in inputs:
            if not isinstance(objs, tuple):
                objs = [objs]
            for obj in objs:
                c.execute("insert into rule_input (rule_id, name, obj_id) values (?, ?, ?)", [rule_id, name, obj.id])

        rule = Rule(rule_id, inputs, transform)

        for add_rule_listener in self.add_rule_listeners:
            add_rule_listener(rule)

        return rule_id


class RulePending:
    def __init__(self, id, rule_id, inputs, outputs, transform):
        assertInputsValid(inputs)

        self.id = id
        self.transform = transform
        self.inputs = inputs
        self.rule_id = rule_id
        self.status = STATUS_READY
        self.outputs = outputs

    def __repr__(self):
        return "<Rule id:{} rule_id:{} inputs:{} outputs:{} transform:{}>".format(self.id, self.rule_id, self.inputs, self.outputs, self.transform)


class ExecutionLog:
    def __init__(self, obj_history):
        self.obj_history = obj_history

    def cancel_execution(self, rule_id):
        c = get_cursor()
        c.execute("update execution set status = ? where rule_id = ?", [STATUS_CANCELED, rule_id])

    def _make_copy_get_id(self, x):
        return self.obj_history.add(x.timestamp, x.props)

    def add_execution(self, rule):
        c = get_cursor()
        c.execute("insert into execution (rule_id, transform, status) values (?, ?, ?)", [rule.id, rule.transform, STATUS_READY])
        exec_id = c.lastrowid
        for name, objs in rule.inputs:
            is_list = True
            if isinstance(objs, Obj):
                objs = [objs]
                is_list = False
            for obj in objs:
                obj_id = self._make_copy_get_id(obj)
                c.execute("insert into execution_input (execution_id, name, obj_id, is_list) values (?, ?, ?, ?)", [exec_id, name, obj_id, is_list])
        return exec_id

    def _as_RuleList(self, c):
        pending = []
        for exec_id, rule_id, transform in c.fetchall():
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
                in_name_values.append( (name, values) )
            c.execute("select obj_id from execution_output where execution_id = ?", [exec_id])
            outputs = []
            for obj_id, in c.fetchall():
                outputs.append(self.obj_history.get(obj_id))
            pending.append(RulePending(exec_id, rule_id, tuple(in_name_values), outputs, transform))
        return pending

    def get_pending(self):
        c = get_cursor()
        c.execute("select id, rule_id, transform from execution where status = ?", [STATUS_READY])
        return self._as_RuleList(c)

    def get_all(self):
        c = get_cursor()
        c.execute("select id, rule_id, transform from execution")
        return self._as_RuleList(c)

    def record_completed(self, execution_id, new_status, outputs):
        c = get_cursor()
        c.execute("update execution set status = ? where id = ?", [new_status, execution_id])
        for x in outputs:
            obj_id = self._make_copy_get_id(x)
            c.execute("insert into execution_output (execution_id, obj_id) values (?, ?)", [execution_id, obj_id])

    def to_dot(self):
        """
        :return: a graphviz graph in dot syntax of all objects and rules created
        """
        stmts = []
        objs = {}
        #state_color = {WAITING:"gray", READY:"red", STARTED:"blue", FAILED:"green", COMPLETED:"turquoise"}
        for rule in self.get_all():
            for name, value in rule.inputs:
                if not isinstance(value, tuple):
                    value = [value]
                for v in value:
                    stmts.append("o{} -> r{} [label=\"{}\"]".format(v.id, rule.id, name))
                    objs[v.id] = v
                for output in rule.outputs:
                   stmts.append("r{} -> o{}".format(rule.id, output.id))
                   objs[output.id] = output

            #color=state_color[self.get_rule_state(rule.id)]
            color="gray"

            stmts.append("r{} [shape=box, label=\"{}\", style=\"filled\" fillcolor=\"{}\"]".format(rule.id, rule.transform, color))
        for obj in objs.values():
            label = "\\n".join([ "{}: {}".format(k, v) for k,v in obj.props.items() ])
            stmts.append("o{} [label=\"{}\"]".format(obj.id, label))
        return "digraph { " + (";\n".join(stmts)) + " } "

class ForEach:
    def __init__(self, variable, const_constraints = {}):
        assert variable != ""
        self.variable = variable
        self.const_constraints = const_constraints
#        for k, v in self.const_constraints.items():
#            assert isinstance(k, str)
#            assert isinstance(v, str)
    def __repr__(self):
        return "<ForEach {} where {}>".format(self.variable, self.const_constraints)

class ForAll:
    def __init__(self, variable, const_constraints = {}):
        self.variable = variable
        self.const_constraints = const_constraints

class PropEqualsConstant:
    def __init__(self, variable, property, constant):
        self.variable = variable
        self.property = property
        self.constant = constant

    def satisfied(self, bindings):
        return bindings[self.variable][self.property] == self.constant

class Template:
    def __init__(self, queries, predicates, transform, expected=None):
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

    def _predicate_satisifed(self, bindings):
        for p in self.predicates:
            if not p.satisified(bindings):
                return False
        return True

    def _create_rules(self, obj_set, bindings, queries):
        if len(queries) == 0:
            if self._predicate_satisifed(bindings):
                return [bindings]
            else:
                return []

        q_rest = queries[:-1]
        q = queries[-1]

        results = []
        for obj in obj_set.find(q.const_constraints):
            new_binding = dict(bindings)
            new_binding[q.variable] = obj

            results.extend(self._create_rules(obj_set, new_binding, q_rest))
        return results

    def _execute_forall_queries(self, bindings, obj_set):
        bindings = dict(bindings)
        for q in self.forall_queries:
            objs = tuple(obj_set.find(q.const_constraints))
            if len(objs) == 0:
                return None
            bindings[q.variable] = objs
        return bindings

    def create_rules(self, obj_set):
        print ("create_rules, transform:",self.transform,", queries: ", self.foreach_queries)
        if len(self.foreach_queries) == 0:
            bindings = [{}]
        else:
            bindings = self._create_rules(obj_set, {}, self.foreach_queries)

        results = []
        for b in bindings:
            b = self._execute_forall_queries(b, obj_set)
            if b == None:
                continue
            results.append( (tuple(b.items()), self.transform) )

        print ("Created rules for ",self.transform,": ", repr(results), repr(bindings))
        return results


class Jobs:
    """
        Top level class gluing everything together
    """
    def __init__(self, db):
        self.db = db
        self.rule_set = RuleSet()
        self.rule_templates = []
        self.objects = ObjSet("cur_obj")
        self.objects.add_listeners.append(self._object_added)
        self.log = ExecutionLog(ObjSet("past_obj"))
        self.rule_set.add_rule_listeners.append(self.log.add_execution)
        self.rule_set.remove_rule_listeners.append(self.log.cancel_execution)

    def _object_added(self, obj):
        new_rules = []
        for template in self.rule_templates:
            new_rules.extend(template.create_rules(self.objects))

        for rule in new_rules:
            self.rule_set.add_rule(*rule)

    def to_dot(self):
        with transaction(self.db):
            return self.log.to_dot()

    def add_template(self, template):
        with transaction(self.db):
            self.rule_templates.append(template)
            new_rules = template.create_rules(self.objects)
            for rule in new_rules:
                self.rule_set.add_rule(*rule)

    def add_obj(self, timestamp, obj_props, overwrite=True):
        """
        Used to record the creation of an object with a given timestamp

        :param obj_props: either a dict or sequence of (key, value) tuples
        :param timestamp:
        """

        with transaction(self.db):
            if not overwrite:
                existing = self.objects.find(obj_props)
                if len(existing) == 1:
                    return existing[0].id

            return self.objects.add(timestamp, obj_props)

    def get_pending(self):
        with transaction(self.db):
            return self.log.get_pending()

    def record_completed(self, timestamp, execution_id, new_status, outputs):
        with transaction(self.db):
            interned_outputs = []
            for output in outputs:
                obj_id = self.add_obj(timestamp, output)
                interned_outputs.append( self.objects.get(obj_id) )
            self.log.record_completed(execution_id, new_status, interned_outputs)

    def dump(self):
        with transaction(self.db):
            for obj in self.objects:
                print("obj:", obj)

def open_job_db(filename):
    needs_create = not os.path.exists(filename)

    db = sqlite3.connect(filename)

    if needs_create:
        stmts = [
            "create table rule (id INTEGER PRIMARY KEY   AUTOINCREMENT, transform STRING, key STRING)",
            "create table rule_input (id INTEGER PRIMARY KEY   AUTOINCREMENT, rule_id INTEGER, name string, obj_id INTEGER)",
            "create table cur_obj (id INTEGER PRIMARY KEY   AUTOINCREMENT, timestamp STRING, json STRING)",
            "create table past_obj (id INTEGER PRIMARY KEY   AUTOINCREMENT, timestamp STRING, json STRING)",
            "create table execution (id INTEGER PRIMARY KEY   AUTOINCREMENT, rule_id INTEGER, transform STRING, status STRING)",
            "create table execution_input (id INTEGER PRIMARY KEY   AUTOINCREMENT, execution_id INTEGER, name STRING, obj_id INTEGER, is_list INTEGER)",
            "create table execution_output (id INTEGER PRIMARY KEY   AUTOINCREMENT, execution_id INTEGER, obj_id INTEGER)",
            ]
        for stmt in stmts:
            db.execute(stmt)

    return Jobs(db)

