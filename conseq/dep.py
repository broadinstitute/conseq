import json
import sqlite3
import os
import collections
import logging
import re

log = logging.getLogger(__name__)

class InstanceTemplate:
    def __init__(self, props):
        pass

STATUS_UNKNOWN = "unknown"
STATUS_READY = "ready"
STATUS_DEFERRED = "deferred"
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

def split_props_into_key_and_other(props):
    key_props = {}
    other_props = {}

    for k, v in props.items():
        if isinstance(v, dict) and len(v) == 1 and list(v.keys())[0].startswith("$"):
            other_props[k] = list(v.values())[0]
        else:
            key_props[k] = v

    return key_props, other_props

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
        return "<{} {}>".format(self.id, repr(self.props))

class ObjHistory:
    def __init__(self):
        pass

    def get(self, id):
        c = get_cursor()
        c.execute("select id, timestamp, json from past_obj where id = ?", [id])
        o = c.fetchone()
        if o == None:
            return None
        id, timestamp, _json = o
        return Obj(id, timestamp, json.loads(_json))

    def add(self, obj):
        # first check to see if this already exists
        if self.get(obj.id) != None:
            return

        c = get_cursor()
        c.execute("insert into past_obj (id, timestamp, json) values (?, ?, ?)", [obj.id, obj.timestamp, json.dumps(obj.props)])

class ObjSet:
    """
    Models the universe of all known artifacts.

    This prototype implementation does everything in memory but is intended to be replaced with one that read/writes to a persistent DB
    """
    def __init__(self):
        self.add_listeners = []
        self.remove_listeners = []

    def __iter__(self):
        c = get_cursor()
        c.execute("select id, timestamp, json from cur_obj")
        objs = []
        for id, timestamp, _json in c.fetchall():
            objs.append( Obj(id, timestamp, json.loads(_json)) )
        return iter(objs)

    def get(self, id):
        c = get_cursor()
        c.execute("select id, timestamp, json from cur_obj where id = ?", [id])
        id, timestamp, _json = c.fetchone()
        return Obj(id, timestamp, json.loads(_json))

    def remove(self, id):
        c = get_cursor()
        c.execute("delete from cur_obj where id = ?", [id])
        for remove_listener in self.remove_listeners:
            remove_listener(id)

    def add(self, timestamp, props):
        # first check to see if this already exists
        match = self.find_by_key(props)

        if match != None:
            if match.timestamp == timestamp:
                return match.id

            self.remove(match.id)

        c = get_cursor()
        c.execute("insert into cur_obj (timestamp, json) values (?, ?)", [timestamp, json.dumps(props)])
        id = c.lastrowid

        obj = Obj(id, timestamp, props)

        for add_listener in self.add_listeners:
            add_listener(obj)

        return id

    def find_by_key(self, props):
        key_props = split_props_into_key_and_other(props)[0]
        matches = self.find(key_props)
        if len(matches) > 1:
            raise Exception("Too many matches: key_props={}, matches={}".format(key_props, matches))
        elif len(matches) == 1:
            return matches[0]
        else:
            return None

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
        c = get_cursor()
        c.execute("select id, transform from rule")
        rules = c.fetchall()
        return iter(rules)

    def remove_rule(self, rule_id):
        c = get_cursor()
        c.execute("delete from rule where id = ?", [rule_id])
        rows = c.rowcount
        if rows > 0:
            for remove_rule_listener in self.remove_rule_listeners:
                remove_rule_listener(rule_id)
        return rows

    def _mk_rule_natural_key(self, inputs, transform):
        flattened_inputs = []
        for n, vs in inputs:
            if not isinstance(vs, tuple):
                vs = (vs,)
            flattened_inputs.append( (n, tuple([x.id for x in vs]))  )
        flattened_inputs.sort()
        return repr((tuple(flattened_inputs), transform))

    def find_by_input(self, input_id):
        c = get_cursor()
        c.execute("select rule_id from rule_input where obj_id = ?", [input_id])
        return [x[0] for x in c.fetchall()]

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
    def __init__(self, id, rule_id, inputs, outputs, transform, status, exec_xref, job_dir):
        assertInputsValid(inputs)

        self.id = id
        self.transform = transform
        self.inputs = inputs
        self.rule_id = rule_id
        self.status = status
        self.outputs = outputs
        self.exec_xref = exec_xref
        self.job_dir = job_dir

    def __repr__(self):
        return "<Rule id:{} rule_id:{} inputs:{} outputs:{} transform:{} status:{} exec_xref:{}>".format(self.id, self.rule_id, self.inputs, self.outputs, self.transform, self.status, self.exec_xref)


class ExecutionLog:
    def __init__(self, obj_history):
        self.obj_history = obj_history

    def enable_deferred(self):
        c = get_cursor()
        c.execute("update execution set status = ? where status = ?", [STATUS_READY, STATUS_DEFERRED])

    def cancel_execution(self, rule_id=None, exec_id=None):
        assert rule_id != None or exec_id != None
        c = get_cursor()
        if rule_id != None:
            c.execute("update execution set status = ? where rule_id = ?", [STATUS_CANCELED, rule_id])
        else:
            c.execute("update execution set status = ? where id = ?", [STATUS_CANCELED, exec_id])

    def _make_copy_get_id(self, x):
        self.obj_history.add(x)
        return x.id

    def add_execution(self, rule):
        status = STATUS_READY

        # look at the inputs, if any obj is a list (not a Obj), that implies this was a "forall" and we want to mark this as deferred
        for name, objs in rule.inputs:
            if not isinstance(objs, Obj):
                status = STATUS_DEFERRED

        c = get_cursor()
        c.execute("insert into execution (rule_id, transform, status) values (?, ?, ?)", [rule.id, rule.transform, status])
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
        for exec_id, rule_id, transform, status, exec_xref, job_dir in c.fetchall():
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

            outputs = []
            c.execute("select obj_id from execution_output where execution_id = ?", [exec_id])
            for obj_id, in c.fetchall():
                outputs.append(self.obj_history.get(obj_id))

            pending.append(RulePending(exec_id, rule_id, tuple(in_name_values), outputs, transform, status, exec_xref, job_dir))
        return pending

    def get(self, id):
        c = get_cursor()
        c.execute("select id, rule_id, transform, status, execution_xref, job_dir from execution where id = ?", [id])
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

    def get_pending(self):
        c = get_cursor()
        c.execute("select id, rule_id, transform, status, execution_xref, job_dir from execution where status = ?", [STATUS_READY])
        return self._as_RuleList(c)

    def get_by_output(self, obj):
        # probably won't really make a copy, just want to get the corresponding id
        obj_id = self._make_copy_get_id(obj)
        c = get_cursor()
        c.execute("select id, rule_id, transform, status, execution_xref, job_dir from execution e where exists (select 1 from execution_output o where o.execution_id = e.id and obj_id = ?)", [obj_id])
        return self._as_RuleList(c)

    def get_all(self):
        c = get_cursor()
        c.execute("select id, rule_id, transform, status, execution_xref, job_dir from execution")
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

            c.execute("select ei.obj_id from execution_output eo join execution e on eo.execution_id = e.id join execution_input ei on e.id = ei.execution_id where eo.obj_id = ?", [obj_id])
            input_obj_ids = [x[0] for x in c.fetchall()]

            for input_obj_id in input_obj_ids:
                if input_obj_id in objs_reached:
                    continue
                objs_to_explore.append(input_obj_id)
        return objs_reached

#    def compute_inputs_for_obj_map(self):
#        inputs_for_obj = {}
#        for rule in self.get_all():
#            obj_ids = [x.obj_id for x in rule.inputs]
#            for output in rule.outputs:
#                inputs_for_obj[output.id] = obj_ids


    def to_dot(self, detailed):
        """
        :return: a graphviz graph in dot syntax of all objects and rules created
        """
        stmts = []
        objs = {}
        #state_color = {WAITING:"gray", READY:"red", STARTED:"blue", FAILED:"green", COMPLETED:"turquoise"}
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

            #color=state_color[self.get_rule_state(rule.id)]
            color="gray"

            stmts.append("r{} [shape=box, label=\"{}\", style=\"filled\" fillcolor=\"{}\"]".format(rule.id, rule.transform, color))

        for obj in objs.values():
            prop_values = []
            for k,v in obj.props.items():
                if not isinstance(v, dict) or detailed:
                    prop_values.append("{}: {}".format(k, v))
            label = "\\n".join(prop_values)
            stmts.append("o{} [label=\"{}\"]".format(obj.id, label))
        return "digraph { " + (";\n".join(stmts)) + " } "

class ForEach:
    def __init__(self, variable, const_constraints = {}):
        assert variable != ""
        self.variable = variable
        self.const_constraints = const_constraints
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

class PropMatchesRegexp:
    def __init__(self, variable, property, regexp):
        self.variable = variable
        self.property = property
        self.regexp = re.compile(regexp)

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
            if not p.satisfied(bindings):
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
        #print ("create_rules, transform:",self.transform,", queries: ", self.foreach_queries)
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

        log.debug("Created rules for %s: %s", self.transform, results)
        return results

class RuleAndDerivativesFilter:
    def __init__(self, templateNames):
        self.templateNames = templateNames
        self.new_object_ids = set()

    def add_object(self, obj):
        self.new_object_ids.add(obj.id)

    def rule_allowed(self, inputs, transform):
        # if we are executing a rule we've explictly whitelisted
        if transform in self.templateNames:
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
                if obj.id in self.new_object_ids:
                    return True
        # All others should be dropped
        return False

class Jobs:
    """
        Top level class gluing everything together
    """
    def __init__(self, db):
        self.db = db
        self.rule_set = RuleSet()
        self.rule_templates = []
        self.objects = ObjSet()
        self.add_new_obj_listener(self._object_added)
        self.objects.remove_listeners.append(self._object_removed)
        self.log = ExecutionLog(ObjHistory())
        self.rule_set.add_rule_listeners.append(self.log.add_execution)
        self.rule_set.remove_rule_listeners.append(self.log.cancel_execution)
        self.rule_allowed = lambda inputs, transform: True

    def limitStartToTemplates(self, templateNames):
        filter = RuleAndDerivativesFilter(templateNames)
        self.rule_allowed = filter.rule_allowed
        self.add_new_obj_listener(filter.add_object)

    def _object_removed(self, obj):
        for rule_id in self.rule_set.find_by_input(obj):
            self.rule_set.remove_rule(rule_id)

        # forall might result in rules being recreated even without this input
        new_rules = []
        for template in self.rule_templates:
            new_rules.extend(template.create_rules(self.objects))

        for rule in new_rules:
            self._add_rule(rule)

    def _object_added(self, obj):
        new_rules = []
        for template in self.rule_templates:
            new_rules.extend(template.create_rules(self.objects))

        for rule in new_rules:
            self._add_rule(rule)

    def _add_rule(self, rule):
        inputs, transform = rule
        if self.rule_allowed(inputs, transform):
            self.rule_set.add_rule(*rule)

    def add_new_obj_listener(self, listener):
        self.objects.add_listeners.append(listener)

    def to_dot(self, detailed):
        with transaction(self.db):
            return self.log.to_dot(detailed)

    def query_template(self, template):
        with transaction(self.db):
            return template.create_rules(self.objects)

    def add_template(self, template):
        with transaction(self.db):
            self.rule_templates.append(template)
            new_rules = template.create_rules(self.objects)
            for rule in new_rules:
                self._add_rule(rule)

    def add_obj(self, timestamp, obj_props, overwrite=True):
        """
        Used to record the creation of an object with a given timestamp

        :param obj_props: either a dict or sequence of (key, value) tuples
        :param timestamp:
        """

        with transaction(self.db):
            if not overwrite:
                existing = self.objects.find_by_key(obj_props)
                if existing != None:
                    return existing.id

            return self.objects.add(timestamp, obj_props)

    def remove_obj(self, obj_id, with_invalidate):
        with transaction(self.db):
            obj = self.objects.get(obj_id)
            if with_invalidate:
                for x in self.log.get_by_output(obj):
                    self.rule_set.remove_rule(x.rule_id)
            self.objects.remove(obj_id)

    def find_objs(self, query):
        with transaction(self.db):
            return self.objects.find(query)

    def get_pending(self):
        with transaction(self.db):
            return self.log.get_pending()

    def get_all_executions(self):
        with transaction(self.db):
            return self.log.get_all()

    def enable_deferred(self):
        with transaction(self.db):
            return self.log.enable_deferred()

    def record_completed(self, timestamp, execution_id, new_status, outputs):
        with transaction(self.db):
            interned_outputs = []
            for output in outputs:
                obj_id = self.add_obj(timestamp, output)
                interned_outputs.append( self.objects.get(obj_id) )
            self.log.record_completed(execution_id, new_status, interned_outputs)
            if new_status == STATUS_FAILED:
                e = self.log.get(execution_id)
                self.rule_set.remove_rule(e.rule_id)

    def update_exec_xref(self, exec_id, xref, job_dir):
        with transaction(self.db):
            self.log.update_exec_xref(exec_id, xref, job_dir)

    def cancel_execution(self, exec_id):
        with transaction(self.db):
            e = self.log.get(exec_id)
            self.rule_set.remove_rule(e.rule_id)
            self.log.cancel_execution(exec_id=exec_id)

    def invalidate_rule_execution(self, transform):
        with transaction(self.db):
            count = 0
            for r in self.log.get_all():
                if r.transform != transform:
                    continue
                count += self.rule_set.remove_rule(r.rule_id)
        return count

    def gc(self, rm_callback):
        with transaction(self.db):
            root_objs = [o.id for o in self.objects]
            obj_ids = self.log.find_all_reachable_objs(root_objs)

            print("root_objs", root_objs)
            print("obj_ids", obj_ids)

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

    def dump(self):
        with transaction(self.db):
            for obj in self.objects:
                print("obj:", obj)
            for rs in self.rule_set:
                print("rule:", rs)
            for job in self.log.get_all():
                print("all job:", job)
            for job in self.log.get_pending():
                print("pending job:", job)

def open_job_db(filename):
    needs_create = not os.path.exists(filename)

    db = sqlite3.connect(filename)

    if needs_create:
        stmts = [
            "create table rule (id INTEGER PRIMARY KEY AUTOINCREMENT, transform STRING, key STRING)",
            "create table rule_input (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER, name string, obj_id INTEGER)",
            "create table cur_obj (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp STRING, json STRING)",
            "create table past_obj (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp STRING, json STRING)",
            "create table execution (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER, transform STRING, status STRING, execution_xref STRING, job_dir STRING)",
            "create table execution_input (id INTEGER PRIMARY KEY AUTOINCREMENT, execution_id INTEGER, name STRING, obj_id INTEGER, is_list INTEGER)",
            "create table execution_output (id INTEGER PRIMARY KEY AUTOINCREMENT, execution_id INTEGER, obj_id INTEGER)",
            ]
        for stmt in stmts:
            db.execute(stmt)

    return Jobs(db)

