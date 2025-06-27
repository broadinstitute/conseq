import collections
import json
import logging
from .exceptions import MissingObj
from typing import (
    Any,
    Callable,
    Literal,
    Dict,
    Iterator,
    List,
    Tuple,
    Union,
    Optional,
    Iterable,
    Sequence,
)
from .types import PropsType, BindingsDict, Obj
from conseq.db import get_cursor, transaction
from conseq.timeit import timeblock
from conseq.parser import TypeDefStmt
import dataclasses
from .dao.objects import ObjSet, ObjHistory
from .db import prepare_db_connection

log = logging.getLogger(__name__)

DISABLE_AUTO_CREATE_RULES = False

from .types import RE_STATUS_FAILED, STATUS_STARTED, STATUS_FAILED, STATUS_COMPLETED
from .model.objects import  PUBLIC_SPACE
from .dao.execution import RuleSet, ExecutionLog



from sqlite3 import Connection




from .query import ForAll, ForEach, PropsMatch

class Template:
    def __init__(
        self,
        queries: Sequence[Union[ForEach, ForAll]],
        predicates: Sequence[Any],
        transform: str,
        output_matches_expectation: Callable[[Any], bool] = lambda x: True,
    ):
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

                    ov = obj.props[k]
                    if isinstance(ov, dict):
                        ov = list(ov.values())[0]
                    if not v.match(ov):
                        matched = False
                        break
            if matched:
                return True
        return False

    @property
    def name(self) -> str:
        return self.transform

    def _predicate_satisifed(self, bindings: Dict[str, Obj]) -> bool:
        for p in self.predicates:
            if not p.satisfied(bindings):
                return False
        return True

    def _rewrite_queries(
        self, props_to_fix: List[Any], obj: Obj, queries: List[ForEach]
    ) -> List[ForEach]:
        # props_to_fix is a list of (prop name, list of (name, propr))
        q_map = dict([(q.variable, q) for q in queries])
        for prop, targets in props_to_fix:
            if prop in obj.props:
                value = obj[prop]
                for target_name, target_prop in targets:
                    if target_name in q_map:
                        q = q_map[target_name]
                        const_constraints = dict(q.const_constraints)
                        assert isinstance(value, str)
                        const_constraints[target_prop] = value
                        new_q = ForEach(q.variable, const_constraints)
                        q_map[target_name] = new_q
            else:
                # if the object is missing the prop, then there's no queries that should be done
                return [ForEach("_INVALID_", {"_INVALID_": "_INVALID_"})]
        return list(q_map.values())

    def _create_rules(
        self,
        obj_set: ObjSet,
        space: str,
        bindings: Dict[str, Obj],
        queries: List[ForEach],
    ) -> List[Dict[str, Obj]]:
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
                self._create_rules(
                    obj_set,
                    space,
                    new_binding,
                    self._rewrite_queries(props_to_fix, obj, q_rest),
                )
            )
        return results

    def _execute_forall_queries(
        self, bindings: BindingsDict, obj_set: ObjSet, space: str
    ) -> Optional[Dict[str, Union[Obj, Sequence[Obj]]]]:
        bindings = dict(bindings)
        for q in self.forall_queries:
            objs = tuple(obj_set.find(space, q.const_constraints))
            if len(objs) == 0:
                return None
            bindings[q.variable] = objs
        return bindings

    def create_rules(self, obj_set):
        with timeblock(log, "create_rules({})".format(self.transform), min_time=1):
            results = []
            for space in [PUBLIC_SPACE]:
                if len(self.foreach_queries) == 0 and space == obj_set.default_space:
                    bindings = [{}]
                else:
                    bindings = self._create_rules(
                        obj_set, space, {}, self.foreach_queries
                    )

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

    rule_template_by_name: Dict[str, Template]

    def __init__(self, db: Connection) -> None:
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

        for space, inputs, transform in new_rules:
            self._add_rule(space, inputs, transform)

    def _object_added(self, obj):
        new_rules = []
        if not DISABLE_AUTO_CREATE_RULES:
            for template in self.rule_templates:
                if template.is_interested_in(obj):
                    self.pending_rules_to_evaluate.add(template.transform)

        for space, inputs, transform in new_rules:
            self._add_rule(space, inputs, transform)

    def _add_rule(self, space: str, inputs: Any, transform: str) -> None:
        if self.rule_allowed(inputs, transform):
            self.rule_set.add_rule(space, inputs, transform)

    def add_new_obj_listener(self, listener: Callable) -> None:
        self.objects.add_listeners.append(listener)

    def transaction(self):
        return transaction(self.db)

    def query_template(self, template):
        with transaction(self.db):
            return template.create_rules(self.objects)

    def add_template(self, template: Template) -> None:
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
            pending_rules_to_evaluate = self.pending_rules_to_evaluate
            self.pending_rules_to_evaluate = set()
            for template in self.rule_templates:
                if template.transform not in pending_rules_to_evaluate:
                    continue
                new_rules = template.create_rules(self.objects)
                for rule in new_rules:
                    self._add_rule(*rule)
                    # log.info("Refreshed the following templates: %s, refresh_count=%s, added=%s", pending_rules_to_evaluate, refresh_count, add_executions)

    def get_existing_id(self, space, obj_props):
        # hardcoding default on space because "space" is no longer fully working. Really should get rid of it.
        if space is None:
            space = PUBLIC_SPACE
        with transaction(self.db):
            existing = self.objects.find_by_key(space, obj_props)
            if existing is not None:
                return existing.id
            return None

    def get_rule_specifications(self):
        with transaction(self.db):
            return self.rule_set.get_rule_specifications()

    def write_rule_specifications(self, rule_specs):
        with transaction(self.db):
            self.rule_set.write_rule_specifications(rule_specs)

    def add_type_def(self, type_def: TypeDefStmt):
        with transaction(self.db):
            c = get_cursor()
            # replace any existing type
            c.execute("delete from type_def where name = ?", [type_def.name])
            c.execute(
                "insert into type_def (name, definition_json) values (?, ?)",
                [type_def.name, json.dumps(dataclasses.asdict(type_def))],
            )

    def get_type_defs(self):
        with transaction(self.db):
            c = get_cursor()
            c.execute("select name, definition_json from type_def")
            typedefs = []
            for row in c.fetchall():
                typedefs.append(TypeDefStmt(**json.loads(row[1])))
            return typedefs

    def add_obj(self, space, timestamp, obj_props, overwrite=True):
        """
        Used to record the creation of an object with a given timestamp

        :param obj_props: either a dict or sequence of (key, value) tuples
        :param timestamp:
        """
        assert len(obj_props) > 0

        with transaction(self.db):
            if not overwrite:
                existing_id = self.get_existing_id(space, obj_props)
                if existing_id is not None:
                    return existing_id

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

    def find_all_reachable_downstream_objs(self, obj_ids):
        with transaction(self.db):
            obj_ids = self.log.find_all_reachable_downstream_objs(obj_ids)
            result = [self.objects.get(obj_id, must=False) for obj_id in obj_ids]
            return [x for x in result if x is not None]

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

    def enable_deferred(self) -> None:
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
            rule_exec = self.rule_set.get_by_execution_id(execution_id)
            if rule_exec is None:
                log.warning("Could not find rule for execution id %s", execution_id)
            else:
                rule_def = self.rule_template_by_name[rule_exec.transform]
                for output in outputs:
                    if not rule_def.output_matches_expectation(output):
                        log.warning(
                            'Output %s did not match any of the expected outputs on rule "%s"',
                            output,
                            rule_exec.transform,
                        )

            interned_outputs = []
            for output in outputs:
                space = PUBLIC_SPACE

                assert len(output.keys()) > 0
                obj_id = self.add_obj(space, timestamp, output)
                interned_outputs.append(self.objects.get(obj_id))
            return self._record_completed(execution_id, new_status, interned_outputs)

    def update_exec_xref(self, exec_id, xref, job_dir):
        with transaction(self.db):
            self.log.update_exec_xref(exec_id, xref, job_dir)

    def remember_executed(self, exec_stmt):
        space = PUBLIC_SPACE
        transform = exec_stmt.transform

        def resolve_obj(props):
            assert isinstance(props, dict)
            objs = self.objects.find(space, props)
            if len(objs) == 0:
                raise MissingObj()
            elif len(objs) != 1:
                raise Exception(
                    "Expected to find a single object with properties: {}, but found: {}".format(
                        props, objs
                    )
                )
            return objs[0]

        log.debug("Remembering execution: %s, %s", transform, exec_stmt.inputs)
        try:
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
        except MissingObj as ex:
            log.warning("Skipping remembering due to missing obj: {}".format(ex))

    def cleanup_unsuccessful(self) -> None:
        with transaction(self.db):
            self.rule_set.remove_unsuccessful()

    def get_objs_by_ids(self, ids):
        with transaction(self.db):
            objects = []
            for id in ids:
                object = self.objects.get(id)
                assert object is not None
                objects.append(object)
            return objects

    def find_rule_output_ids(self, transform):
        with transaction(self.db):
            self.rule_set.assert_db_sane()
            return [
                self.objects.get(id)
                for id in self.log.get_downstream_object_ids(transform)
            ]

    def invalidate_rule_execution(self, transform):
        with transaction(self.db):
            root_obj_ids = set()

            rules_to_remove = self.rule_set.find_by_name(transform)
            for r in rules_to_remove:
                # get all the objects that are downstream of this rule execution
                if r.execution_id is not None:
                    execution = self.log.get(r.execution_id)
                    assert execution is not None
                    root_obj_ids.update([o.id for o in execution.outputs])

            # now find all downstream objects
            all_objs = self.find_all_reachable_downstream_objs(root_obj_ids)
            for obj in all_objs:
                log.warning("invaliding rule %s, rm object %s", transform, obj)
                self.remove_objects([obj.id for obj in all_objs])

            for r in rules_to_remove:
                if r.execution_id is not None:
                    self.log.delete(r.execution_id)
                self.rule_set.remove_rule(r.id)

    def gc(self):
        """Deletes executions which are not associated with a reachable artifact."""
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
                # if the e has an output that is associated with an artifact, don't delete it
                # also, if e has no outputs, don't bother to clean it
                if not has_reachable_output(e) and len(e.outputs) > 0:
                    to_drop.append(e.id)

            for e_id in to_drop:
                self.log.delete(e_id)

        return to_drop

    def dump(self):
        with transaction(self.db):
            for obj in self.objects:
                print("obj:", obj)
            for rs in self.rule_set:
                print("rule:", rs)
            for job in self.log.get_all():
                print("all job:", job)




def open_job_db(filename: str) -> Jobs:
    db = prepare_db_connection(filename)
    return Jobs(db)


