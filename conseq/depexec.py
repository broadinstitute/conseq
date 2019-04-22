import collections
import datetime
import json
import logging
import os
import textwrap
import time
from typing import Any, Callable, Dict, List, Tuple, Union

import six
from jinja2.environment import Environment

from conseq import debug_log
from conseq import dep
from conseq import exec_client
from conseq import ui
from conseq import xref
from conseq.config import Rules
from conseq.config import read_rules
from conseq.dep import ForEach, Jobs, RuleExecution, Template
from conseq.exec_client import DelegateExecClient, DelegateExecution, Execution, LocalExecClient, ResolveState
from conseq.parser import QueryVariable
from conseq.parser import Rule, RunStmt
from conseq.template import MissingTemplateVar, render_template
from conseq.util import indent_str
from conseq.xref import Resolver

log = logging.getLogger(__name__)


class FatalUserError(Exception):
    pass


class JobFailedError(FatalUserError):
    pass


def to_template(jinja2_env: Environment, rule: Rule, config: Dict[str, Union[str, Dict[str, str]]]) -> Template:
    queries, predicates = convert_input_spec_to_queries(jinja2_env, rule, config)
    return dep.Template(queries, predicates, rule.name, output_matches_expectation=rule.output_matches_expectation)


ConfigType = Dict[str, Union[str, Dict[str, str]]]


def generate_run_stmts(job_dir: str, command_and_bodies: List[RunStmt], jinja2_env: Environment, config: ConfigType,
                       inputs: Dict[str, Dict[str, str]], resolver_state: ResolveState) -> List[str]:
    run_stmts = []
    for i, x in enumerate(command_and_bodies):
        exec_profile, command, script_body = x
        assert exec_profile == "default"
        command, script_body = expand_run(jinja2_env, command, script_body, config, inputs)
        if script_body != None:
            formatted_script_body = textwrap.dedent(script_body)
            script_name = os.path.abspath(os.path.join(job_dir, "script_%d" % i))
            with open(script_name, "w") as fd:
                fd.write(formatted_script_body)
            command += " " + os.path.relpath(script_name, job_dir)
            resolver_state.add_script(script_name)

        run_stmts.append(command)
    return run_stmts


def format_inputs(inputs: Dict[str, Dict[str, str]]) -> str:
    lines = []

    def append_kv(v):
        for prop, prop_value in v.items():
            lines.append("     {}: {}\n".format(prop, repr(prop_value)))

    for k, v in inputs.items():
        if isinstance(v, list):
            for vi, ve in enumerate(v):
                lines.append("  {}[{}]:\n".format(k, vi))
                append_kv(ve)
        else:
            lines.append("  {}:\n".format(k))
            append_kv(v)

    return "".join(lines)


def publish_manifest(location, dictionary, config):
    from conseq import helper
    accesskey = config['AWS_ACCESS_KEY_ID']
    secretaccesskey = config['AWS_SECRET_ACCESS_KEY']
    remote = helper.Remote(os.path.dirname(location), ".", accesskey=accesskey, secretaccesskey=secretaccesskey)
    remote.upload_str(os.path.basename(location), json.dumps(dictionary, indent=2))


def publish(jinja2_env, location_template, config, inputs):
    location = render_template(jinja2_env, location_template, config, inputs=inputs)
    log.info("publishing artifacts to %s", location)
    publish_manifest(location, inputs, config)


def execute(name: str, resolver: Resolver, jinja2_env: Environment, id: int, job_dir: str,
            inputs: Dict[str, Dict[str, str]], rule: Rule, config: Dict[str, Union[str, Dict[str, str]]],
            capture_output: bool, resolver_state: ResolveState,
            client: Union[DelegateExecClient, LocalExecClient]) -> Execution:
    try:
        prologue = render_template(jinja2_env, config["PROLOGUE"], config)

        if rule.outputs == None:
            outputs = None
        else:
            outputs = [expand_outputs(jinja2_env, output, config, inputs=inputs) for output in rule.outputs]
        assert isinstance(inputs, dict)

        log.info("Executing %s in %s with inputs:\n%s", name, job_dir, format_inputs(inputs))
        desc_name = "{} with inputs {} ({})".format(name, format_inputs(inputs), job_dir)

        if len(rule.run_stmts) > 0:
            run_stmts = generate_run_stmts(job_dir, rule.run_stmts, jinja2_env, config, inputs, resolver_state)

            debug_log.log_execute(name, id, job_dir, inputs, run_stmts)
            execution = client.exec_script(name,
                                           id,
                                           job_dir,
                                           run_stmts,
                                           outputs,
                                           capture_output,
                                           prologue,
                                           desc_name,
                                           resolver_state,
                                           rule.resources)
        elif outputs != None:
            log.warning("No commands to run for rule %s", name)
            # fast path when there's no need to spawn an external process.  (mostly used by tests)
            execution = exec_client.SuccessfulExecutionStub(id, outputs)
        else:
            assert rule.is_publish_rule, "No body, nor outputs specified and not a publish rule.  This rule does nothing."
            execution = exec_client.SuccessfulExecutionStub(id, [])

        return execution

    except MissingTemplateVar as ex:
        return exec_client.FailedExecutionStub(id, ex.get_error())


def reattach(j: Jobs, rules: Rules, pending_jobs: List[Execution]) -> List[DelegateExecution]:
    executing = []
    for e in pending_jobs:
        if e.exec_xref != None:
            rule = rules.get_rule(e.transform)
            client = rules.get_client(rule.executor)
            ee = client.reattach(e.exec_xref)
            executing.append(ee)
            log.warn("Reattaching existing job {}: {}".format(e.transform, e.exec_xref))
        else:
            log.warn("Canceling {}".format(e.id))
            j.cancel_execution(e.id)
    return executing


def get_job_dir(state_dir: str, job_id: int) -> str:
    return os.path.join(state_dir, "r" + str(job_id))


def get_long_execution_summary(executing: Union[List[Execution], List[DelegateExecution]],
                               pending: List[RuleExecution]) -> str:
    from tabulate import tabulate
    counts = collections.defaultdict(lambda: dict(count=0, dirs=[]))
    for e in executing:
        k = (e.get_state_label(), e.transform)
        rec = counts[k]
        rec['count'] += 1
        rec['dirs'].append(e.job_dir)

    for p in pending:
        k = ("pending", p.transform)
        rec = counts[k]
        rec['count'] += 1

    rows = []
    for k, rec in counts.items():
        state, transform = k
        dirs = " ".join(rec['dirs'])
        if len(dirs) > 30:
            dirs = dirs[:30 - 4] + " ..."
        rows.append([state, transform, rec['count'], dirs])
    return indent_str(tabulate(rows, ["state", "transform", "count", "dirs"], tablefmt="simple"), 4)


def get_execution_summary(executing: Union[List[Execution], List[DelegateExecution]]) -> str:
    counts = collections.defaultdict(lambda: 0)
    for e in executing:
        counts[e.get_state_label()] += 1
    keys = list(counts.keys())
    keys.sort()
    return ", ".join(["%s:%d" % (k, counts[k]) for k in keys])


def get_satisfiable_jobs(rules: Rules, resources_per_client: Dict[str, Dict[str, Union[float, int]]],
                         pending_jobs: List[RuleExecution],
                         executions: Union[List[Execution], List[DelegateExecution]]) -> List[RuleExecution]:
    # print("get_satisfiable_jobs", len(pending_jobs), executions)
    ready = []

    # copy resources_per_client to a version we'll decrement as we consume
    resources_remaining_per_client = dict([(name, dict(resources)) for name, resources in resources_per_client.items()])

    # print("max resources", resources_remaining_per_client)

    def get_remaining(job):  # returns the remaining resources for the client used by a given job
        rule = rules.get_rule(job.transform)
        return resources_remaining_per_client[rule.executor]

    for job in executions:
        rule = rules.get_rule(job.transform)
        resources = rule.resources
        # print("job.id={}, active_job_ids={}".format(repr(job.id), repr(active_job_ids)))
        resources_remaining = get_remaining(job)
        # print("decrementing ", job.transform, rules.get_rule(job.transform).executor, resources_remaining, " by ", resources)
        for resource, amount in resources.items():
            resources_remaining[resource] -= amount

    for job in pending_jobs:
        satisfiable = True
        rule = rules.get_rule(job.transform)
        resources = rule.resources
        resources_remaining = get_remaining(job)
        # print("for ", job.transform, rules.get_rule(job.transform).executor, resources_remaining)
        for resource, amount in resources.items():
            if resources_remaining[resource] < amount:
                satisfiable = False
                break

        if satisfiable:
            for resource, amount in resources.items():
                resources_remaining[resource] -= amount

            ready.append(job)

    return ready


class TimelineLog:
    def __init__(self, filename: str) -> None:
        if filename is not None:
            import csv
            is_new = not os.path.exists(filename)
            self.fd = open(filename, "at")
            self.w = csv.writer(self.fd)
            if is_new:
                self.w.writerow(["timestamp", "jobid", "status"])

        else:
            self.fd = None
            self.w = None

    def log(self, job_id: int, status: str) -> None:
        if self.fd is None:
            return
        self.w.writerow([datetime.datetime.now().isoformat(), job_id, status])
        self.fd.flush()

    def close(self):
        self.fd.close()
        self.fd = None
        self.w = None


class Lazy:
    def __init__(self, fn: Callable) -> None:
        self.evaled = False
        self.fn = fn

    def __call__(self, *args, **kwargs):
        if not self.evaled:
            self.result = self.fn(*args, **kwargs)
            self.evaled = True
        return self.result


def main_loop(jinja2_env: Environment, j: Jobs, new_object_listener: Callable, rules: Rules, state_dir: str,
              executing: List[DelegateExecution], capture_output: bool, req_confirm: bool, maxfail: int,
              maxstart: None) -> None:
    from conseq.exec_client import create_publish_exec_client
    _client_for_publishing = Lazy(lambda: create_publish_exec_client(rules.get_vars()))

    resources_per_client = dict([(name, client.resources) for name, client in rules.exec_clients.items()])
    timings = TimelineLog(state_dir + "/timeline.log")
    active_job_ids = set([e.id for e in executing])

    resolver = xref.Resolver(state_dir, rules.vars)

    prev_msg = None
    abort = False
    success_count = 0
    failure_count = 0
    start_count = 0
    job_ids_to_ignore = set()
    skip_remaining = False

    def get_pending():
        pending_jobs = j.get_pending()
        if skip_remaining:
            pending_jobs = []
            job_ids_to_ignore.update([pj.id for pj in pending_jobs])
        else:
            pending_jobs = [pj for pj in pending_jobs if pj.id not in job_ids_to_ignore]

        return pending_jobs

    with ui.capture_sigint() as was_interrupted_fn:
        while not abort:
            interrupted = was_interrupted_fn()
            if interrupted:
                break

            if failure_count >= maxfail:
                we_should_stop = True
                if len(executing) > 0:
                    # if we have other tasks which are still running, ask user if we really want to abort now.
                    we_should_stop, maxfail = ui.user_says_we_should_stop(failure_count, executing)
                if we_should_stop:
                    break

            pending_jobs = get_pending()

            summary = get_execution_summary(executing)

            msg = "%d processes running (%s), %d executions pending, %d skipped" % (
                len(executing), summary, len(pending_jobs), len(job_ids_to_ignore))
            if prev_msg != msg:
                log.info(msg)
                if len(pending_jobs) + len(executing) > 0:
                    long_summary = get_long_execution_summary(executing, pending_jobs)
                    log.info("Summary of queue:\n%s\n", long_summary)

            prev_msg = msg
            cannot_start_more = (maxstart is not None and start_count >= maxstart) or skip_remaining
            if len(executing) == 0 and (cannot_start_more or len(pending_jobs) == 0):
                # now that we've completed everything, check for deferred jobs by marking them as ready.  If we have any, loop again
                j.enable_deferred()
                deferred_jobs = len(get_pending())
                if deferred_jobs > 0 and not cannot_start_more:
                    log.info("Marked deferred %d executions as ready", deferred_jobs)
                    continue
                break

            did_useful_work = False

            # might be worth checking to see if the inputs are identical to previous call
            # to avoid wasting CPU time checking to schedule over and over when resources are exhausted.

            # also, the current design has an issue when rerunning part of of the execution tree.  Imagine
            # rule "A" produces "a1", "b1", and "c1", rule "T" transforms "a1" to "a2", "b1" to "b2, and "c1" to "c2".
            # Lastly rule F takes in a2, b2, and c2 and produces "f".
            # Now, everything is great if starting from a clean slate.  But we've run once, in the artifact db we have
            # a1, a2, b1, b2, c1, c2, f.   If we then rerun T, then we'll get the following executions:  (new objects denoted with
            # "*", old objects from previous run have no star.)
            # T(a1) -> a2*
            # F(a2*, b2, c2) -> f*
            # T(b1) -> b2*
            # F(a2*, b2*, c2) -> f*
            # T(c1) -> c2*
            # F(a2*, b2*, c2*) -> f*
            #
            # So in the end the right thing would get done.  However, we've run F three times as many as necessary.  If we
            # had a priority queue for work, then we could just set each rule execution priority to be the max(input.id)
            # That would force a breadth-first execution of the graph.  However, since jobs can execute in parallel,
            # priortizing is not enough.  (And we can't block based on priority or there'd be no parallelism!)
            #
            # ultimately, I don't think there's a shortcut, and we may need to check the DAG from the previous execution to see
            # if ancestor node is being re-executed, if so, prune that pending rule execution from the pending list until that
            # task is done.
            ready_jobs = get_satisfiable_jobs(rules, resources_per_client, pending_jobs, executing)
            for job in ready_jobs:
                assert isinstance(job, dep.RuleExecution)

                if maxstart is not None and start_count >= maxstart:
                    break

                active_job_ids.add(job.id)
                did_useful_work = True

                rule = rules.get_rule(job.transform)

                timings.log(job.id, "preprocess_xrefs")
                # process xrefs which might require rewriting an artifact
                xrefs_resolved = exec_client.preprocess_xref_inputs(j, resolver, job.inputs)
                if xrefs_resolved:
                    log.info("Resolved xrefs on rule, new version will be executed next pass")
                    timings.log(job.id, "resolved_xrefs")
                    continue

                timings.log(job.id, "preprocess_inputs")
                if rule.is_publish_rule:
                    client = _client_for_publishing()
                else:
                    # localize paths that will be used in scripts
                    client = rules.get_client(rule.executor)
                inputs, resolver_state = client.preprocess_inputs(resolver, job.inputs)
                debug_log.log_input_preprocess(job.id, job.inputs, inputs)

                # if we're required confirmation from the user, do this before we continue
                if req_confirm:
                    answer = ui.confirm_execution(job.transform, inputs)
                    if answer == "a":
                        req_confirm = False
                    elif answer == "q":
                        abort = True
                        break
                    elif answer == "s":
                        job_ids_to_ignore.add(job.id)
                        continue
                    elif answer == "S":
                        skip_remaining = True
                        break

                if rule.is_publish_rule:
                    publish(jinja2_env, rule.publish_location, rules.get_vars(), inputs)

                # maybe record_started and update_exec_xref should be merged so anything started
                # always has an xref
                exec_id = j.record_started(job.id)
                timings.log(job.id, "start")

                job_dir = get_job_dir(state_dir, exec_id)
                if not os.path.exists(job_dir):
                    os.makedirs(job_dir)

                e = execute(job.transform, resolver, jinja2_env, exec_id, job_dir, inputs, rule, rules.get_vars(),
                            capture_output, resolver_state, client)
                executing.append(e)
                j.update_exec_xref(e.id, e.get_external_id(), job_dir)
                start_count += 1

            # now poll the jobs which are running and look for which have completed
            new_completions = False
            for i, e in reversed(list(enumerate(executing))):
                failure, completion = e.get_completion()

                if failure == None and completion == None:
                    continue

                del executing[i]
                timestamp = datetime.datetime.now().isoformat()

                if failure != None:
                    job_id = j.record_completed(timestamp, e.id, dep.STATUS_FAILED, {})
                    failure_count += 1
                    debug_log.log_completed(job_id, dep.STATUS_FAILED, completion)
                    timings.log(job_id, "fail")
                elif completion != None:
                    job_id = j.record_completed(timestamp, e.id, dep.STATUS_COMPLETED, completion)
                    debug_log.log_completed(job_id, dep.STATUS_COMPLETED, completion)
                    success_count += 1
                    new_completions = True
                    timings.log(job_id, "complete")

                did_useful_work = True

            # if dep.DISABLE_AUTO_CREATE_RULES and new_completions:
            j.refresh_rules()

            if not did_useful_work:
                time.sleep(0.5)

    if len(executing) > 0:
        ui.ask_user_to_cancel(j, executing)

    log.info("%d jobs successfully executed", success_count)
    if failure_count > 0:
        # maybe also show summary of which jobs failed?
        log.warning("%d jobs failed", failure_count)
        return -1

    return 0


def _datetimefromiso(isostr):
    return datetime.datetime.strptime(isostr, "%Y-%m-%dT%H:%M:%S.%f")


def add_artifact_if_missing(j: Jobs, obj: Dict[str, Union[str, Dict[str, str]]]) -> int:
    timestamp = datetime.datetime.now()
    d = dict(obj)
    return j.add_obj(dep.DEFAULT_SPACE, timestamp.isoformat(), d, overwrite=False)


def expand_run(jinja2_env: Environment, command: str, script_body: None, config: Dict[str, Union[str, Dict[str, str]]],
               inputs: Dict[str, Dict[str, str]]) -> Tuple[str, None]:
    command = render_template(jinja2_env, command, config, inputs=inputs)
    if script_body != None:
        script_body = render_template(jinja2_env, script_body, config, inputs=inputs)
    return (command, script_body)


def expand_dict(jinja2_env: Environment, d: Dict[str, Union[str, Dict[str, str]]],
                config: Dict[str, Union[str, Dict[str, str]]], **kwargs) -> Dict[str, Union[str, Dict[str, str]]]:
    assert isinstance(d, dict)
    assert isinstance(config, dict)

    new_output = {}
    for k, v in d.items():
        #        print("expanding k", k)
        k = render_template(jinja2_env, k, config, **kwargs)
        # QueryVariables get introduced via expand input spec
        if not isinstance(v, QueryVariable):
            if isinstance(v, dict):
                v = expand_dict(jinja2_env, v, config, **kwargs)
            else:
                v = render_template(jinja2_env, v, config, **kwargs)
        new_output[k] = v

    return new_output


def expand_outputs(jinja2_env: Environment, output: Dict[str, Union[str, Dict[str, str]]],
                   config: Dict[str, Union[str, Dict[str, str]]], **kwargs) -> Dict[str, Union[str, Dict[str, str]]]:
    return expand_dict(jinja2_env, output, config, **kwargs)


def expand_input_spec(jinja2_env: Environment, spec: Dict[str, str], config: Dict[str, Union[str, Dict[str, str]]]) -> \
        Dict[str, str]:
    spec = dict(spec)
    regexps = {}
    for k, v in spec.items():
        # if the value is a regexp, don't expand
        if not isinstance(v, six.string_types):
            regexps[k] = v
    for k in regexps.keys():
        del spec[k]

    expanded = expand_dict(jinja2_env, spec, config)
    for k, v in regexps.items():
        expanded[k] = v
    return expanded


def convert_input_spec_to_queries(jinja2_env: Environment, rule: Rule, config: Dict[str, Union[str, Dict[str, str]]]) -> \
        Tuple[List[ForEach], List[Any]]:
    queries = []
    predicates = []
    pairs_by_var = collections.defaultdict(lambda: [])
    for bound_name, spec, for_all in rule.inputs:
        assert bound_name != ""
        spec = expand_input_spec(jinja2_env, spec, config)

        constants = {}
        for prop_name, value in spec.items():
            if isinstance(value, QueryVariable):
                pairs_by_var[value.name].append((bound_name, prop_name))
            else:
                constants[prop_name] = value
        if for_all:
            q = dep.ForAll(bound_name, constants)
        else:
            q = dep.ForEach(bound_name, constants)

        queries.append(q)

    for var, pairs in pairs_by_var.items():
        predicates.append(dep.PropsMatch(pairs))

    return queries, predicates


def select_space(state_dir, name, create_if_missing):
    db_path = os.path.join(state_dir, "db.sqlite3")
    j = dep.open_job_db(db_path)
    j.select_space(name, create_if_missing)


def print_spaces(state_dir):
    db_path = os.path.join(state_dir, "db.sqlite3")
    j = dep.open_job_db(db_path)
    current_space = j.get_current_space()
    for space in j.get_spaces():
        selected = "*" if current_space == space else " "
        print("{} {}".format(selected, space))


def force_execution_of_rules(j, forced_targets):
    import re
    rule_names = []
    limits = []
    for target in forced_targets:
        # handle syntax rulename:variable=value to limit to only executions where an input had that value
        m = re.match("([^:]+):(.*)", target)
        if m is not None:
            rule_name = m.group(1)
            constraints = m.group(2).split(",")
            constraint_list = []
            for constraint in constraints:
                m = re.match("([^.]+)\\.([^=]+)=(.*)", constraint)
                if m is None:
                    raise Exception("Could not parse target {}", repr(target))
                constraint_input = m.group(1)
                constraint_var = m.group(2)
                constraint_value = m.group(3)
                constraint_list.append((constraint_input, constraint_var, constraint_value))

            print(rule_name, constraint_list)

            def inputs_has_constraint(inputs, constraint_var, constraint_value, constraint_input):
                for name, value in inputs:
                    if name == constraint_input and constraint_var in value.props:
                        v = value.props[constraint_var]
                        if v == constraint_value:
                            return True
                return False

            def only_rules_with_input(inputs, rule_name, expected_rule_name=rule_name, constraint_list=constraint_list):
                if rule_name != expected_rule_name:
                    return False

                for constraint_input, constraint_var, constraint_value in constraint_list:
                    if not inputs_has_constraint(inputs, constraint_var, constraint_value, constraint_input):
                        return False
                return True

            limits.append(only_rules_with_input)

        else:
            rule_name = target
            limits.append(lambda inputs, name, expected_rule_name=rule_name: name == expected_rule_name)
        rule_names.append(rule_name)

    j.limitStartToTemplates(limits)
    for rule_name in rule_names:
        # TODO: would be better to only invalidate those that satisfied the constraint as well
        j.invalidate_rule_execution(rule_name)
        log.info("Cleared old executions of %s", rule_name)

    return rule_names


def reconcile_add_if_missing(j, objs):
    unseen_objs = {}
    for obj in j.find_objs(dep.DEFAULT_SPACE, {"$manually-added": "true"}):
        unseen_objs[obj.id] = obj

    new_objs = []
    for obj in objs:
        existing_id = j.get_existing_id(dep.DEFAULT_SPACE, obj)
        if existing_id is None:
            new_objs.append(obj)
        else:
            if existing_id in unseen_objs:
                del unseen_objs[existing_id]

    return new_objs, unseen_objs.values()


def remove_obj_and_children(j, root_obj_ids, dry_run):
    all_objs = j.find_all_reachable_downstream_objs(root_obj_ids)
    for obj in all_objs:
        log.warning("rm %s", obj)

    if not dry_run:
        j.remove_objects([obj.id for obj in all_objs])


def process_add_if_missing(j: Jobs, jinja2_env: Environment, objs: List[Dict[str, Union[str, Dict[str, str]]]],
                           vars: Dict[str, Union[str, Dict[str, str]]], force: bool = False) -> None:
    # rewrite the objects, expanding templates and marking this as one which was manually added from the config file
    processed = []
    for obj in objs:
        obj = dict(obj)
        if "$manually-added" not in obj:
            obj["$manually-added"] = {"$value": "true"}
        processed.append(expand_dict(jinja2_env, obj, vars))

    new_objs, missing_objs = reconcile_add_if_missing(j, processed)

    if len(missing_objs) > 0:
        print("The following objects were not specified in the conseq file:")
        for obj in missing_objs:
            print("   {}".format(obj))
        if force or ui.ask_y_n("do you wish to remove them?"):
            remove_obj_and_children(j, [o.id for o in missing_objs], False)

    for obj in new_objs:
        add_artifact_if_missing(j, obj)


def main(depfile: str, state_dir: str, forced_targets: List[Any], override_vars: Dict[Any, Any],
         max_concurrent_executions: int, capture_output: bool, req_confirm: bool,
         config_file: str, maxfail: int = 1, maxstart: None = None, force_no_targets: bool = False, reattach_existing=None) -> int:
    if not os.path.exists(state_dir):
        os.makedirs(state_dir)

    db_path = os.path.join(state_dir, "db.sqlite3")
    j = dep.open_job_db(db_path)

    # handle case where we explicitly state some templates to execute.  Make sure nothing else executes
    if len(forced_targets) > 0 or force_no_targets:
        forced_rule_names = force_execution_of_rules(j, forced_targets)
    else:
        forced_rule_names = []

    rules = read_rules(state_dir, depfile, config_file, initial_config={})
    jinja2_env = rules.jinja2_env

    if rules.get_client("default", must=False) is None:
        rules.add_client("default", exec_client.LocalExecClient({}))
    # override with max_concurrent_executions
    rules.get_client("default").resources["slots"] = max_concurrent_executions

    for var, value in override_vars.items():
        rules.set_var(var, value)

    # handle the "add-if-missing" objects
    process_add_if_missing(j, jinja2_env, rules.objs, rules.vars)

    # handle the remember-executed statements
    with j.transaction():
        for exec_ in rules.remember_executed:
            j.remember_executed(exec_)

    # finish initializing exec clients
    for name, props in list(rules.exec_clients.items()):
        if isinstance(props, dict):
            config = rules.get_vars()
            props = expand_dict(jinja2_env, props, config)

            class VirtualDict():
                def __getitem__(self, key):
                    value = rules.get_vars()[key]
                    return render_template(jinja2_env, value, config)

                def get(self, key, default=None):
                    value = rules.get_vars().get(key, default)
                    if value is None:
                        return None
                    return render_template(jinja2_env, value, config)

            client = exec_client.create_client(name, VirtualDict(), props)
            rules.add_client(name, client)

    # Reattach or cancel jobs from previous invocation
    executing = []
    pending_jobs = j.get_started_executions()
    if len(pending_jobs) > 0:
        log.warning(
            "Reattaching jobs that were started in a previous invocation of conseq, but had not terminated before conseq exited: %s",
            pending_jobs)

        if reattach_existing is None:
            reattach_existing = ui.user_wants_reattach()

        if reattach_existing:
            executing = reattach(j, rules, pending_jobs)
        else:
            pending_jobs = j.get_started_executions()
            for e in pending_jobs:
                log.warning("Canceling {} which was started from earlier execution".format(e.id))
                j.cancel_execution(e.id)

    # any jobs killed or other failures need to be removed so we'll attempt to re-run them
    j.cleanup_unsuccessful()

    assert len(j.get_pending()) == 0

    for dec in rules:
        try:
            j.add_template(to_template(jinja2_env, dec, rules.vars))
        except MissingTemplateVar as ex:
            log.error("Could not load rule {}: {}".format(dec.name, ex.get_error()))
            return -1

    # now check the rules we requested exist
    for rule_name in forced_rule_names:
        if not (j.has_template(rule_name)):
            raise Exception("No such rule: {}".format(rule_name))

    def new_object_listener(obj):
        timestamp = datetime.datetime.now().isoformat()
        j.add_obj(timestamp, obj)

    try:
        ret = main_loop(jinja2_env, j, new_object_listener, rules, state_dir, executing, capture_output, req_confirm, maxfail,
                        maxstart)
    except FatalUserError as e:
        print("Error: {}".format(e))
        return -1

    return ret
