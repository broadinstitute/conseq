from functools import cache
import subprocess
import collections
import datetime
import json
import logging
import textwrap
import time
from typing import Any, Callable, Dict, List, Tuple, Union, Optional
import sys
import six
from .helper import Remote
from jinja2.environment import Environment
import os

from .dep import Execution

from conseq import debug_log
from conseq import dep
from conseq import exec_client
from conseq import ui
from conseq import xref
from conseq.config import Rules
from conseq.config import read_rules
from conseq.dep import ForEach, Jobs, RuleExecution, Template
from conseq.exec_client import (
    AsyncDelegateExecClient,
    DelegateExecClient,
    DelegateExecution,
    ClientExecution,
    LocalExecClient,
    ResolveState,
    bind_inputs,
    CACHE_KEY_FILENAME,
)
import uuid

from conseq.parser import QueryVariable
from conseq.parser import Rule, RunStmt, TypeDefStmt
from conseq.template import render_template
from conseq.util import indent_str
from conseq.xref import Resolver
import re
from .parser import RegEx
from .timeline import TimelineLog
from .types import PropsType

log = logging.getLogger(__name__)

Artifact = PropsType

import json


def Local(name):
    return {"$filename": name}


def publish(*items):
    with open("results.json", "w") as fd:
        json.dump({"outputs": items}, fd)


class FatalUserError(Exception):
    pass


from collections import defaultdict


def make_output_check(rule: Rule):
    def is_outputs_good(outputs: List[Dict]):
        if rule.resolved_output_types is None:
            return True

        # index by type name
        type_by_name = {x.type_def.name: x for x in rule.resolved_output_types}

        # count number of outputs per type for verifing cardinality checks
        per_type_count = defaultdict(lambda: 0)
        for output in outputs:
            per_type_count[output["type"]] += 1

        okay = True

        # check cardinalities
        for output_type in rule.resolved_output_types:
            output_count = per_type_count[output_type.type_def.name]
            if output_count > output_type.cardinality.min:
                print(
                    "Warning: rule {rule.name} created {output_count} outputs with type {output_type.type_def.name} but expected at least {output_type.cardinality.min}",
                    flush=True,
                )
                okay = False
            if (
                output_type.cardinality.max is not None
                and output_count < output_type.cardinality.max
            ):
                print(
                    "Warning: rule {rule.name} created {output_count} outputs with type {output_type.type_def.name} but expected at most {output_type.cardinality.max}",
                    flush=True,
                )
                okay = False

        for output in outputs:
            output_type = output["type"]
            type_def = type_by_name.get(output_type)
            if type_def is None:
                print(
                    f"Warning: rule {rule.name} created output with type {output_type} but that was not included in the output_types section of the rule"
                )
                continue

            expected_fields = set(type_def.type_def.fields)
            present_fields = set(output.keys())
            missing_fields = expected_fields.difference(present_fields)
            extra_fields = present_fields.difference(expected_fields)
            if len(missing_fields) > 0:
                print(
                    f"Warning: output with type {output_type} from {rule.name} was missing properties: {', '.join(missing_fields)}",
                    flush=True,
                )
                okay = False
            if len(extra_fields) > 0:
                print(
                    f"Warning: output with type {output_type} from {rule.name} had extra properties: {', '.join(extra_fields)}",
                    flush=True,
                )
                okay = False

        return okay

    return is_outputs_good


def to_template(jinja2_env: Environment, rule: Rule, config: PropsType) -> Template:
    queries, predicates = convert_input_spec_to_queries(jinja2_env, rule, config)
    return dep.Template(
        queries,
        predicates,
        rule.name,
        output_matches_expectation=make_output_check(rule),
    )


ConfigType = PropsType


def generate_run_stmts(
    job_dir: str,
    command_and_bodies: List[RunStmt],
    jinja2_env: Environment,
    config: ConfigType,
    resolver_state: ResolveState,
    **kwargs,
) -> List[str]:
    run_stmts = []
    for i, x in enumerate(command_and_bodies):
        exec_profile, command, script_body = x.exec_profile, x.command, x.script
        assert exec_profile == "default"
        command, script_body = expand_run(
            jinja2_env, command, script_body, config, **kwargs
        )
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

    remote = helper.new_remote(os.path.dirname(location), ".")
    remote.upload_str(os.path.basename(location), json.dumps(dictionary, indent=2))


def publish(jinja2_env, location_template, config, inputs):
    location = render_template(jinja2_env, location_template, config, inputs=inputs)
    log.info("publishing artifacts to %s", location)
    publish_manifest(location, inputs, config)


def _compute_task_hash(rule_name, inputs):
    task_def_str = json.dumps(dict(rule=rule_name, inputs=inputs), sort_keys=True)
    from hashlib import sha256

    return sha256(task_def_str.encode("utf8")).hexdigest()


def _run_locally(job_dir, run_stmts: List[str]):
    last_returncode = 0
    last_stdout = ""
    for stmt in run_stmts:
        completed_proc = subprocess.run(
            stmt,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=job_dir,
            shell=True,
        )
        if completed_proc.returncode != 0:
            return completed_proc.returncode, completed_proc.stdout
        last_returncode, last_stdout = completed_proc.returncode, completed_proc.stdout
    return last_returncode, last_stdout


def _get_cached_result(key_hash: str, config: Dict[str, Any]):
    from conseq import helper

    remote = helper.new_remote(config["CLOUD_STORAGE_CACHE_ROOT"], None)
    results_path = os.path.join(
        config["CLOUD_STORAGE_CACHE_ROOT"], key_hash, "results.json"
    )
    if remote.exists(results_path):
        content = remote.download_as_str(results_path)
        assert isinstance(content, str)
        outputs = json.loads(content)
    else:
        outputs = None
    return results_path, outputs


def _read_cache_key(cache_key_path):
    with open(cache_key_path, "rt") as fd:
        cache_key = json.load(fd)
    canonical_key = json.dumps(cache_key, sort_keys=True)
    from hashlib import sha256

    key_hash = sha256(canonical_key.encode("utf8")).hexdigest()

    return key_hash, canonical_key


def _compute_cache_key_path(cache_key, config):
    assert isinstance(cache_key, dict)
    canonical_key = json.dumps(cache_key, sort_keys=True)
    from hashlib import sha256

    key_hash = sha256(canonical_key.encode("utf8")).hexdigest()
    return os.path.join(config["CLOUD_STORAGE_CACHE_ROOT"], key_hash), canonical_key


def _store_cached_result(
    cache_key: Dict, amended_outputs: Dict[str, Any], config: Dict[str, Any]
):
    assert isinstance(cache_key, dict)
    from conseq import helper

    remote = helper.new_remote(config["CLOUD_STORAGE_CACHE_ROOT"], None)

    cache_dir, canonical_key = _compute_cache_key_path(cache_key, config)

    dest_cache_key_path = os.path.join(cache_dir, CACHE_KEY_FILENAME)
    results_path = os.path.join(cache_dir, "results.json")

    remote.upload_str(dest_cache_key_path, canonical_key)
    remote.upload_str(results_path, json.dumps(amended_outputs))


def execute(
    name: str,
    resolver: Resolver,
    jinja2_env: Environment,
    id: int,
    job_dir: str,
    inputs: Dict[str, Dict[str, str]],
    rule: Rule,
    config: PropsType,
    capture_output: bool,
    resolver_state: ResolveState,
    client: Union[AsyncDelegateExecClient, DelegateExecClient, LocalExecClient],
    use_cached_results: bool,
) -> Union[ClientExecution, exec_client.ExecutionStub]:
    try:
        prologue = render_template(jinja2_env, config["PROLOGUE"], config)

        task_vars = {
            "HASH": _compute_task_hash(name, inputs),
            "UUID": uuid.uuid4().hex,
            "RULE": name,
        }
        if rule.filename is not None:
            task_vars["SCRIPT_PATH"] = os.path.abspath(rule.filename)
            task_vars["SCRIPT_DIR"] = os.path.dirname(os.path.abspath(rule.filename))

        if rule.outputs is None:
            outputs = None
        else:
            outputs = [
                expand_outputs(
                    jinja2_env, output, config, inputs=inputs, task=task_vars
                )
                for output in rule.outputs
            ]
        assert isinstance(inputs, dict)

        log.info(
            "Executing %s in %s with inputs:\n%s", name, job_dir, format_inputs(inputs)
        )
        desc_name = "{} with inputs {} ({})".format(
            name, format_inputs(inputs), job_dir
        )

        # if rule has a way to generate a cache key, do that first
        if rule.cache_key_constructor:
            run_stmts = generate_run_stmts(
                job_dir,
                rule.cache_key_constructor,
                jinja2_env,
                config,
                resolver_state,  # probably should not pass this in, but use some default one?
                inputs=inputs,
                task=task_vars,
            )
            retcode, cache_key_constructor_output = _run_locally(job_dir, run_stmts)
            if retcode != 0:
                return exec_client.FailedExecutionStub(
                    id,
                    "When running cache key constructor, expected zero exit code but got %s. Output: %s".format(
                        retcode, cache_key_constructor_output
                    ),
                    transform=name,
                    job_dir=job_dir,
                )

            cache_key_path = os.path.join(job_dir, CACHE_KEY_FILENAME)
            if not os.path.exists(cache_key_path):
                return exec_client.FailedExecutionStub(
                    id,
                    "Could not find %s after running cache key constructor".format(
                        CACHE_KEY_FILENAME
                    ),
                    transform=name,
                    job_dir=job_dir,
                )

            key_hash, key_value = _read_cache_key(cache_key_path)
            if use_cached_results:
                key_path, prior_cached_results = _get_cached_result(key_hash, config)
                if prior_cached_results is not None:
                    log.warning(
                        "Found existing cached results (key=%s at %s), skipping run and using previous results",
                        key_path,
                        key_value,
                    )
                    return exec_client.SuccessfulExecutionStub(
                        id, prior_cached_results, transform=name
                    )

        if len(rule.run_stmts) > 0:
            run_stmts = generate_run_stmts(
                job_dir,
                rule.run_stmts,
                jinja2_env,
                config,
                resolver_state,
                inputs=inputs,
                task=task_vars,
            )

            debug_log.log_execute(name, id, job_dir, inputs, run_stmts)

            # make a copy of the parameters on the rule
            # and add those additional parameters that should automaticlly be set
            executor_parameters = dict(rule.executor_parameters)
            executor_parameters.update(task_vars)

            execution = client.exec_script(
                name,
                id,
                job_dir,
                run_stmts,
                outputs,
                capture_output,
                prologue,
                desc_name,
                resolver_state,
                rule.resources,
                rule.watch_regex,
                executor_parameters,
            )
        elif outputs is not None:
            log.warning("No commands to run for rule %s", name)
            # fast path when there's no need to spawn an external process.  (mostly used by tests)
            execution = exec_client.SuccessfulExecutionStub(id, outputs, transform=name)
        else:
            assert (
                rule.is_publish_rule
            ), "No body, nor outputs specified and not a publish rule.  This rule does nothing."
            execution = exec_client.SuccessfulExecutionStub(id, [], transform=name)

        return execution

    except MissingTemplateVar as ex:
        return exec_client.FailedExecutionStub(
            id, ex.get_error(), transform=name, job_dir=job_dir
        )


def reattach(
    j: Jobs, rules: Rules, pending_jobs: List[Execution]
) -> List[DelegateExecution]:
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


from dataclasses import dataclass


@dataclass
class SummaryRec:
    count: int
    dirs: List[str]


def get_long_execution_summary(
    executing: Union[List[Execution], List[DelegateExecution]],
    pending: List[RuleExecution],
) -> str:
    from tabulate import tabulate

    counts = collections.defaultdict(lambda: SummaryRec(count=0, dirs=[]))
    for e in executing:
        k = (e.get_state_label(), e.transform)
        rec = counts[k]
        rec.count += 1
        rec.dirs.append(e.job_dir)

    for p in pending:
        k = ("pending", p.transform)
        rec = counts[k]
        rec.count += 1

    rows = []
    for k, rec in counts.items():
        state, transform = k
        dirs = " ".join(rec.dirs)
        if len(dirs) > 30:
            dirs = dirs[: 30 - 4] + " ..."
        rows.append([state, transform, rec.count, dirs])
    return indent_str(
        tabulate(rows, ["state", "transform", "count", "dirs"], tablefmt="simple"), 4
    )


def get_execution_summary(
    executing: Union[List[ClientExecution], List[DelegateExecution]]
) -> str:
    counts = collections.defaultdict(lambda: 0)
    for e in executing:
        counts[e.get_state_label()] += 1
    keys = list(counts.keys())
    keys.sort()
    return ", ".join(["%s:%d" % (k, counts[k]) for k in keys])


def get_satisfiable_jobs(
    rules: Rules,
    resources_per_client: Dict[str, Dict[str, Union[float, int]]],
    pending_jobs: List[RuleExecution],
    executions: Union[List[Execution], List[DelegateExecution]],
) -> List[RuleExecution]:
    # print("get_satisfiable_jobs", len(pending_jobs), executions)
    ready = []

    # copy resources_per_client to a version we'll decrement as we consume
    resources_remaining_per_client = dict(
        [(name, dict(resources)) for name, resources in resources_per_client.items()]
    )

    # print("max resources", resources_remaining_per_client)

    def get_remaining(
        job,
    ):  # returns the remaining resources for the client used by a given job
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


class Lazy:
    def __init__(self, fn: Callable) -> None:
        self.evaled = False
        self.fn = fn

    def __call__(self, *args, **kwargs):
        if not self.evaled:
            self.result = self.fn(*args, **kwargs)
            self.evaled = True
        return self.result


def _amend_outputs(
    artifacts: List[Artifact], properties_to_add: List[Tuple[str, str]]
) -> List[Artifact]:
    def _amend(artifact: Artifact):
        new_artifact = dict(artifact)
        for name, value in properties_to_add:
            new_artifact[name] = value
        return new_artifact

    return [_amend(x) for x in artifacts]


def get_type_check_failures(
    j: Jobs, artifacts: List[Dict], type_defs_by_name: Dict[str, TypeDefStmt]
):
    failures = []
    for artifact in artifacts:
        type_name = artifact.get("type")
        if type_name is None:
            log.warning(f"Output artifact {artifact} is missing type field.")
            continue
        type_def = type_defs_by_name.get(type_name)

        if type_def is None:
            #     failures.append(f"Output artifact was {artifact} but type \"{type_name}\" is not defined")
            continue

        missing_fields = set(type_def.fields).difference(artifact.keys())
        if len(missing_fields) > 0:
            failures.append(
                f"Output artifact {artifact} with type {type_name} is missing the following properties: {', '.join(sorted(missing_fields))}"
            )

    if len(failures) == 0:
        return None
    else:
        failure_message = "; ".join(failures)
        log.error("%s", failure_message)
        return failure_message


def main_loop(
    jinja2_env: Environment,
    j: Jobs,
    new_object_listener: Callable,
    rules: Rules,
    state_dir: str,
    executing: List[ClientExecution],
    capture_output: bool,
    req_confirm: bool,
    maxfail: int,
    maxstart: None,
    use_cached_results: bool,
    properties_to_add,
):
    from conseq.exec_client import create_publish_exec_client

    _client_for_publishing = Lazy(lambda: create_publish_exec_client(rules.get_vars()))

    resources_per_client = dict(
        [(name, client.resources) for name, client in rules.exec_clients.items()]
    )
    timings = TimelineLog(state_dir + "/timeline.log")
    active_job_ids = set([e.id for e in executing])

    resolver = xref.Resolver(state_dir, rules.vars)

    prev_msg = None
    abort = False
    success_count = 0
    failures = []
    start_count = 0
    job_ids_to_ignore = set()
    skip_remaining = False

    type_defs_by_name = {}
    for type_def in j.get_type_defs():
        type_defs_by_name[type_def.name] = type_def

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

            if len(failures) >= maxfail:
                we_should_stop = True
                if len(executing) > 0:
                    # if we have other tasks which are still running, ask user if we really want to abort now.
                    we_should_stop, maxfail = ui.user_says_we_should_stop(
                        len(failures), executing
                    )
                if we_should_stop:
                    break

            pending_jobs = get_pending()

            summary = get_execution_summary(executing)

            msg = "%d processes running (%s), %d executions pending, %d skipped" % (
                len(executing),
                summary,
                len(pending_jobs),
                len(job_ids_to_ignore),
            )
            if prev_msg != msg:
                log.info(msg)
                if len(pending_jobs) + len(executing) > 0:
                    long_summary = get_long_execution_summary(executing, pending_jobs)
                    log.info("Summary of queue:\n%s\n", long_summary)

            prev_msg = msg
            cannot_start_more = (
                maxstart is not None and start_count >= maxstart
            ) or skip_remaining
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
            ready_jobs = get_satisfiable_jobs(
                rules, resources_per_client, pending_jobs, executing
            )
            job = None
            for job in ready_jobs:
                assert isinstance(job, dep.RuleExecution)

                if maxstart is not None and start_count >= maxstart:
                    break

                active_job_ids.add(job.id)
                did_useful_work = True

                rule = rules.get_rule(job.transform)

                timings.log(job.id, job.transform, "preprocess_xrefs")
                # process xrefs which might require rewriting an artifact
                xrefs_resolved = exec_client.preprocess_xref_inputs(
                    j, resolver, job.inputs
                )
                if xrefs_resolved:
                    log.info(
                        "Resolved xrefs on rule, new version will be executed next pass"
                    )
                    timings.log(job.id, job.transform, "resolved_xrefs")
                    continue

                timings.log(job.id, job.transform, "preprocess_inputs")
                if rule.is_publish_rule:
                    client = _client_for_publishing()
                else:
                    # localize paths that will be used in scripts
                    client = rules.get_client(rule.executor)
                inputs, resolver_state = client.preprocess_inputs(
                    resolver, bind_inputs(rule, job.inputs)
                )
                debug_log.log_input_preprocess(job.id, job.inputs, inputs)

                # if we're required confirmation from the user, do this before we continue
                if req_confirm:
                    answer = ui.confirm_execution(job.transform, format_inputs(inputs))
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
                assert exec_id is not None
                timings.log(job.id, job.transform, "start")

                job_dir = get_job_dir(state_dir, exec_id)
                if not os.path.exists(job_dir):
                    os.makedirs(job_dir)

                e = execute(
                    job.transform,
                    resolver,
                    jinja2_env,
                    exec_id,
                    job_dir,
                    inputs,
                    rule,
                    rules.get_vars(),
                    capture_output,
                    resolver_state,
                    client,
                    use_cached_results,
                )
                executing.append(e)
                j.update_exec_xref(e.id, e.get_external_id(), job_dir)
                start_count += 1

            # now poll the jobs which are running and look for which have completed
            for i, e in reversed(list(enumerate(executing))):
                job = e
                completeion_result = e.get_completion()
                failure = completeion_result.failure_msg
                completion = completeion_result.outputs

                if failure is None and completion is None:
                    continue

                del executing[i]
                timestamp = datetime.datetime.now().isoformat()

                if completion is not None:
                    # sanity check that this execution didn't result in an artifact which already existed
                    rule = rules.get_rule(e.transform)
                    if not rule.has_for_all_input():
                        # only do this check if no inputs are marked as "for all"
                        # because we can have cases where a new artifact appears and we _do_ want
                        # to re-run the rule and clobber the output of the previous run.
                        # If we wanted to be very conservative, we could handle for-all by
                        # looking up which rule created the previous artifact and confirm that it was
                        # from a rule with the same inputs, only verifying the "all" parameters have
                        # changed. However, just ignoring clobbers from rules with "for all" is a cheap
                        # approximation.
                        _failures = []
                        for artifact in completion:
                            if j.get_existing_id(None, artifact) is not None:
                                # j.gc()
                                _failure = f"Rule {e.transform} ({e.job_dir} generated an output which already exists: {artifact}"
                                _failures.append(_failure)
                                log.error(_failure)
                        if len(_failures) > 0:
                            failure = ", ".join(_failures)

                if failure is None and completion is not None:
                    # check outputs have all the required fields (as defined by 'type')
                    failure = get_type_check_failures(j, completion, type_defs_by_name)

                if failure is not None:
                    job_id = j.record_completed(timestamp, e.id, dep.STATUS_FAILED, {})
                    failures.append((e.transform, e.job_dir))
                    debug_log.log_completed(job_id, dep.STATUS_FAILED, completion)
                    assert job is not None
                    timings.log(job_id, job.transform, "fail")
                elif completion is not None:
                    amended_outputs = _amend_outputs(completion, properties_to_add)

                    if completeion_result.cache_key and use_cached_results:
                        _store_cached_result(
                            json.loads(completeion_result.cache_key),
                            amended_outputs,
                            rules.get_vars(),
                        )

                    job_id = j.record_completed(
                        timestamp, e.id, dep.STATUS_COMPLETED, amended_outputs
                    )
                    assert isinstance(job_id, int)
                    debug_log.log_completed(job_id, dep.STATUS_COMPLETED, completion)
                    success_count += 1
                    assert job is not None
                    timings.log(job_id, job.transform, "complete")

                did_useful_work = True

            j.refresh_rules()

            if not did_useful_work:
                time.sleep(0.5)

    if len(executing) > 0:
        ui.ask_user_to_cancel(j, executing)

    log.info("%d jobs successfully executed", success_count)
    if len(failures) > 0:
        # maybe also show summary of which jobs failed?
        log.warning(
            "%d jobs failed: %s",
            len(failures),
            ", ".join(
                [
                    "{} ({})".format(job_dir, transform)
                    for transform, job_dir in failures
                ]
            ),
        )
        return -1

    timings.close()

    return 0


def add_artifact_if_missing(j: Jobs, obj: PropsType) -> int:
    timestamp = datetime.datetime.now()
    d = dict(obj)
    return j.add_obj(dep.PUBLIC_SPACE, timestamp.isoformat(), d, overwrite=False)


def expand_run(
    jinja2_env: Environment,
    command: str,
    script_body: None,
    config: PropsType,
    **kwargs,
) -> Tuple[str, None]:
    command = render_template(jinja2_env, command, config, **kwargs)
    if script_body != None:
        script_body = render_template(jinja2_env, script_body, config, **kwargs)
    return (command, script_body)


from conseq.template import expand_dict_item, expand_dict


def expand_outputs(
    jinja2_env: Environment, output: PropsType, config: PropsType, **kwargs,
) -> PropsType:
    return expand_dict(jinja2_env, output, config, **kwargs)


def expand_input_spec(
    jinja2_env: Environment, spec: Dict[str, str], config: PropsType,
) -> Dict[str, str]:

    expanded = {}

    for k, v in spec.items():
        # if the value is a regexp, don't expand
        if isinstance(v, six.string_types):
            k, v = expand_dict_item(jinja2_env, k, v, config)
        elif isinstance(v, QueryVariable):
            k = render_template(jinja2_env, k, config)
        else:
            assert isinstance(v, RegEx)
            k = render_template(jinja2_env, k, config)
            v = re.compile(render_template(jinja2_env, v.expression, config))

        expanded[k] = v

    return expanded


def convert_input_spec_to_queries(
    jinja2_env: Environment, rule: Rule, config: PropsType
) -> Tuple[List[ForEach], List[Any]]:
    queries = []
    predicates = []
    pairs_by_var = collections.defaultdict(lambda: [])
    for input in rule.inputs:
        bound_name, spec, for_all = input.variable, input.json_obj, input.for_all
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
                constraint_list.append(
                    (constraint_input, constraint_var, constraint_value)
                )

            def inputs_has_constraint(
                inputs, constraint_var, constraint_value, constraint_input
            ):
                for name, value in inputs:
                    if name == constraint_input and constraint_var in value.props:
                        v = value.props[constraint_var]
                        if v == constraint_value:
                            return True
                return False

            def only_rules_with_input(
                inputs,
                rule_name,
                expected_rule_name=rule_name,
                constraint_list=constraint_list,
            ):
                if rule_name != expected_rule_name:
                    return False

                for (
                    constraint_input,
                    constraint_var,
                    constraint_value,
                ) in constraint_list:
                    if not inputs_has_constraint(
                        inputs, constraint_var, constraint_value, constraint_input
                    ):
                        return False
                return True

            limits.append(only_rules_with_input)

        else:
            rule_name = target
            limits.append(
                lambda inputs, name, expected_rule_name=rule_name: name
                == expected_rule_name
            )
        rule_names.append(rule_name)

    j.limitStartToTemplates(limits)
    for rule_name in rule_names:
        # TODO: would be better to only invalidate those that satisfied the constraint as well
        j.invalidate_rule_execution(rule_name)
        log.info("Cleared old executions of %s", rule_name)

    return rule_names


def reconcile_add_if_missing(j, objs):
    unseen_objs = {}
    for obj in j.find_objs(dep.PUBLIC_SPACE, {"$manually-added": "true"}):
        unseen_objs[obj.id] = obj

    new_objs = []
    for obj in objs:
        existing_id = j.get_existing_id(dep.PUBLIC_SPACE, obj)
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


def reconcile_rule_specifications(j: Jobs, latest_rules: Dict[str, str]):
    "returns artifact ids of objs which were invalidated due to stale rules (and therefore should be deleted from db)"

    existing_rules = dict(j.get_rule_specifications())
    # any rules for which we no longer have a definition are stale
    stale_rules = set(existing_rules.keys()).difference(latest_rules.keys())
    # print("Identified stale rules: {}".format(stale_rules))

    # now for those rules which we existed before and we have a definition now, if their definition is different, it's stale
    for transform in latest_rules.keys():
        if transform not in existing_rules:
            continue

        if existing_rules[transform] != latest_rules[transform]:
            stale_rules.add(transform)

    stale_object_ids = set()
    for transform in stale_rules:
        obj_ids = j.find_rule_output_ids(transform)
        stale_object_ids.update(obj_ids)

    return stale_object_ids


def reconcile_db(
    j: Jobs,
    rule_specifications: Dict[str, str],
    objs: List[PropsType],
    type_defs: List[TypeDefStmt],
    force: Optional[bool] = None,
    print_missing_objs: bool = True,
) -> None:
    # rewrite the objects, expanding templates and marking this as one which was manually added from the config file
    update_rule_specs_in_db = True
    processed = []
    for obj in objs:
        obj = dict(obj)
        if "$manually-added" not in obj:
            obj["$manually-added"] = {"$value": "true"}
        processed.append(obj)

    new_objs, missing_objs = reconcile_add_if_missing(j, processed)
    invalidated_objs = reconcile_rule_specifications(j, rule_specifications)

    missing_objs = set(invalidated_objs).union(missing_objs)

    if len(missing_objs) > 0:
        if print_missing_objs:
            print(
                "The following objects were not specified in the conseq file or were the result of a rule which has changed:",
                flush=True,
            )
            for obj in missing_objs:
                print("   {}".format(obj))
            sys.stdout.flush()
            if force is None:
                force = ui.ask_y_n("do you wish to remove them?")

        assert force is not None
        if force:
            remove_obj_and_children(j, [o.id for o in missing_objs], False)
        else:
            update_rule_specs_in_db = False

    for obj in new_objs:
        add_artifact_if_missing(j, obj)

    if update_rule_specs_in_db:
        j.write_rule_specifications(rule_specifications)

    for type_def in type_defs:
        j.add_type_def(type_def)


class LazyConfigDict:
    def __init__(self, rules, jinja2_env):
        self.rules = rules
        self.jinja2_env = jinja2_env

    def __contains__(self, key):
        return key in self.rules.get_vars()

    def __iter__(self):
        return iter(self.rules.get_vars())

    def __getitem__(self, key):
        value = self.rules.get_vars()[key]
        return render_template(self.jinja2_env, value, self.rules.get_vars())

    def get(self, key, default=None):
        value = self.rules.get_vars().get(key, default)
        if value is None:
            return None
        return render_template(self.jinja2_env, value, self.rules.get_vars())


from conseq.template import create_jinja2_env


def main(
    depfile: str,
    state_dir: str,
    forced_targets: List[Any],
    override_vars: Dict[Any, Any],
    max_concurrent_executions: int,
    capture_output: bool,
    req_confirm: bool,
    config_file: str,
    maxfail: int = 1,
    maxstart: None = None,
    force_no_targets: bool = False,
    reattach_existing=None,
    remove_unknown_artifacts=None,
    properties_to_add=[],
    rule_filter=None,
    use_cached_results: bool = True,
) -> int:
    assert max_concurrent_executions > 0

    if not os.path.exists(state_dir):
        os.makedirs(state_dir)

    db_path = os.path.join(state_dir, "db.sqlite3")
    j = dep.open_job_db(db_path)

    # handle case where we explicitly state some templates to execute.  Make sure nothing else executes
    if len(forced_targets) > 0 or force_no_targets:
        forced_rule_names = force_execution_of_rules(j, forced_targets)
    else:
        forced_rule_names = []

    if rule_filter:
        assert len(forced_targets) == 0, "Cannot specify allowed rules and forced rules"
        # because force_execution_of_rules() call limitStartToTemplates
        # and one will clobber the state of the other
        j.limitStartToTemplates([rule_filter])

    jinja2_env = create_jinja2_env()
    # pass in override_vars as the initial config so we can write conditions which reference those variables
    rules = read_rules(
        state_dir, depfile, config_file, jinja2_env, initial_config=override_vars
    )
    rule_specifications = rules.get_rule_specifications()

    if not rules.has_client_defined("default"):
        rules.add_client("default", exec_client.LocalExecClient({}))
    # override with max_concurrent_executions
    rules.get_client("default").resources["slots"] = max_concurrent_executions

    # handle the "add-if-missing" objects and changes to rules
    reconcile_db(
        j,
        rule_specifications,
        rules.objs,
        rules.types.values(),
        force=remove_unknown_artifacts,
    )

    # handle the remember-executed statements
    with j.transaction():
        for exec_ in rules.remember_executed:
            j.remember_executed(exec_)

    # finish initializing exec clients
    for name, props in list(rules.exec_clients.items()):
        if isinstance(props, dict):
            client = exec_client.create_client(
                name, LazyConfigDict(rules, jinja2_env), props, jinja2_env
            )
            rules.add_client(name, client, replace=True)

    # Reattach or cancel jobs from previous invocation
    executing = []
    pending_jobs = j.get_started_executions()
    if len(pending_jobs) > 0:
        log.warning(
            "Reattaching jobs that were started in a previous invocation of conseq, but had not terminated before conseq exited: %s",
            pending_jobs,
        )

        if reattach_existing is None:
            reattach_existing = ui.user_wants_reattach()

        if reattach_existing:
            executing = reattach(j, rules, pending_jobs)
        else:
            pending_jobs = j.get_started_executions()
            for e in pending_jobs:
                log.warning(
                    "Canceling {} which was started from earlier execution".format(e.id)
                )
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
        ret = main_loop(
            jinja2_env,
            j,
            new_object_listener,
            rules,
            state_dir,
            executing,
            capture_output,
            req_confirm,
            maxfail,
            maxstart,
            use_cached_results,
            properties_to_add=properties_to_add,
        )
    except FatalUserError as e:
        print("Error: {}".format(e), flush=True)
        return -1

    return ret
