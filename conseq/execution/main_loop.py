import time
import logging
from sched import scheduler
from typing import Any, Callable, Dict, List, Tuple, Union, Optional
from jinja2.environment import Environment
import os
from conseq.config import Rules
from .summary import get_execution_summary
from .. import exec_client
from . import cache
from .. import dep
from .. import ui
import json
import datetime
from ..types import Artifact, PropsType
from conseq.exec_client import (
    AsyncDelegateExecClient,
    DelegateExecClient,
    ClientExecution,
    LocalExecClient,
    ResolveState,
    bind_inputs,
    CACHE_KEY_FILENAME,
)
from . import runner
import subprocess
from conseq.parser import Rule, TypeDefStmt
from ..dep import Jobs
from .. import xref
from . import template_utils
from ..timeline import TimelineLog
from ..dao.execution import  RuleExecution

from conseq.template import render_template
from conseq.xref import Resolver
import uuid
from ..exceptions import MissingTemplateVar
from . import  scheduler
from .summary import get_long_execution_summary

from conseq import debug_log

log = logging.getLogger(__name__)

class Lazy:
    def __init__(self, fn: Callable) -> None:
        self.evaled = False
        self.fn = fn

    def __call__(self, *args, **kwargs):
        if not self.evaled:
            self.result = self.fn(*args, **kwargs)
            self.evaled = True
        return self.result


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
            ready_jobs = scheduler.get_satisfiable_jobs(
                rules, resources_per_client, pending_jobs, executing
            )
            job = None
            for job in ready_jobs:
                assert isinstance(job, RuleExecution)

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
                        cache._store_cached_result(
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
                template_utils.expand_outputs(
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
            run_stmts = runner.generate_run_stmts(
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

            key_hash, key_value = cache._read_cache_key(cache_key_path)
            if use_cached_results:
                key_path, prior_cached_results = cache._get_cached_result(key_hash, config)
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
            run_stmts = runner.generate_run_stmts(
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


def get_job_dir(state_dir: str, job_id: int) -> str:
    return os.path.join(state_dir, "r" + str(job_id))
