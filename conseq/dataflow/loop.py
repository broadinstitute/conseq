from .dataflow import DataFlow
import logging
import os
from dataclasses import dataclass
from typing import List
from conseq.depexec import (
    get_execution_summary,
    get_long_execution_summary,
    TimelineLog,
)
import datetime
from conseq.dep import STATUS_COMPLETED, STATUS_FAILED
from conseq.dep import RuleExecution, RuleSet, Jobs
from conseq.depexec import bind_inputs, publish, debug_log, get_job_dir, execute, Lazy
from typing import Callable, Sequence, Tuple
from conseq.exec_client import DelegateExecution, ExecClient
from conseq.exec_client import create_publish_exec_client

from conseq import ui
from conseq.xref import Resolver

log = logging.getLogger(__name__)


@dataclass
class Status:
    success_count: int
    failures = List[str]
    start_count: int
    pending_jobs: List[unknown]
    executing: List[Executions]


@dataclass
class Completion:
    failure: object
    completion: object
    timestamp: str


def _poll_until_next_completion(status: Status) -> List[Completion]:
    completions = []

    executing = status.executing
    pending_jobs = status.pending_jobs
    prev_msg = None
    while len(completions) == 0:
        # generate and print status message
        summary = get_execution_summary(executing)

        msg = "%d processes running (%s), %d executions pending" % (
            len(executing),
            summary,
            len(pending_jobs),
        )
        if prev_msg != msg:
            log.info(msg)
            if len(pending_jobs) + len(executing) > 0:
                long_summary = get_long_execution_summary(executing, pending_jobs)
                log.info("Summary of queue:\n%s\n", long_summary)

        # now poll the jobs which are running and look for which have completed
        for i, e in reversed(list(enumerate(executing))):
            result = e.get_completion()
            failure = result.failure_result
            completion = result.outputs

            if failure is None and completion is None:
                continue

            del executing[i]

            timestamp = datetime.datetime.now().isoformat()
            completions.append(Completion(failure, completion, timestamp))

    return completions


def _handle_completion(p: Completion, rules, status, properties_to_add):
    e, failure, completion, timestamp = p
    if completion is not None:
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

    if failure is not None:
        job_id = j.record_completed(timestamp, e.id, STATUS_FAILED, {})
        status.failures.append((e.transform, e.job_dir))
        debug_log.log_completed(job_id, STATUS_FAILED, completion)
        status.timings.log(job_id, "fail")
    elif completion is not None:
        amended_outputs = _amend_outputs(completion, properties_to_add)

        job_id = j.record_completed(timestamp, e.id, STATUS_COMPLETED, amended_outputs)
        debug_log.log_completed(job_id, STATUS_COMPLETED, completion)
        status.success_count += 1
        status.timings.log(job_id, "complete")


def _start_job(
    j : Jobs,
    state_dir: str,
    job: RuleExecution,
    rules: RuleSet,
    timings: TimelineLog,
    status: Status,
    get_client_for_publishing: Callable[[], ExecClient],
    resolver: Resolver,
    context,
):
    assert isinstance(job, RuleExecution)

    status.active_job_ids.add(job.id)

    rule = rules.get_rule(job.transform)
    if rule.is_publish_rule:
        client = get_client_for_publishing()
    else:
        # localize paths that will be used in scripts
        client = rules.get_client(rule.executor)

    timings.log(job.id, "preprocess_xrefs")
    # process xrefs which might require rewriting an artifact
    xrefs_resolved = client.preprocess_xref_inputs(j, resolver, job.inputs)
    if xrefs_resolved:
        log.info("Resolved xrefs on rule, new version will be executed next pass")
        timings.log(job.id, "resolved_xrefs")
        return

    timings.log(job.id, "preprocess_inputs")

    inputs, resolver_state = client.preprocess_inputs(
        resolver, bind_inputs(rule, job.inputs)
    )
    debug_log.log_input_preprocess(job.id, job.inputs, inputs)

    if rule.is_publish_rule:
        publish(context.jinja2_env, rule.publish_location, rules.get_vars(), inputs)

    # maybe record_started and update_exec_xref should be merged so anything started
    # always has an xref
    exec_id = j.record_started(job.id)
    timings.log(job.id, "start")

    job_dir = get_job_dir(state_dir, exec_id)
    if not os.path.exists(job_dir):
        os.makedirs(job_dir)

    e = execute(
        job.transform,
        resolver,
        context.jinja2_env,
        exec_id,
        job_dir,
        inputs,
        rule,
        rules.get_vars(),
        context.capture_output,
        resolver_state,
        client,
    )
    status.executing.append(e)
    j.update_exec_xref(e.id, e.get_external_id(), job_dir)
    status.start_count += 1


class ResourceCap:
    def __init__(self, exec_clients):
        self.resources_per_client = dict(
            [(name, client.resources) for name, client in exec_clients.items()]
        )

    def filter_out_unsatisfiable(self, jobs):
        raise NotImplemented

# TODO: pipeline for running job actually should be:
#    created execution
#    prepare execution artifacts
#    pending execution
#    runnable execution
#    started execution
#    Completed execution

def dataflow_main_loop(
    graph: DataFlow,
    jinja2_env: Environment,
    j: Jobs,
    rules: RuleSet,
    state_dir: str,
    executing: List[DelegateExecution],
    properties_to_add: Sequence[Tuple[str, str]],
    job_is_good_callback: Callable[
        [List[DelegateExecution], List[DelegateExecution]], bool
    ],
    should_we_stop_callback: Callable[[Status], bool],
) -> int:
    _client_for_publishing = Lazy(lambda: create_publish_exec_client(rules.get_vars()))

    timings = TimelineLog(state_dir + "/timeline.log")
    # active_job_ids = set([e.id for e in executing])

    resolver = Resolver(state_dir, rules.vars)
    resource_cap = ResourceCap(rules.exec_clients)

    # does not support re-attaching yet. Reattaching would require running through dataflow graph
    # and if we find ourselves wanting to start an existing run, then we could re-attach. Any jobs not
    # identified in the first pass should be canceled because we won't know what to do with the results
    # and it my mess up the execution plan.
    assert len(executing) == 0, "Re-attaching not yet supported"

    status = Status()

    with ui.capture_sigint() as was_interrupted_fn:
        while True:
            # handle ctrl-C
            interrupted = was_interrupted_fn()
            if interrupted:
                break

            # blocks until at least on job has completed.
            completed_execs = _poll_until_next_completion(status)
            for completed_exec in completed_execs:
                _handle_completion(completed_exec, rules, status, properties_to_add)

            if should_we_stop_callback(status):
                break

            next_jobs = _get_next_jobs(j, graph, completed_execs)

            # filter out any that we might not want to run (because the user is prompted and declines)
            next_jobs = [x for x in next_jobs if job_is_good_callback(x)]

            status.pending_jobs.extend(next_jobs)

            # now, find a subset of the pending jobs which we can start now (based on resource constraints),
            # and start them.
            ready_jobs = resource_cap.filter_out_unsatisfiable(
                status.pending_jobs, status.executing
            )

            # start each of these jobs
            for job in ready_jobs:
                _start_job(
                    j,
                    state_dir,
                    job,
                    rules,
                    timings,
                    status,
                    _client_for_publishing,
                    resolver,
                    context,
                )

    if len(status.executing) > 0:
        ui.ask_user_to_cancel(j, status.executing)

    # Wrap up by printing out summary message about completion/failures
    log.info("%d jobs successfully executed", status.success_count)
    if len(status.failures) > 0:
        # maybe also show summary of which jobs failed?
        log.warning(
            "%d jobs failed: %s",
            len(status.failures),
            ", ".join(
                [
                    "{} ({})".format(job_dir, transform)
                    for transform, job_dir in status.failures
                ]
            ),
        )
        return -1

    return 0
