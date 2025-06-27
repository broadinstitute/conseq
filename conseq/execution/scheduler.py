from conseq.config import Rules

from conseq.exec_client import (
    DelegateExecution,
)
from ..dao.execution import  RuleExecution, Execution

from typing import Any, Callable, Dict, List, Tuple, Union, Optional

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
