import datetime
import logging
from typing import Any, Callable, Dict, List, Tuple, Union, Optional
import os

from .dao.execution import Execution

from conseq import dep
from conseq import exec_client
from conseq import ui
from conseq.config import Rules
from conseq.config import read_rules
from conseq.dep import Jobs
from .exceptions import MissingTemplateVar
from conseq.template import render_template
from .execution import template_utils, reconcilation, main_loop
from conseq.template import create_jinja2_env
import re
from .exceptions import FatalUserError

log = logging.getLogger(__name__)



def reattach(
    j: Jobs, rules: Rules, pending_jobs: List[Execution]
) -> List[exec_client.DelegateExecution]:
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

def force_execution_of_rules(j, forced_targets):
    rule_names = []
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


        else:
            rule_name = target
        rule_names.append(rule_name)

    for rule_name in rule_names:
        # TODO: would be better to only invalidate those that satisfied the constraint as well
        j.invalidate_rule_execution(rule_name)
        log.info("Cleared old executions of %s", rule_name)

    return rule_names




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
    maxstart: Optional[int] = None,
    force_no_targets: bool = False,
    reattach_existing=None,
    remove_unknown_artifacts=None,
    properties_to_add=[],
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
    reconcilation.reconcile_db(
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
            j.add_template(template_utils.to_template(jinja2_env, dec, rules.vars))
        except MissingTemplateVar as ex:
            log.error("Could not load rule {}: {}".format(dec.name, ex.get_error()))
            return -1

    # now check the rules we requested exist
    for rule_name in forced_rule_names:
        if not (j.has_template(rule_name)):
            raise Exception("No such rule: {}".format(rule_name))

    try:
        ret = main_loop.main_loop(
            jinja2_env,
            j,
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
