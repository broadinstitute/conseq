import textwrap

from typing import Any, Callable, Dict, List, Tuple, Union, Optional
from jinja2.environment import Environment
import os
from conseq.exec_client import (
    ResolveState,
)
from conseq.parser import Rule, RunStmt, TypeDefStmt
from ..execution import template_utils, cache
from ..types import ConfigType

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
        command, script_body = template_utils.expand_run(
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
